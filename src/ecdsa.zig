//! CGGMP24 threshold ECDSA: 3-round presigning + 1-round signing.
//! Mirrors cggmp24/src/signing.rs (signing_n_out_of_n):
//!
//!   Round 1a (broadcast): K=Enc(k), G=Enc(γ), El-Gamal points Y,A1,A2,B1,B2
//!   Round 1b (p2p):       Πenc-elg for k (ψ⁰) and γ (ψ¹)
//!   Round 2  (p2p):       Γ_i, MtA ciphertexts D,F,D̂,F̂ + Πelog + 2×Πaff-g
//!   Round 3  (broadcast): δ_i, S_i, Δ_i + Πelog'
//!   Output:               presignature (Γ, k̃=k/δ, χ̃=χ/δ)
//!   Signing (1 round):    σ_i = k̃·m + r·χ̃  with r = Γ.x;  s = Σσ_i
//!
//! Effective nonce is γ: R = Γ = γG, s = γ⁻¹(m + r·x).
//! Parties hold ADDITIVE shares (x_i, X_i); t-of-n key shares are converted
//! via Lagrange coefficients before calling (see `toAdditive` helper).
//! Identifiable abort: on δ/S mismatch the protocol aborts without blame
//! (matching the reference; blame paths are future work).

const std = @import("std");
const Allocator = std.mem.Allocator;
const zk = @import("zk.zig");
const vss = @import("vss.zig");
const transcript = @import("transcript.zig");
const message = @import("message.zig");

const common = zk.common;
const Transcript = transcript.Transcript;
pub const ExecutionId = transcript.ExecutionId;

pub fn Ecdsa(comptime P: type, comptime E: type) type {
    comptime std.debug.assert(E.scalar_endian == .big); // Weierstrass curves only
    const Pl = common.Pail(P);
    const EncElg = zk.enc_elg.EncElg(P, E);
    const AffG = zk.aff_g.AffG(P, E);
    const Elog = zk.elog.Elog(E);
    const S = P.S;

    return struct {
        pub const PartyData = struct {
            ek: Pl.EncryptionKey,
            pedersen: common.Aux(P),
        };

        /// Everything a signer needs, with ADDITIVE key shares over the
        /// signing set indexed 1..n.
        pub const Keys = struct {
            /// This signer's 1-based index within the signing set.
            i: u16,
            /// Number of signers.
            n: u16,
            eid: ExecutionId,
            /// Additive secret share.
            x_i: E.Scalar,
            /// Additive public shares of every signer, indexed by signer-1.
            big_x: []const E.Point,
            /// Group public key (= Σ big_x).
            pk: E.Point,
            /// Own Paillier decryption key.
            dk: Pl.DecryptionKey,
            /// Every signer's Paillier + Pedersen data, indexed by signer-1.
            parties: []const PartyData,

            /// The invariants every round body relies on when it indexes
            /// `parties[i - 1]` / `big_x[i - 1]` and loops `1..=n`. round1
            /// checks these inline, but the CLI runs each later round in a
            /// separate process that reloads `Keys` from a decoded `State`, so
            /// a tampered frame with `i = 0` (u16 underflow to 65535) or
            /// `n > parties.len` would otherwise index out of bounds. Every
            /// round entry point revalidates.
            pub fn validate(self: Keys) !void {
                if (self.i < 1 or self.i > self.n or self.n < 2) return error.InvalidParams;
                if (self.big_x.len != self.n or self.parties.len != self.n) return error.InvalidParams;
            }
        };

        /// Convert a t-of-n VSS share to the additive share for a signing set.
        /// `signer_indices` are the original party indices of the signing set.
        pub fn toAdditive(secret_share: E.Scalar, signer_indices: []const u16, my_pos: usize) !E.Scalar {
            const lambda = try vss.lagrangeAtZero(E, signer_indices, my_pos);
            return lambda.mul(secret_share);
        }

        pub const From = message.From;
        pub const To = message.To;

        pub const Round1aBroadcast = struct {
            k_ct: Pl.Ciphertext,
            g_ct: Pl.Ciphertext,
            y: E.Point,
            a1: E.Point,
            a2: E.Point,
            b1: E.Point,
            b2: E.Point,
        };

        pub const Round1bP2p = struct {
            psi0: EncElg.Proof,
            psi1: EncElg.Proof,
        };

        pub const Round2P2p = struct {
            gamma: E.Point,
            d: Pl.Ciphertext,
            f: Pl.Ciphertext,
            hat_d: Pl.Ciphertext,
            hat_f: Pl.Ciphertext,
            tilde_psi: Elog.Proof,
            psi: AffG.Proof,
            hat_psi: AffG.Proof,
        };

        pub const Round3Broadcast = struct {
            delta: E.Scalar,
            s_pt: E.Point,
            delta_pt: E.Point,
            psi_prime: Elog.Proof,
        };

        pub const Presignature = struct {
            gamma: E.Point,
            tilde_k: E.Scalar,
            tilde_chi: E.Scalar,

            pub fn zeroize(self: *Presignature) void {
                self.tilde_k.zeroize();
                self.tilde_chi.zeroize();
            }
        };

        /// A signer's contribution to one signature.
        ///
        /// It carries Γ as well as σ_i so that combining needs nothing but the
        /// partials: Γ is public (it is the signature's r), so including it
        /// costs nothing, and it spares every signer from keeping a used
        /// presignature alive.
        pub const PartialSig = struct {
            gamma: E.Point,
            sigma: E.Scalar,
        };

        pub const Signature = struct {
            r: E.Scalar,
            s: E.Scalar,
        };

        // ------------------------------------------------------------------
        // helpers
        // ------------------------------------------------------------------

        /// Curve scalar → signed integer in ±q/2 (the reference's
        /// `scalar_to_pm_bignumber`).
        fn scalarToPm(s_: E.Scalar) S {
            const enc = E.Scalar.encoded_length;
            const be = s_.toBytes();
            // q/2
            const half = comptime blk: {
                var h = E.order_be;
                var carry: u8 = 0;
                for (&h) |*b| {
                    const next: u8 = b.* & 1;
                    b.* = (carry << 7) | (b.* >> 1);
                    carry = next;
                }
                break :blk h;
            };
            if (std.mem.order(u8, &be, &half) != .gt) {
                var mag: P.FInt.Bytes = @splat(0);
                @memcpy(mag[P.FInt.num_bytes - enc ..], &be);
                return S.fromMag(mag);
            }
            const neg_be = s_.neg().toBytes();
            var mag: P.FInt.Bytes = @splat(0);
            @memcpy(mag[P.FInt.num_bytes - enc ..], &neg_be);
            return (S{ .neg = true, .mag = mag }).canonPub();
        }

        /// Paillier decrypt into a signed value in (-N/2, N/2).
        fn decryptSigned(dk: Pl.DecryptionKey, ct: Pl.Ciphertext) !S {
            const m = try dk.decrypt(ct);
            var half_n = dk.ek.n;
            var carry: u8 = 0;
            for (&half_n) |*b| {
                const next: u8 = b.* & 1;
                b.* = (carry << 7) | (b.* >> 1);
                carry = next;
            }
            if (P.Fn.cmp(m, half_n) != .gt) {
                return S.fromMag(P.lift(P.Fn, m));
            }
            const mag = P.Fn.sub(dk.ek.n, m);
            return (S{ .neg = true, .mag = P.lift(P.Fn, mag) }).canonPub();
        }

        /// x-coordinate of a point reduced into a scalar.
        fn scalarFromX(pt: E.Point) E.Scalar {
            const x_bytes = pt.xOnly();
            var wide: [64]u8 = @splat(0);
            @memcpy(wide[64 - x_bytes.len ..], &x_bytes);
            return E.Scalar.fromWideBytes(wide);
        }

        fn encTranscript(eid: ExecutionId, prover: u16, num: u8) Transcript {
            var t = Transcript.init("zig-mpc/ecdsa/proof-enc/v1");
            t.appendExecutionId(eid);
            t.appendU64("prover", prover);
            t.appendU64("num", num);
            return t;
        }

        fn psiTranscript(eid: ExecutionId, prover: u16, hat: bool) Transcript {
            var t = Transcript.init("zig-mpc/ecdsa/proof-psi/v1");
            t.appendExecutionId(eid);
            t.appendU64("prover", prover);
            t.appendU64("hat", @intFromBool(hat));
            return t;
        }

        fn elogTranscript(eid: ExecutionId, prover: u16, prime: bool) Transcript {
            var t = Transcript.init("zig-mpc/ecdsa/proof-elog/v1");
            t.appendExecutionId(eid);
            t.appendU64("prover", prover);
            t.appendU64("prime", @intFromBool(prime));
            return t;
        }

        // ------------------------------------------------------------------
        // presigning
        // ------------------------------------------------------------------

        pub const State1 = struct {
            keys: Keys,
            gamma_i: E.Scalar,
            k_i: E.Scalar,
            v_i: Pl.Nonce,
            rho_i: Pl.Nonce,
            y_i: E.Point,
            a_i: E.Scalar,
            b_i: E.Scalar,
            own_1a: Round1aBroadcast,
        };

        pub const Round1Result = struct {
            state: State1,
            broadcast: Round1aBroadcast,
            /// One entry per other signer, addressed to that signer.
            p2p: []To(Round1bP2p),
        };

        pub fn round1(allocator: Allocator, keys: Keys, rng: std.Random) !Round1Result {
            try keys.validate();

            const gamma_i = E.Scalar.random(rng);
            const k_i = E.Scalar.random(rng);
            const ek_i = keys.dk.ek;
            const v_i = ek_i.randomNonce(rng);
            const rho_i = ek_i.randomNonce(rng);

            const g_ct = try common.encryptSigned(P, ek_i, scalarToPm(gamma_i), v_i);
            const k_ct = try common.encryptSigned(P, ek_i, scalarToPm(k_i), rho_i);

            const y_secret = E.Scalar.random(rng);
            const y_i = common.baseMul(E, y_secret);
            const a_i = E.Scalar.random(rng);
            const b_i = E.Scalar.random(rng);
            const bcast = Round1aBroadcast{
                .k_ct = k_ct,
                .g_ct = g_ct,
                .y = y_i,
                .a1 = common.baseMul(E, a_i),
                .a2 = common.pointMulPub(E, y_i, a_i).add(common.baseMul(E, k_i)),
                .b1 = common.baseMul(E, b_i),
                .b2 = common.pointMulPub(E, y_i, b_i).add(common.baseMul(E, gamma_i)),
            };

            const p2p = try allocator.alloc(To(Round1bP2p), keys.n - 1);
            errdefer allocator.free(p2p);
            var k: usize = 0;
            var j: u16 = 1;
            while (j <= keys.n) : (j += 1) {
                if (j == keys.i) continue;
                const r_j = keys.parties[j - 1].pedersen;
                const psi0 = try EncElg.prove(encTranscript(keys.eid, keys.i, 0), rng, r_j, .{
                    .ek = ek_i,
                    .c = k_ct,
                    .a = y_i,
                    .b = bcast.a1,
                    .x = bcast.a2,
                }, .{ .plaintext = scalarToPm(k_i), .nonce = rho_i, .b = a_i });
                const psi1 = try EncElg.prove(encTranscript(keys.eid, keys.i, 1), rng, r_j, .{
                    .ek = ek_i,
                    .c = g_ct,
                    .a = y_i,
                    .b = bcast.b1,
                    .x = bcast.b2,
                }, .{ .plaintext = scalarToPm(gamma_i), .nonce = v_i, .b = b_i });
                p2p[k] = .{ .to = j, .msg = .{ .psi0 = psi0, .psi1 = psi1 } };
                k += 1;
            }

            return .{
                .state = .{
                    .keys = keys,
                    .gamma_i = gamma_i,
                    .k_i = k_i,
                    .v_i = v_i,
                    .rho_i = rho_i,
                    .y_i = y_i,
                    .a_i = a_i,
                    .b_i = b_i,
                    .own_1a = bcast,
                },
                .broadcast = bcast,
                .p2p = p2p,
            };
        }

        pub const State2 = struct {
            s1: State1,
            peers_1a: []?Round1aBroadcast, // indexed by signer-1 (own = null)
            beta_sum: E.Scalar,
            hat_beta_sum: E.Scalar,
            gamma_pt: E.Point, // Γ_i
            allocator: Allocator,

            pub fn deinit(self: *State2) void {
                self.allocator.free(self.peers_1a);
                self.* = undefined;
            }
        };

        pub const Round2Result = struct {
            state: State2,
            /// One entry per other signer, addressed to that signer.
            p2p: []To(Round2P2p),
        };

        pub fn round2(
            allocator: Allocator,
            state: State1,
            incoming_1a: []const From(Round1aBroadcast),
            incoming_1b: []const From(Round1bP2p),
            rng: std.Random,
        ) !Round2Result {
            const keys = state.keys;
            try keys.validate();
            const n = keys.n;
            if (incoming_1a.len != n - 1 or incoming_1b.len != n - 1) return error.MissingMessage;

            const peers = try allocator.alloc(?Round1aBroadcast, n);
            errdefer allocator.free(peers);
            @memset(peers, null);

            const r_i = keys.parties[keys.i - 1].pedersen;

            for (incoming_1a) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == keys.i) return error.InvalidSender;
                if (peers[j - 1] != null) return error.DuplicateMessage;

                // find the matching proofs
                var proofs: ?Round1bP2p = null;
                for (incoming_1b) |pm| {
                    if (pm.from == j) proofs = pm.msg;
                }
                const pf = proofs orelse return error.MissingMessage;

                const ek_j = keys.parties[j - 1].ek;
                EncElg.verify(encTranscript(keys.eid, j, 0), r_i, .{
                    .ek = ek_j,
                    .c = m.msg.k_ct,
                    .a = m.msg.y,
                    .b = m.msg.a1,
                    .x = m.msg.a2,
                }, pf.psi0) catch return error.InvalidEncProof;
                EncElg.verify(encTranscript(keys.eid, j, 1), r_i, .{
                    .ek = ek_j,
                    .c = m.msg.g_ct,
                    .a = m.msg.y,
                    .b = m.msg.b1,
                    .x = m.msg.b2,
                }, pf.psi1) catch return error.InvalidEncProof;

                peers[j - 1] = m.msg;
            }
            for (peers, 0..) |p, idx| {
                if (idx != keys.i - 1 and p == null) return error.MissingMessage;
            }

            const gamma_pt = common.baseMul(E, state.gamma_i);
            const tilde_psi = try Elog.prove(elogTranscript(keys.eid, keys.i, false), rng, .{
                .l = state.own_1a.b1,
                .m = state.own_1a.b2,
                .x = state.y_i,
                .y = gamma_pt,
                .h = E.Point.generator,
            }, state.gamma_i, state.b_i);

            const ek_i = keys.dk.ek;
            const j_bound = P.pow2(P.l_y);
            var beta_sum = E.Scalar.zero;
            var hat_beta_sum = E.Scalar.zero;

            const p2p = try allocator.alloc(To(Round2P2p), n - 1);
            errdefer allocator.free(p2p);
            var out_k: usize = 0;
            var j: u16 = 1;
            while (j <= n) : (j += 1) {
                if (j == keys.i) continue;
                const peer = peers[j - 1].?;
                const ek_j = keys.parties[j - 1].ek;
                const r_j = keys.parties[j - 1].pedersen;

                const r_ij = ek_i.randomNonce(rng);
                const hat_r_ij = ek_i.randomNonce(rng);
                const s_ij = ek_j.randomNonce(rng);
                const hat_s_ij = ek_j.randomNonce(rng);

                const beta_ij = S.sampleHalfPm(rng, j_bound);
                const hat_beta_ij = S.sampleHalfPm(rng, j_bound);
                beta_sum = beta_sum.add(common.toCurveScalar(P, E, beta_ij));
                hat_beta_sum = hat_beta_sum.add(common.toCurveScalar(P, E, hat_beta_ij));

                // D_ji = γ_i ⊙ K_j ⊕ Enc_j(-β_ij; s_ij)
                const gamma_pm = scalarToPm(state.gamma_i);
                const d_ji = blk: {
                    const gk = try common.homMulSigned(P, ek_j, peer.k_ct, gamma_pm);
                    const nb = try common.encryptSigned(P, ek_j, beta_ij.negate(), s_ij);
                    break :blk ek_j.homAdd(gk, nb);
                };
                const f_ji = try common.encryptSigned(P, ek_i, beta_ij.negate(), r_ij);

                // D̂_ji = x_i ⊙ K_j ⊕ Enc_j(-β̂_ij; ŝ_ij)
                const x_pm = scalarToPm(keys.x_i);
                const hat_d_ji = blk: {
                    const xk = try common.homMulSigned(P, ek_j, peer.k_ct, x_pm);
                    const nb = try common.encryptSigned(P, ek_j, hat_beta_ij.negate(), hat_s_ij);
                    break :blk ek_j.homAdd(xk, nb);
                };
                const hat_f_ji = try common.encryptSigned(P, ek_i, hat_beta_ij.negate(), hat_r_ij);

                const psi_ji = try AffG.prove(psiTranscript(keys.eid, keys.i, false), rng, r_j, .{
                    .key_j = ek_j,
                    .key_i = ek_i,
                    .c = peer.k_ct,
                    .d = d_ji,
                    .y = f_ji,
                    .x = gamma_pt,
                }, .{ .x = gamma_pm, .y = beta_ij.negate(), .nonce = s_ij, .nonce_y = r_ij });

                const hat_psi_ji = try AffG.prove(psiTranscript(keys.eid, keys.i, true), rng, r_j, .{
                    .key_j = ek_j,
                    .key_i = ek_i,
                    .c = peer.k_ct,
                    .d = hat_d_ji,
                    .y = hat_f_ji,
                    .x = keys.big_x[keys.i - 1],
                }, .{ .x = x_pm, .y = hat_beta_ij.negate(), .nonce = hat_s_ij, .nonce_y = hat_r_ij });

                p2p[out_k] = .{ .to = j, .msg = .{
                    .gamma = gamma_pt,
                    .d = d_ji,
                    .f = f_ji,
                    .hat_d = hat_d_ji,
                    .hat_f = hat_f_ji,
                    .tilde_psi = tilde_psi,
                    .psi = psi_ji,
                    .hat_psi = hat_psi_ji,
                } };
                out_k += 1;
            }

            return .{
                .state = .{
                    .s1 = state,
                    .peers_1a = peers,
                    .beta_sum = beta_sum,
                    .hat_beta_sum = hat_beta_sum,
                    .gamma_pt = gamma_pt,
                    .allocator = allocator,
                },
                .p2p = p2p,
            };
        }

        pub const State3 = struct {
            s1: State1,
            big_gamma: E.Point, // Γ = ΣΓ_j
            delta_i: E.Scalar,
            chi_i: E.Scalar,
            delta_pt_i: E.Point,
            peers_1a: []?Round1aBroadcast,
            allocator: Allocator,

            pub fn deinit(self: *State3) void {
                self.allocator.free(self.peers_1a);
                self.* = undefined;
            }
        };

        pub const Round3Result = struct {
            state: State3,
            broadcast: Round3Broadcast,
        };

        pub fn round3(state: State2, incoming: []const From(Round2P2p), rng: std.Random) !Round3Result {
            var st = state;
            const keys = st.s1.keys;
            try keys.validate();
            const n = keys.n;
            if (incoming.len != n - 1) return error.MissingMessage;

            const ek_i = keys.dk.ek;
            const r_i = keys.parties[keys.i - 1].pedersen;

            var big_gamma = st.gamma_pt;
            var alpha_sum = E.Scalar.zero;
            var hat_alpha_sum = E.Scalar.zero;

            const seen = try st.allocator.alloc(bool, n);
            defer st.allocator.free(seen);
            @memset(seen, false);
            seen[keys.i - 1] = true;

            for (incoming) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == keys.i) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;
                const peer = st.peers_1a[j - 1].?;
                const ek_j = keys.parties[j - 1].ek;

                Elog.verify(elogTranscript(keys.eid, j, false), .{
                    .l = peer.b1,
                    .m = peer.b2,
                    .x = peer.y,
                    .y = m.msg.gamma,
                    .h = E.Point.generator,
                }, m.msg.tilde_psi) catch return error.InvalidElogProof;

                AffG.verify(psiTranscript(keys.eid, j, false), r_i, .{
                    .key_j = ek_i,
                    .key_i = ek_j,
                    .c = st.s1.own_1a.k_ct,
                    .d = m.msg.d,
                    .y = m.msg.f,
                    .x = m.msg.gamma,
                }, m.msg.psi) catch return error.InvalidAffGProof;

                AffG.verify(psiTranscript(keys.eid, j, true), r_i, .{
                    .key_j = ek_i,
                    .key_i = ek_j,
                    .c = st.s1.own_1a.k_ct,
                    .d = m.msg.hat_d,
                    .y = m.msg.hat_f,
                    .x = keys.big_x[j - 1],
                }, m.msg.hat_psi) catch return error.InvalidAffGProof;

                big_gamma = big_gamma.add(m.msg.gamma);
                const alpha_ij = try decryptSigned(keys.dk, m.msg.d);
                const hat_alpha_ij = try decryptSigned(keys.dk, m.msg.hat_d);
                alpha_sum = alpha_sum.add(common.toCurveScalar(P, E, alpha_ij));
                hat_alpha_sum = hat_alpha_sum.add(common.toCurveScalar(P, E, hat_alpha_ij));
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            const delta_i = st.s1.gamma_i.mul(st.s1.k_i).add(alpha_sum).add(st.beta_sum);
            const chi_i = keys.x_i.mul(st.s1.k_i).add(hat_alpha_sum).add(st.hat_beta_sum);
            const delta_pt_i = common.pointMulPub(E, big_gamma, st.s1.k_i);
            const s_pt_i = common.pointMulPub(E, big_gamma, chi_i);

            const psi_prime = try Elog.prove(elogTranscript(keys.eid, keys.i, true), rng, .{
                .l = st.s1.own_1a.a1,
                .m = st.s1.own_1a.a2,
                .x = st.s1.y_i,
                .y = delta_pt_i,
                .h = big_gamma,
            }, st.s1.k_i, st.s1.a_i);

            const bcast = Round3Broadcast{
                .delta = delta_i,
                .s_pt = s_pt_i,
                .delta_pt = delta_pt_i,
                .psi_prime = psi_prime,
            };

            const peers = st.peers_1a;
            const allocator = st.allocator;
            const s1 = st.s1;
            return .{
                .state = .{
                    .s1 = s1,
                    .big_gamma = big_gamma,
                    .delta_i = delta_i,
                    .chi_i = chi_i,
                    .delta_pt_i = delta_pt_i,
                    .peers_1a = peers,
                    .allocator = allocator,
                },
                .broadcast = bcast,
            };
        }

        pub fn finalize(state: State3, incoming: []const From(Round3Broadcast)) !Presignature {
            var st = state;
            const allocator = st.allocator;
            const keys = st.s1.keys;
            try keys.validate();
            const n = keys.n;
            if (incoming.len != n - 1) return error.MissingMessage;

            var delta = st.delta_i;
            var delta_pt = st.delta_pt_i;
            var s_pt = common.pointMulPub(E, st.big_gamma, st.chi_i);

            const seen = try allocator.alloc(bool, n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[keys.i - 1] = true;

            for (incoming) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == keys.i) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;
                const peer = st.peers_1a[j - 1].?;

                Elog.verify(elogTranscript(keys.eid, j, true), .{
                    .l = peer.a1,
                    .m = peer.a2,
                    .x = peer.y,
                    .y = m.msg.delta_pt,
                    .h = st.big_gamma,
                }, m.msg.psi_prime) catch return error.InvalidElogProof;

                delta = delta.add(m.msg.delta);
                delta_pt = delta_pt.add(m.msg.delta_pt);
                s_pt = s_pt.add(m.msg.s_pt);
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            // δG == Δ and δ·pk == S, else abort
            if (!common.baseMul(E, delta).eql(delta_pt)) return error.MismatchedDelta;
            if (!common.pointMulPub(E, keys.pk, delta).eql(s_pt)) return error.MismatchedDelta;
            if (delta.isZero()) return error.MismatchedDelta;

            const delta_inv = delta.invert();
            const presig = Presignature{
                .gamma = st.big_gamma,
                .tilde_k = st.s1.k_i.mul(delta_inv),
                .tilde_chi = st.chi_i.mul(delta_inv),
            };
            st.deinit();
            return presig;
        }

        // ------------------------------------------------------------------
        // signing
        // ------------------------------------------------------------------

        pub fn partialSign(presig: Presignature, msg_scalar: E.Scalar) E.Scalar {
            const r = scalarFromX(presig.gamma);
            return presig.tilde_k.mul(msg_scalar).add(r.mul(presig.tilde_chi));
        }

        /// Combine partial signatures; the caller MUST verify the result
        /// (a bad share yields an invalid signature, not an error here).
        pub fn combine(gamma: E.Point, partials: []const E.Scalar, msg_scalar: E.Scalar) !Signature {
            _ = msg_scalar;
            if (partials.len == 0) return error.NoPartialSignatures;
            const r = scalarFromX(gamma);
            if (r.isZero()) return error.ZeroR;
            var s = E.Scalar.zero;
            for (partials) |p| s = s.add(p);
            if (s.isZero()) return error.ZeroS;
            // low-s normalization
            return .{ .r = r, .s = normalizeS(s) };
        }

        fn normalizeS(s: E.Scalar) E.Scalar {
            const half = comptime blk: {
                var h = E.order_be;
                var carry: u8 = 0;
                for (&h) |*b| {
                    const next: u8 = b.* & 1;
                    b.* = (carry << 7) | (b.* >> 1);
                    carry = next;
                }
                break :blk h;
            };
            const be = s.toBytes();
            if (std.mem.order(u8, &be, &half) == .gt) return s.neg();
            return s;
        }

        /// Standard ECDSA verification.
        pub fn verify(pk: E.Point, msg_scalar: E.Scalar, sig: Signature) bool {
            if (sig.r.isZero() or sig.s.isZero()) return false;
            const s_inv = sig.s.invert();
            const ua = msg_scalar.mul(s_inv);
            const ub = sig.r.mul(s_inv);
            const rp = blk: {
                if (ua.isZero()) break :blk common.pointMulPub(E, pk, ub);
                break :blk E.Point.mulDoubleBasePublic(E.Point.generator, ua, pk, ub) catch return false;
            };
            if (rp.isIdentity()) return false;
            return scalarFromX(rp).eql(sig.r);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const curve = @import("curve.zig");

test "2-party CGGMP24 presign + sign end to end" {
    // Signing plaintexts are full curve scalars: l must be >= 256, N must
    // comfortably exceed the MtA value range.
    const P = common.Params(320, 256, 512, 384);
    const E = curve.Secp256k1;
    const T = Ecdsa(P, E);
    const Pl = common.Pail(P);
    var prng = std.Random.DefaultPrng.init(777001);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const n: u16 = 2;
    const eid = ExecutionId.random(rng);

    // trusted-dealer key setup (protocol-level DKG is tested elsewhere)
    const x1 = E.Scalar.random(rng);
    const x2 = E.Scalar.random(rng);
    const x = x1.add(x2);
    const pk = try E.Point.mulBase(x);
    const big_x = [_]E.Point{ try E.Point.mulBase(x1), try E.Point.mulBase(x2) };

    // per-party paillier + pedersen
    var dks: [n]Pl.DecryptionKey = undefined;
    var parties: [n]T.PartyData = undefined;
    for (0..n) |i| {
        dks[i] = try Pl.DecryptionKey.generate(rng);
        var gen = try common.Aux(P).generate(rng, false);
        gen.secret.zeroize();
        parties[i] = .{ .ek = dks[i].ek, .pedersen = gen.aux };
    }
    defer for (&dks) |*dk| dk.zeroize();

    const keys1 = T.Keys{ .i = 1, .n = n, .eid = eid, .x_i = x1, .big_x = &big_x, .pk = pk, .dk = dks[0], .parties = &parties };
    const keys2 = T.Keys{ .i = 2, .n = n, .eid = eid, .x_i = x2, .big_x = &big_x, .pk = pk, .dk = dks[1], .parties = &parties };

    // round 1
    const r1_1 = try T.round1(allocator, keys1, rng);
    defer allocator.free(r1_1.p2p);
    const r1_2 = try T.round1(allocator, keys2, rng);
    defer allocator.free(r1_2.p2p);

    // round 2
    const r2_1 = try T.round2(allocator, r1_1.state, &.{.{ .from = 2, .msg = r1_2.broadcast }}, &.{.{ .from = 2, .msg = r1_2.p2p[0].msg }}, rng);
    defer allocator.free(r2_1.p2p);
    const r2_2 = try T.round2(allocator, r1_2.state, &.{.{ .from = 1, .msg = r1_1.broadcast }}, &.{.{ .from = 1, .msg = r1_1.p2p[0].msg }}, rng);
    defer allocator.free(r2_2.p2p);

    // round 3
    const r3_1 = try T.round3(r2_1.state, &.{.{ .from = 2, .msg = r2_2.p2p[0].msg }}, rng);
    const r3_2 = try T.round3(r2_2.state, &.{.{ .from = 1, .msg = r2_1.p2p[0].msg }}, rng);

    // finalize -> presignatures
    var presig1 = try T.finalize(r3_1.state, &.{.{ .from = 2, .msg = r3_2.broadcast }});
    defer presig1.zeroize();
    var presig2 = try T.finalize(r3_2.state, &.{.{ .from = 1, .msg = r3_1.broadcast }});
    defer presig2.zeroize();

    try std.testing.expect(presig1.gamma.eql(presig2.gamma));

    // sign
    const msg = "cggmp24 in zig";
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &h);
    const m_scalar = E.Scalar.fromWideBytes(wide);

    const sigma1 = T.partialSign(presig1, m_scalar);
    const sigma2 = T.partialSign(presig2, m_scalar);
    const sig = try T.combine(presig1.gamma, &.{ sigma1, sigma2 }, m_scalar);

    // verifies under our ECDSA verify
    try std.testing.expect(T.verify(pk, m_scalar, sig));
    // and fails for a different message
    try std.testing.expect(!T.verify(pk, m_scalar.add(E.Scalar.one), sig));

    // cross-check: the signature verifies under std.crypto's independent
    // ECDSA implementation (which hashes `msg` with SHA-256 itself)
    const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const std_pk = try StdEcdsa.PublicKey.fromSec1(&pk.toBytes());
    var sig_bytes: [64]u8 = undefined;
    sig_bytes[0..32].* = sig.r.toBytes();
    sig_bytes[32..].* = sig.s.toBytes();
    const std_sig = StdEcdsa.Signature.fromBytes(sig_bytes);
    try std_sig.verify(msg, std_pk);
}
