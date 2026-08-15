//! CGGMP24 auxiliary-info generation (3 rounds): every party generates a
//! Paillier key N = pq and ring-Pedersen parameters (N̂, s, t), then proves
//! them well-formed to everyone else:
//!   Round 1: hash-commit to (N, N̂, s, t, Πprm, ρ_i).       [broadcast]
//!   Round 2: decommit.                                     [broadcast]
//!   Round 3: Πmod for N, plus a per-peer Πfac bound to the
//!            recipient's Pedersen parameters.              [p2p]
//! Output: own Paillier decryption key + every party's validated
//! (N_i, N̂_i, s_i, t_i) and the joint randomness ρ.
//!
//! Mirrors cggmp24/src/key_refresh/aux_only.rs. The transport MUST provide
//! consistent broadcast (reliability echo round not yet implemented).

const std = @import("std");
const Allocator = std.mem.Allocator;
const zk = @import("zk.zig");
const transcript = @import("transcript.zig");
const message = @import("message.zig");

const common = zk.common;
const Transcript = transcript.Transcript;
pub const ExecutionId = transcript.ExecutionId;

pub fn AuxGen(comptime P: type, comptime M: usize) type {
    const Pl = common.Pail(P);
    const Aux = common.Aux(P);
    const Prm = zk.prm.Prm(P, M);
    const BlumMod = zk.blum_mod.BlumMod(P, M);
    const Fac = zk.fac.Fac(P);

    return struct {
        pub const Primes = struct {
            p: P.Fp.Bytes,
            q: P.Fp.Bytes,
            hat_p: P.Fp.Bytes,
            hat_q: P.Fp.Bytes,

            /// `safe = true` matches the reference (4 safe primes); tests use
            /// Blum primes for speed.
            pub fn generate(rng: std.Random, comptime safe: bool) !Primes {
                const gen = struct {
                    fn one(r: std.Random) !P.Fp.Bytes {
                        return if (safe)
                            P.Fp.generateSafePrime(r, P.prime_bits)
                        else
                            P.Fp.generatePrime(r, P.prime_bits, true);
                    }
                }.one;
                return .{ .p = try gen(rng), .q = try gen(rng), .hat_p = try gen(rng), .hat_q = try gen(rng) };
            }

            pub fn zeroize(self: *Primes) void {
                std.crypto.secureZero(u8, &self.p);
                std.crypto.secureZero(u8, &self.q);
                std.crypto.secureZero(u8, &self.hat_p);
                std.crypto.secureZero(u8, &self.hat_q);
            }
        };

        pub const From = message.From;
        pub const To = message.To;

        pub const Round1Broadcast = struct {
            commitment_hash: [32]u8,
        };

        pub const Round2Broadcast = struct {
            n: P.Fn.Bytes,
            hat_n: P.Fn.Bytes,
            s: P.Fn.Bytes,
            t: P.Fn.Bytes,
            prm_proof: Prm.Proof,
            rho: [32]u8,
            decommit_nonce: [32]u8,
        };

        pub const Round3P2p = struct {
            mod_proof: BlumMod.Proof,
            fac_proof: Fac.Proof,
        };

        /// One party's public aux data.
        pub const PartyAux = struct {
            /// Paillier modulus N_i.
            n: P.Fn.Bytes,
            /// Ring-Pedersen commitment parameters.
            pedersen: Aux,
        };

        pub const AuxInfo = struct {
            party: u16,
            n_parties: u16,
            /// Own Paillier decryption key.
            dk: Pl.DecryptionKey,
            /// Secret Pedersen data (φ(N̂), λ) - needed for later proofs.
            pedersen_secret: Aux.Secret,
            /// Every party's public aux data, indexed by party-1.
            parties: []PartyAux,
            /// Joint randomness.
            rho: [32]u8,
            allocator: Allocator,

            pub fn deinit(self: *AuxInfo) void {
                self.dk.zeroize();
                self.pedersen_secret.zeroize();
                self.allocator.free(self.parties);
                self.* = undefined;
            }
        };

        fn prmTranscript(eid: ExecutionId, prover: u16) Transcript {
            var t = Transcript.init("zig-mpc/aux-gen/prm/v1");
            t.appendExecutionId(eid);
            t.appendU64("prover", prover);
            return t;
        }

        fn modTranscript(eid: ExecutionId, rho: [32]u8, prover: u16) Transcript {
            var t = Transcript.init("zig-mpc/aux-gen/mod/v1");
            t.appendExecutionId(eid);
            t.appendBytes("rho", &rho);
            t.appendU64("prover", prover);
            return t;
        }

        fn facTranscript(eid: ExecutionId, rho: [32]u8, prover: u16) Transcript {
            var t = Transcript.init("zig-mpc/aux-gen/fac/v1");
            t.appendExecutionId(eid);
            t.appendBytes("rho", &rho);
            t.appendU64("prover", prover);
            return t;
        }

        fn commitmentHash(eid: ExecutionId, party: u16, msg: Round2Broadcast) [32]u8 {
            var t = Transcript.init("zig-mpc/aux-gen/commit/v1");
            t.appendExecutionId(eid);
            t.appendU64("party", party);
            t.appendBytes("n", &msg.n);
            t.appendBytes("hat-n", &msg.hat_n);
            t.appendBytes("s", &msg.s);
            t.appendBytes("t", &msg.t);
            for (msg.prm_proof.commitment) |a| t.appendBytes("prm-com", &a);
            for (msg.prm_proof.zs) |z| t.appendBytes("prm-z", &z);
            t.appendBytes("rho", &msg.rho);
            t.appendBytes("decommit-nonce", &msg.decommit_nonce);
            var rng = t.challengeRng();
            var out: [32]u8 = undefined;
            rng.fill(&out);
            return out;
        }

        pub const State1 = struct {
            party: u16,
            n_parties: u16,
            eid: ExecutionId,
            dk: Pl.DecryptionKey,
            pedersen: Aux,
            pedersen_secret: Aux.Secret,
            decommitment: Round2Broadcast,
        };

        pub const Round1Result = struct { state: State1, broadcast: Round1Broadcast };

        pub fn round1(party: u16, n_parties: u16, eid: ExecutionId, primes: Primes, rng: std.Random) !Round1Result {
            if (party < 1 or party > n_parties or n_parties < 2) return error.InvalidParams;

            const dk = try Pl.DecryptionKey.fromPrimes(primes.p, primes.q);
            const ped = try Aux.fromPrimes(rng, primes.hat_p, primes.hat_q);

            const prm_proof = Prm.prove(prmTranscript(eid, party), rng, ped.aux, ped.secret.phi, ped.secret.lambda);

            var rho: [32]u8 = undefined;
            rng.bytes(&rho);
            var nonce: [32]u8 = undefined;
            rng.bytes(&nonce);

            const decommitment = Round2Broadcast{
                .n = dk.ek.n,
                .hat_n = ped.aux.n_hat,
                .s = ped.aux.s,
                .t = ped.aux.t,
                .prm_proof = prm_proof,
                .rho = rho,
                .decommit_nonce = nonce,
            };

            return .{
                .state = .{
                    .party = party,
                    .n_parties = n_parties,
                    .eid = eid,
                    .dk = dk,
                    .pedersen = ped.aux,
                    .pedersen_secret = ped.secret,
                    .decommitment = decommitment,
                },
                .broadcast = .{ .commitment_hash = commitmentHash(eid, party, decommitment) },
            };
        }

        pub const State2 = struct {
            s1: State1,
            hashes: []?[32]u8,
            allocator: Allocator,

            pub fn deinit(self: *State2) void {
                self.allocator.free(self.hashes);
                self.* = undefined;
            }
        };

        pub const Round2Result = struct { state: State2, broadcast: Round2Broadcast };

        pub fn round2(allocator: Allocator, state: State1, incoming: []const From(Round1Broadcast)) !Round2Result {
            const n = state.n_parties;
            const hashes = try allocator.alloc(?[32]u8, n);
            errdefer allocator.free(hashes);
            @memset(hashes, null);
            hashes[state.party - 1] = commitmentHash(state.eid, state.party, state.decommitment);
            for (incoming) |m| {
                if (m.from < 1 or m.from > n or m.from == state.party) return error.InvalidSender;
                if (hashes[m.from - 1] != null) return error.DuplicateMessage;
                hashes[m.from - 1] = m.msg.commitment_hash;
            }
            for (hashes) |h| if (h == null) return error.MissingMessage;

            return .{
                .state = .{ .s1 = state, .hashes = hashes, .allocator = allocator },
                .broadcast = state.decommitment,
            };
        }

        pub const State3 = struct {
            s1: State1,
            parties: []PartyAux,
            rho: [32]u8,
            allocator: Allocator,
        };

        pub const Round3Result = struct {
            state: State3,
            /// One entry per other party, addressed to that party.
            p2p: []To(Round3P2p),
        };

        pub fn round3(state: State2, rng: std.Random, incoming: []const From(Round2Broadcast)) !Round3Result {
            var st = state;
            const s1 = st.s1;
            const n = s1.n_parties;
            const allocator = st.allocator;
            if (incoming.len != n - 1) return error.MissingMessage;

            const parties = try allocator.alloc(PartyAux, n);
            errdefer allocator.free(parties);
            const seen = try allocator.alloc(bool, n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[s1.party - 1] = true;
            parties[s1.party - 1] = .{ .n = s1.dk.ek.n, .pedersen = s1.pedersen };

            var rho = s1.decommitment.rho;

            for (incoming) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == s1.party) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;

                // decommitment must match round-1 hash
                const actual = commitmentHash(s1.eid, j, m.msg);
                if (!std.crypto.timing_safe.eql([32]u8, st.hashes[j - 1].?, actual))
                    return error.DecommitmentMismatch;

                // moduli must be full-size, s/t must be units
                if (P.Fn.bitLength(m.msg.n) < P.n_bits - 1) return error.InvalidModulusSize;
                if (P.Fn.bitLength(m.msg.hat_n) < P.n_bits - 1) return error.InvalidModulusSize;
                const ped = Aux.fromParts(m.msg.hat_n, m.msg.s, m.msg.t) catch return error.InvalidPedersenParams;

                // Πprm
                Prm.verify(prmTranscript(s1.eid, j), ped, m.msg.prm_proof) catch return error.InvalidPrmProof;

                for (&rho, m.msg.rho) |*a, b| a.* ^= b;
                parties[j - 1] = .{ .n = m.msg.n, .pedersen = ped };
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            // Πmod for own N, once
            const mod_proof = try BlumMod.prove(modTranscript(s1.eid, rho, s1.party), rng, s1.dk.ek.n, s1.dk.p, s1.dk.q);

            // per-peer Πfac against the recipient's Pedersen parameters
            const fac_data = Fac.Data.fromModulus(s1.dk.ek.n);
            const p2p = try allocator.alloc(To(Round3P2p), n - 1);
            errdefer allocator.free(p2p);
            var k: usize = 0;
            var j: u16 = 1;
            while (j <= n) : (j += 1) {
                if (j == s1.party) continue;
                const fac_proof = try Fac.prove(
                    facTranscript(s1.eid, rho, s1.party),
                    rng,
                    parties[j - 1].pedersen,
                    fac_data,
                    s1.dk.p,
                    s1.dk.q,
                );
                p2p[k] = .{ .to = j, .msg = .{ .mod_proof = mod_proof, .fac_proof = fac_proof } };
                k += 1;
            }

            st.deinit();
            return .{
                .state = .{ .s1 = s1, .parties = parties, .rho = rho, .allocator = allocator },
                .p2p = p2p,
            };
        }

        pub fn finalize(state: State3, rng: std.Random, incoming: []const From(Round3P2p)) !AuxInfo {
            const s1 = state.s1;
            const n = s1.n_parties;
            const allocator = state.allocator;
            if (incoming.len != n - 1) return error.MissingMessage;

            const seen = try allocator.alloc(bool, n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[s1.party - 1] = true;

            for (incoming) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == s1.party) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;

                const n_j = state.parties[j - 1].n;
                BlumMod.verify(modTranscript(s1.eid, state.rho, j), rng, n_j, m.msg.mod_proof) catch
                    return error.InvalidModProof;
                Fac.verify(
                    facTranscript(s1.eid, state.rho, j),
                    s1.pedersen,
                    Fac.Data.fromModulus(n_j),
                    m.msg.fac_proof,
                ) catch return error.InvalidFacProof;
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            return .{
                .party = s1.party,
                .n_parties = n,
                .dk = s1.dk,
                .pedersen_secret = s1.pedersen_secret,
                .parties = state.parties,
                .rho = state.rho,
                .allocator = allocator,
            };
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "3-party aux-info generation end to end" {
    const P = common.TestParams;
    const A = AuxGen(P, 16);
    var prng = std.Random.DefaultPrng.init(60601);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const n: u16 = 3;
    const eid = ExecutionId.random(rng);

    var r1: [n]A.Round1Result = undefined;
    for (0..n) |i| {
        var primes = try A.Primes.generate(rng, false);
        defer primes.zeroize();
        r1[i] = try A.round1(@intCast(i + 1), n, eid, primes, rng);
    }

    var r2: [n]A.Round2Result = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]A.From(A.Round1Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r1[j].broadcast };
            k += 1;
        }
        r2[i] = try A.round2(allocator, r1[i].state, &incoming);
    }

    var r3: [n]A.Round3Result = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]A.From(A.Round2Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
            k += 1;
        }
        r3[i] = try A.round3(r2[i].state, rng, &incoming);
    }
    defer for (0..n) |i| allocator.free(r3[i].p2p);

    var infos: [n]A.AuxInfo = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]A.From(A.Round3P2p) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            for (r3[j].p2p) |pm| {
                if (pm.to == i + 1) {
                    incoming[k] = .{ .from = @intCast(j + 1), .msg = pm.msg };
                    k += 1;
                }
            }
        }
        infos[i] = try A.finalize(r3[i].state, rng, &incoming);
    }
    defer for (&infos) |*info| info.deinit();

    // all parties agree on rho and on each other's public aux data
    try std.testing.expectEqualSlices(u8, &infos[0].rho, &infos[1].rho);
    try std.testing.expectEqualSlices(u8, &infos[1].rho, &infos[2].rho);
    for (0..n) |i| {
        for (0..n) |j| {
            try std.testing.expectEqualSlices(u8, &infos[0].parties[j].n, &infos[i].parties[j].n);
            try std.testing.expectEqualSlices(u8, &infos[0].parties[j].pedersen.s, &infos[i].parties[j].pedersen.s);
        }
    }

    // own paillier key works
    const m = P.Fn.fromU64(424242);
    const enc = try infos[0].dk.ek.encrypt(m, rng);
    const dec = try infos[0].dk.decrypt(enc.c);
    try std.testing.expectEqualSlices(u8, &m, &dec);
}

test "aux-gen rejects tampered decommitment" {
    const P = common.TestParams;
    const A = AuxGen(P, 16);
    var prng = std.Random.DefaultPrng.init(70707);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const eid = ExecutionId.random(rng);

    var p1 = try A.Primes.generate(rng, false);
    defer p1.zeroize();
    var p2 = try A.Primes.generate(rng, false);
    defer p2.zeroize();

    const a1 = try A.round1(1, 2, eid, p1, rng);
    const a2 = try A.round1(2, 2, eid, p2, rng);

    const b1 = try A.round2(allocator, a1.state, &.{.{ .from = 2, .msg = a2.broadcast }});
    var b2 = try A.round2(allocator, a2.state, &.{.{ .from = 1, .msg = a1.broadcast }});
    defer b2.state.deinit();

    // party 2's decommitment gets tampered in flight
    var tampered = b2.broadcast;
    tampered.rho[0] ^= 1;
    var st = b1.state;
    try std.testing.expectError(error.DecommitmentMismatch, A.round3(st, rng, &.{.{ .from = 2, .msg = tampered }}));
    st.deinit();
}
