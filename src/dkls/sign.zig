//! DKLs23 threshold ECDSA signing, Protocol 3.6 of
//! <https://eprint.iacr.org/2023/765.pdf>.
//!
//! Three communication rounds around four local phases:
//!
//!   phase1   sample the instance key, commit to it, open a multiplication
//!            against every counterparty                          [p2p]
//!   phase2   convert the key share to this quorum, answer each
//!            multiplication as the sender                        [p2p]
//!   phase3   check every counterparty, close the multiplications,
//!            publish this party's two signature components  [broadcast]
//!   phase4   assemble and verify the signature                  [local]
//!
//! The signature that comes out is an ordinary ECDSA signature, verifiable by
//! anyone with no knowledge that a threshold scheme was involved.
//!
//! # What makes this cheap
//!
//! ECDSA needs `k^-1 (m + r x)`, a product of two secret-shared values. CGGMP24
//! buys that with Paillier encryption and range proofs, and a separate aux-info
//! ceremony to set up the moduli. DKLs23 buys it with oblivious transfer
//! instead: `mul.zig` turns two shared secrets into shares of their product
//! using nothing but elliptic-curve and symmetric primitives. There is no
//! Paillier, no RSA modulus, and nothing per-signature beyond what is here.
//!
//! # Deviations from the reference
//!
//! The reference passes the signature's `r` between phases as a hex *string*
//! and re-parses it to a scalar twice. That round-trip is dropped; `r` stays a
//! point and a scalar. The value hashed and signed is identical.
//!
//! Party indices are written into session ids as big-endian `u16` rather than
//! `u8`, because this library carries `u16` party indices throughout. That
//! makes the derived multiplication session ids differ from the reference's,
//! which matters only for wire interop with it, not for security.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash = @import("hash.zig");
const mul = @import("mul.zig");
const zeroshare = @import("zeroshare.zig");

pub const Error = error{
    /// The quorum does not match the key share, or contains this party twice.
    InvalidQuorum,
    /// A message arrived from a party not in the quorum, or twice.
    UnexpectedSender,
    DuplicateSender,
    /// Fewer or more messages than counterparties.
    WrongMessageCount,
    /// No setup material for a counterparty in the quorum.
    MissingSetup,
    /// A counterparty opened a commitment it did not make.
    CommitmentMismatch,
    /// A counterparty published the identity as its instance point.
    TrivialInstancePoint,
    /// The instance points summed to the identity. Astronomically unlikely,
    /// and fatal to the signature if ignored.
    TrivialNonce,
    /// The public shares did not reconstruct the group key: the quorum
    /// disagrees about the key, or a share is wrong.
    PublicKeyMismatch,
    /// A counterparty's multiplication output is inconsistent with the point
    /// it published. Attributable, and per DKLs23 grounds for exclusion.
    GammaInconsistency,
    /// The assembled signature does not verify.
    SignatureInvalid,
    ZeroDenominator,
};

pub const Params = struct {
    party: u16,
    n: u16,
    threshold: u16,
};

/// An ordinary ECDSA signature.
pub fn Signature(comptime E: type) type {
    return struct {
        r: E.Scalar,
        s: E.Scalar,
        /// Bit 0: the nonce point's y is odd. Bit 1: its x exceeded the group
        /// order and was reduced. Together these let a verifier recover the
        /// public key from the signature.
        recovery_id: u8,

        pub fn toBytes(self: @This()) [2 * E.Scalar.encoded_length]u8 {
            var out: [2 * E.Scalar.encoded_length]u8 = undefined;
            @memcpy(out[0..E.Scalar.encoded_length], &self.r.toBytes());
            @memcpy(out[E.Scalar.encoded_length..], &self.s.toBytes());
            return out;
        }
    };
}

/// One counterparty's setup material.
pub fn Peer(comptime E: type) type {
    return struct {
        index: u16,
        /// Used when this party is the multiplication sender (phase 2).
        as_sender: mul.Sender(E),
        /// Used when this party is the multiplication receiver (phases 1, 3).
        as_receiver: mul.Receiver(E),

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            self.as_sender.zeroize();
            self.as_receiver.zeroize();
            gpa.free(self.as_sender.gadget);
            gpa.free(self.as_receiver.gadget);
            self.* = undefined;
        }
    };
}

/// Everything a party carries between key generation and signing.
pub fn Party(comptime E: type) type {
    return struct {
        const Self = @This();

        params: Params,
        /// The execution id shared by the DKG and setup.
        execution_id: [32]u8,
        chain_code: [32]u8,
        /// This party's Shamir share of the group secret.
        key_share: E.Scalar,
        public_key: E.Point,
        zero: zeroshare.Share(E),
        /// Sorted by index.
        peers: []Peer(E),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.key_share.zeroize();
            self.zero.deinit(gpa);
            for (self.peers) |*p| p.deinit(gpa);
            gpa.free(self.peers);
            self.* = undefined;
        }

        fn peerOf(self: Self, index: u16) ?*const Peer(E) {
            for (self.peers) |*p| {
                if (p.index == index) return p;
            }
            return null;
        }
    };
}

pub const SignData = struct {
    /// Distinguishes this signing session from every other under the same key.
    sign_id: [32]u8,
    /// Every party signing, including this one. Sorted, no duplicates.
    quorum: []const u16,
    /// The already-hashed message.
    message_hash: [32]u8,
};

/// Session id for the multiplication between a receiver and a sender.
/// Both parties must derive the same string, so the roles are named explicitly
/// rather than by who is calling.
fn mulSessionId(
    buf: *std.ArrayList(u8),
    gpa: Allocator,
    receiver: u16,
    sender: u16,
    execution_id: [32]u8,
    sign_id: [32]u8,
    chain_code: [32]u8,
) Allocator.Error![]const u8 {
    buf.clearRetainingCapacity();
    var idx: [2]u8 = undefined;
    try buf.appendSlice(gpa, "Multiplication protocol");
    std.mem.writeInt(u16, &idx, receiver, .big);
    try buf.appendSlice(gpa, &idx);
    std.mem.writeInt(u16, &idx, sender, .big);
    try buf.appendSlice(gpa, &idx);
    try buf.appendSlice(gpa, &execution_id);
    try buf.appendSlice(gpa, &sign_id);
    try buf.appendSlice(gpa, &chain_code);
    return buf.items;
}

fn zeroSessionId(buf: *std.ArrayList(u8), gpa: Allocator, execution_id: [32]u8, sign_id: [32]u8, chain_code: [32]u8) Allocator.Error![]const u8 {
    buf.clearRetainingCapacity();
    try buf.appendSlice(gpa, "Zero shares protocol");
    try buf.appendSlice(gpa, &execution_id);
    try buf.appendSlice(gpa, &sign_id);
    try buf.appendSlice(gpa, &chain_code);
    return buf.items;
}

/// x-coordinate of a point, reduced into a scalar. This is the signature's `r`.
fn scalarFromX(comptime E: type, p: E.Point) E.Scalar {
    const x = p.xOnly();
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[64 - x.len ..], &x);
    return E.Scalar.fromWideBytes(wide);
}

/// Lagrange coefficient taking this party's Shamir share to its additive share
/// for `quorum`, evaluated at zero.
fn lagrange(comptime E: type, self_index: u16, counterparties: []const u16) E.Scalar {
    var num = E.Scalar.one;
    var den = E.Scalar.one;
    const xi = E.Scalar.fromU64(self_index);
    for (counterparties) |j| {
        const xj = E.Scalar.fromU64(j);
        num = num.mul(xj);
        den = den.mul(xj.sub(xi));
    }
    return num.mul(den.invert());
}

fn normalizeS(comptime E: type, s: E.Scalar) E.Scalar {
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

/// Textbook ECDSA verification, used as the final gate before a signature is
/// returned. A share that is wrong in a way the per-counterparty checks miss
/// still cannot escape as a valid-looking signature.
pub fn verify(comptime E: type, pk: E.Point, message_hash: [32]u8, sig: Signature(E)) bool {
    if (sig.r.isZero() or sig.s.isZero()) return false;
    const m = hash.reduceToScalar(E, message_hash);
    const s_inv = sig.s.invert();
    const a = m.mul(s_inv);
    const b = sig.r.mul(s_inv);
    const p = E.Point.mulDoubleBasePublic(E.Point.generator, a, pk, b) catch return false;
    if (p.isIdentity()) return false;
    return scalarFromX(E, p).eql(sig.r);
}

// ---------------------------------------------------------------------------
// messages
// ---------------------------------------------------------------------------

pub fn Round1(comptime E: type) type {
    return struct {
        commitment: hash.Digest,
        mul_open: mul.ote.DataToSender(E),
    };
}

pub fn Round2(comptime E: type) type {
    return struct {
        /// c_u * G and c_v * G, which let the receiver check the products.
        gamma_u: E.Point,
        gamma_v: E.Point,
        /// The inversion mask, offset by this pair's multiplication output.
        psi: E.Scalar,
        /// This party's additive key share as a point.
        public_share: E.Point,
        /// The instance point, opening the round-1 commitment.
        instance_point: E.Point,
        salt: hash.Salt,
        mul_reply: mul.DataToReceiver(E),
    };
}

pub fn Round3(comptime E: type) type {
    return struct { u: E.Scalar, w: E.Scalar };
}

// ---------------------------------------------------------------------------
// phases
// ---------------------------------------------------------------------------

pub fn Signer(comptime E: type) type {
    return struct {
        const P = Party(E);

        /// Per-counterparty state kept from phase 1 to phase 2.
        pub const Kept1 = struct {
            index: u16,
            salt: hash.Salt,
            /// This pair's multiplication input, `b` in `mul.zig`.
            chi: E.Scalar,
            /// Ownership moves to `State2` in phase 2, leaving null behind, so
            /// that cleaning up either state is safe whichever phase failed.
            mul_kept: ?mul.Receiver(E).Kept,
        };

        pub const State1 = struct {
            instance_key: E.Scalar,
            instance_point: E.Point,
            inversion_mask: E.Scalar,
            zeta: E.Scalar,
            kept: []Kept1,

            pub fn deinit(self: *State1, gpa: Allocator) void {
                self.instance_key.zeroize();
                self.inversion_mask.zeroize();
                self.zeta.zeroize();
                for (self.kept) |*k| {
                    k.chi.zeroize();
                    if (k.mul_kept) |*m| m.deinit(gpa);
                }
                gpa.free(self.kept);
                self.* = undefined;
            }
        };

        pub const Kept2 = struct {
            index: u16,
            c_u: E.Scalar,
            c_v: E.Scalar,
            commitment: hash.Digest,
            chi: E.Scalar,
            mul_kept: mul.Receiver(E).Kept,
        };

        pub const State2 = struct {
            instance_key: E.Scalar,
            instance_point: E.Point,
            inversion_mask: E.Scalar,
            key_share: E.Scalar,
            public_share: E.Point,
            kept: []Kept2,

            pub fn deinit(self: *State2, gpa: Allocator) void {
                self.instance_key.zeroize();
                self.inversion_mask.zeroize();
                self.key_share.zeroize();
                for (self.kept) |*k| {
                    k.chi.zeroize();
                    k.mul_kept.deinit(gpa);
                }
                gpa.free(self.kept);
                self.* = undefined;
            }
        };

        pub const Out1 = struct {
            state: State1,
            /// One per counterparty, in quorum order.
            messages: []Round1(E),

            pub fn deinit(self: *Out1, gpa: Allocator) void {
                self.state.deinit(gpa);
                for (self.messages) |*m| m.mul_open.deinit(gpa);
                gpa.free(self.messages);
                self.* = undefined;
            }
        };

        pub const Out2 = struct {
            state: State2,
            messages: []Round2(E),

            pub fn deinit(self: *Out2, gpa: Allocator) void {
                self.state.deinit(gpa);
                for (self.messages) |*m| m.mul_reply.deinit(gpa);
                gpa.free(self.messages);
                self.* = undefined;
            }
        };

        fn counterpartiesOf(gpa: Allocator, party: u16, quorum: []const u16) (Error || Allocator.Error)![]u16 {
            var seen_self = false;
            for (quorum, 0..) |q, i| {
                if (q == party) seen_self = true;
                if (i > 0 and quorum[i - 1] >= q) return error.InvalidQuorum;
            }
            if (!seen_self) return error.InvalidQuorum;
            const out = try gpa.alloc(u16, quorum.len - 1);
            var k: usize = 0;
            for (quorum) |q| {
                if (q == party) continue;
                out[k] = q;
                k += 1;
            }
            return out;
        }

        /// Phase 1: sample the instance key, commit to it, and open one
        /// multiplication per counterparty as the receiver.
        pub fn phase1(gpa: Allocator, party: P, data: SignData, rng: std.Random) (Error || Allocator.Error)!Out1 {
            if (data.quorum.len != party.params.threshold) return error.InvalidQuorum;
            const cps = try counterpartiesOf(gpa, party.params.party, data.quorum);
            defer gpa.free(cps);

            var sid_buf = std.ArrayList(u8).empty;
            defer sid_buf.deinit(gpa);

            var instance_key = E.Scalar.random(rng);
            while (instance_key.isZero()) instance_key = E.Scalar.random(rng);
            const instance_point = E.Point.mulBase(instance_key) catch return error.TrivialInstancePoint;
            const inversion_mask = E.Scalar.random(rng);

            const kept = try gpa.alloc(Kept1, cps.len);
            errdefer gpa.free(kept);
            const messages = try gpa.alloc(Round1(E), cps.len);
            errdefer gpa.free(messages);

            for (cps, 0..) |cp, i| {
                const peer = party.peerOf(cp) orelse return error.MissingSetup;
                // Every counterparty gets its own commitment: opening to one
                // must not open to another.
                const c = hash.commitPoint(E, instance_point, rng);
                const sid = try mulSessionId(&sid_buf, gpa, party.params.party, cp, party.execution_id, data.sign_id, party.chain_code);
                const started = try peer.as_receiver.start(gpa, sid, rng);
                kept[i] = .{ .index = cp, .salt = c.salt, .chi = started.b, .mul_kept = started.kept };
                _ = &kept[i];
                messages[i] = .{ .commitment = c.digest, .mul_open = started.to_sender };
            }

            const zsid = try zeroSessionId(&sid_buf, gpa, party.execution_id, data.sign_id, party.chain_code);
            const zeta = party.zero.compute(zsid, cps);

            return .{
                .state = .{
                    .instance_key = instance_key,
                    .instance_point = instance_point,
                    .inversion_mask = inversion_mask,
                    .zeta = zeta,
                    .kept = kept,
                },
                .messages = messages,
            };
        }

        /// Phase 2: convert the Shamir share to this quorum's additive share and
        /// answer every multiplication as the sender.
        pub fn phase2(
            gpa: Allocator,
            party: P,
            data: SignData,
            state: *State1,
            from: []const u16,
            received: []const Round1(E),
            rng: std.Random,
        ) (Error || mul.Error || mul.ote.Error || Allocator.Error)!Out2 {
            const cps = try counterpartiesOf(gpa, party.params.party, data.quorum);
            defer gpa.free(cps);
            if (received.len != cps.len or from.len != received.len) return error.WrongMessageCount;

            var sid_buf = std.ArrayList(u8).empty;
            defer sid_buf.deinit(gpa);

            // The quorum-specific additive share: the Shamir share scaled by its
            // Lagrange coefficient, re-randomized by the share of zero so no
            // individual public share leaks anything about the key.
            const l = lagrange(E, party.params.party, cps);
            const key_share = party.key_share.mul(l).add(state.zeta);
            const public_share = E.Point.mulBase(key_share) catch return error.PublicKeyMismatch;
            const input = [_]E.Scalar{ state.instance_key, key_share };

            const kept = try gpa.alloc(Kept2, cps.len);
            errdefer gpa.free(kept);
            const messages = try gpa.alloc(Round2(E), cps.len);
            errdefer gpa.free(messages);

            var handled = try gpa.alloc(bool, cps.len);
            defer gpa.free(handled);
            @memset(handled, false);

            for (from, received) |sender, msg| {
                const slot = std.mem.indexOfScalar(u16, cps, sender) orelse return error.UnexpectedSender;
                if (handled[slot]) return error.DuplicateSender;
                handled[slot] = true;

                const peer = party.peerOf(sender) orelse return error.MissingSetup;
                const k1 = &state.kept[slot];

                // Roles reverse here: this party answers as the multiplication
                // sender, so the session id names the counterparty as receiver.
                const sid = try mulSessionId(&sid_buf, gpa, sender, party.params.party, party.execution_id, data.sign_id, party.chain_code);
                const sent = try peer.as_sender.run(gpa, sid, input, msg.mul_open, rng);

                kept[slot] = .{
                    .index = sender,
                    .c_u = sent.output[0],
                    .c_v = sent.output[1],
                    .commitment = msg.commitment,
                    .chi = k1.chi,
                    .mul_kept = k1.mul_kept orelse return error.MissingSetup,
                };
                // Moved, not copied: phase 1's state must not free it too.
                k1.mul_kept = null;
                messages[slot] = .{
                    .gamma_u = E.Point.mulBase(sent.output[0]) catch E.Point.identity,
                    .gamma_v = E.Point.mulBase(sent.output[1]) catch E.Point.identity,
                    .psi = state.inversion_mask.sub(k1.chi),
                    .public_share = public_share,
                    .instance_point = state.instance_point,
                    .salt = k1.salt,
                    .mul_reply = sent.to_receiver,
                };
            }

            return .{
                .state = .{
                    .instance_key = state.instance_key,
                    .instance_point = state.instance_point,
                    .inversion_mask = state.inversion_mask,
                    .key_share = key_share,
                    .public_share = public_share,
                    .kept = kept,
                },
                .messages = messages,
            };
        }

        pub const Out3 = struct {
            /// The signature's `r`, and the point it came from.
            nonce_point: E.Point,
            r: E.Scalar,
            broadcast: Round3(E),
        };

        /// Phase 3: check every counterparty, close the multiplications, and
        /// publish this party's two components of the signature.
        pub fn phase3(
            gpa: Allocator,
            party: P,
            data: SignData,
            state: *State2,
            from: []const u16,
            received: []const Round2(E),
        ) (Error || mul.Error || Allocator.Error)!Out3 {
            const cps = try counterpartiesOf(gpa, party.params.party, data.quorum);
            defer gpa.free(cps);
            if (received.len != cps.len or from.len != received.len) return error.WrongMessageCount;

            var sid_buf = std.ArrayList(u8).empty;
            defer sid_buf.deinit(gpa);

            var expected_pk = state.public_share;
            var nonce_point = state.instance_point;
            var mask_sum = state.inversion_mask;
            var sum_u = E.Scalar.zero;
            var sum_v = E.Scalar.zero;

            var handled = try gpa.alloc(bool, cps.len);
            defer gpa.free(handled);
            @memset(handled, false);

            for (from, received) |sender, msg| {
                const slot = std.mem.indexOfScalar(u16, cps, sender) orelse return error.UnexpectedSender;
                if (handled[slot]) return error.DuplicateSender;
                handled[slot] = true;

                if (msg.instance_point.isIdentity()) return error.TrivialInstancePoint;
                const k2 = &state.kept[slot];
                if (!hash.verifyCommitmentPoint(E, msg.instance_point, k2.commitment, msg.salt)) {
                    return error.CommitmentMismatch;
                }

                const peer = party.peerOf(sender) orelse return error.MissingSetup;
                const sid = try mulSessionId(&sid_buf, gpa, party.params.party, sender, party.execution_id, data.sign_id, party.chain_code);
                const d = try peer.as_receiver.finish(gpa, sid, k2.mul_kept, msg.mul_reply);

                // The counterparty's multiplication outputs must be consistent
                // with the points it published. Without these two checks a
                // counterparty could bias the signature by feeding a different
                // value into the product than the one it committed to.
                const lhs_u = msg.instance_point.mul(k2.chi) catch E.Point.identity;
                const rhs_u = (E.Point.mulBase(d[0]) catch E.Point.identity).add(msg.gamma_u);
                if (!lhs_u.eql(rhs_u)) return error.GammaInconsistency;

                const lhs_v = msg.public_share.mul(k2.chi) catch E.Point.identity;
                const rhs_v = (E.Point.mulBase(d[1]) catch E.Point.identity).add(msg.gamma_v);
                if (!lhs_v.eql(rhs_v)) return error.GammaInconsistency;

                expected_pk = expected_pk.add(msg.public_share);
                nonce_point = nonce_point.add(msg.instance_point);
                mask_sum = mask_sum.add(msg.psi);
                sum_u = sum_u.add(k2.c_u).add(d[0]);
                sum_v = sum_v.add(k2.c_v).add(d[1]);
            }

            // The additive shares must reconstruct the group key. This catches a
            // quorum that disagrees about the key before anything is signed.
            if (!expected_pk.eql(party.public_key)) return error.PublicKeyMismatch;
            if (nonce_point.isIdentity()) return error.TrivialNonce;

            const r = scalarFromX(E, nonce_point);
            const m = hash.reduceToScalar(E, data.message_hash);

            const u = state.instance_key.mul(mask_sum).add(sum_u);
            const v = state.key_share.mul(mask_sum).add(sum_v);
            const w = m.mul(state.inversion_mask).add(v.mul(r));

            return .{ .nonce_point = nonce_point, .r = r, .broadcast = .{ .u = u, .w = w } };
        }

        /// Phase 4: assemble the signature from every party's components.
        ///
        /// The sums are of `k * mask` and `m * mask + v * r`, so their quotient
        /// is the ordinary `k^-1 (m + r x)`; the masks cancel.
        pub fn phase4(
            party: P,
            data: SignData,
            out3: Out3,
            broadcasts: []const Round3(E),
        ) Error!Signature(E) {
            if (broadcasts.len != data.quorum.len) return error.WrongMessageCount;

            var numerator = E.Scalar.zero;
            var denominator = E.Scalar.zero;
            for (broadcasts) |b| {
                numerator = numerator.add(b.w);
                denominator = denominator.add(b.u);
            }
            if (denominator.isZero()) return error.ZeroDenominator;

            const s = normalizeS(E, numerator.mul(denominator.invert()));
            if (s.isZero()) return error.SignatureInvalid;

            // Recovery id, from the nonce point every party agreed on.
            const x = out3.nonce_point.xOnly();
            const x_was_reduced = !std.mem.eql(u8, &x, &out3.r.toBytes());
            var rec: u8 = if (out3.nonce_point.hasEvenY()) 0 else 1;
            if (x_was_reduced) rec |= 2;
            // Normalizing s flips the nonce point's parity.
            const raw_s = numerator.mul(denominator.invert());
            if (!raw_s.eql(s)) rec ^= 1;

            const sig = Signature(E){ .r = out3.r, .s = s, .recovery_id = rec };
            if (!verify(E, party.public_key, data.message_hash, sig)) return error.SignatureInvalid;
            return sig;
        }
    };
}

const testing = std.testing;
const K1 = @import("../curve.zig").Secp256k1;

const Dealt = struct { parties: []Party(K1), public_key: K1.Point };

/// Deal `n` parties directly, as key generation plus setup would.
///
/// Test support only: this holds every secret at once, and it takes the fast
/// path through `mul.pairFromRandomSeeds` rather than running base OTs.
/// `setup.zig` is the real thing.
fn dealParties(gpa: Allocator, n: u16, threshold: u16, rng: std.Random) !Dealt {
    // Shamir sharing of a fresh group secret.
    const coeffs = try gpa.alloc(K1.Scalar, threshold);
    defer gpa.free(coeffs);
    for (coeffs) |*c| c.* = K1.Scalar.random(rng);
    const public_key = try K1.Point.mulBase(coeffs[0]);

    const parties = try gpa.alloc(Party(K1), n);
    for (parties, 0..) |*p, idx| {
        const i: u16 = @intCast(idx + 1);
        // Horner evaluation of the sharing polynomial at i.
        const x = K1.Scalar.fromU64(i);
        var acc = K1.Scalar.zero;
        var k = coeffs.len;
        while (k > 0) {
            k -= 1;
            acc = acc.mul(x).add(coeffs[k]);
        }

        const peers = try gpa.alloc(Peer(K1), n - 1);
        const pairs = try gpa.alloc(zeroshare.SeedPair, n - 1);
        var m: usize = 0;
        for (1..n + 1) |jj| {
            const j: u16 = @intCast(jj);
            if (j == i) continue;
            peers[m] = .{ .index = j, .as_sender = undefined, .as_receiver = undefined };
            pairs[m] = .{ .counterparty = j, .lowest = i <= j, .seed = @splat(0) };
            m += 1;
        }
        p.* = .{
            .params = .{ .party = i, .n = n, .threshold = threshold },
            .execution_id = @splat(0xE1),
            .chain_code = @splat(0xCC),
            .key_share = acc,
            .public_key = public_key,
            .zero = .{ .pairs = pairs },
            .peers = peers,
        };
    }

    // One multiplication setup per ordered pair, one zero-share seed per
    // unordered pair.
    for (1..n + 1) |ii| {
        const i: u16 = @intCast(ii);
        for (ii + 1..n + 1) |jj| {
            const j: u16 = @intCast(jj);

            for ([_][2]u16{ .{ i, j }, .{ j, i } }) |dir| {
                const snd = dir[0];
                const rcv = dir[1];
                const pr = try mul.pairFromRandomSeeds(K1, gpa, rng);
                // Each side needs its own allocation, or freeing both parties
                // would free the gadget twice.
                const other_gadget = try gpa.dupe(K1.Scalar, pr.gadget);
                for (parties[snd - 1].peers) |*pe| {
                    if (pe.index == rcv) pe.as_sender = .{ .ote_sender = pr.sender.ote_sender, .gadget = pr.gadget };
                }
                for (parties[rcv - 1].peers) |*pe| {
                    if (pe.index == snd) pe.as_receiver = .{ .ote_receiver = pr.receiver.ote_receiver, .gadget = other_gadget };
                }
            }

            var half_i: zeroshare.Seed = undefined;
            var half_j: zeroshare.Seed = undefined;
            rng.bytes(&half_i);
            rng.bytes(&half_j);
            for (parties[i - 1].zero.pairs) |*sp| {
                if (sp.counterparty == j) sp.* = zeroshare.combine(i, j, half_i, half_j);
            }
            for (parties[j - 1].zero.pairs) |*sp| {
                if (sp.counterparty == i) sp.* = zeroshare.combine(j, i, half_j, half_i);
            }
        }
    }
    return .{ .parties = parties, .public_key = public_key };
}

fn freeParties(gpa: Allocator, parties: []Party(K1)) void {
    for (parties) |*p| p.deinit(gpa);
    gpa.free(parties);
}

/// Index of `other` within `self`'s counterparty list for `quorum`.
fn slotOf(quorum: []const u16, self_index: u16, other: u16) usize {
    var k: usize = 0;
    for (quorum) |q| {
        if (q == self_index) continue;
        if (q == other) return k;
        k += 1;
    }
    unreachable;
}

/// Drive a whole signing session across `quorum`, returning the signature each
/// party independently arrived at.
fn runSigning(gpa: Allocator, parties: []Party(K1), quorum: []const u16, msg_hash: [32]u8, rng: std.Random) ![]Signature(K1) {
    const t = quorum.len;
    const S = Signer(K1);
    const data_for = struct {
        fn f(q: []const u16, h: [32]u8) SignData {
            return .{ .sign_id = @splat(0x5A), .quorum = q, .message_hash = h };
        }
    }.f;

    const out1 = try gpa.alloc(S.Out1, t);
    defer gpa.free(out1);
    for (quorum, 0..) |p, a| out1[a] = try S.phase1(gpa, parties[p - 1], data_for(quorum, msg_hash), rng);

    // Round 1 delivery.
    const out2 = try gpa.alloc(S.Out2, t);
    defer gpa.free(out2);
    for (quorum, 0..) |p, a| {
        const from = try gpa.alloc(u16, t - 1);
        defer gpa.free(from);
        const msgs = try gpa.alloc(Round1(K1), t - 1);
        defer gpa.free(msgs);
        var k: usize = 0;
        for (quorum, 0..) |q, b| {
            if (q == p) continue;
            from[k] = q;
            msgs[k] = out1[b].messages[slotOf(quorum, q, p)];
            k += 1;
        }
        out2[a] = try S.phase2(gpa, parties[p - 1], data_for(quorum, msg_hash), &out1[a].state, from, msgs, rng);
    }
    for (out1) |*o| {
        o.state.deinit(gpa);
        for (o.messages) |*m| m.mul_open.deinit(gpa);
        gpa.free(o.messages);
    }

    // Round 2 delivery.
    const out3 = try gpa.alloc(S.Out3, t);
    defer gpa.free(out3);
    for (quorum, 0..) |p, a| {
        const from = try gpa.alloc(u16, t - 1);
        defer gpa.free(from);
        const msgs = try gpa.alloc(Round2(K1), t - 1);
        defer gpa.free(msgs);
        var k: usize = 0;
        for (quorum, 0..) |q, b| {
            if (q == p) continue;
            from[k] = q;
            msgs[k] = out2[b].messages[slotOf(quorum, q, p)];
            k += 1;
        }
        out3[a] = try S.phase3(gpa, parties[p - 1], data_for(quorum, msg_hash), &out2[a].state, from, msgs);
    }
    for (out2) |*o| {
        o.state.deinit(gpa);
        for (o.messages) |*m| m.mul_reply.deinit(gpa);
        gpa.free(o.messages);
    }

    // Round 3 is a broadcast, so everyone sees every component.
    const broadcasts = try gpa.alloc(Round3(K1), t);
    defer gpa.free(broadcasts);
    for (out3, 0..) |o, a| broadcasts[a] = o.broadcast;

    const sigs = try gpa.alloc(Signature(K1), t);
    for (quorum, 0..) |p, a| {
        sigs[a] = try S.phase4(parties[p - 1], data_for(quorum, msg_hash), out3[a], broadcasts);
    }
    return sigs;
}

test "a 2-of-3 DKLs23 signature verifies as ordinary ECDSA" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(51));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);

    const msg = "dkls23 in zig";
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});

    const quorum = [_]u16{ 1, 3 };
    const sigs = try runSigning(gpa, dealt.parties, &quorum, h, rng);
    defer gpa.free(sigs);

    // Every signer must reach the same signature, byte for byte.
    for (sigs[1..]) |s| {
        try testing.expect(s.r.eql(sigs[0].r));
        try testing.expect(s.s.eql(sigs[0].s));
    }

    try testing.expect(verify(K1, dealt.public_key, h, sigs[0]));

    // The real gate: an independent ECDSA implementation accepts it, hashing
    // the message itself.
    const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const std_pk = try StdEcdsa.PublicKey.fromSec1(&dealt.public_key.toBytes());
    const std_sig = StdEcdsa.Signature.fromBytes(sigs[0].toBytes());
    try std_sig.verify(msg, std_pk);
}

test "every quorum signs under the same key" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(52));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("quorum independence", &h, .{});

    // The signature must depend on the key, not on who happened to sign.
    for ([_][]const u16{ &.{ 1, 2 }, &.{ 1, 3 }, &.{ 2, 3 } }) |quorum| {
        const sigs = try runSigning(gpa, dealt.parties, quorum, h, rng);
        defer gpa.free(sigs);
        try testing.expect(verify(K1, dealt.public_key, h, sigs[0]));
    }
}

test "a 3-of-3 signature works too" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(53));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 3, rng);
    defer freeParties(gpa, dealt.parties);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("all three", &h, .{});
    const sigs = try runSigning(gpa, dealt.parties, &.{ 1, 2, 3 }, h, rng);
    defer gpa.free(sigs);
    try testing.expect(verify(K1, dealt.public_key, h, sigs[0]));
}

test "a signature does not verify against another message" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(54));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("the real message", &h, .{});
    const sigs = try runSigning(gpa, dealt.parties, &.{ 1, 2 }, h, rng);
    defer gpa.free(sigs);

    var other: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("a different message", &other, .{});
    try testing.expect(!verify(K1, dealt.public_key, other, sigs[0]));
    // Nor against a different key.
    const other_pk = try K1.Point.mulBase(K1.Scalar.fromU64(4242));
    try testing.expect(!verify(K1, other_pk, h, sigs[0]));
}

test "a counterparty that opens the wrong instance point is caught" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(55));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);
    const S = Signer(K1);
    const quorum = [_]u16{ 1, 2 };
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("commitment binding", &h, .{});
    const data = SignData{ .sign_id = @splat(0x5A), .quorum = &quorum, .message_hash = h };

    var a1 = try S.phase1(gpa, dealt.parties[0], data, rng);
    var b1 = try S.phase1(gpa, dealt.parties[1], data, rng);

    var a2 = try S.phase2(gpa, dealt.parties[0], data, &a1.state, &.{2}, &.{b1.messages[0]}, rng);
    var b2 = try S.phase2(gpa, dealt.parties[1], data, &b1.state, &.{1}, &.{a1.messages[0]}, rng);
    a1.deinit(gpa);
    b1.deinit(gpa);

    // Party 2 opens to a point it never committed to. Without the commitment
    // check it could pick its nonce after seeing everyone else's.
    var tampered = b2.messages[0];
    tampered.instance_point = tampered.instance_point.add(K1.Point.generator);
    try testing.expectError(
        error.CommitmentMismatch,
        S.phase3(gpa, dealt.parties[0], data, &a2.state, &.{2}, &.{tampered}),
    );

    a2.deinit(gpa);
    b2.deinit(gpa);
}

test "a quorum that disagrees about the key is caught before signing" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(56));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);
    const S = Signer(K1);
    const quorum = [_]u16{ 1, 2 };
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("key agreement", &h, .{});
    const data = SignData{ .sign_id = @splat(0x5A), .quorum = &quorum, .message_hash = h };

    var a1 = try S.phase1(gpa, dealt.parties[0], data, rng);
    var b1 = try S.phase1(gpa, dealt.parties[1], data, rng);
    var a2 = try S.phase2(gpa, dealt.parties[0], data, &a1.state, &.{2}, &.{b1.messages[0]}, rng);
    var b2 = try S.phase2(gpa, dealt.parties[1], data, &b1.state, &.{1}, &.{a1.messages[0]}, rng);
    a1.deinit(gpa);
    b1.deinit(gpa);

    // A public share that does not belong to this key must abort the session,
    // not produce a signature under some other key.
    var tampered = b2.messages[0];
    tampered.public_share = tampered.public_share.add(K1.Point.generator);
    const got = S.phase3(gpa, dealt.parties[0], data, &a2.state, &.{2}, &.{tampered});
    try testing.expect(got == error.GammaInconsistency or got == error.PublicKeyMismatch);

    a2.deinit(gpa);
    b2.deinit(gpa);
}

test "quorum validation rejects malformed inputs" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(57));
    const rng = prng.random();

    const dealt = try dealParties(gpa, 3, 2, rng);
    defer freeParties(gpa, dealt.parties);
    const S = Signer(K1);
    var h: [32]u8 = @splat(1);

    // Not a member of its own quorum.
    const excluded = [_]u16{ 2, 3 };
    try testing.expectError(error.InvalidQuorum, S.phase1(gpa, dealt.parties[0], .{ .sign_id = @splat(0), .quorum = &excluded, .message_hash = h }, rng));

    // Unsorted, which would silently mismatch counterparty ordering between
    // parties and route messages to the wrong slots.
    const unsorted = [_]u16{ 3, 1 };
    try testing.expectError(error.InvalidQuorum, S.phase1(gpa, dealt.parties[0], .{ .sign_id = @splat(0), .quorum = &unsorted, .message_hash = h }, rng));

    // Wrong size for the threshold.
    const too_many = [_]u16{ 1, 2, 3 };
    try testing.expectError(error.InvalidQuorum, S.phase1(gpa, dealt.parties[0], .{ .sign_id = @splat(0), .quorum = &too_many, .message_hash = h }, rng));
    h = @splat(0);
}
