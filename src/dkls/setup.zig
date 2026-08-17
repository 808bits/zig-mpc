//! One-time pairwise setup, run once after key generation.
//!
//! DKLs23 signing needs two things per pair of parties that key generation does
//! not produce: base-OT correlations for the multiplication, and a shared seed
//! for the shares of zero. Both are established here, reused by every later
//! signature, and independent of which quorum eventually signs.
//!
//! This is the DKLs23 analogue of `auxgen.zig`, and the comparison is the point
//! of the whole protocol: CGGMP24's aux-info step generates safe primes and
//! proves properties of a Paillier modulus, which is the slowest thing in this
//! library. Here the cost is `kappa` endemic OTs and one proof of work per
//! ordered pair, all on the curve already in use.
//!
//! Two rounds:
//!
//!   round1   everything for the base OTs in both directions, plus a
//!            commitment to this party's half of each zero-share seed  [p2p]
//!   round2   open those commitments                                   [p2p]
//!
//! The base OTs need no second round because each party sends its half of both
//! directions at once. The zero-share seeds do: committing first stops a party
//! choosing its half after seeing its counterparty's.
//!
//! # Session ids
//!
//! Each ordered pair gets its own session id, named by role so both sides
//! derive the same string: `sid(receiver, sender)` where the roles are the
//! *multiplication's*. Party `i` is the multiplication receiver toward `j`
//! under `sid(i, j)` and the sender under `sid(j, i)`. Within a direction the
//! base OT's roles are the reverse, which is where the crossover lives.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash = @import("hash.zig");
const proofs = @import("proofs.zig");
const ot = @import("ot.zig");
const ote = @import("ote.zig");
const mul = @import("mul.zig");
const zeroshare = @import("zeroshare.zig");
const sign = @import("sign.zig");

pub const Error = error{
    WrongMessageCount,
    UnexpectedSender,
    DuplicateSender,
    /// A counterparty opened a zero-share half it had not committed to.
    DecommitmentMismatch,
};

/// Derive the session id for one direction. `receiver`/`sender` are the
/// multiplication roles.
fn directionId(execution_id: [32]u8, receiver: u16, sender: u16) [36]u8 {
    var out: [36]u8 = undefined;
    @memcpy(out[0..32], &execution_id);
    std.mem.writeInt(u16, out[32..34], receiver, .big);
    std.mem.writeInt(u16, out[34..36], sender, .big);
    return out;
}

/// What each party sends every counterparty in round 1.
pub fn Round1(comptime E: type) type {
    return struct {
        /// Base-OT sender material for the direction where this party is the
        /// multiplication receiver.
        dlog_proof: proofs.DLog(E),
        /// The gadget nonce for that same direction, chosen by the receiver.
        nonce: E.Scalar,
        /// Base-OT receiver material for the opposite direction.
        seed: ot.Seed,
        enc_proofs: []proofs.Enc(E),
        /// Commitment to this party's half of the zero-share seed.
        zero_commitment: hash.Digest,

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            gpa.free(self.enc_proofs);
            self.* = undefined;
        }
    };
}

pub fn Round2(comptime E: type) type {
    _ = E;
    return struct {
        zero_half: zeroshare.Seed,
        zero_salt: hash.Salt,
    };
}

/// Per-counterparty state carried between the two rounds. Secret.
pub fn Kept(comptime E: type) type {
    return struct {
        index: u16,
        /// This party's base-OT sender secret for the direction it receives in.
        base_sender: ot.Sender(E),
        /// The nonce it chose for that direction.
        nonce: E.Scalar,
        /// Base-OT receiver state for the opposite direction.
        base_seed: ot.Seed,
        correlation: [ote.row_len]u8,
        rs: []E.Scalar,
        zero_half: zeroshare.Seed,
        zero_salt: hash.Salt,

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            self.base_sender.deinit();
            self.nonce.zeroize();
            std.crypto.secureZero(u8, &self.base_seed);
            std.crypto.secureZero(u8, &self.correlation);
            for (self.rs) |*r| r.zeroize();
            gpa.free(self.rs);
            std.crypto.secureZero(u8, &self.zero_half);
            self.* = undefined;
        }
    };
}

pub fn Setup(comptime E: type) type {
    return struct {
        const Self = @This();

        pub const State1 = struct {
            kept: []Kept(E),

            pub fn deinit(self: *State1, gpa: Allocator) void {
                for (self.kept) |*k| k.deinit(gpa);
                gpa.free(self.kept);
                self.* = undefined;
            }
        };

        pub const Out1 = struct {
            state: State1,
            /// One per counterparty, in ascending index order.
            messages: []Round1(E),

            pub fn deinit(self: *Out1, gpa: Allocator) void {
                self.state.deinit(gpa);
                for (self.messages) |*m| m.deinit(gpa);
                gpa.free(self.messages);
                self.* = undefined;
            }
        };

        fn counterparties(gpa: Allocator, party: u16, n: u16) Allocator.Error![]u16 {
            const out = try gpa.alloc(u16, n - 1);
            var k: usize = 0;
            for (1..n + 1) |jj| {
                const j: u16 = @intCast(jj);
                if (j == party) continue;
                out[k] = j;
                k += 1;
            }
            return out;
        }

        /// Round 1: base-OT material in both directions plus a zero-share
        /// commitment, for every counterparty.
        ///
        /// This is the expensive call. Each counterparty costs one Fischlin
        /// proof of work and `kappa` encryption proofs.
        pub fn round1(
            gpa: Allocator,
            params: sign.Params,
            execution_id: [32]u8,
            rng: std.Random,
        ) (proofs.Error || Allocator.Error)!Out1 {
            const cps = try counterparties(gpa, params.party, params.n);
            defer gpa.free(cps);

            const kept = try gpa.alloc(Kept(E), cps.len);
            errdefer gpa.free(kept);
            const messages = try gpa.alloc(Round1(E), cps.len);
            errdefer gpa.free(messages);

            for (cps, 0..) |cp, i| {
                // Direction in which this party receives: it is the base OT's
                // sender, so it proves knowledge of its secret exponent.
                const recv_sid = directionId(execution_id, params.party, cp);
                var base_sender = try ot.Sender(E).init(&recv_sid, rng);
                errdefer base_sender.deinit();
                const nonce = E.Scalar.random(rng);

                // Direction in which this party sends: it is the base OT's
                // receiver, so it publishes a seed and one proof per choice bit.
                const send_sid = directionId(execution_id, cp, params.party);
                const base_receiver = ot.Receiver(E).init(rng);
                var correlation: [ote.row_len]u8 = undefined;
                rng.bytes(&correlation);

                const rs = try gpa.alloc(E.Scalar, ote.kappa);
                errdefer gpa.free(rs);
                const enc_proofs = try gpa.alloc(proofs.Enc(E), ote.kappa);
                errdefer gpa.free(enc_proofs);
                const scratch = try gpa.alloc(u8, ot.scratchLen(send_sid.len));
                defer gpa.free(scratch);
                base_receiver.chooseBatch(&send_sid, &correlation, ote.kappa, rs, enc_proofs, scratch, rng);

                var zero_half: zeroshare.Seed = undefined;
                rng.bytes(&zero_half);
                const c = hash.commit(&zero_half, rng);

                kept[i] = .{
                    .index = cp,
                    .base_sender = base_sender,
                    .nonce = nonce,
                    .base_seed = base_receiver.seed,
                    .correlation = correlation,
                    .rs = rs,
                    .zero_half = zero_half,
                    .zero_salt = c.salt,
                };
                messages[i] = .{
                    .dlog_proof = base_sender.publicProof(),
                    .nonce = nonce,
                    .seed = base_receiver.seed,
                    .enc_proofs = enc_proofs,
                    .zero_commitment = c.digest,
                };
            }

            return .{ .state = .{ .kept = kept }, .messages = messages };
        }

        pub const Out2 = struct {
            messages: []Round2(E),

            pub fn deinit(self: *Out2, gpa: Allocator) void {
                gpa.free(self.messages);
                self.* = undefined;
            }
        };

        /// Round 2: open the zero-share commitments. Nothing is verified here;
        /// the counterparties' round-1 material is checked in `finalize`, which
        /// is the first point at which everything needed is present.
        pub fn round2(gpa: Allocator, state: State1) Allocator.Error!Out2 {
            const messages = try gpa.alloc(Round2(E), state.kept.len);
            for (state.kept, 0..) |k, i| {
                messages[i] = .{ .zero_half = k.zero_half, .zero_salt = k.zero_salt };
            }
            return .{ .messages = messages };
        }

        /// Build the signing party from both rounds' messages.
        ///
        /// `from` names the sender of each message; all three slices are
        /// parallel and must cover every counterparty exactly once.
        pub fn finalize(
            gpa: Allocator,
            params: sign.Params,
            execution_id: [32]u8,
            chain_code: [32]u8,
            key_share: E.Scalar,
            public_key: E.Point,
            state: State1,
            from: []const u16,
            r1: []const Round1(E),
            r2: []const Round2(E),
        ) (Error || ot.Error || Allocator.Error)!sign.Party(E) {
            const cps = try counterparties(gpa, params.party, params.n);
            defer gpa.free(cps);
            if (r1.len != cps.len or r2.len != cps.len or from.len != cps.len) return error.WrongMessageCount;

            const peers = try gpa.alloc(sign.Peer(E), cps.len);
            errdefer gpa.free(peers);
            const pairs = try gpa.alloc(zeroshare.SeedPair, cps.len);
            errdefer gpa.free(pairs);

            // Two separate marks. `seen` is set as soon as a sender is
            // accepted, so a duplicate is caught before any work; `built` is
            // set only once the peer actually exists, so the error path never
            // frees an uninitialized slot.
            var seen = try gpa.alloc(bool, cps.len);
            defer gpa.free(seen);
            @memset(seen, false);
            var built = try gpa.alloc(bool, cps.len);
            defer gpa.free(built);
            @memset(built, false);

            errdefer for (built, 0..) |done, i| {
                if (done) peers[i].deinit(gpa);
            };

            for (from, r1, r2) |sender, m1, m2| {
                const slot = std.mem.indexOfScalar(u16, cps, sender) orelse return error.UnexpectedSender;
                if (seen[slot]) return error.DuplicateSender;
                seen[slot] = true;
                const k = &state.kept[slot];

                if (!hash.verifyCommitment(&m2.zero_half, m1.zero_commitment, m2.zero_salt)) {
                    return error.DecommitmentMismatch;
                }
                pairs[slot] = zeroshare.combine(params.party, sender, k.zero_half, m2.zero_half);

                // Direction where this party receives: consume the
                // counterparty's seed and proofs as the base OT's sender.
                const recv_sid = directionId(execution_id, params.party, sender);
                const scratch_r = try gpa.alloc(u8, ot.scratchLen(recv_sid.len));
                defer gpa.free(scratch_r);
                const m0 = try gpa.alloc(hash.Digest, ote.kappa);
                defer gpa.free(m0);
                const m1s = try gpa.alloc(hash.Digest, ote.kappa);
                defer gpa.free(m1s);
                try k.base_sender.receiveBatch(&recv_sid, m1.seed, m1.enc_proofs, m0, m1s, scratch_r);

                var as_receiver: mul.Receiver(E) = .{
                    .ote_receiver = .{ .seeds0 = undefined, .seeds1 = undefined },
                    .gadget = try gpa.alloc(E.Scalar, ote.batch_size),
                };
                @memcpy(&as_receiver.ote_receiver.seeds0, m0);
                @memcpy(&as_receiver.ote_receiver.seeds1, m1s);
                // The receiver's own nonce fixes this direction's gadget.
                mul.deriveGadget(E, &recv_sid, k.nonce, as_receiver.gadget);

                // Opposite direction: finish as the base OT's receiver against
                // the counterparty's discrete-log proof.
                const send_sid = directionId(execution_id, sender, params.party);
                const scratch_s = try gpa.alloc(u8, ot.scratchLen(send_sid.len));
                defer gpa.free(scratch_s);
                const chosen = try gpa.alloc(hash.Digest, ote.kappa);
                defer gpa.free(chosen);
                try ot.Receiver(E).finishBatch(&send_sid, k.rs, m1.dlog_proof, chosen, scratch_s);

                var as_sender: mul.Sender(E) = .{
                    .ote_sender = .{ .correlation = k.correlation, .seeds = undefined },
                    .gadget = try gpa.alloc(E.Scalar, ote.batch_size),
                };
                @memcpy(&as_sender.ote_sender.seeds, chosen);
                // Here the counterparty is the multiplication receiver, so its
                // nonce fixes the gadget.
                mul.deriveGadget(E, &send_sid, m1.nonce, as_sender.gadget);

                peers[slot] = .{ .index = sender, .as_sender = as_sender, .as_receiver = as_receiver };
                built[slot] = true;
            }

            // `cps` is built in ascending order and every peer was written at
            // its own slot, so `peers` is already sorted by index, which is what
            // the signing phases assume. Sorting explicitly is not an option:
            // a `Peer` is ~24 KB and `std.mem.sort`'s rotate cannot handle a
            // type that large.

            return .{
                .params = params,
                .execution_id = execution_id,
                .chain_code = chain_code,
                .key_share = key_share,
                .public_key = public_key,
                .zero = .{ .pairs = pairs },
                .peers = peers,
            };
        }
    };
}

const testing = std.testing;
const K1 = @import("../curve.zig").Secp256k1;

test "setup produces parties that can sign" {
    // This is the slow one: a real 2-party setup runs 2 Fischlin proofs and
    // 512 encryption proofs. It is the only test that exercises the genuine
    // path from setup through to a signature.
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(61));
    const rng = prng.random();

    const n: u16 = 2;
    const threshold: u16 = 2;
    const eid: [32]u8 = @splat(0xE7);
    const chain: [32]u8 = @splat(0xC3);

    // A trivial 2-of-2 sharing.
    const secret = K1.Scalar.random(rng);
    const a1 = K1.Scalar.random(rng);
    const shares = [_]K1.Scalar{
        secret.add(a1.mul(K1.Scalar.fromU64(1))),
        secret.add(a1.mul(K1.Scalar.fromU64(2))),
    };
    const public_key = try K1.Point.mulBase(secret);

    const S = Setup(K1);
    var o1a = try S.round1(gpa, .{ .party = 1, .n = n, .threshold = threshold }, eid, rng);
    defer o1a.deinit(gpa);
    var o1b = try S.round1(gpa, .{ .party = 2, .n = n, .threshold = threshold }, eid, rng);
    defer o1b.deinit(gpa);

    var o2a = try S.round2(gpa, o1a.state);
    defer o2a.deinit(gpa);
    var o2b = try S.round2(gpa, o1b.state);
    defer o2b.deinit(gpa);

    var pa = try S.finalize(gpa, .{ .party = 1, .n = n, .threshold = threshold }, eid, chain, shares[0], public_key, o1a.state, &.{2}, &.{o1b.messages[0]}, &.{o2b.messages[0]});
    defer pa.deinit(gpa);
    var pb = try S.finalize(gpa, .{ .party = 2, .n = n, .threshold = threshold }, eid, chain, shares[1], public_key, o1b.state, &.{1}, &.{o1a.messages[0]}, &.{o2a.messages[0]});
    defer pb.deinit(gpa);

    // The zero shares from a real setup must still cancel.
    const zsum = pa.zero.compute("z", &.{2}).add(pb.zero.compute("z", &.{1}));
    try testing.expect(zsum.isZero());

    // And the parties must be able to sign together.
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("real setup", &h, .{});
    const quorum = [_]u16{ 1, 2 };
    const data = sign.SignData{ .sign_id = @splat(0x11), .quorum = &quorum, .message_hash = h };
    const Sg = sign.Signer(K1);

    var f1a = try Sg.phase1(gpa, pa, data, rng);
    var f1b = try Sg.phase1(gpa, pb, data, rng);
    var f2a = try Sg.phase2(gpa, pa, data, &f1a.state, &.{2}, &.{f1b.messages[0]}, rng);
    var f2b = try Sg.phase2(gpa, pb, data, &f1b.state, &.{1}, &.{f1a.messages[0]}, rng);
    f1a.deinit(gpa);
    f1b.deinit(gpa);

    const f3a = try Sg.phase3(gpa, pa, data, &f2a.state, &.{2}, &.{f2b.messages[0]});
    const f3b = try Sg.phase3(gpa, pb, data, &f2b.state, &.{1}, &.{f2a.messages[0]});
    f2a.deinit(gpa);
    f2b.deinit(gpa);

    const bcast = [_]sign.Round3(K1){ f3a.broadcast, f3b.broadcast };
    const sig = try Sg.phase4(pa, data, f3a, &bcast);
    const sig_b = try Sg.phase4(pb, data, f3b, &bcast);
    try testing.expect(sig.r.eql(sig_b.r) and sig.s.eql(sig_b.s));

    const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const std_pk = try StdEcdsa.PublicKey.fromSec1(&public_key.toBytes());
    const std_sig = StdEcdsa.Signature.fromBytes(sig.toBytes());
    try std_sig.verify("real setup", std_pk);
}

test "a peer that opens the wrong zero-share half is caught" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(62));
    const rng = prng.random();

    const params = sign.Params{ .party = 1, .n = 2, .threshold = 2 };
    const other = sign.Params{ .party = 2, .n = 2, .threshold = 2 };
    const eid: [32]u8 = @splat(0xE7);
    const S = Setup(K1);

    var o1a = try S.round1(gpa, params, eid, rng);
    defer o1a.deinit(gpa);
    var o1b = try S.round1(gpa, other, eid, rng);
    defer o1b.deinit(gpa);
    var o2b = try S.round2(gpa, o1b.state);
    defer o2b.deinit(gpa);

    // Opening a half that was never committed would let a party pick the
    // shared seed after seeing its counterparty's contribution.
    var tampered = o2b.messages[0];
    tampered.zero_half[0] ^= 1;

    const pk = try K1.Point.mulBase(K1.Scalar.one);
    try testing.expectError(error.DecommitmentMismatch, S.finalize(gpa, params, eid, @splat(0), K1.Scalar.one, pk, o1a.state, &.{2}, &.{o1b.messages[0]}, &.{tampered}));
}
