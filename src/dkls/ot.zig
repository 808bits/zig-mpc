//! Endemic oblivious transfer (Zhou et al., <https://eprint.iacr.org/2022/1525.pdf>
//! Section 3), the base OT that DKLs23 names on page 30.
//!
//! One execution transfers one of two 32-byte strings: the sender learns both
//! `m0` and `m1` and nothing about the choice, the receiver learns exactly
//! `m_bit` and nothing about the other. Neither string is chosen by anyone;
//! they fall out of the transcript, which is what "endemic" means and what
//! makes the protocol cheap.
//!
//! The extension in `ote.zig` needs `kappa` of these, so everything here has a
//! batch form. Both parties reuse their expensive state across the batch: the
//! sender reuses one secret and one discrete-log proof, the receiver reuses one
//! seed. That reuse is what the paper's first paragraph on page 18 permits, and
//! it is why the proof of work in `proofs.zig` is paid once rather than 256
//! times. Each element of the batch still gets its own session id, so the
//! transfers stay independent.
//!
//! Roles here are the OT's own. In the extension they are swapped: an extension
//! sender is a base-OT receiver and vice versa.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash = @import("hash.zig");
const proofs = @import("proofs.zig");

pub const Error = error{
    /// The receiver's encryption proof did not verify, or claimed a base that
    /// does not match the seed it published. Attributable to the receiver.
    ReceiverCheated,
    /// The sender's discrete-log proof did not verify. Attributable to the
    /// sender.
    SenderCheated,
};

/// The receiver's reusable seed. Public: it is sent in the clear, and the
/// choice bits are hidden by the encryption proof, not by this.
pub const Seed = [hash.security]u8;

/// Derive the base point both sides must agree on from the receiver's seed.
fn baseFromSeed(comptime E: type, session_id: []const u8, seed: Seed) E.Point {
    const s = hash.taggedHashScalar(E, hash.tag.ot_base_h, &.{ session_id, &seed });
    return E.Point.mulBase(s) catch E.Point.identity;
}

/// The session id used for element `i` of a batch: a big-endian index in front
/// of the batch's own id.
fn batchSessionId(buf: []u8, i: u16, session_id: []const u8) []const u8 {
    std.mem.writeInt(u16, buf[0..2], i, .big);
    @memcpy(buf[2..][0..session_id.len], session_id);
    return buf[0 .. 2 + session_id.len];
}

/// Derive the transferred string from the agreed point.
fn message(comptime E: type, session_id: []const u8, p: E.Point) hash.Digest {
    const b = p.toBytes();
    return hash.taggedHash(hash.tag.ot_base_msg, &.{ session_id, &b });
}

pub fn Sender(comptime E: type) type {
    return struct {
        const Self = @This();
        pub const Proof = proofs.DLog(E);

        /// Secret exponent. Reused across the whole batch.
        s: E.Scalar,
        /// Proof that `s * G` is well formed, sent once and reused.
        proof: Proof,

        pub fn init(session_id: []const u8, rng: std.Random) proofs.Error!Self {
            var s = E.Scalar.random(rng);
            while (s.isZero()) s = E.Scalar.random(rng);
            return .{ .s = s, .proof = try Proof.prove(s, session_id, rng) };
        }

        pub fn deinit(self: *Self) void {
            self.s.zeroize();
        }

        /// What the sender publishes. The point `z = s * G` is inside it.
        pub fn publicProof(self: Self) Proof {
            return self.proof;
        }

        /// Complete one transfer against the receiver's proof.
        pub fn receive(self: Self, session_id: []const u8, seed: Seed, enc: proofs.Enc(E)) Error!struct { m0: hash.Digest, m1: hash.Digest } {
            const h = baseFromSeed(E, session_id, seed);
            // The proof must verify *and* be about the base this seed implies.
            // Checking only the proof would let the receiver prove a statement
            // about a base of its own choosing.
            if (!enc.verify(session_id) or !h.eql(enc.base_h)) return error.ReceiverCheated;

            const for_m0 = enc.v.mul(self.s) catch E.Point.identity;
            const for_m1 = enc.v.sub(h).mul(self.s) catch E.Point.identity;
            return .{
                .m0 = message(E, session_id, for_m0),
                .m1 = message(E, session_id, for_m1),
            };
        }

        /// Complete a whole batch. `m0`/`m1` are filled with one entry per proof.
        pub fn receiveBatch(
            self: Self,
            session_id: []const u8,
            seed: Seed,
            encs: []const proofs.Enc(E),
            m0: []hash.Digest,
            m1: []hash.Digest,
            scratch: []u8,
        ) Error!void {
            std.debug.assert(m0.len == encs.len and m1.len == encs.len);
            for (encs, 0..) |enc, i| {
                const sid = batchSessionId(scratch, @intCast(i), session_id);
                const out = try self.receive(sid, seed, enc);
                m0[i] = out.m0;
                m1[i] = out.m1;
            }
        }
    };
}

pub fn Receiver(comptime E: type) type {
    return struct {
        const Self = @This();

        seed: Seed,

        pub fn init(rng: std.Random) Self {
            var seed: Seed = undefined;
            rng.bytes(&seed);
            return .{ .seed = seed };
        }

        /// Start one transfer for `bit`. The scalar is kept, the proof is sent.
        pub fn choose(self: Self, session_id: []const u8, bit: u1, rng: std.Random) struct { r: E.Scalar, proof: proofs.Enc(E) } {
            const r = E.Scalar.random(rng);
            const h = baseFromSeed(E, session_id, self.seed);
            return .{ .r = r, .proof = proofs.Enc(E).prove(session_id, h, r, bit, rng) };
        }

        /// Start a batch, one transfer per choice bit. `bits` is packed.
        pub fn chooseBatch(
            self: Self,
            session_id: []const u8,
            bits: []const u8,
            count: usize,
            out_r: []E.Scalar,
            out_proofs: []proofs.Enc(E),
            scratch: []u8,
            rng: std.Random,
        ) void {
            std.debug.assert(out_r.len == count and out_proofs.len == count);
            for (0..count) |i| {
                const sid = batchSessionId(scratch, @intCast(i), session_id);
                const bit: u1 = @truncate(bits[i >> 3] >> @intCast(i & 7));
                const got = self.choose(sid, bit, rng);
                out_r[i] = got.r;
                out_proofs[i] = got.proof;
            }
        }

        /// Check the sender's proof once, before the per-element work.
        pub fn acceptSender(session_id: []const u8, proof: proofs.DLog(E)) Error!E.Point {
            if (!proof.verify(session_id)) return error.SenderCheated;
            return proof.point;
        }

        /// Finish one transfer, given the kept scalar and the sender's point.
        pub fn finish(session_id: []const u8, r: E.Scalar, z: E.Point) hash.Digest {
            const p = z.mul(r) catch E.Point.identity;
            return message(E, session_id, p);
        }

        /// Finish a batch. The sender's proof is verified once for all of them.
        pub fn finishBatch(
            session_id: []const u8,
            rs: []const E.Scalar,
            proof: proofs.DLog(E),
            out: []hash.Digest,
            scratch: []u8,
        ) Error!void {
            std.debug.assert(out.len == rs.len);
            const z = try acceptSender(session_id, proof);
            for (rs, 0..) |r, i| {
                const sid = batchSessionId(scratch, @intCast(i), session_id);
                out[i] = finish(sid, r, z);
            }
        }
    };
}

/// Scratch space a batch needs for its per-element session ids.
pub fn scratchLen(session_id_len: usize) usize {
    return 2 + session_id_len;
}

const testing = std.testing;
const curve = @import("../curve.zig");
const K1 = curve.Secp256k1;

test "one transfer moves exactly the chosen string" {
    var prng = std.Random.DefaultCsprng.init(@splat(11));
    const rng = prng.random();
    const sid = "base-ot";

    var sender = try Sender(K1).init(sid, rng);
    defer sender.deinit();
    const receiver = Receiver(K1).init(rng);

    for ([_]u1{ 0, 1 }) |bit| {
        const chosen = receiver.choose(sid, bit, rng);
        const out = try sender.receive(sid, receiver.seed, chosen.proof);
        const z = try Receiver(K1).acceptSender(sid, sender.publicProof());
        const got = Receiver(K1).finish(sid, chosen.r, z);

        const want = if (bit == 0) out.m0 else out.m1;
        const other = if (bit == 0) out.m1 else out.m0;
        try testing.expectEqualSlices(u8, &want, &got);
        // The receiver must not be able to derive the string it did not pick.
        try testing.expect(!std.mem.eql(u8, &other, &got));
    }
}

test "a receiver that lies about its seed is caught" {
    var prng = std.Random.DefaultCsprng.init(@splat(12));
    const rng = prng.random();
    const sid = "base-ot";

    var sender = try Sender(K1).init(sid, rng);
    defer sender.deinit();
    const receiver = Receiver(K1).init(rng);
    const chosen = receiver.choose(sid, 1, rng);

    // Proof is internally valid but describes a base derived from a different
    // seed, which is the attack the base check exists to stop.
    var other_seed = receiver.seed;
    other_seed[0] ^= 0xFF;
    try testing.expectError(error.ReceiverCheated, sender.receive(sid, other_seed, chosen.proof));
}

test "a bad sender proof is caught before any transfer" {
    var prng = std.Random.DefaultCsprng.init(@splat(13));
    const rng = prng.random();
    var sender = try Sender(K1).init("sid", rng);
    defer sender.deinit();

    var bad = sender.publicProof();
    bad.point = bad.point.add(K1.Point.generator);
    try testing.expectError(error.SenderCheated, Receiver(K1).acceptSender("sid", bad));
    // The same proof under a different session must also fail.
    try testing.expectError(error.SenderCheated, Receiver(K1).acceptSender("other", sender.publicProof()));
}

test "a batch transfers every chosen string, and elements are independent" {
    const n = 32;
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(14));
    const rng = prng.random();
    const sid = "batch-sid";

    var sender = try Sender(K1).init(sid, rng);
    defer sender.deinit();
    const receiver = Receiver(K1).init(rng);

    var bits: [n / 8]u8 = undefined;
    rng.bytes(&bits);

    const rs = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(rs);
    const ps = try gpa.alloc(proofs.Enc(K1), n);
    defer gpa.free(ps);
    const scratch = try gpa.alloc(u8, scratchLen(sid.len));
    defer gpa.free(scratch);

    receiver.chooseBatch(sid, &bits, n, rs, ps, scratch, rng);

    const m0 = try gpa.alloc(hash.Digest, n);
    defer gpa.free(m0);
    const m1 = try gpa.alloc(hash.Digest, n);
    defer gpa.free(m1);
    try sender.receiveBatch(sid, receiver.seed, ps, m0, m1, scratch);

    const got = try gpa.alloc(hash.Digest, n);
    defer gpa.free(got);
    try Receiver(K1).finishBatch(sid, rs, sender.publicProof(), got, scratch);

    for (0..n) |i| {
        const bit: u1 = @truncate(bits[i >> 3] >> @intCast(i & 7));
        const want = if (bit == 0) m0[i] else m1[i];
        try testing.expectEqualSlices(u8, &want, &got[i]);
    }

    // Distinct session ids per element: no two transfers produced the same
    // pair, which would mean the index was not actually bound in.
    for (0..n) |i| {
        for (i + 1..n) |j| {
            try testing.expect(!std.mem.eql(u8, &m0[i], &m0[j]));
        }
    }
}
