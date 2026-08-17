//! KOS OT extension (<https://eprint.iacr.org/2015/546.pdf>, Fig. 10), with the
//! SoftSpokenOT correction and DKLs23's Fiat-Shamir round reduction.
//!
//! This file holds the bit-level core of the whole port: a GF(2^208)
//! multiplication and a bit-matrix transpose. Both are checked against vectors
//! generated from the reference implementation, because a slip in either is
//! invisible to protocol-level tests (the two halves of one implementation
//! agree with each other while both being wrong).
//!
//! # Where this deviates from the reference, on purpose
//!
//! **`fieldMul` is branch-free.** The reference tests `if (a[j] >> k) % 2 == 1`
//! and conditionally XORs. That branch is on a bit of `a`, and `a` is secret at
//! both call sites: the receiver feeds in its packed choice bits, and both
//! parties feed in PRG output derived from the base-OT seeds. A branch there is
//! a timing oracle on exactly the values the protocol is meant to hide, so the
//! conditional XOR is done with a mask instead. Same output, checked by vector.
//!
//! **Bits are packed everywhere.** The reference carries choice bits and the
//! correlation as `Vec<bool>` and separately derives a packed form when it
//! needs one. Keeping only the packed form removes the two representations
//! that have to agree, and with them a class of indexing bug. Bit `i` lives in
//! byte `i/8` at position `i%8`, which is the reference's packing.

const std = @import("std");
const hash = @import("hash.zig");

/// Computational security parameter, and the number of base OTs the extension
/// consumes. `kappa` in the papers.
pub const kappa = 256;
/// Statistical security parameter.
pub const stat_security = 80;
/// Security of the consistency check field, `128 + lambda_s`.
pub const ot_security = 208;
/// OTs produced per extension call.
pub const batch_size = 256 + 2 * stat_security;
/// Batch plus the noise rows the consistency check consumes.
pub const extended_batch_size = batch_size + ot_security;

pub const prg_len = extended_batch_size / 8;
pub const field_len = ot_security / 8;
pub const row_len = kappa / 8;
pub const batch_bytes = batch_size / 8;

comptime {
    // The consistency check splits a row into exactly three field elements,
    // which only works if the sizes line up. `m` in KOS Fig. 10 is 2.
    std.debug.assert(extended_batch_size == 3 * ot_security);
    std.debug.assert(batch_size % 8 == 0);
    std.debug.assert(extended_batch_size % 8 == 0);
}

/// One row of PRG output: `extended_batch_size` bits, packed.
pub const PrgRow = [prg_len]u8;
/// A GF(2^208) element, packed little-endian by byte.
pub const FieldElement = [field_len]u8;
/// One transposed row: `kappa` bits, packed.
pub const TransposedRow = [row_len]u8;

/// Read bit `i` from a packed bit array.
pub fn getBit(bytes: []const u8, i: usize) u1 {
    return @truncate(bytes[i >> 3] >> @intCast(i & 7));
}

/// Write bit `i` of a packed bit array.
pub fn setBit(bytes: []u8, i: usize, v: u1) void {
    const mask = @as(u8, 1) << @intCast(i & 7);
    if (v == 1) bytes[i >> 3] |= mask else bytes[i >> 3] &= ~mask;
}

// ---------------------------------------------------------------------------
// GF(2^208)
// ---------------------------------------------------------------------------

/// Multiply in GF(2^208) modulo f(X) = X^208 + X^9 + X^3 + X + 1.
///
/// Right-to-left comb multiplication (Hankerson-Menezes-Vanstone Alg. 2.34)
/// followed by the reduction of their Fig. 2.9. Branch-free: see the note at
/// the top of this file for why that matters here.
pub fn fieldMul(a_bytes: FieldElement, b_bytes: FieldElement) FieldElement {
    const w = 64;
    const t = 4;

    var a: [t]u64 = @splat(0);
    var b: [t + 1]u64 = @splat(0);
    var c: [2 * t]u64 = @splat(0);

    for (0..field_len) |i| {
        a[i >> 3] |= @as(u64, a_bytes[i]) << @intCast((i & 7) << 3);
        b[i >> 3] |= @as(u64, b_bytes[i]) << @intCast((i & 7) << 3);
    }

    for (0..w) |k| {
        for (0..t) |j| {
            // mask is all-ones when bit k of a[j] is set, all-zeros otherwise.
            // This replaces the reference's data-dependent branch.
            const bit: u64 = (a[j] >> @intCast(k)) & 1;
            const mask: u64 = ~bit +% 1;
            for (0..t + 1) |i| c[j + i] ^= b[i] & mask;
        }
        if (k != w - 1) {
            var i: usize = t;
            while (i >= 1) : (i -= 1) b[i] = (b[i] << 1) | (b[i - 1] >> 63);
        }
        b[0] <<= 1;
    }

    // Reduce the high half. 208 = 3*64 + 16, so each folded word contributes to
    // two lower words; the shift amounts follow the exponents (9, 3, 1, 0).
    var i: usize = 2 * t;
    while (i > t) {
        i -= 1;
        const v = c[i];
        c[i - 4] ^= (v << 57) ^ (v << 51) ^ (v << 49) ^ (v << 48);
        c[i - 3] ^= (v >> 7) ^ (v >> 13) ^ (v >> 15) ^ (v >> 16);
        c[i] = 0;
    }
    // c[t-1] holds 16 live bits; fold the rest.
    const v = c[t - 1] >> 16;
    c[0] ^= (v << 9) ^ (v << 3) ^ (v << 1) ^ v;
    c[t - 1] &= 0xFFFF;

    var out: FieldElement = undefined;
    for (0..field_len) |k| {
        out[k] = @truncate((c[k >> 3] >> @intCast((k & 7) << 3)) & 0xFF);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Transpose
// ---------------------------------------------------------------------------

/// Transpose a `kappa` x `extended_batch_size` bit matrix, keeping the first
/// `batch_size` columns.
///
/// Rows of the input are packed little-endian by bit, so the row
/// [1,1,1,0,0,0,0,0, 1,0,1,0,0,0,0,0] is the bytes [7, 5], not [224, 160].
/// The output rows are packed the same way.
///
/// `out` must have `batch_size` entries; it is fully written.
pub fn cutAndTranspose(out: []TransposedRow, input: []const PrgRow) void {
    std.debug.assert(out.len == batch_size);
    std.debug.assert(input.len == kappa);
    for (out) |*r| r.* = @splat(0);

    for (0..row_len) |row_byte| {
        for (0..8) |row_bit| {
            const src = &input[(row_byte << 3) + row_bit];
            const shift: u3 = @intCast(row_bit);
            for (0..batch_bytes) |col_byte| {
                const packed_byte = src[col_byte];
                for (0..8) |col_bit| {
                    const entry: u8 = (packed_byte >> @intCast(col_bit)) & 1;
                    out[(col_byte << 3) + col_bit][row_byte] |= entry << shift;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PRG
// ---------------------------------------------------------------------------

/// Expand a 32-byte seed into one `extended_batch_size`-bit row.
///
/// SHA-256 gives 32 bytes and a row needs 78, so chunks are concatenated with a
/// counter until full and the tail is discarded, exactly as the reference does.
pub fn expandSeed(session_id: []const u8, index: u16, seed: hash.Digest) PrgRow {
    var out: PrgRow = undefined;
    var written: usize = 0;
    var count: u16 = 0;
    while (written < prg_len) {
        var index_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &index_be, index, .big);
        var count_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &count_be, count, .big);
        count += 1;
        const chunk = hash.taggedHash(hash.tag.ote_prg, &.{ session_id, &index_be, &count_be, &seed });
        const take = @min(chunk.len, prg_len - written);
        @memcpy(out[written..][0..take], chunk[0..take]);
        written += take;
    }
    return out;
}

// ---------------------------------------------------------------------------
// The extension protocol
// ---------------------------------------------------------------------------

const Allocator = std.mem.Allocator;
const ot = @import("ot.zig");
const proofs = @import("proofs.zig");

pub const Error = error{
    /// The receiver's consistency-check values did not match. Per KOS this is
    /// an active cheat, not noise, and the base-OT correlations are now
    /// compromised: the counterparty must be excluded, not retried.
    ConsistencyCheckFailed,
};

/// Number of correlations carried per extension call. DKLs23 runs the
/// multiplication with `L = 2` inputs and needs a pad plus a check value for
/// each, so a single batch of the receiver's OT instances serves four
/// payloads. This is the "forced reuse" of the paper's page 8.
pub const ot_width = 4;

fn chiPair(session_id: []const u8, u: []const PrgRow) [2]FieldElement {
    // DKLs23 replaces KOS's extra round with Fiat-Shamir over the matrix the
    // receiver has already committed to by sending.
    const flat: []const u8 = @as([*]const u8, @ptrCast(u.ptr))[0 .. u.len * prg_len];
    var out: [2]FieldElement = undefined;
    inline for (.{ "chi1", "chi2" }, 0..) |label, i| {
        const d = hash.taggedHash(hash.tag.ote_chi, &.{ session_id, label, flat });
        @memcpy(&out[i], d[0..field_len]);
    }
    return out;
}

/// Fold one `extended_batch_size`-bit row into the check field: the row splits
/// into three field elements, the first two weighted by chi.
fn foldRow(row: *const PrgRow, chi: [2]FieldElement) FieldElement {
    const a = fieldMul(row[0..field_len].*, chi[0]);
    const b = fieldMul(row[field_len .. 2 * field_len].*, chi[1]);
    var out: FieldElement = undefined;
    for (&out, a, b, row[2 * field_len .. 3 * field_len]) |*o, x, y, z| o.* = x ^ y ^ z;
    return out;
}

/// What the receiver sends to open the extension.
pub fn DataToSender(comptime E: type) type {
    _ = E;
    return struct {
        const Self = @This();
        u: []PrgRow,
        verify_x: FieldElement,
        verify_t: []FieldElement,

        pub fn init(gpa: Allocator) !Self {
            const u = try gpa.alloc(PrgRow, kappa);
            errdefer gpa.free(u);
            const t = try gpa.alloc(FieldElement, kappa);
            return .{ .u = u, .verify_x = @splat(0), .verify_t = t };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.u);
            gpa.free(self.verify_t);
            self.* = undefined;
        }
    };
}

/// Sender state, carried across signings. Both fields are secret.
pub fn Sender(comptime E: type) type {
    return struct {
        const Self = @This();

        /// The sender's `kappa` base-OT choice bits, packed.
        correlation: [row_len]u8,
        /// The base-OT outputs for those choices.
        seeds: [kappa]hash.Digest,

        pub fn zeroize(self: *Self) void {
            std.crypto.secureZero(u8, &self.correlation);
            for (&self.seeds) |*s| std.crypto.secureZero(u8, s);
        }

        /// Run the extension. `inputs` is `ot_width * batch_size` correlations,
        /// row-major by width. Returns the sender's share and the `tau`
        /// adjustment the receiver needs, both the same shape as `inputs`.
        pub fn run(
            self: Self,
            gpa: Allocator,
            session_id: []const u8,
            inputs: []const E.Scalar,
            data: DataToSender(E),
            out_share: []E.Scalar,
            out_tau: []E.Scalar,
        ) (Error || Allocator.Error)!void {
            std.debug.assert(inputs.len == ot_width * batch_size);
            std.debug.assert(out_share.len == inputs.len and out_tau.len == inputs.len);
            std.debug.assert(data.u.len == kappa and data.verify_t.len == kappa);

            const q = try gpa.alloc(PrgRow, kappa);
            defer gpa.free(q);

            // q = (correlation_i AND u_i) XOR PRG(seed_i): where the sender's
            // base-OT choice was 1 it sees the receiver's XOR, otherwise not.
            for (0..kappa) |i| {
                const expanded = expandSeed(session_id, @intCast(i), self.seeds[i]);
                const mask: u8 = ~@as(u8, getBit(&self.correlation, i)) +% 1;
                for (&q[i], expanded, data.u[i]) |*out, e, uu| out.* = (uu & mask) ^ e;
            }

            const chi = chiPair(session_id, data.u);

            // Consistency check, in constant time: a variable-time compare
            // would leak which row failed and hence bits of the correlation.
            var diff: u8 = 0;
            for (0..kappa) |i| {
                const from_q = foldRow(&q[i], chi);
                const mask: u8 = ~@as(u8, getBit(&self.correlation, i)) +% 1;
                for (from_q, data.verify_t[i], data.verify_x) |a, t, x| {
                    diff |= a ^ (t ^ (x & mask));
                }
            }
            if (diff != 0) return error.ConsistencyCheckFailed;

            const transposed = try gpa.alloc(TransposedRow, batch_size);
            defer gpa.free(transposed);
            cutAndTranspose(transposed, q);

            for (0..ot_width) |iter| {
                for (0..batch_size) |j| {
                    var flipped: TransposedRow = undefined;
                    for (&flipped, transposed[j], self.correlation) |*o, t, c| o.* = t ^ c;

                    const v0 = randomize(E, session_id, @intCast(j), @intCast(iter), &transposed[j]);
                    const v1 = randomize(E, session_id, @intCast(j), @intCast(iter), &flipped);

                    const at = iter * batch_size + j;
                    out_share[at] = v0;
                    // tau carries the correlation across, blinded by v1 - v0.
                    out_tau[at] = v1.sub(v0).add(inputs[at]);
                }
            }
        }
    };
}

/// Receiver state, carried across signings. Both fields are secret.
pub fn Receiver(comptime E: type) type {
    return struct {
        const Self = @This();

        seeds0: [kappa]hash.Digest,
        seeds1: [kappa]hash.Digest,

        pub fn zeroize(self: *Self) void {
            for (&self.seeds0) |*s| std.crypto.secureZero(u8, s);
            for (&self.seeds1) |*s| std.crypto.secureZero(u8, s);
        }

        /// Open the extension for `choice_bits` (packed, `batch_size` of them).
        /// `kept` receives the expansion of seeds0, needed to finish.
        pub fn start(
            self: Self,
            session_id: []const u8,
            choice_bits: *const [batch_bytes]u8,
            kept: []PrgRow,
            data: *DataToSender(E),
            rng: std.Random,
        ) void {
            std.debug.assert(kept.len == kappa);

            // The batch's choice bits, extended with noise so the check does
            // not reveal them.
            var extended: PrgRow = @splat(0);
            @memcpy(extended[0..batch_bytes], choice_bits);
            rng.bytes(extended[batch_bytes..]);

            for (0..kappa) |i| {
                kept[i] = expandSeed(session_id, @intCast(i), self.seeds0[i]);
                const e1 = expandSeed(session_id, @intCast(i), self.seeds1[i]);
                for (&data.u[i], kept[i], e1, extended) |*out, a, b, c| out.* = a ^ b ^ c;
            }

            const chi = chiPair(session_id, data.u);
            data.verify_x = foldRow(&extended, chi);
            for (0..kappa) |i| data.verify_t[i] = foldRow(&kept[i], chi);

            std.crypto.secureZero(u8, &extended);
        }

        /// Finish, given the sender's `tau`. Writes `ot_width * batch_size`
        /// shares.
        pub fn finish(
            gpa: Allocator,
            session_id: []const u8,
            choice_bits: *const [batch_bytes]u8,
            kept: []const PrgRow,
            tau: []const E.Scalar,
            out_share: []E.Scalar,
        ) Allocator.Error!void {
            std.debug.assert(kept.len == kappa);
            std.debug.assert(tau.len == ot_width * batch_size and out_share.len == tau.len);

            const transposed = try gpa.alloc(TransposedRow, batch_size);
            defer gpa.free(transposed);
            cutAndTranspose(transposed, kept);

            for (0..ot_width) |iter| {
                for (0..batch_size) |j| {
                    const v = randomize(E, session_id, @intCast(j), @intCast(iter), &transposed[j]);
                    const at = iter * batch_size + j;
                    const bit = getBit(choice_bits, j);
                    // Where the choice bit is set, tau is added in; the two
                    // shares then sum to the correlation rather than zero.
                    out_share[at] = if (bit == 1) tau[at].sub(v) else v.neg();
                }
            }
        }
    };
}

/// Final randomization of one transposed row into a scalar.
fn randomize(comptime E: type, session_id: []const u8, j: u16, iteration: u8, row: *const TransposedRow) E.Scalar {
    var j_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &j_be, j, .big);
    const iter_be = [_]u8{iteration};
    return hash.taggedHashScalar(E, hash.tag.ote_randomize, &.{ session_id, &j_be, &iter_be, row });
}

/// Establish both sides' state by running `kappa` base OTs. Roles are swapped:
/// the extension's sender is the base OT's receiver.
pub fn setupPair(
    comptime E: type,
    gpa: Allocator,
    session_id: []const u8,
    rng: std.Random,
) !struct { sender: Sender(E), receiver: Receiver(E) } {
    const scratch = try gpa.alloc(u8, ot.scratchLen(session_id.len));
    defer gpa.free(scratch);

    var base_sender = try ot.Sender(E).init(session_id, rng);
    defer base_sender.deinit();
    const base_receiver = ot.Receiver(E).init(rng);

    var correlation: [row_len]u8 = undefined;
    rng.bytes(&correlation);

    const rs = try gpa.alloc(E.Scalar, kappa);
    defer gpa.free(rs);
    const ps = try gpa.alloc(proofs.Enc(E), kappa);
    defer gpa.free(ps);
    base_receiver.chooseBatch(session_id, &correlation, kappa, rs, ps, scratch, rng);

    const m0 = try gpa.alloc(hash.Digest, kappa);
    defer gpa.free(m0);
    const m1 = try gpa.alloc(hash.Digest, kappa);
    defer gpa.free(m1);
    try base_sender.receiveBatch(session_id, base_receiver.seed, ps, m0, m1, scratch);

    const chosen = try gpa.alloc(hash.Digest, kappa);
    defer gpa.free(chosen);
    try ot.Receiver(E).finishBatch(session_id, rs, base_sender.publicProof(), chosen, scratch);

    var sender: Sender(E) = .{ .correlation = correlation, .seeds = undefined };
    @memcpy(&sender.seeds, chosen);
    var receiver: Receiver(E) = .{ .seeds0 = undefined, .seeds1 = undefined };
    @memcpy(&receiver.seeds0, m0);
    @memcpy(&receiver.seeds1, m1);
    return .{ .sender = sender, .receiver = receiver };
}

/// Build a consistent sender/receiver pair directly, without running the base OT.
///
/// The extension only requires that the sender's seed for row `i` equals the
/// receiver's `seeds0`/`seeds1` entry picked out by the sender's correlation
/// bit. Where that agreement comes from is the base OT's business, and
/// `ot.zig` tests it there. Building it directly keeps the extension's own
/// tests from paying for 256 endemic OTs, which in a debug build dominates
/// everything else by orders of magnitude.
///
/// Test support only: these seeds are known to whoever called this, so real
/// deployments must go through `setupPair`.
pub fn pairFromRandomSeeds(comptime E: type, rng: std.Random) struct { sender: Sender(E), receiver: Receiver(E) } {
    var receiver: Receiver(E) = .{ .seeds0 = undefined, .seeds1 = undefined };
    for (&receiver.seeds0) |*s| rng.bytes(s);
    for (&receiver.seeds1) |*s| rng.bytes(s);

    var sender: Sender(E) = .{ .correlation = undefined, .seeds = undefined };
    rng.bytes(&sender.correlation);
    for (&sender.seeds, 0..) |*s, k| {
        s.* = if (getBit(&sender.correlation, k) == 1) receiver.seeds1[k] else receiver.seeds0[k];
    }
    return .{ .sender = sender, .receiver = receiver };
}

const testing = std.testing;
const vectors = @import("../testdata/dkls_vectors.zig");

fn unhex(buf: []u8, text: []const u8) []const u8 {
    return std.fmt.hexToBytes(buf, text) catch unreachable;
}

test "field multiplication matches dkls23-core" {
    var ab: [field_len]u8 = undefined;
    var bb: [field_len]u8 = undefined;
    var ob: [field_len]u8 = undefined;
    for (vectors.field_mul) |v| {
        const a = unhex(&ab, v.a);
        const b = unhex(&bb, v.b);
        const expected = unhex(&ob, v.out);
        const got = fieldMul(a[0..field_len].*, b[0..field_len].*);
        try testing.expectEqualSlices(u8, expected, &got);
    }
}

test "field multiplication is a commutative ring with 1" {
    var one: FieldElement = @splat(0);
    one[0] = 1;
    var x: FieldElement = undefined;
    for (&x, 0..) |*b, i| b.* = @intCast((i *% 37 +% 11) & 0xFF);
    var y: FieldElement = undefined;
    for (&y, 0..) |*b, i| b.* = @intCast((i *% 53 +% 2) & 0xFF);

    try testing.expectEqual(x, fieldMul(x, one));
    try testing.expectEqual(fieldMul(x, y), fieldMul(y, x));
    try testing.expectEqual(@as(FieldElement, @splat(0)), fieldMul(x, @splat(0)));

    // Distributivity over XOR, which is what the consistency check relies on.
    var xy: FieldElement = undefined;
    for (&xy, x, y) |*o, a, b| o.* = a ^ b;
    var lhs = fieldMul(xy, x);
    const r1 = fieldMul(x, x);
    const r2 = fieldMul(y, x);
    var rhs: FieldElement = undefined;
    for (&rhs, r1, r2) |*o, a, b| o.* = a ^ b;
    try testing.expectEqual(lhs, rhs);
    lhs = undefined;
}

test "transpose matches dkls23-core" {
    // Same deterministic input the generator used.
    const input = try testing.allocator.alloc(PrgRow, kappa);
    defer testing.allocator.free(input);
    for (input, 0..) |*row, i| {
        for (row, 0..) |*b, j| b.* = @intCast((i * 131 + j * 17 + 5) % 256);
    }
    const out = try testing.allocator.alloc(TransposedRow, batch_size);
    defer testing.allocator.free(out);
    cutAndTranspose(out, input);

    try testing.expectEqual(@as(usize, vectors.transpose_rows), out.len);

    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, unhex(&buf, vectors.transpose_row0), &out[0]);
    var buf1: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, unhex(&buf1, vectors.transpose_row1), &out[1]);
    var bufl: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, unhex(&bufl, vectors.transpose_row_last), &out[out.len - 1]);

    // The whole matrix, not just the sampled rows.
    const flat = try testing.allocator.alloc(u8, out.len * row_len);
    defer testing.allocator.free(flat);
    for (out, 0..) |r, i| @memcpy(flat[i * row_len ..][0..row_len], &r);
    var dbuf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, unhex(&dbuf, vectors.transpose_digest), &hash.taggedHash("dump", &.{flat}));
}

test "transpose really is the transpose" {
    // Independent of the reference: bit (i,j) of the input must land at (j,i).
    const input = try testing.allocator.alloc(PrgRow, kappa);
    defer testing.allocator.free(input);
    var prng = std.Random.DefaultPrng.init(0xDEAD);
    const rng = prng.random();
    for (input) |*row| rng.bytes(row);

    const out = try testing.allocator.alloc(TransposedRow, batch_size);
    defer testing.allocator.free(out);
    cutAndTranspose(out, input);

    for (0..kappa) |i| {
        for (0..batch_size) |j| {
            try testing.expectEqual(getBit(&input[i], j), getBit(&out[j], i));
        }
    }
}

test "bit accessors round-trip" {
    var b: [prg_len]u8 = @splat(0);
    for (0..extended_batch_size) |i| {
        const v: u1 = @intCast(i % 3 & 1);
        setBit(&b, i, v);
        try testing.expectEqual(v, getBit(&b, i));
    }
    // Clearing works too, not just setting.
    setBit(&b, 5, 1);
    setBit(&b, 5, 0);
    try testing.expectEqual(@as(u1, 0), getBit(&b, 5));
}

test "PRG expansion matches dkls23-core" {
    var sid_buf: [16]u8 = undefined;
    var seed_buf: [32]u8 = undefined;
    var out_buf: [prg_len]u8 = undefined;
    const sid = unhex(&sid_buf, vectors.prg_sid);
    const seed = unhex(&seed_buf, vectors.prg_seed);
    const expected = unhex(&out_buf, vectors.prg_out);
    const got = expandSeed(sid, vectors.prg_index, seed[0..32].*);
    try testing.expectEqualSlices(u8, expected, &got);
}

test "PRG expansion is seed- and index-separated" {
    const a = expandSeed("s", 0, @splat(1));
    const b = expandSeed("s", 1, @splat(1));
    const c = expandSeed("s", 0, @splat(2));
    const d = expandSeed("t", 0, @splat(1));
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!std.mem.eql(u8, &a, &c));
    try testing.expect(!std.mem.eql(u8, &a, &d));
}

const K1 = @import("../curve.zig").Secp256k1;

test "extension produces correlated shares" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(21));
    const rng = prng.random();
    const sid = "ote-sid";

    var pair = pairFromRandomSeeds(K1, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();

    var choice_bits: [batch_bytes]u8 = undefined;
    rng.bytes(&choice_bits);

    var data = try DataToSender(K1).init(gpa);
    defer data.deinit(gpa);
    const kept = try gpa.alloc(PrgRow, kappa);
    defer gpa.free(kept);
    pair.receiver.start(sid, &choice_bits, kept, &data, rng);

    const n = ot_width * batch_size;
    const inputs = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(inputs);
    for (inputs, 0..) |*x, i| x.* = K1.Scalar.fromU64(@as(u64, i) * 7 + 1);

    const sender_share = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(sender_share);
    const tau = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(tau);
    try pair.sender.run(gpa, sid, inputs, data, sender_share, tau);

    const receiver_share = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(receiver_share);
    try Receiver(K1).finish(gpa, sid, &choice_bits, kept, tau, receiver_share);

    // The defining property of correlated OT: the shares sum to the input
    // exactly where the receiver's choice bit is 1, and to zero elsewhere.
    for (0..ot_width) |iter| {
        for (0..batch_size) |j| {
            const at = iter * batch_size + j;
            const sum = sender_share[at].add(receiver_share[at]);
            const want = if (getBit(&choice_bits, j) == 1) inputs[at] else K1.Scalar.zero;
            try testing.expect(sum.eql(want));
        }
    }
}

test "a tampered opening fails the consistency check" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(22));
    const rng = prng.random();

    var pair = pairFromRandomSeeds(K1, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();

    var choice_bits: [batch_bytes]u8 = undefined;
    rng.bytes(&choice_bits);

    var data = try DataToSender(K1).init(gpa);
    defer data.deinit(gpa);
    const kept = try gpa.alloc(PrgRow, kappa);
    defer gpa.free(kept);
    pair.receiver.start("ote-sid", &choice_bits, kept, &data, rng);

    const n = ot_width * batch_size;
    const inputs = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(inputs);
    @memset(inputs, K1.Scalar.one);
    const a = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(a);
    const b = try gpa.alloc(K1.Scalar, n);
    defer gpa.free(b);

    // Flipping one bit of the opened matrix must be caught: this is the check
    // that makes the extension actively secure rather than merely passive.
    data.u[100][3] ^= 0x08;
    try testing.expectError(error.ConsistencyCheckFailed, pair.sender.run(gpa, "ote-sid", inputs, data, a, b));
}

test "a different session id yields unrelated shares" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(23));
    const rng = prng.random();

    var pair = pairFromRandomSeeds(K1, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();

    var choice_bits: [batch_bytes]u8 = @splat(0);
    var d1 = try DataToSender(K1).init(gpa);
    defer d1.deinit(gpa);
    var d2 = try DataToSender(K1).init(gpa);
    defer d2.deinit(gpa);
    const k1 = try gpa.alloc(PrgRow, kappa);
    defer gpa.free(k1);
    const k2 = try gpa.alloc(PrgRow, kappa);
    defer gpa.free(k2);

    pair.receiver.start("sid-a", &choice_bits, k1, &d1, rng);
    pair.receiver.start("sid-b", &choice_bits, k2, &d2, rng);
    // Seeds are reused across signings, so the session id is the only thing
    // separating one extension from the next.
    try testing.expect(!std.mem.eql(u8, &k1[0], &k2[0]));
}
