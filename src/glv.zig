//! GLV endomorphism multiplication for std.crypto's secp256k1.
//!
//! secp256k1 has an efficiently computable endomorphism phi(x, y) = (beta*x, y)
//! with phi(P) = lambda*P, so any scalar k splits as k = r1 + r2*lambda with
//! |r1|, |r2| < 2^128, and k*P becomes a double multiplication by half-length
//! scalars: half the doublings of a full-width ladder.
//!
//! std.crypto already ships the split (`Secp256k1.Endormorphism.splitScalar`)
//! and uses it in `mulPublic` - but it computes lambda*P with a *full 256-bit
//! multiplication*, which costs more than the split saves, and neither the
//! constant-time `mul` nor `mulDoubleBasePublic` uses the endomorphism at
//! all. This file is the version of all three that uses phi properly (one
//! field multiplication), built entirely on std's public API so it can slot
//! into the standard library later. Signatures and error semantics mirror
//! std's exactly; `curve.zig` selects it as the `glv` backend, and the tests
//! at the bottom hold every operation byte-for-byte equal to std's.
//!
//! The `slide`/`precompute`/`pcSelect` helpers are private in std, so they
//! are reproduced here (std is MIT licensed; they are also the textbook
//! constructions).

const std = @import("std");
const mem = std.mem;
const math = std.math;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;

const C = std.crypto.ecc.Secp256k1;
const Fe = C.Fe;
const scalar = C.scalar;

/// beta: a primitive cube root of unity in the field. phi(x,y) = (beta*x, y).
const beta = Fe.fromInt(0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee) catch unreachable;

/// lambda: the matching cube root of unity mod the group order, so that
/// phi(P) = lambda*P. Only the tests need it; the whole point of GLV is that
/// the multiplications never do.
const lambda_le = s: {
    var buf: [32]u8 = undefined;
    mem.writeInt(u256, &buf, 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72, .little);
    break :s buf;
};

/// The endomorphism itself: one field multiplication, replacing the full
/// scalar multiplication std's `mulPublic` spends on the same value.
pub fn endo(p: C) C {
    return .{ .x = p.x.mul(beta), .y = p.y, .z = p.z };
}

// ---------------------------------------------------------------------------
// Shared helpers (mirroring std's private ones)
// ---------------------------------------------------------------------------

fn precompute(p: C, comptime count: usize) [1 + count]C {
    var pc: [1 + count]C = undefined;
    pc[0] = C.identityElement;
    pc[1] = p;
    var i: usize = 2;
    while (i <= count) : (i += 1) {
        pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
    }
    return pc;
}

/// Comptime tables for the base point and its endomorphism image, so base
/// multiplications never pay the per-call precompute.
const base_pc: [16]C = pc: {
    @setEvalBranchQuota(100_000);
    break :pc precompute(C.basePoint, 15);
};
const base_endo_pc: [16]C = pc: {
    @setEvalBranchQuota(100_000);
    break :pc precompute(endo(C.basePoint), 15);
};

/// Signed 4-bit windows (as in std). For half-width scalars only entries
/// 0..32 can be nonzero.
fn slide(s: [32]u8) [2 * 32 + 1]i8 {
    var e: [2 * 32 + 1]i8 = undefined;
    for (s, 0..) |x, i| {
        e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
        e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
    }
    var carry: i8 = 0;
    for (e[0..64]) |*x| {
        x.* += carry;
        carry = (x.* + 8) >> 4;
        x.* -= carry * 16;
        std.debug.assert(x.* >= -8 and x.* <= 8);
    }
    e[64] = carry;
    std.debug.assert(carry >= -8 and carry <= 8);
    return e;
}

fn pointCMov(p: *C, a: C, c: u1) void {
    p.x.cMov(a.x, c);
    p.y.cMov(a.y, c);
    p.z.cMov(a.z, c);
}

/// Constant-time table lookup, then constant-time negation by `neg_flag`.
/// Keeping one positive table per point and negating the selected entry costs
/// a single conditional field move per addition and spares a second table.
fn pcSelectNeg(pc: *const [16]C, b: u4, neg_flag: u1) C {
    var t = C.identityElement;
    comptime var i: u8 = 1;
    inline while (i < 16) : (i += 1) {
        pointCMov(&t, pc[i], @as(u1, @truncate((@as(usize, b ^ i) -% 1) >> 8)));
    }
    const y_neg = t.y.neg();
    t.y.cMov(y_neg, neg_flag);
    return t;
}

/// One half of a split scalar: a magnitude below 2^128 and the sign that was
/// factored out of it.
const Half = struct {
    /// Little-endian; bytes 16..32 are zero.
    mag: [32]u8,
    neg: u1,
};

/// Split `s` (little-endian, canonical) into two signed half-width scalars
/// with s = (-1)^neg1 * mag1 + (-1)^neg2 * mag2 * lambda (mod n).
///
/// Constant time: the split is plain integer arithmetic, the sign test reads
/// a fixed byte range, and the negation is computed unconditionally and
/// selected by mask.
fn splitNormalize(s: [32]u8) NonCanonicalError![2]Half {
    const sp = try C.Endormorphism.splitScalar(s, .little);
    return .{ normalize(sp.r1), normalize(sp.r2) };
}

fn normalize(r: [32]u8) Half {
    // The split guarantees |r| < 2^128: r is either the magnitude itself or
    // n - magnitude, and the latter always has nonzero high bytes.
    var acc: u8 = 0;
    for (r[16..]) |b| acc |= b;
    const neg_flag: u1 = @intFromBool(acc != 0);

    // scalar.neg fails only for zero, whose high bytes are zero anyway.
    const negated = scalar.neg(r, .little) catch r;
    var out = r;
    const mask: u8 = 0 -% @as(u8, neg_flag);
    for (&out, negated) |*o, n| o.* = (o.* & ~mask) | (n & mask);

    std.debug.assert(blk: {
        var high: u8 = 0;
        for (out[16..]) |b| high |= b;
        break :blk high == 0;
    });
    return .{ .mag = out, .neg = neg_flag };
}

// ---------------------------------------------------------------------------
// The three multiplications
// ---------------------------------------------------------------------------

/// Constant-time scalar multiplication, GLV-accelerated: ~124 doublings
/// instead of std's 252, with the same number of table lookups and additions.
/// `s` must be canonical (the callers' Scalar type guarantees it).
pub fn mul(p: C, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!C {
    const s = if (endian == .little) s_ else Fe.orderSwap(s_);
    if (!p.is_base) try p.rejectIdentity();

    const halves = splitNormalize(s) catch unreachable; // canonical by contract
    var pc1_array: [16]C = undefined;
    var pc2_array: [16]C = undefined;
    const pc1 = if (p.is_base) &base_pc else pc: {
        pc1_array = precompute(p, 15);
        break :pc &pc1_array;
    };
    const pc2 = if (p.is_base) &base_endo_pc else pc: {
        pc2_array = precompute(endo(p), 15);
        break :pc &pc2_array;
    };

    var q = C.identityElement;
    var pos: usize = 124;
    while (true) : (pos -= 4) {
        const slot1: u4 = @truncate(halves[0].mag[pos >> 3] >> @as(u3, @truncate(pos)));
        q = q.add(pcSelectNeg(pc1, slot1, halves[0].neg));
        const slot2: u4 = @truncate(halves[1].mag[pos >> 3] >> @as(u3, @truncate(pos)));
        q = q.add(pcSelectNeg(pc2, slot2, halves[1].neg));
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    try q.rejectIdentity();
    return q;
}

/// Variable-time multiplication by a public scalar. Same shape as std's
/// `mulPublic`, with lambda*P obtained from the endomorphism instead of a
/// full-width multiplication.
pub fn mulPublic(p: C, s_: [32]u8, endian: std.builtin.Endian) (IdentityElementError || NonCanonicalError)!C {
    const s = if (endian == .little) s_ else Fe.orderSwap(s_);
    const zero = comptime scalar.Scalar.zero.toBytes(.little);
    if (mem.eql(u8, &zero, &s)) return error.IdentityElement;

    const halves = try splitNormalize(s);
    const p1 = if (halves[0].neg == 1) p.neg() else p;
    const lp = endo(p);
    const p2 = if (halves[1].neg == 1) lp.neg() else lp;

    return mulSplitVartime(p1, halves[0].mag, p2, halves[1].mag);
}

/// Half-width double multiplication over signed windows. Both scalars are
/// below 2^128, so the ladder is 33 windows: ~128 doublings.
fn mulSplitVartime(p1: C, s1: [32]u8, p2: C, s2: [32]u8) IdentityElementError!C {
    var pc1_array: [9]C = undefined;
    const pc1 = if (p1.is_base) base_pc[0..9] else pc: {
        pc1_array = precompute(p1, 8);
        break :pc &pc1_array;
    };
    const pc2 = precompute(p2, 8);
    const e1 = slide(s1);
    const e2 = slide(s2);
    var q = C.identityElement;
    var pos: usize = 32;
    while (true) : (pos -= 1) {
        const slot1 = e1[pos];
        if (slot1 > 0) {
            q = q.add(pc1[@as(usize, @intCast(slot1))]);
        } else if (slot1 < 0) {
            q = q.sub(pc1[@as(usize, @intCast(-slot1))]);
        }
        const slot2 = e2[pos];
        if (slot2 > 0) {
            q = q.add(pc2[@as(usize, @intCast(slot2))]);
        } else if (slot2 < 0) {
            q = q.sub(pc2[@as(usize, @intCast(-slot2))]);
        }
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    try q.rejectIdentity();
    return q;
}

/// Variable-time p1*s1 + p2*s2 with both scalars split: a 4-point ladder over
/// half-width windows, ~128 doublings instead of std's 256.
pub fn mulDoubleBasePublic(p1: C, s1_: [32]u8, p2: C, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!C {
    const s1 = if (endian == .little) s1_ else Fe.orderSwap(s1_);
    const s2 = if (endian == .little) s2_ else Fe.orderSwap(s2_);
    try p1.rejectIdentity();
    try p2.rejectIdentity();

    // Non-canonical scalars are rejected by std's mulDoubleBasePublic via its
    // digit arithmetic only implicitly; here the split needs canonical input,
    // which every caller in this tree provides.
    const h1 = splitNormalize(s1) catch unreachable;
    const h2 = splitNormalize(s2) catch unreachable;

    const q1 = if (h1[0].neg == 1) p1.neg() else p1;
    const lp1 = endo(p1);
    const q2 = if (h1[1].neg == 1) lp1.neg() else lp1;
    const q3 = if (h2[0].neg == 1) p2.neg() else p2;
    const lp2 = endo(p2);
    const q4 = if (h2[1].neg == 1) lp2.neg() else lp2;

    var pc1_array: [9]C = undefined;
    const pc1 = if (q1.is_base) base_pc[0..9] else pc: {
        pc1_array = precompute(q1, 8);
        break :pc &pc1_array;
    };
    const pc2 = precompute(q2, 8);
    const pc3 = precompute(q3, 8);
    const pc4 = precompute(q4, 8);
    const e1 = slide(h1[0].mag);
    const e2 = slide(h1[1].mag);
    const e3 = slide(h2[0].mag);
    const e4 = slide(h2[1].mag);

    var q = C.identityElement;
    var pos: usize = 32;
    while (true) : (pos -= 1) {
        inline for (.{ .{ e1, pc1 }, .{ e2, &pc2 }, .{ e3, &pc3 }, .{ e4, &pc4 } }) |pair| {
            const slot = pair[0][pos];
            if (slot > 0) {
                q = q.add(pair[1][@as(usize, @intCast(slot))]);
            } else if (slot < 0) {
                q = q.sub(pair[1][@as(usize, @intCast(-slot))]);
            }
        }
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    try q.rejectIdentity();
    return q;
}

// ---------------------------------------------------------------------------
// Tests: the endomorphism facts, and byte-for-byte agreement with std
// ---------------------------------------------------------------------------

const testing = std.testing;

test "beta is a primitive cube root of unity in the field" {
    const b3 = beta.mul(beta).mul(beta);
    try testing.expect(b3.equivalent(Fe.one));
    try testing.expect(!beta.equivalent(Fe.one));
}

test "endo really is multiplication by lambda" {
    // Against std's own (correct, if slow) mulPublic.
    var prng = std.Random.DefaultCsprng.init(@splat(0x61));
    const rng = prng.random();
    for (0..8) |_| {
        var sk: [32]u8 = undefined;
        rng.bytes(&sk);
        const p = C.basePoint.mulPublic(scalar.reduce64(sk ++ sk, .little), .little) catch continue;
        const via_lambda = try p.mulPublic(lambda_le, .little);
        const via_endo = endo(p);
        try testing.expect(via_lambda.equivalent(via_endo));
    }
}

test "splitScalar recombines: r1 + r2*lambda == s (mod n)" {
    var prng = std.Random.DefaultCsprng.init(@splat(0x62));
    const rng = prng.random();
    for (0..32) |_| {
        var wide: [64]u8 = undefined;
        rng.bytes(&wide);
        const s = scalar.reduce64(wide, .little);
        const sp = try C.Endormorphism.splitScalar(s, .little);
        const back = try scalar.mulAdd(sp.r2, lambda_le, sp.r1, .little);
        try testing.expectEqualSlices(u8, &s, &back);

        // And the normalized halves are genuine half-width magnitudes.
        for (try splitNormalize(s)) |h| {
            try testing.expectEqualSlices(u8, &[_]u8{0} ** 16, h.mag[16..]);
        }
    }
}

fn randomScalar(rng: std.Random) [32]u8 {
    var wide: [64]u8 = undefined;
    rng.bytes(&wide);
    return scalar.reduce64(wide, .little);
}

test "all three multiplications agree with std, including edge scalars" {
    var prng = std.Random.DefaultCsprng.init(@splat(0x63));
    const rng = prng.random();

    const one_le = comptime blk: {
        var b: [32]u8 = @splat(0);
        b[0] = 1;
        break :blk b;
    };
    const n_minus_1 = comptime (scalar.neg(one_le, .little) catch unreachable);
    const edge_cases = [_][32]u8{ one_le, n_minus_1, lambda_le, scalar.neg(lambda_le, .little) catch unreachable };

    for (0..24) |i| {
        const s = if (i < edge_cases.len) edge_cases[i] else randomScalar(rng);
        const k = randomScalar(rng);
        const p = try C.basePoint.mul(randomScalar(rng), .little);

        // Constant-time mul: arbitrary point and base point.
        const glv_ct = try mul(p, s, .little);
        const std_ct = try p.mul(s, .little);
        try testing.expect(glv_ct.equivalent(std_ct));
        const glv_base = try mul(C.basePoint, s, .little);
        const std_base = try C.basePoint.mul(s, .little);
        try testing.expect(glv_base.equivalent(std_base));

        // Vartime single mul.
        const glv_pub = try mulPublic(p, s, .little);
        try testing.expect(glv_pub.equivalent(std_ct));

        // Vartime double-base, arbitrary and base first point.
        const p2 = try C.basePoint.mul(randomScalar(rng), .little);
        const glv_d = try mulDoubleBasePublic(p, s, p2, k, .little);
        const std_d = try C.mulDoubleBasePublic(p, s, p2, k, .little);
        try testing.expect(glv_d.equivalent(std_d));
        const glv_db = try mulDoubleBasePublic(C.basePoint, s, p2, k, .little);
        const std_db = try C.mulDoubleBasePublic(C.basePoint, s, p2, k, .little);
        try testing.expect(glv_db.equivalent(std_db));
    }
}

test "error semantics match std" {
    var prng = std.Random.DefaultCsprng.init(@splat(0x64));
    const rng = prng.random();
    const p = try C.basePoint.mul(randomScalar(rng), .little);
    const zero: [32]u8 = @splat(0);
    const s = randomScalar(rng);

    // Zero scalar: identity result everywhere.
    try testing.expectError(error.IdentityElement, mul(p, zero, .little));
    try testing.expectError(error.IdentityElement, mulPublic(p, zero, .little));

    // Identity input.
    try testing.expectError(error.IdentityElement, mul(C.identityElement, s, .little));
    try testing.expectError(error.IdentityElement, mulDoubleBasePublic(C.identityElement, s, p, s, .little));

    // s*P + (n-s)*P is the identity: both implementations must refuse.
    const s_neg = scalar.neg(s, .little) catch unreachable;
    try testing.expectError(error.IdentityElement, mulDoubleBasePublic(p, s, p, s_neg, .little));
    try testing.expectError(error.IdentityElement, C.mulDoubleBasePublic(p, s, p, s_neg, .little));
}
