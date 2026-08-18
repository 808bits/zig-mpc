//! secp256k1 backed by bitcoin-core/libsecp256k1, presenting exactly the
//! declaration surface of `curve.zig`'s `Secp256k1Std`.
//!
//! Why this exists: benchmarks put `std.crypto`'s secp256k1 scalar
//! multiplication at ~4x slower than the optimized implementations
//! (no GLV endomorphism, no large precomputed tables), and DKLs23's setup is
//! nearly pure scalar multiplication. This backend swaps only the point
//! arithmetic; **scalars stay on std.crypto** - they are microseconds-cheap,
//! and keeping them means byte-identical encodings, one canonicality rule,
//! and `E.Scalar` being literally the same type under both backends.
//!
//! Selection lives in build.zig (`-Dsecp=std|libsecp`); `curve.Secp256k1` is
//! an alias to whichever backend was chosen, and every protocol is generic
//! over the curve type, so nothing else in the tree knows the difference.
//! Wire bytes (compressed SEC1, big-endian scalars) are identical across
//! backends: artifacts and frames interoperate.
//!
//! # Constant-time mapping
//!
//! libsecp256k1's public API splits along the same line as our interface,
//! but the obvious function is the wrong one: `ec_pubkey_tweak_mul` runs the
//! *variable-time* `secp256k1_ecmult`, so it backs `mulPublic` and
//! `mulDoubleBasePublic` only. The constant-time path for secret scalars is
//! the ECDH module (`secp256k1_ecmult_const`) with a callback that copies the
//! raw point out instead of hashing it - the mechanism the ECDH API documents
//! for exactly this purpose. `mulBase` uses `ec_pubkey_create`
//! (`ecmult_gen`, constant-time).
//!
//! # Representation
//!
//! A point is its compressed SEC1 encoding plus an infinity flag, because
//! libsecp's `secp256k1_pubkey` cannot represent infinity and its byte layout
//! is platform-dependent, while SEC1 bytes are the canonical form everything
//! here serializes anyway. Ops parse on entry and serialize on exit; the
//! parse costs a field square root, a few percent of the multiplication it
//! precedes. Negation never touches C at all: flipping the SEC1 prefix byte
//! flips the y parity.

const std = @import("std");
const curve = @import("curve.zig");

/// Scalars are std.crypto's, unchanged. Same type, same bytes, same checks.
const Std = curve.Secp256k1Std;

const c = struct {
    const Context = opaque {};
    const Pubkey = extern struct { data: [64]u8 };

    /// Compressed serialization: FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION.
    const EC_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

    const CONTEXT_NONE: c_uint = 1;

    extern fn secp256k1_context_create(flags: c_uint) *Context;

    extern fn secp256k1_ec_pubkey_parse(ctx: *const Context, pubkey: *Pubkey, input: [*]const u8, inputlen: usize) c_int;
    extern fn secp256k1_ec_pubkey_serialize(ctx: *const Context, output: [*]u8, outputlen: *usize, pubkey: *const Pubkey, flags: c_uint) c_int;
    extern fn secp256k1_ec_pubkey_create(ctx: *const Context, pubkey: *Pubkey, seckey: *const [32]u8) c_int;
    extern fn secp256k1_ec_pubkey_tweak_mul(ctx: *const Context, pubkey: *Pubkey, tweak: *const [32]u8) c_int;
    extern fn secp256k1_ec_pubkey_combine(ctx: *const Context, out: *Pubkey, ins: [*]const *const Pubkey, n: usize) c_int;
    extern fn secp256k1_ecdh(
        ctx: *const Context,
        output: [*]u8,
        pubkey: *const Pubkey,
        seckey: *const [32]u8,
        hashfp: ?*const fn ([*]u8, [*]const u8, [*]const u8, ?*anyopaque) callconv(.c) c_int,
        data: ?*anyopaque,
    ) c_int;
};

// One context for the whole process, created on first use and never
// destroyed. `secp256k1_context_static` would cover everything except
// `ec_pubkey_create`, which insists on a heap context with the ecmult_gen
// tables attached; one context serves both. After creation every call here
// treats it as const, which libsecp documents as thread-safe (only the
// randomization API mutates, and this backend does not use it).
var shared_ctx: ?*const c.Context = null;

fn ctx() *const c.Context {
    // Idempotent initialization without a once primitive: a race between two
    // first callers creates two identical contexts and leaks the loser, which
    // costs a few kilobytes exactly once and affects no behavior.
    if (@atomicLoad(?*const c.Context, &shared_ctx, .acquire)) |existing| return existing;
    const created = c.secp256k1_context_create(c.CONTEXT_NONE);
    @atomicStore(?*const c.Context, &shared_ctx, created, .release);
    return created;
}

/// ECDH "hash" that just hands back the affine point, uncompressed-SEC1
/// shaped so it can be re-parsed. This is the documented way to get a raw
/// constant-time point multiplication out of libsecp's public API.
fn ecdhCopyPoint(output: [*]u8, x32: [*]const u8, y32: [*]const u8, data: ?*anyopaque) callconv(.c) c_int {
    _ = data;
    output[0] = 0x04;
    @memcpy(output[1..33], x32[0..32]);
    @memcpy(output[33..65], y32[0..32]);
    return 1;
}

/// The field prime, for canonicality checks that need no arithmetic.
const field_p: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
};

pub const Secp256k1 = struct {
    pub const name = "secp256k1";

    pub const point_encoded_length = 33;
    pub const order_be = Std.order_be;
    pub const scalar_endian = Std.scalar_endian;

    pub const Scalar = Std.Scalar;

    /// Whether `bytes` is a canonical field element (big-endian, < p).
    pub fn feCanonical(bytes: [32]u8) bool {
        return std.mem.order(u8, &bytes, &field_p) == .lt;
    }

    pub const Point = struct {
        /// Compressed SEC1; all-zero when `inf` (nothing valid starts 0x00).
        sec1: [point_encoded_length]u8,
        inf: bool = false,

        pub const encoded_length = point_encoded_length;

        pub const generator = Point{ .sec1 = .{
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0,
            0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
            0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        } };
        pub const identity = Point{ .sec1 = @splat(0), .inf = true };

        fn toPk(self: Point) error{IdentityElement}!c.Pubkey {
            if (self.inf) return error.IdentityElement;
            var pk: c.Pubkey = undefined;
            // Only `fromBytes`-validated or op-produced encodings live in
            // `sec1`, so a parse failure here is a bug, not bad input.
            if (c.secp256k1_ec_pubkey_parse(ctx(), &pk, &self.sec1, point_encoded_length) != 1) unreachable;
            return pk;
        }

        fn fromPk(pk: *const c.Pubkey) Point {
            var out: Point = .{ .sec1 = undefined };
            var len: usize = point_encoded_length;
            if (c.secp256k1_ec_pubkey_serialize(ctx(), &out.sec1, &len, pk, c.EC_COMPRESSED) != 1) unreachable;
            std.debug.assert(len == point_encoded_length);
            return out;
        }

        pub fn fromBytes(bytes: [encoded_length]u8) error{ InvalidEncoding, NonCanonical, NotSquare }!Point {
            var pk: c.Pubkey = undefined;
            // parse enforces on-curve, canonical x < p, and a 02/03 prefix,
            // which is everything serde's input validation relies on.
            if (c.secp256k1_ec_pubkey_parse(ctx(), &pk, &bytes, encoded_length) != 1) return error.InvalidEncoding;
            return .{ .sec1 = bytes };
        }

        pub fn toBytes(self: Point) [encoded_length]u8 {
            return self.sec1;
        }

        pub fn add(a: Point, b: Point) Point {
            if (a.inf) return b;
            if (b.inf) return a;
            const pa = a.toPk() catch unreachable;
            const pb = b.toPk() catch unreachable;
            var sum: c.Pubkey = undefined;
            const ins = [_]*const c.Pubkey{ &pa, &pb };
            // combine fails exactly when the sum is the point at infinity.
            if (c.secp256k1_ec_pubkey_combine(ctx(), &sum, &ins, 2) != 1) return identity;
            return fromPk(&sum);
        }

        pub fn sub(a: Point, b: Point) Point {
            return a.add(b.neg());
        }

        pub fn neg(a: Point) Point {
            if (a.inf) return a;
            var out = a;
            // -P has the same x and the other y parity; in compressed SEC1
            // that is exactly the prefix byte.
            out.sec1[0] ^= 0x01;
            return out;
        }

        /// Constant-time scalar multiplication (use for secret scalars).
        /// Errors if the scalar is zero or the point is the identity.
        pub fn mul(self: Point, s: Scalar) error{IdentityElement}!Point {
            if (s.isZero()) return error.IdentityElement;
            const pk = try self.toPk();
            var raw: [65]u8 = undefined;
            const sk = s.toBytes();
            if (c.secp256k1_ecdh(ctx(), &raw, &pk, &sk, ecdhCopyPoint, null) != 1) return error.IdentityElement;
            var out_pk: c.Pubkey = undefined;
            if (c.secp256k1_ec_pubkey_parse(ctx(), &out_pk, &raw, raw.len) != 1) unreachable;
            return fromPk(&out_pk);
        }

        /// Variable-time scalar multiplication for PUBLIC scalars only.
        pub fn mulPublic(self: Point, s: Scalar) error{ IdentityElement, NonCanonical }!Point {
            if (s.isZero()) return error.IdentityElement;
            var pk = try self.toPk();
            const sk = s.toBytes();
            if (c.secp256k1_ec_pubkey_tweak_mul(ctx(), &pk, &sk) != 1) return error.IdentityElement;
            return fromPk(&pk);
        }

        /// Constant-time base-point multiplication.
        pub fn mulBase(s: Scalar) error{IdentityElement}!Point {
            var pk: c.Pubkey = undefined;
            const sk = s.toBytes();
            if (c.secp256k1_ec_pubkey_create(ctx(), &pk, &sk) != 1) return error.IdentityElement;
            return fromPk(&pk);
        }

        /// Variable-time a*P + b*Q for public inputs (verification equations).
        pub fn mulDoubleBasePublic(p1: Point, s1: Scalar, p2: Point, s2: Scalar) error{IdentityElement}!Point {
            const t1: Point = if (p1.inf or s1.isZero()) identity else p1.mulPublic(s1) catch identity;
            const t2: Point = if (p2.inf or s2.isZero()) identity else p2.mulPublic(s2) catch identity;
            const sum = t1.add(t2);
            if (sum.inf) return error.IdentityElement;
            return sum;
        }

        pub fn eql(a: Point, b: Point) bool {
            if (a.inf or b.inf) return a.inf and b.inf;
            return std.mem.eql(u8, &a.sec1, &b.sec1);
        }

        pub fn isIdentity(a: Point) bool {
            return a.inf;
        }

        /// x-coordinate reduced into a scalar: ECDSA's `r`.
        pub fn xScalar(self: Point) Scalar {
            var wide: [64]u8 = @splat(0);
            @memcpy(wide[32..], self.sec1[1..]);
            return Scalar.fromWideBytes(wide);
        }

        /// BIP-340 helpers.
        pub fn xOnly(self: Point) [32]u8 {
            return self.sec1[1..].*;
        }

        pub fn hasEvenY(self: Point) bool {
            return self.sec1[0] == 0x02;
        }

        pub fn fromXOnly(x_bytes: [32]u8) error{ InvalidEncoding, NonCanonical, NotSquare }!Point {
            var bytes: [encoded_length]u8 = undefined;
            bytes[0] = 0x02; // even y, per BIP-340
            @memcpy(bytes[1..], &x_bytes);
            return fromBytes(bytes);
        }
    };
};

// ---------------------------------------------------------------------------
// Tests: every operation agrees byte-for-byte with the std backend. These are
// what make "switch back to std.crypto" a one-flag change rather than a leap:
// any divergence between the backends fails here, not in a ceremony.
// ---------------------------------------------------------------------------

const testing = std.testing;
const L = Secp256k1;

fn testRng() std.Random.DefaultCsprng {
    return std.Random.DefaultCsprng.init(@splat(0x2b));
}

test "generator and encodings match the std backend" {
    try testing.expectEqualSlices(u8, &Std.Point.generator.toBytes(), &L.Point.generator.toBytes());
    try testing.expectEqual(Std.Point.encoded_length, L.Point.encoded_length);
    try testing.expectEqualSlices(u8, &Std.order_be, &L.order_be);
}

test "mulBase, mul and mulPublic agree with the std backend" {
    var prng = testRng();
    const rng = prng.random();
    for (0..16) |_| {
        const s = L.Scalar.random(rng);
        const k = L.Scalar.random(rng);

        const lib_base = try L.Point.mulBase(s);
        const std_base = try Std.Point.mulBase(s);
        try testing.expectEqualSlices(u8, &std_base.toBytes(), &lib_base.toBytes());

        const lib_mul = try lib_base.mul(k);
        const std_mul = try std_base.mul(k);
        try testing.expectEqualSlices(u8, &std_mul.toBytes(), &lib_mul.toBytes());

        const lib_pub = try lib_base.mulPublic(k);
        try testing.expectEqualSlices(u8, &std_mul.toBytes(), &lib_pub.toBytes());
    }
}

test "add, sub, neg and double-base agree with the std backend" {
    var prng = testRng();
    const rng = prng.random();
    for (0..16) |_| {
        const a = L.Scalar.random(rng);
        const b = L.Scalar.random(rng);
        const lib_pa = try L.Point.mulBase(a);
        const lib_pb = try L.Point.mulBase(b);
        const std_pa = try Std.Point.mulBase(a);
        const std_pb = try Std.Point.mulBase(b);

        try testing.expectEqualSlices(u8, &std_pa.add(std_pb).toBytes(), &lib_pa.add(lib_pb).toBytes());
        try testing.expectEqualSlices(u8, &std_pa.sub(std_pb).toBytes(), &lib_pa.sub(lib_pb).toBytes());
        try testing.expectEqualSlices(u8, &std_pa.neg().toBytes(), &lib_pa.neg().toBytes());

        const lib_d = try L.Point.mulDoubleBasePublic(lib_pa, b, lib_pb, a);
        const std_d = try Std.Point.mulDoubleBasePublic(std_pa, b, std_pb, a);
        try testing.expectEqualSlices(u8, &std_d.toBytes(), &lib_d.toBytes());

        try testing.expect(lib_pa.xScalar().eql(std_pa.xScalar()));
        try testing.expectEqual(std_pa.hasEvenY(), lib_pa.hasEvenY());
        try testing.expectEqualSlices(u8, &std_pa.xOnly(), &lib_pa.xOnly());
    }
}

test "identity edge cases" {
    var prng = testRng();
    const rng = prng.random();
    const p = try L.Point.mulBase(L.Scalar.random(rng));

    // P + (-P) is the one place addition meets infinity.
    try testing.expect(p.add(p.neg()).isIdentity());
    try testing.expect(L.Point.identity.add(p).eql(p));
    try testing.expect(p.add(L.Point.identity).eql(p));
    try testing.expect(p.sub(p).isIdentity());
    try testing.expect(!p.isIdentity());
    try testing.expect(L.Point.identity.isIdentity());

    // Zero scalars and identity operands error exactly like the std backend.
    try testing.expectError(error.IdentityElement, p.mul(L.Scalar.zero));
    try testing.expectError(error.IdentityElement, L.Point.mulBase(L.Scalar.zero));
    try testing.expectError(error.IdentityElement, L.Point.identity.mul(L.Scalar.one));
}

test "fromBytes validates like the std backend" {
    var prng = testRng();
    const rng = prng.random();
    const p = try L.Point.mulBase(L.Scalar.random(rng));

    // Round trip.
    const back = try L.Point.fromBytes(p.toBytes());
    try testing.expect(back.eql(p));

    // Off-curve x: flip a byte until parse rejects (overwhelmingly likely
    // immediately; both backends must agree on each candidate).
    var bad = p.toBytes();
    bad[13] ^= 0x5a;
    const lib_res = L.Point.fromBytes(bad);
    const std_res = Std.Point.fromBytes(bad);
    try testing.expectEqual(std_res == error.InvalidEncoding or std_res == error.NonCanonical or std_res == error.NotSquare, lib_res == error.InvalidEncoding);

    // A bad prefix byte is rejected outright.
    var bad_prefix = p.toBytes();
    bad_prefix[0] = 0x05;
    try testing.expectError(error.InvalidEncoding, L.Point.fromBytes(bad_prefix));

    // The all-zero identity sentinel never parses as a point.
    try testing.expectError(error.InvalidEncoding, L.Point.fromBytes(@splat(0)));
}

test "fromXOnly lifts to the even-y point, as BIP-340 requires" {
    var prng = testRng();
    const rng = prng.random();
    for (0..8) |_| {
        const p = try L.Point.mulBase(L.Scalar.random(rng));
        const lifted = try L.Point.fromXOnly(p.xOnly());
        try testing.expect(lifted.hasEvenY());
        const std_lifted = try Std.Point.fromXOnly(p.xOnly());
        try testing.expectEqualSlices(u8, &std_lifted.toBytes(), &lifted.toBytes());
    }
}

test "feCanonical agrees with the std backend's field check" {
    try testing.expect(L.feCanonical(@splat(0)));
    try testing.expect(!L.feCanonical(@splat(0xFF)));
    try testing.expect(!L.feCanonical(field_p));
    var just_below = field_p;
    just_below[31] -= 1;
    try testing.expect(L.feCanonical(just_below));
    try testing.expectEqual(Std.feCanonical(just_below), L.feCanonical(just_below));
    try testing.expectEqual(Std.feCanonical(field_p), L.feCanonical(field_p));
}
