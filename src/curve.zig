//! Comptime-generic curve interface over std.crypto.ecc.
//!
//! Every curve type exposed here presents the same declaration surface so that
//! protocol code (VSS, DKG, FROST, CGGMP) can be written once, generic over the
//! curve. Canonical scalar/point wire encodings follow each curve's ecosystem
//! convention: big-endian SEC1 for the short-Weierstrass curves, little-endian
//! RFC 8032 for Ed25519.

const std = @import("std");
const crypto = std.crypto;

/// Weierstrass curves from std.crypto.ecc share one API shape (endian-parameterized
/// scalar ops, SEC1 point encodings); this wraps any of them.
fn WeierstrassCurve(comptime C: type, comptime curve_name: []const u8) type {
    return struct {
        pub const name = curve_name;
        pub const Underlying = C;
        const sc = C.scalar;

        /// Compressed SEC1 encoding length (1 + field size).
        pub const point_encoded_length = 1 + C.Fe.encoded_length;

        /// Group order, big-endian.
        pub const order_be: [sc.encoded_length]u8 = blk: {
            var b: [sc.encoded_length]u8 = undefined;
            std.mem.writeInt(@Int(.unsigned, sc.encoded_length * 8), &b, sc.field_order, .big);
            break :blk b;
        };
        /// Endianness of the canonical scalar encoding.
        pub const scalar_endian: std.builtin.Endian = .big;

        pub const Scalar = struct {
            /// Canonical big-endian encoding; always fully reduced.
            b: [sc.encoded_length]u8,

            pub const encoded_length = sc.encoded_length;

            pub const zero = Scalar{ .b = @splat(0) };
            pub const one = blk: {
                var b: [encoded_length]u8 = @splat(0);
                b[encoded_length - 1] = 1;
                break :blk Scalar{ .b = b };
            };

            pub fn fromBytes(bytes: [encoded_length]u8) error{NonCanonical}!Scalar {
                try sc.rejectNonCanonical(bytes, .big);
                return .{ .b = bytes };
            }

            pub fn toBytes(self: Scalar) [encoded_length]u8 {
                return self.b;
            }

            /// Reduce 64 uniform bytes into a scalar (negligible bias for all
            /// supported curves).
            pub fn fromWideBytes(wide: [64]u8) Scalar {
                return .{ .b = sc.reduce64(wide, .big) };
            }

            pub fn fromU64(x: u64) Scalar {
                var b: [encoded_length]u8 = @splat(0);
                std.mem.writeInt(u64, b[encoded_length - 8 ..][0..8], x, .big);
                return .{ .b = b };
            }

            pub fn random(rng: std.Random) Scalar {
                var wide: [64]u8 = undefined;
                defer crypto.secureZero(u8, &wide);
                rng.bytes(&wide);
                return fromWideBytes(wide);
            }

            pub fn add(x: Scalar, y: Scalar) Scalar {
                return .{ .b = sc.add(x.b, y.b, .big) catch unreachable };
            }

            pub fn sub(x: Scalar, y: Scalar) Scalar {
                return .{ .b = sc.sub(x.b, y.b, .big) catch unreachable };
            }

            pub fn mul(x: Scalar, y: Scalar) Scalar {
                return .{ .b = sc.mul(x.b, y.b, .big) catch unreachable };
            }

            pub fn neg(x: Scalar) Scalar {
                return .{ .b = sc.neg(x.b, .big) catch unreachable };
            }

            pub fn invert(x: Scalar) Scalar {
                const expanded = sc.Scalar.fromBytes(x.b, .big) catch unreachable;
                return .{ .b = expanded.invert().toBytes(.big) };
            }

            pub fn isZero(x: Scalar) bool {
                return crypto.timing_safe.eql([encoded_length]u8, x.b, zero.b);
            }

            pub fn eql(x: Scalar, y: Scalar) bool {
                return crypto.timing_safe.eql([encoded_length]u8, x.b, y.b);
            }

            pub fn zeroize(x: *Scalar) void {
                crypto.secureZero(u8, &x.b);
            }
        };

        pub const Point = struct {
            p: C,

            pub const encoded_length = point_encoded_length;

            pub const generator = Point{ .p = C.basePoint };
            pub const identity = Point{ .p = C.identityElement };

            pub fn fromBytes(bytes: [encoded_length]u8) !Point {
                return .{ .p = try C.fromSec1(&bytes) };
            }

            pub fn toBytes(self: Point) [encoded_length]u8 {
                return self.p.toCompressedSec1();
            }

            pub fn add(a: Point, b: Point) Point {
                return .{ .p = a.p.add(b.p) };
            }

            pub fn sub(a: Point, b: Point) Point {
                return .{ .p = a.p.add(b.p.neg()) };
            }

            pub fn neg(a: Point) Point {
                return .{ .p = a.p.neg() };
            }

            /// Constant-time scalar multiplication (use for secret scalars).
            /// Errors if the scalar is zero or the result is the identity.
            pub fn mul(self: Point, s: Scalar) error{IdentityElement}!Point {
                return .{ .p = try self.p.mul(s.b, .big) };
            }

            /// Variable-time scalar multiplication for PUBLIC scalars only.
            pub fn mulPublic(self: Point, s: Scalar) error{ IdentityElement, NonCanonical }!Point {
                return .{ .p = try self.p.mulPublic(s.b, .big) };
            }

            /// Constant-time base-point multiplication.
            pub fn mulBase(s: Scalar) error{IdentityElement}!Point {
                return .{ .p = try C.basePoint.mul(s.b, .big) };
            }

            /// Variable-time a*P + b*Q for public inputs (verification equations).
            pub fn mulDoubleBasePublic(p1: Point, s1: Scalar, p2: Point, s2: Scalar) error{IdentityElement}!Point {
                return .{ .p = try C.mulDoubleBasePublic(p1.p, s1.b, p2.p, s2.b, .big) };
            }

            pub fn eql(a: Point, b: Point) bool {
                return a.p.equivalent(b.p);
            }

            pub fn isIdentity(a: Point) bool {
                a.p.rejectIdentity() catch return true;
                return false;
            }

            /// BIP-340 helpers (meaningful on secp256k1).
            pub fn xOnly(self: Point) [C.Fe.encoded_length]u8 {
                return self.p.affineCoordinates().x.toBytes(.big);
            }

            pub fn hasEvenY(self: Point) bool {
                return !self.p.affineCoordinates().y.isOdd();
            }

            pub fn fromXOnly(x_bytes: [C.Fe.encoded_length]u8) !Point {
                const x = try C.Fe.fromBytes(x_bytes, .big);
                const y = try C.recoverY(x, false); // even y
                return .{ .p = try C.fromAffineCoordinates(.{ .x = x, .y = y }) };
            }
        };
    };
}

pub const Secp256k1 = WeierstrassCurve(crypto.ecc.Secp256k1, "secp256k1");
pub const P256 = WeierstrassCurve(crypto.ecc.P256, "p256");
pub const P384 = WeierstrassCurve(crypto.ecc.P384, "p384");

/// Ed25519 (Edwards25519 group, RFC 8032 conventions: little-endian encodings).
pub const Ed25519 = struct {
    pub const name = "ed25519";
    const C = crypto.ecc.Edwards25519;
    pub const Underlying = C;
    const sc = C.scalar;

    pub const point_encoded_length = 32;

    /// Group order, big-endian.
    pub const order_be: [32]u8 = blk: {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, sc.field_order, .big);
        break :blk b;
    };
    /// Endianness of the canonical scalar encoding.
    pub const scalar_endian: std.builtin.Endian = .little;

    pub const Scalar = struct {
        /// Canonical little-endian encoding; always fully reduced.
        b: [32]u8,

        pub const encoded_length = 32;

        pub const zero = Scalar{ .b = @splat(0) };
        pub const one = blk: {
            var b: [32]u8 = @splat(0);
            b[0] = 1;
            break :blk Scalar{ .b = b };
        };

        pub fn fromBytes(bytes: [32]u8) error{NonCanonical}!Scalar {
            try sc.rejectNonCanonical(bytes);
            return .{ .b = bytes };
        }

        pub fn toBytes(self: Scalar) [32]u8 {
            return self.b;
        }

        pub fn fromWideBytes(wide: [64]u8) Scalar {
            return .{ .b = sc.reduce64(wide) };
        }

        pub fn fromU64(x: u64) Scalar {
            var b: [32]u8 = @splat(0);
            std.mem.writeInt(u64, b[0..8], x, .little);
            return .{ .b = b };
        }

        pub fn random(rng: std.Random) Scalar {
            var wide: [64]u8 = undefined;
            defer crypto.secureZero(u8, &wide);
            rng.bytes(&wide);
            return fromWideBytes(wide);
        }

        pub fn add(x: Scalar, y: Scalar) Scalar {
            return .{ .b = sc.add(x.b, y.b) };
        }

        pub fn sub(x: Scalar, y: Scalar) Scalar {
            return .{ .b = sc.sub(x.b, y.b) };
        }

        pub fn mul(x: Scalar, y: Scalar) Scalar {
            return .{ .b = sc.mul(x.b, y.b) };
        }

        pub fn neg(x: Scalar) Scalar {
            return .{ .b = sc.neg(x.b) };
        }

        pub fn invert(x: Scalar) Scalar {
            const expanded = sc.Scalar.fromBytes(x.b);
            return .{ .b = expanded.invert().toBytes() };
        }

        pub fn isZero(x: Scalar) bool {
            return crypto.timing_safe.eql([32]u8, x.b, zero.b);
        }

        pub fn eql(x: Scalar, y: Scalar) bool {
            return crypto.timing_safe.eql([32]u8, x.b, y.b);
        }

        pub fn zeroize(x: *Scalar) void {
            crypto.secureZero(u8, &x.b);
        }
    };

    pub const Point = struct {
        p: C,

        pub const encoded_length = point_encoded_length;

        pub const generator = Point{ .p = C.basePoint };
        pub const identity = Point{ .p = C.identityElement };

        pub fn fromBytes(bytes: [32]u8) !Point {
            return .{ .p = try C.fromBytes(bytes) };
        }

        pub fn toBytes(self: Point) [32]u8 {
            return self.p.toBytes();
        }

        pub fn add(a: Point, b: Point) Point {
            return .{ .p = a.p.add(b.p) };
        }

        pub fn sub(a: Point, b: Point) Point {
            return .{ .p = a.p.sub(b.p) };
        }

        pub fn neg(a: Point) Point {
            return .{ .p = a.p.neg() };
        }

        pub fn mul(self: Point, s: Scalar) error{ IdentityElement, WeakPublicKey }!Point {
            return .{ .p = try self.p.mul(s.b) };
        }

        pub fn mulPublic(self: Point, s: Scalar) error{ IdentityElement, WeakPublicKey }!Point {
            return .{ .p = try self.p.mulPublic(s.b) };
        }

        pub fn mulBase(s: Scalar) error{ IdentityElement, WeakPublicKey }!Point {
            return .{ .p = try C.basePoint.mul(s.b) };
        }

        pub fn mulDoubleBasePublic(p1: Point, s1: Scalar, p2: Point, s2: Scalar) error{WeakPublicKey}!Point {
            return .{ .p = try C.mulDoubleBasePublic(p1.p, s1.b, p2.p, s2.b) };
        }

        pub fn eql(a: Point, b: Point) bool {
            // Compressed encoding is canonical for Edwards25519.
            return crypto.timing_safe.eql([32]u8, a.p.toBytes(), b.p.toBytes());
        }

        pub fn isIdentity(a: Point) bool {
            a.p.rejectIdentity() catch return true;
            return false;
        }
    };
};

test "scalar arithmetic roundtrip (all curves)" {
    inline for (.{ Secp256k1, P256, P384, Ed25519 }) |E| {
        const two = E.Scalar.one.add(E.Scalar.one);
        const four = two.mul(two);
        try std.testing.expect(four.eql(two.add(two)));
        try std.testing.expect(four.sub(two).eql(two));
        try std.testing.expect(two.mul(two.invert()).eql(E.Scalar.one));
        try std.testing.expect(two.add(two.neg()).isZero());

        // encode/decode roundtrip
        const dec = try E.Scalar.fromBytes(four.toBytes());
        try std.testing.expect(dec.eql(four));
    }
}

test "point arithmetic and encoding (all curves)" {
    inline for (.{ Secp256k1, P256, P384, Ed25519 }) |E| {
        const three = E.Scalar.fromU64(3);
        const g3 = try E.Point.mulBase(three);
        const g_plus_g_plus_g = E.Point.generator.add(E.Point.generator).add(E.Point.generator);
        try std.testing.expect(g3.eql(g_plus_g_plus_g));

        const dec = try E.Point.fromBytes(g3.toBytes());
        try std.testing.expect(dec.eql(g3));

        try std.testing.expect(g3.sub(E.Point.generator).eql(E.Point.generator.add(E.Point.generator)));
        try std.testing.expect(!g3.isIdentity());
    }
}

test "wide reduction matches modular arithmetic" {
    inline for (.{ Secp256k1, Ed25519 }) |E| {
        // 2^256 mod q computed two ways
        var wide: [64]u8 = @splat(0);
        // set value 1 followed by 32 zero bytes => 2^256 in the appropriate endianness
        if (E == Ed25519) {
            wide[32] = 1; // little-endian: byte 32 = 2^256
        } else {
            wide[31] = 1; // big-endian: byte 31 (from left in 64-byte string) = 2^256
        }
        const r = E.Scalar.fromWideBytes(wide);
        // compute 2^256 by repeated doubling of 1
        var acc = E.Scalar.one;
        var i: usize = 0;
        while (i < 256) : (i += 1) acc = acc.add(acc);
        try std.testing.expect(r.eql(acc));
    }
}

test "bip340 x-only helpers (secp256k1)" {
    const E = Secp256k1;
    const k = E.Scalar.fromU64(7);
    const p = try E.Point.mulBase(k);
    const x = p.xOnly();
    const recovered = try E.Point.fromXOnly(x);
    try std.testing.expect(recovered.hasEvenY());
    // recovered point equals p or -p; x coordinates must match
    try std.testing.expectEqualSlices(u8, &x, &recovered.xOnly());
}
