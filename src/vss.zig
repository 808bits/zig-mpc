//! Shamir secret sharing with Feldman verifiability, plus Lagrange
//! interpolation - shared foundation for FROST and CGGMP DKGs.
//!
//! Party i (1-based, i >= 1) receives the share f(i) of a degree-(t-1)
//! polynomial f with f(0) = secret. The Feldman commitment publishes
//! A_k = coeff_k * G, letting anyone verify a share against the commitment.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// The scalar x-coordinate assigned to party `index` (1-based).
///
/// Party 0 is the secret's own x-coordinate (f(0) = secret), never a party.
/// This used to be a debug-only assert, which compiles out in ReleaseFast /
/// ReleaseSmall, so in a release build a coordinator-supplied index of 0 would
/// flow through `publicShareOf`/`verifyShare` and turn them into an oracle
/// against the group secret. It is a returned error so the guard survives in
/// every build mode.
pub fn shareIndex(comptime E: type, index: u16) !E.Scalar {
    if (index == 0) return error.InvalidPartyIndex;
    return E.Scalar.fromU64(index);
}

pub fn Polynomial(comptime E: type) type {
    return struct {
        const Self = @This();

        /// coeffs[0] is the secret / constant term.
        coeffs: []E.Scalar,
        allocator: Allocator,

        /// Random polynomial of degree `threshold - 1` with f(0) = secret.
        /// `threshold` is the number of parties required to reconstruct.
        /// Coefficients (and the secret) must be non-zero so that Feldman
        /// commitments are well-defined; zero coefficients are resampled
        /// (probability ~2^-256 each).
        pub fn initRandom(allocator: Allocator, secret: E.Scalar, threshold: u16, rng: std.Random) !Self {
            if (threshold < 1) return error.InvalidThreshold;
            if (secret.isZero()) return error.ZeroSecret;
            const coeffs = try allocator.alloc(E.Scalar, threshold);
            errdefer allocator.free(coeffs);
            coeffs[0] = secret;
            for (coeffs[1..]) |*c| {
                c.* = E.Scalar.random(rng);
                while (c.isZero()) c.* = E.Scalar.random(rng);
            }
            return .{ .coeffs = coeffs, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            for (self.coeffs) |*c| c.zeroize();
            self.allocator.free(self.coeffs);
            self.* = undefined;
        }

        /// Horner evaluation f(x).
        pub fn evaluate(self: Self, x: E.Scalar) E.Scalar {
            var acc = E.Scalar.zero;
            var i = self.coeffs.len;
            while (i > 0) {
                i -= 1;
                acc = acc.mul(x).add(self.coeffs[i]);
            }
            return acc;
        }

        /// The share for party `index` (1-based).
        pub fn share(self: Self, index: u16) !E.Scalar {
            return self.evaluate(try shareIndex(E, index));
        }

        /// Feldman commitment: A_k = coeff_k * G.
        pub fn commit(self: Self, allocator: Allocator) !Commitment(E) {
            const points = try allocator.alloc(E.Point, self.coeffs.len);
            errdefer allocator.free(points);
            for (self.coeffs, points) |c, *p| {
                p.* = E.Point.mulBase(c) catch return error.ZeroCoefficient;
            }
            return .{ .points = points, .allocator = allocator };
        }
    };
}

pub fn Commitment(comptime E: type) type {
    return struct {
        const Self = @This();

        /// points[k] = coeff_k * G; points[0] = secret * G (the public key).
        points: []E.Point,
        allocator: Allocator,

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.points);
            self.* = undefined;
        }

        pub fn publicKey(self: Self) E.Point {
            return self.points[0];
        }

        pub fn threshold(self: Self) u16 {
            return @intCast(self.points.len);
        }

        /// Evaluate the commitment "in the exponent":
        /// sum_k x^k * A_k = f(x) * G, for public x.
        pub fn evaluate(self: Self, x: E.Scalar) !E.Point {
            // A commitment with no coefficients commits to nothing. Reject it
            // rather than underflowing the index below - a deserialized
            // commitment is attacker-controlled data, not a local invariant.
            if (self.points.len == 0) return error.EmptyCommitment;
            // Horner in the exponent: acc = A_{n-1}; acc = x*acc + A_k.
            var i = self.points.len - 1;
            var acc = self.points[i];
            while (i > 0) {
                i -= 1;
                acc = (try acc.mulPublic(x)).add(self.points[i]);
            }
            return acc;
        }

        /// Verify that `share_value` is a consistent share for party `index`.
        pub fn verifyShare(self: Self, index: u16, share_value: E.Scalar) bool {
            const x = shareIndex(E, index) catch return false;
            const expected = self.evaluate(x) catch return false;
            const actual = E.Point.mulBase(share_value) catch return false;
            return expected.eql(actual);
        }

        /// Homomorphically add another commitment (same threshold), producing
        /// the commitment to the sum polynomial. Used by DKGs where the group
        /// polynomial is the sum of every party's polynomial.
        pub fn addAssign(self: *Self, other: Self) !void {
            if (other.points.len != self.points.len) return error.ThresholdMismatch;
            for (self.points, other.points) |*a, b| a.* = a.add(b);
        }
    };
}

/// Lagrange coefficient λ_j at x = 0 for the party set `indices` (1-based,
/// distinct): λ_j = Π_{m != j} x_m / (x_m - x_j).
/// `j` is a position within `indices`, not a party index.
pub fn lagrangeAtZero(comptime E: type, indices: []const u16, j: usize) !E.Scalar {
    return lagrangeAt(E, indices, j, E.Scalar.zero);
}

/// Lagrange coefficient λ_j at arbitrary public x.
pub fn lagrangeAt(comptime E: type, indices: []const u16, j: usize, x: E.Scalar) !E.Scalar {
    if (j >= indices.len) return error.IndexOutOfRange;
    for (indices, 0..) |a, m| {
        for (indices[m + 1 ..]) |b| {
            if (a == b) return error.DuplicateIndex;
        }
    }
    var num = E.Scalar.one;
    var den = E.Scalar.one;
    const xj = try shareIndex(E, indices[j]);
    for (indices, 0..) |idx, m| {
        if (m == j) continue;
        const xm = try shareIndex(E, idx);
        num = num.mul(xm.sub(x));
        den = den.mul(xm.sub(xj));
    }
    return num.mul(den.invert());
}

/// Reconstruct the secret f(0) from shares held by `indices`.
pub fn reconstructAtZero(comptime E: type, indices: []const u16, shares: []const E.Scalar) !E.Scalar {
    if (indices.len != shares.len or indices.len == 0) return error.InvalidInput;
    var acc = E.Scalar.zero;
    for (shares, 0..) |s, j| {
        const lambda = try lagrangeAtZero(E, indices, j);
        acc = acc.add(lambda.mul(s));
    }
    return acc;
}

test "share and reconstruct (all curves)" {
    const curve = @import("curve.zig");
    var prng = std.Random.DefaultPrng.init(1234);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    inline for (.{ curve.Secp256k1, curve.P256, curve.P384, curve.Ed25519 }) |E| {
        const secret = E.Scalar.random(rng);
        var poly = try Polynomial(E).initRandom(allocator, secret, 3, rng);
        defer poly.deinit();

        // any 3 of 5 shares reconstruct
        const indices = [_]u16{ 2, 4, 5 };
        const shares = [_]E.Scalar{ try poly.share(2), try poly.share(4), try poly.share(5) };
        const rec = try reconstructAtZero(E, &indices, &shares);
        try std.testing.expect(rec.eql(secret));

        // 2 shares reconstruct something else
        const indices2 = [_]u16{ 2, 4 };
        const shares2 = [_]E.Scalar{ try poly.share(2), try poly.share(4) };
        const wrong = try reconstructAtZero(E, &indices2, &shares2);
        try std.testing.expect(!wrong.eql(secret));
    }
}

test "feldman verification accepts good shares, rejects bad" {
    const curve = @import("curve.zig");
    var prng = std.Random.DefaultPrng.init(99);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    inline for (.{ curve.Secp256k1, curve.Ed25519 }) |E| {
        const secret = E.Scalar.random(rng);
        var poly = try Polynomial(E).initRandom(allocator, secret, 4, rng);
        defer poly.deinit();
        var com = try poly.commit(allocator);
        defer com.deinit();

        var i: u16 = 1;
        while (i <= 6) : (i += 1) {
            try std.testing.expect(com.verifyShare(i, try poly.share(i)));
        }
        // tampered share fails
        const bad = (try poly.share(3)).add(E.Scalar.one);
        try std.testing.expect(!com.verifyShare(3, bad));
        // right share, wrong index fails
        try std.testing.expect(!com.verifyShare(2, try poly.share(3)));

        // commitment[0] is the public key secret*G
        const pk = try E.Point.mulBase(secret);
        try std.testing.expect(com.publicKey().eql(pk));
    }
}

test "commitment homomorphic addition matches summed polynomials" {
    const curve = @import("curve.zig");
    const E = curve.Secp256k1;
    var prng = std.Random.DefaultPrng.init(7);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    var p1 = try Polynomial(E).initRandom(allocator, E.Scalar.random(rng), 3, rng);
    defer p1.deinit();
    var p2 = try Polynomial(E).initRandom(allocator, E.Scalar.random(rng), 3, rng);
    defer p2.deinit();

    var c1 = try p1.commit(allocator);
    defer c1.deinit();
    var c2 = try p2.commit(allocator);
    defer c2.deinit();

    try c1.addAssign(c2);

    // summed shares verify against summed commitment
    var i: u16 = 1;
    while (i <= 4) : (i += 1) {
        const sum_share = (try p1.share(i)).add(try p2.share(i));
        try std.testing.expect(c1.verifyShare(i, sum_share));
    }
}

test "lagrange coefficients sum property" {
    const curve = @import("curve.zig");
    const E = curve.Ed25519;
    // sum of lagrange-at-zero coefficients over any index set = 1
    const indices = [_]u16{ 1, 3, 7, 10 };
    var acc = E.Scalar.zero;
    for (0..indices.len) |j| {
        acc = acc.add(try lagrangeAtZero(E, &indices, j));
    }
    try std.testing.expect(acc.eql(E.Scalar.one));

    // duplicate indices rejected
    const dup = [_]u16{ 1, 3, 3 };
    try std.testing.expectError(error.DuplicateIndex, lagrangeAtZero(E, &dup, 0));
}

test "party index 0 is rejected in every build mode" {
    const curve = @import("curve.zig");
    const E = curve.Secp256k1;
    // This must be a returned error, not a debug-only assert: index 0 is the
    // secret's own x-coordinate, and letting it reach publicShareOf/verifyShare
    // turns them into an oracle against the group secret in release builds.
    try std.testing.expectError(error.InvalidPartyIndex, shareIndex(E, 0));

    var prng = std.Random.DefaultPrng.init(3);
    const rng = prng.random();
    var poly = try Polynomial(E).initRandom(std.testing.allocator, E.Scalar.random(rng), 2, rng);
    defer poly.deinit();
    var com = try poly.commit(std.testing.allocator);
    defer com.deinit();
    // verifyShare must not accept party 0 against the group public key.
    try std.testing.expect(!com.verifyShare(0, E.Scalar.one));
}
