//! Pairwise-seeded shares of zero (DKLs23 Functionality 3.4).
//!
//! Every pair of parties agrees on one seed at setup. From then on, for any
//! session id and any subset of the parties, each member can derive a scalar
//! locally, with no communication, such that the derived scalars sum to zero
//! across the subset.
//!
//! The trick is antisymmetry: both members of a pair derive the same fragment
//! from their shared seed, and the one with the lower index subtracts it while
//! the other adds. Every pair therefore cancels, so the total is zero however
//! many parties take part. Signing uses this to re-randomize each party's key
//! share without changing their sum.
//!
//! A party only includes pairs whose counterparty is actually signing, which is
//! why the same setup works for every quorum.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash = @import("hash.zig");

pub const Seed = [hash.security]u8;

/// One party's half of a pairwise seed.
pub const SeedPair = struct {
    /// The other party, 1-based.
    counterparty: u16,
    /// Whether this party holds the lower index, which fixes the sign.
    lowest: bool,
    seed: Seed,

    pub fn zeroize(self: *SeedPair) void {
        std.crypto.secureZero(u8, &self.seed);
    }
};

/// Combine the two halves a pair exchanged into their shared seed.
///
/// XOR rather than the paper's addition: it is the same for the security
/// argument and neither side's contribution can bias the result.
pub fn combine(party: u16, counterparty: u16, own: Seed, theirs: Seed) SeedPair {
    var seed: Seed = undefined;
    for (&seed, own, theirs) |*o, a, b| o.* = a ^ b;
    return .{
        .counterparty = counterparty,
        .lowest = party <= counterparty,
        .seed = seed,
    };
}

/// A party's complete set of pairwise seeds.
pub fn Share(comptime E: type) type {
    return struct {
        const Self = @This();

        pairs: []SeedPair,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.pairs) |*p| p.zeroize();
            gpa.free(self.pairs);
            self.* = undefined;
        }

        /// Derive this party's share of zero for `session_id`, counting only
        /// pairs whose counterparty appears in `quorum`.
        pub fn compute(self: Self, session_id: []const u8, quorum: []const u16) E.Scalar {
            var acc = E.Scalar.zero;
            for (self.pairs) |pair| {
                if (std.mem.indexOfScalar(u16, quorum, pair.counterparty) == null) continue;
                const fragment = hash.taggedHashScalar(E, hash.tag.zero_share_fragment, &.{ session_id, &pair.seed });
                // Opposite signs across the pair are what make the sum cancel.
                acc = if (pair.lowest) acc.sub(fragment) else acc.add(fragment);
            }
            return acc;
        }
    };
}

const testing = std.testing;
const K1 = @import("../curve.zig").Secp256k1;

/// Build `n` parties' seed sets from a fresh RNG, as setup would.
fn dealSeeds(gpa: Allocator, n: u16, rng: std.Random) ![]Share(K1) {
    const halves = try gpa.alloc(Seed, @as(usize, n) * n);
    defer gpa.free(halves);
    for (halves) |*s| rng.bytes(s);

    const shares = try gpa.alloc(Share(K1), n);
    for (shares, 0..) |*sh, idx| {
        const i: u16 = @intCast(idx + 1);
        const pairs = try gpa.alloc(SeedPair, n - 1);
        var k: usize = 0;
        for (1..n + 1) |jj| {
            const j: u16 = @intCast(jj);
            if (j == i) continue;
            // Party i's own half toward j, and j's half toward i.
            pairs[k] = combine(i, j, halves[(i - 1) * n + (j - 1)], halves[(j - 1) * n + (i - 1)]);
            k += 1;
        }
        sh.* = .{ .pairs = pairs };
    }
    return shares;
}

test "shares of zero sum to zero over any quorum" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(41));
    const rng = prng.random();

    const n: u16 = 8;
    const shares = try dealSeeds(gpa, n, rng);
    defer {
        for (shares) |*s| s.deinit(gpa);
        gpa.free(shares);
    }

    // The same seeds must work for every subset, which is what lets one setup
    // serve every future quorum.
    const quorums = [_][]const u16{
        &.{ 1, 2 },
        &.{ 1, 3, 5, 7, 8 },
        &.{ 2, 4, 6 },
        &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
    };
    for (quorums) |quorum| {
        var total = K1.Scalar.zero;
        for (quorum) |party| {
            var others: [8]u16 = undefined;
            var k: usize = 0;
            for (quorum) |q| {
                if (q != party) {
                    others[k] = q;
                    k += 1;
                }
            }
            total = total.add(shares[party - 1].compute("sid", others[0..k]));
        }
        try testing.expect(total.isZero());
    }
}

test "a different session gives different, still-cancelling shares" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(42));
    const rng = prng.random();

    const shares = try dealSeeds(gpa, 3, rng);
    defer {
        for (shares) |*s| s.deinit(gpa);
        gpa.free(shares);
    }

    const a = shares[0].compute("sid-a", &.{ 2, 3 });
    const b = shares[0].compute("sid-b", &.{ 2, 3 });
    // Reusing a share across sessions would leak the key share it masks.
    try testing.expect(!a.eql(b));

    var total = K1.Scalar.zero;
    total = total.add(shares[0].compute("sid-b", &.{ 2, 3 }));
    total = total.add(shares[1].compute("sid-b", &.{ 1, 3 }));
    total = total.add(shares[2].compute("sid-b", &.{ 1, 2 }));
    try testing.expect(total.isZero());
}

test "a single share is not zero, and pairs are antisymmetric" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(43));
    const rng = prng.random();

    const shares = try dealSeeds(gpa, 2, rng);
    defer {
        for (shares) |*s| s.deinit(gpa);
        gpa.free(shares);
    }

    const a = shares[0].compute("sid", &.{2});
    const b = shares[1].compute("sid", &.{1});
    // Each is a real mask, not zero, or it would hide nothing.
    try testing.expect(!a.isZero());
    try testing.expect(!b.isZero());
    try testing.expect(a.add(b).isZero());
    try testing.expect(a.eql(b.neg()));
}

test "excluding a counterparty drops exactly its fragment" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(44));
    const rng = prng.random();

    const shares = try dealSeeds(gpa, 4, rng);
    defer {
        for (shares) |*s| s.deinit(gpa);
        gpa.free(shares);
    }

    const with = shares[0].compute("sid", &.{ 2, 3, 4 });
    const without = shares[0].compute("sid", &.{ 2, 3 });
    const only4 = shares[0].compute("sid", &.{4});
    try testing.expect(with.eql(without.add(only4)));
}
