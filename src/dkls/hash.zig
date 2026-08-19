//! Random oracles and commitments for DKLs23.
//!
//! This deliberately does not use `transcript.zig`. The encoding here is
//! byte-for-byte the one in 0xCarbon's `utilities/hashes.rs`:
//!
//!     SHA-256( len(tag) || tag || len(c0) || c0 || len(c1) || c1 || ... )
//!
//! with every length a big-endian u64. No DKLs23 test vectors exist, so the
//! only way to validate this port is to dump intermediate values from the Rust
//! and compare. That is only possible while the oracle encoding matches
//! exactly, which is worth more here than consistency with the rest of the
//! library. `transcript.zig` uses little-endian lengths and a domain string, so
//! it cannot be substituted without breaking that option.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// SHA-256 output, and the size of every seed and commitment in the protocol.
/// `lambda_c / 8` in the paper.
pub const security = 32;

pub const Digest = [security]u8;

/// Domain-separation tags. Same strings as the Rust, for the reason above.
pub const tag = struct {
    pub const commitment = "dkls23/commitment/v1";
    pub const dlog_fischlin = "dkls23/proofs/dlog/fischlin/v1";
    pub const enc_proof_fs = "dkls23/proofs/enc/fs/v1";
    pub const zero_share_fragment = "dkls23/zero-share/fragment/v1";
    pub const ot_base_h = "dkls23/ot/base/h/v1";
    pub const ot_base_msg = "dkls23/ot/base/msg/v1";
    pub const ote_prg = "dkls23/ot/extension/prg/v1";
    pub const ote_chi = "dkls23/ot/extension/chi/v1";
    pub const ote_randomize = "dkls23/ot/extension/randomize/v1";
    pub const mul_gadget = "dkls23/mul/gadget/v1";
    pub const mul_chi_tilde = "dkls23/mul/chi-tilde/v1";
    pub const mul_chi_hat = "dkls23/mul/chi-hat/v1";
    pub const mul_verify = "dkls23/mul/verify/v1";
};

fn appendLenPrefixed(h: *Sha256, component: []const u8) void {
    var len_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_buf, component.len, .big);
    h.update(&len_buf);
    h.update(component);
}

/// Length-delimited tagged hash.
pub fn taggedHash(t: []const u8, components: []const []const u8) Digest {
    var h = Sha256.init(.{});
    appendLenPrefixed(&h, t);
    for (components) |c| appendLenPrefixed(&h, c);
    var out: Digest = undefined;
    h.final(&out);
    return out;
}

/// Reduce a 32-byte big-endian value into a scalar.
///
/// The curve layer only exposes a 64-byte reduction, so the digest is
/// zero-extended on the left. That is the same integer, hence the same
/// residue, which is what the Rust's `Reduce<FieldBytes>` computes.
pub fn reduceToScalar(comptime E: type, bytes: Digest) E.Scalar {
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &bytes);
    return E.Scalar.fromWideBytes(wide);
}

/// Streaming form of `taggedHash`, producing the identical byte stream, for
/// callers that hash a large fixed prefix under many small suffixes. The
/// Fischlin proof of work is the motivating case: ~8,000 attempts per proof,
/// each differing only in the last ~40 bytes of a 2 KB message. Feed the
/// fixed part once, then `fork` per attempt - a struct copy of the midstate -
/// instead of rehashing the prefix.
pub const Stream = struct {
    h: Sha256,

    pub fn init(t: []const u8) Stream {
        var st = Stream{ .h = Sha256.init(.{}) };
        st.component(t);
        return st;
    }

    /// One complete length-prefixed component.
    pub fn component(self: *Stream, bytes: []const u8) void {
        appendLenPrefixed(&self.h, bytes);
    }

    /// Open a component whose `total` bytes will arrive via `raw` calls.
    /// The caller must supply exactly `total` bytes before finishing.
    pub fn beginComponent(self: *Stream, total: usize) void {
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, total, .big);
        self.h.update(&len_buf);
    }

    pub fn raw(self: *Stream, bytes: []const u8) void {
        self.h.update(bytes);
    }

    /// A copy of the midstate, so the suffix can be hashed many times.
    pub fn fork(self: Stream) Stream {
        return self;
    }

    pub fn digest(self: *Stream) Digest {
        var out: Digest = undefined;
        self.h.final(&out);
        return out;
    }
};

/// Length-delimited tagged hash, reduced into a scalar.
pub fn taggedHashScalar(comptime E: type, t: []const u8, components: []const []const u8) E.Scalar {
    return reduceToScalar(E, taggedHash(t, components));
}

/// The salt for a commitment: `2 * lambda_c` bits, as the paper specifies.
pub const Salt = [2 * security]u8;

pub const Commitment = struct {
    digest: Digest,
    salt: Salt,
};

/// Commit to a message. The digest goes out now, the salt and message later.
pub fn commit(msg: []const u8, rng: std.Random) Commitment {
    var salt: Salt = undefined;
    rng.bytes(&salt);
    return .{ .digest = taggedHash(tag.commitment, &.{ &salt, msg }), .salt = salt };
}

pub fn verifyCommitment(msg: []const u8, digest: Digest, salt: Salt) bool {
    const expected = taggedHash(tag.commitment, &.{ &salt, msg });
    return std.crypto.timing_safe.eql(Digest, expected, digest);
}

/// Commit to a curve point, which is what signing round 1 actually needs.
pub fn commitPoint(comptime E: type, p: E.Point, rng: std.Random) Commitment {
    const b = p.toBytes();
    return commit(&b, rng);
}

pub fn verifyCommitmentPoint(comptime E: type, p: E.Point, digest: Digest, salt: Salt) bool {
    const b = p.toBytes();
    return verifyCommitment(&b, digest, salt);
}

const testing = std.testing;
const curve = @import("../curve.zig");
const K1 = curve.Secp256k1;

test "tagged hash is length-delimited, not concatenation" {
    // The length prefixes are the whole point: without them ("ab","c") and
    // ("a","bc") would collide and a hostile peer could move bytes across a
    // component boundary.
    const a = taggedHash("t", &.{ "ab", "c" });
    const b = taggedHash("t", &.{ "a", "bc" });
    try testing.expect(!std.mem.eql(u8, &a, &b));

    // The tag is separated from the components too.
    const c = taggedHash("tab", &.{"c"});
    try testing.expect(!std.mem.eql(u8, &a, &c));
}

test "tagged hash matches its specified encoding" {
    // Pin the construction against an independent computation, so a future
    // refactor cannot silently change the oracle and invalidate the option of
    // cross-checking against the Rust.
    var h = Sha256.init(.{});
    h.update(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 3 });
    h.update("tag");
    h.update(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 2 });
    h.update("hi");
    var expected: Digest = undefined;
    h.final(&expected);
    try testing.expectEqual(expected, taggedHash("tag", &.{"hi"}));
}

test "distinct tags give distinct oracles" {
    const a = taggedHash(tag.ot_base_h, &.{"x"});
    const b = taggedHash(tag.ot_base_msg, &.{"x"});
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "commitment binds and hides" {
    var seed: [32]u8 = @splat(7);
    var prng = std.Random.DefaultCsprng.init(seed);
    const rng = prng.random();
    seed = @splat(0);

    const c = commit("hello", rng);
    try testing.expect(verifyCommitment("hello", c.digest, c.salt));
    try testing.expect(!verifyCommitment("hellp", c.digest, c.salt));

    var wrong_salt = c.salt;
    wrong_salt[0] ^= 1;
    try testing.expect(!verifyCommitment("hello", c.digest, wrong_salt));

    // Two commitments to the same message differ, so the digest leaks nothing.
    const c2 = commit("hello", rng);
    try testing.expect(!std.mem.eql(u8, &c.digest, &c2.digest));
}

test "point commitment round trips" {
    var seed: [32]u8 = @splat(9);
    var prng = std.Random.DefaultCsprng.init(seed);
    const rng = prng.random();
    seed = @splat(0);

    const p = try K1.Point.mulBase(K1.Scalar.fromU64(12345));
    const c = commitPoint(K1, p, rng);
    try testing.expect(verifyCommitmentPoint(K1, p, c.digest, c.salt));

    const q = try K1.Point.mulBase(K1.Scalar.fromU64(12346));
    try testing.expect(!verifyCommitmentPoint(K1, q, c.digest, c.salt));
}

test "scalar reduction agrees with the wide reduction" {
    var d: Digest = undefined;
    for (&d, 0..) |*b, i| b.* = @intCast(i);
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &d);
    try testing.expect(reduceToScalar(K1, d).eql(K1.Scalar.fromWideBytes(wide)));
}

// ---------------------------------------------------------------------------
// Cross-implementation vectors
//
// Generated from 0xCarbon's dkls23-core, the implementation this is ported
// from. These are what turn "the two halves of my own port agree" into "the
// oracle really is the one the reference computes"; an encoding slip here
// would otherwise stay invisible until it broke interop with nothing.
// ---------------------------------------------------------------------------

const vectors = @import("../testdata/dkls_vectors.zig");

/// Decode hex into `buf`, returning the populated prefix.
fn unhex(buf: []u8, text: []const u8) []const u8 {
    return std.fmt.hexToBytes(buf, text) catch unreachable;
}

test "tagged hash matches dkls23-core" {
    var tag_buf: [64]u8 = undefined;
    var part_bufs: [8][128]u8 = undefined;
    var out_buf: [32]u8 = undefined;

    for (vectors.tagged_hash) |v| {
        const t = unhex(&tag_buf, v.tag);
        var parts: [8][]const u8 = undefined;
        for (v.parts, 0..) |p, i| parts[i] = unhex(&part_bufs[i], p);
        const expected = unhex(&out_buf, v.out);
        const got = taggedHash(t, parts[0..v.parts.len]);
        try testing.expectEqualSlices(u8, expected, &got);
    }
}

test "tagged hash as scalar matches dkls23-core" {
    var tag_buf: [64]u8 = undefined;
    var part_bufs: [8][128]u8 = undefined;
    var out_buf: [32]u8 = undefined;

    for (vectors.tagged_hash_scalar) |v| {
        const t = unhex(&tag_buf, v.tag);
        var parts: [8][]const u8 = undefined;
        for (v.parts, 0..) |p, i| parts[i] = unhex(&part_bufs[i], p);
        const expected = unhex(&out_buf, v.out);
        const got = taggedHashScalar(K1, t, parts[0..v.parts.len]);
        try testing.expectEqualSlices(u8, expected, &got.toBytes());
    }
}

test "zero-share fragment matches dkls23-core" {
    var sid_buf: [16]u8 = undefined;
    var seed_buf: [32]u8 = undefined;
    var out_buf: [32]u8 = undefined;
    const sid = unhex(&sid_buf, vectors.zero_share_sid);
    const seed = unhex(&seed_buf, vectors.zero_share_seed);
    const expected = unhex(&out_buf, vectors.zero_share_out);
    const got = taggedHashScalar(K1, tag.zero_share_fragment, &.{ sid, seed });
    try testing.expectEqualSlices(u8, expected, &got.toBytes());
}

test "OTE randomize step matches dkls23-core" {
    // Pinned here because the index widths matter and are easy to get wrong:
    // the reference writes j as a big-endian u16 and the iteration as a u8.
    var sid_buf: [16]u8 = undefined;
    var row_buf: [32]u8 = undefined;
    var out_buf: [32]u8 = undefined;
    const sid = unhex(&sid_buf, vectors.randomize_sid);
    const row = unhex(&row_buf, vectors.randomize_row);
    const expected = unhex(&out_buf, vectors.randomize_out);

    var j_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &j_be, vectors.randomize_j, .big);
    const iter_be = [_]u8{vectors.randomize_iteration};
    const got = taggedHashScalar(K1, tag.ote_randomize, &.{ sid, &j_be, &iter_be, row });
    try testing.expectEqualSlices(u8, expected, &got.toBytes());
}

test "Stream reproduces taggedHash byte for byte" {
    // The Fischlin optimization rests entirely on this equivalence.
    const parts = [_][]const u8{ "session", "a longer static prefix", "tail" };
    const flat = "a longer static prefixtail";
    const direct = taggedHash(tag.dlog_fischlin, &.{ parts[0], flat });

    var st = Stream.init(tag.dlog_fischlin);
    st.component(parts[0]);
    st.beginComponent(flat.len);
    st.raw(parts[1]);
    var forked = st.fork();
    forked.raw(parts[2]);
    try testing.expectEqual(direct, forked.digest());

    // The midstate is reusable: a second fork gives the same digest again.
    var forked2 = st.fork();
    forked2.raw(parts[2]);
    try testing.expectEqual(direct, forked2.digest());
}
