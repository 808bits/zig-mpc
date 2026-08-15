//! Unambiguous transcript hashing and Fiat-Shamir challenge derivation.
//!
//! Every value fed into a transcript is length-prefixed (u64 LE) so that
//! distinct sequences of appends can never collide ("udigest"-style
//! unambiguous encoding). Challenges are drawn from a hash-seeded
//! deterministic RNG (`HashRng`), giving arbitrary-length Fiat-Shamir output.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Session/execution identifier mixed into every protocol transcript so that
/// proofs and messages can never be replayed across executions.
pub const ExecutionId = struct {
    bytes: [32]u8,

    pub fn fromBytes(bytes: [32]u8) ExecutionId {
        return .{ .bytes = bytes };
    }

    pub fn random(rng: std.Random) ExecutionId {
        var b: [32]u8 = undefined;
        rng.bytes(&b);
        return .{ .bytes = b };
    }
};

pub const Transcript = struct {
    h: Sha256,

    /// `domain` is the protocol-wide domain separation tag,
    /// e.g. "zig-mpc/frost/ed25519/v1".
    pub fn init(comptime domain: []const u8) Transcript {
        var t = Transcript{ .h = Sha256.init(.{}) };
        t.appendRaw(domain);
        return t;
    }

    fn appendRaw(self: *Transcript, data: []const u8) void {
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, data.len, .little);
        self.h.update(&len_buf);
        self.h.update(data);
    }

    /// Append a labeled byte string. Label and data are independently
    /// length-prefixed.
    pub fn appendBytes(self: *Transcript, label: []const u8, data: []const u8) void {
        self.appendRaw(label);
        self.appendRaw(data);
    }

    pub fn appendU64(self: *Transcript, label: []const u8, x: u64) void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, x, .little);
        self.appendBytes(label, &buf);
    }

    pub fn appendExecutionId(self: *Transcript, eid: ExecutionId) void {
        self.appendBytes("execution-id", &eid.bytes);
    }

    /// Append a curve point (any curve type from curve.zig).
    pub fn appendPoint(self: *Transcript, comptime E: type, label: []const u8, p: E.Point) void {
        const b = p.toBytes();
        self.appendBytes(label, &b);
    }

    /// Append a curve scalar. Only for PUBLIC scalars - transcripts are not a
    /// safe place for secrets.
    pub fn appendScalar(self: *Transcript, comptime E: type, label: []const u8, s: E.Scalar) void {
        const b = s.toBytes();
        self.appendBytes(label, &b);
    }

    /// Clone the current transcript state (for deriving multiple independent
    /// challenges from a common prefix).
    pub fn fork(self: Transcript, label: []const u8) Transcript {
        var t = self;
        t.appendRaw(label);
        return t;
    }

    /// Finalize into a deterministic RNG for challenge extraction.
    /// The transcript should not be used after this.
    pub fn challengeRng(self: *Transcript) HashRng {
        var seed: [32]u8 = undefined;
        self.h.final(&seed);
        return HashRng.init(seed);
    }

    /// Convenience: derive a single scalar challenge.
    pub fn challengeScalar(self: *Transcript, comptime E: type) E.Scalar {
        var rng = self.challengeRng();
        return rng.scalar(E);
    }
};

/// Deterministic expandable-output RNG: block i = SHA-256(seed || i).
/// Used as the Fiat-Shamir challenge stream.
pub const HashRng = struct {
    seed: [32]u8,
    counter: u64,
    buf: [32]u8,
    buf_used: usize,

    pub fn init(seed: [32]u8) HashRng {
        return .{ .seed = seed, .counter = 0, .buf = undefined, .buf_used = 32 };
    }

    fn refill(self: *HashRng) void {
        var h = Sha256.init(.{});
        h.update(&self.seed);
        var ctr_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &ctr_buf, self.counter, .little);
        h.update(&ctr_buf);
        h.final(&self.buf);
        self.counter += 1;
        self.buf_used = 0;
    }

    pub fn fill(self: *HashRng, out: []u8) void {
        var i: usize = 0;
        while (i < out.len) {
            if (self.buf_used == 32) self.refill();
            const n = @min(32 - self.buf_used, out.len - i);
            @memcpy(out[i..][0..n], self.buf[self.buf_used..][0..n]);
            self.buf_used += n;
            i += n;
        }
    }

    /// Derive a uniformly distributed scalar for curve E via wide reduction.
    pub fn scalar(self: *HashRng, comptime E: type) E.Scalar {
        var wide: [64]u8 = undefined;
        self.fill(&wide);
        return E.Scalar.fromWideBytes(wide);
    }

    fn randomFill(ptr: *anyopaque, buf: []u8) void {
        const self: *HashRng = @ptrCast(@alignCast(ptr));
        self.fill(buf);
    }

    /// Expose as std.Random so deterministic challenge derivation can reuse
    /// generic samplers. The HashRng must outlive the returned interface.
    pub fn random(self: *HashRng) std.Random {
        return .{ .ptr = self, .fillFn = randomFill };
    }
};

test "transcript determinism and sensitivity" {
    const curve = @import("curve.zig");

    var t1 = Transcript.init("zig-mpc/test/v1");
    t1.appendBytes("msg", "hello");
    var t2 = Transcript.init("zig-mpc/test/v1");
    t2.appendBytes("msg", "hello");

    const c1 = t1.challengeScalar(curve.Secp256k1);
    const c2 = t2.challengeScalar(curve.Secp256k1);
    try std.testing.expect(c1.eql(c2));

    // different label -> different challenge
    var t3 = Transcript.init("zig-mpc/test/v1");
    t3.appendBytes("other", "hello");
    const c3 = t3.challengeScalar(curve.Secp256k1);
    try std.testing.expect(!c1.eql(c3));

    // length-prefixing: ("ab","c") must differ from ("a","bc")
    var t4 = Transcript.init("zig-mpc/test/v1");
    t4.appendBytes("ab", "c");
    var t5 = Transcript.init("zig-mpc/test/v1");
    t5.appendBytes("a", "bc");
    const c4 = t4.challengeScalar(curve.Secp256k1);
    const c5 = t5.challengeScalar(curve.Secp256k1);
    try std.testing.expect(!c4.eql(c5));
}

test "hashrng streams consistently regardless of read sizes" {
    var r1 = HashRng.init(@splat(42));
    var r2 = HashRng.init(@splat(42));

    var out1: [100]u8 = undefined;
    r1.fill(&out1);

    var out2: [100]u8 = undefined;
    r2.fill(out2[0..7]);
    r2.fill(out2[7..64]);
    r2.fill(out2[64..]);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}
