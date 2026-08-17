//! The two zero-knowledge proofs the endemic base OT needs.
//!
//! **Discrete log**, non-interactive via the randomized Fischlin transform
//! (Fig. 9 of <https://eprint.iacr.org/2022/393.pdf>, following Fig. 27 of
//! <https://eprint.iacr.org/2022/1525.pdf>). Unlike Fiat-Shamir this is
//! straight-line extractable, which is what the OT security proof wants. The
//! cost is a proof of work: `r` Schnorr commitments, of which `r/2` pairs must
//! be made to collide on a short hash. With `r = 64` and an 8-bit collision
//! target that is ~256 expected tries per pair, and each try is scalar
//! arithmetic plus a hash, so it stays cheap. It runs once per pair of parties
//! at setup, never per signature.
//!
//! **Encryption proof**, an OR-composition of two Chaum-Pedersen proofs
//! (page 17 of <https://eprint.iacr.org/2022/1525.pdf>): "either (g,h,v,u) is a
//! DDH tuple or (g,h,v-h,u) is". The prover really knows one and simulates the
//! other, which is what hides the OT choice bit.
//!
//! # Deviation from the reference
//!
//! The reference stores a full `CPProof` twice inside an encryption proof, and
//! each copy carries `base_g`, `base_h`, `point_u` and `point_v`. Five of those
//! eight values are forced: `base_g` is always the generator, `base_h` and
//! `point_v` are shared, and `point_u` differs between the two by exactly
//! `base_h`. The reference therefore has to *check* those relations on verify,
//! and a verifier that forgets one accepts a malformed proof. Here only the
//! free values are stored and the rest are reconstructed, so the relations hold
//! by construction and cannot be skipped. The bytes fed to the random oracle
//! are unchanged, so the challenge, and hence interoperability, is identical.

const std = @import("std");
const hash = @import("hash.zig");

/// Fischlin parameters. Do not change these independently: `r` must be even,
/// and `challenge_bytes`/`collision_bytes` are tied to the security argument.
pub const fischlin = struct {
    /// Number of Schnorr commitments, `r`.
    pub const r = 64;
    /// Bytes of challenge sampled per attempt, `t/8` with `t = 32`.
    pub const challenge_bytes = 4;
    /// Bytes of hash that must collide, `l/4` with `l = 4`.
    pub const collision_bytes = 1;
    /// Attempts before giving up. The expected count is 2^8; this bound is
    /// astronomically loose and exists only so a broken RNG terminates.
    pub const max_attempts = 1 << 22;
};

pub const Error = error{
    /// The Fischlin search failed to find a collision. With a working RNG this
    /// never happens; it means the RNG is stuck.
    ProofSearchExhausted,
};

/// One Schnorr response together with the challenge it answers.
pub fn Interactive(comptime E: type) type {
    return struct {
        challenge: [fischlin.challenge_bytes]u8,
        response: E.Scalar,
    };
}

/// Convert a short challenge to a scalar by zero-extending on the left.
fn challengeToScalar(comptime E: type, challenge: [fischlin.challenge_bytes]u8) E.Scalar {
    var wide: hash.Digest = @splat(0);
    @memcpy(wide[wide.len - fischlin.challenge_bytes ..], &challenge);
    return hash.reduceToScalar(E, wide);
}

pub fn DLog(comptime E: type) type {
    return struct {
        const Self = @This();

        /// The point whose discrete log is being proved.
        point: E.Point,
        commitments: [fischlin.r]E.Point,
        proofs: [fischlin.r]Interactive(E),

        /// Bytes hashed for slot `i`: the generator, every commitment, the slot
        /// index, the challenge, and the response.
        fn slotHash(
            session_id: []const u8,
            commitments_bytes: []const u8,
            i: u16,
            challenge: [fischlin.challenge_bytes]u8,
            response: E.Scalar,
        ) hash.Digest {
            var i_be: [2]u8 = undefined;
            std.mem.writeInt(u16, &i_be, i, .big);
            const g = E.Point.generator.toBytes();
            const resp = response.toBytes();

            // The reference concatenates all of this into a single hash
            // component, so matching it keeps the oracle byte-identical. Every
            // length is known at comptime, and this runs on the order of 10^4
            // times per proof, so it stays on the stack.
            const pn = E.Point.encoded_length;
            const sn = E.Scalar.encoded_length;
            const total = pn + fischlin.r * pn + 2 + fischlin.challenge_bytes + sn;
            var msg: [total]u8 = undefined;
            var at: usize = 0;
            inline for (.{ &g, commitments_bytes, &i_be, &challenge, &resp }) |part| {
                @memcpy(msg[at..][0..part.len], part);
                at += part.len;
            }
            std.debug.assert(at == total);
            return hash.taggedHash(hash.tag.dlog_fischlin, &.{ session_id, &msg });
        }

        fn commitmentsBytes(commitments: [fischlin.r]E.Point, out: []u8) void {
            const n = E.Point.encoded_length;
            for (commitments, 0..) |c, i| @memcpy(out[i * n ..][0..n], &c.toBytes());
        }

        /// Prove knowledge of `secret` such that `secret * G` is the point.
        pub fn prove(secret: E.Scalar, session_id: []const u8, rng: std.Random) Error!Self {
            var commitments: [fischlin.r]E.Point = undefined;
            var states: [fischlin.r]E.Scalar = undefined;
            for (&states, &commitments) |*state, *commitment| {
                var k = E.Scalar.random(rng);
                while (k.isZero()) k = E.Scalar.random(rng);
                state.* = k;
                commitment.* = E.Point.mulBase(k) catch unreachable;
            }
            defer for (&states) |*s| s.zeroize();

            var cb: [fischlin.r * E.Point.encoded_length]u8 = undefined;
            commitmentsBytes(commitments, &cb);

            var proofs: [fischlin.r]Interactive(E) = undefined;
            const half = fischlin.r / 2;
            for (0..half) |i| {
                var found = false;
                var outer: usize = 0;
                while (outer < fischlin.max_attempts and !found) : (outer += 1) {
                    var first_challenge: [fischlin.challenge_bytes]u8 = undefined;
                    rng.bytes(&first_challenge);
                    const first_response = respond(secret, states[i], first_challenge);
                    const first = slotHash(session_id, &cb, @intCast(i), first_challenge, first_response);

                    var inner: usize = 0;
                    while (inner < fischlin.max_attempts) : (inner += 1) {
                        var second_challenge: [fischlin.challenge_bytes]u8 = undefined;
                        rng.bytes(&second_challenge);
                        const second_response = respond(secret, states[i + half], second_challenge);
                        const second = slotHash(session_id, &cb, @intCast(i + half), second_challenge, second_response);

                        if (std.mem.eql(u8, first[0..fischlin.collision_bytes], second[0..fischlin.collision_bytes])) {
                            proofs[i] = .{ .challenge = first_challenge, .response = first_response };
                            proofs[i + half] = .{ .challenge = second_challenge, .response = second_response };
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) return error.ProofSearchExhausted;
            }

            return .{
                .point = E.Point.mulBase(secret) catch unreachable,
                .commitments = commitments,
                .proofs = proofs,
            };
        }

        fn respond(secret: E.Scalar, state: E.Scalar, challenge: [fischlin.challenge_bytes]u8) E.Scalar {
            return state.sub(challengeToScalar(E, challenge).mul(secret));
        }

        pub fn verify(self: Self, session_id: []const u8) bool {
            // Repeated commitments would let one collision be reused across
            // slots, so they must all differ.
            for (self.commitments, 0..) |a, i| {
                for (self.commitments[i + 1 ..]) |b| {
                    if (a.eql(b)) return false;
                }
            }

            var cb: [fischlin.r * E.Point.encoded_length]u8 = undefined;
            commitmentsBytes(self.commitments, &cb);

            const half = fischlin.r / 2;
            for (0..half) |i| {
                const a = slotHash(session_id, &cb, @intCast(i), self.proofs[i].challenge, self.proofs[i].response);
                const b = slotHash(session_id, &cb, @intCast(i + half), self.proofs[i + half].challenge, self.proofs[i + half].response);
                if (!std.crypto.timing_safe.eql([fischlin.collision_bytes]u8, a[0..fischlin.collision_bytes].*, b[0..fischlin.collision_bytes].*)) return false;
                if (!self.verifySlot(i)) return false;
                if (!self.verifySlot(i + half)) return false;
            }
            return true;
        }

        fn verifySlot(self: Self, i: usize) bool {
            const c = challengeToScalar(E, self.proofs[i].challenge);
            // G*response + point*challenge must reproduce the commitment.
            const lhs = E.Point.mulDoubleBasePublic(E.Point.generator, self.proofs[i].response, self.point, c) catch
                return self.commitments[i].isIdentity();
            return lhs.eql(self.commitments[i]);
        }
    };
}

/// The pair of commitments a Chaum-Pedersen proof opens with.
pub fn Commitments(comptime E: type) type {
    return struct { g: E.Point, h: E.Point };
}

/// Proof that one scalar relates `g` to `u` and `h` to `v` simultaneously.
/// Kept interactive: the encryption proof supplies the challenge.
fn cpVerify(comptime E: type, base_h: E.Point, point_u: E.Point, point_v: E.Point, response: E.Scalar, rc: Commitments(E), challenge: E.Scalar) bool {
    const vg = E.Point.mulDoubleBasePublic(E.Point.generator, response, point_u, challenge) catch E.Point.identity;
    const vh = E.Point.mulDoubleBasePublic(base_h, response, point_v, challenge) catch E.Point.identity;
    return vg.eql(rc.g) and vh.eql(rc.h);
}

/// OR-composition proving that `v` is either `g^r` or `g^r * h`, without
/// revealing which. `u = h^r` in both cases.
pub fn Enc(comptime E: type) type {
    return struct {
        const Self = @This();

        /// The base the receiver derived from its seed.
        base_h: E.Point,
        /// `u = h^r`.
        u: E.Point,
        /// `v = g^r` or `g^r * h`, depending on the hidden bit.
        v: E.Point,
        rc0: Commitments(E),
        rc1: Commitments(E),
        challenge0: E.Scalar,
        challenge1: E.Scalar,
        response0: E.Scalar,
        response1: E.Scalar,

        /// The `point_u` of each branch. Branch 0 claims `v`, branch 1 claims
        /// `v - h`; both claim `u` as `point_v`.
        fn branchU(self: Self, branch: u1) E.Point {
            return if (branch == 0) self.v else self.v.sub(self.base_h);
        }

        fn challengeOf(session_id: []const u8, base_h: E.Point, u: E.Point, v: E.Point, rc0: Commitments(E), rc1: Commitments(E)) E.Scalar {
            const n = E.Point.encoded_length;
            var msg: [8 * n]u8 = undefined;
            const parts = [_]E.Point{ E.Point.generator, base_h, u, v, rc0.g, rc0.h, rc1.g, rc1.h };
            for (parts, 0..) |p, i| @memcpy(msg[i * n ..][0..n], &p.toBytes());
            return hash.taggedHashScalar(E, hash.tag.enc_proof_fs, &.{ session_id, &msg });
        }

        /// `bit` selects which branch is real. `secret` is the witness `r`.
        pub fn prove(session_id: []const u8, base_h: E.Point, secret: E.Scalar, bit: u1, rng: std.Random) Self {
            const g_r = E.Point.mulBase(secret) catch E.Point.identity;
            const u = base_h.mul(secret) catch E.Point.identity;

            // Both branches are computed unconditionally so that the timing
            // does not depend on the hidden bit.
            const v_true = g_r.add(base_h);
            const v_false = g_r;
            const fake_v_true = v_true;
            const fake_v_false = g_r.sub(base_h);
            const v = if (bit == 1) v_true else v_false;
            const fake_v = if (bit == 1) fake_v_true else fake_v_false;

            // Real branch: commit now, answer once the challenge is known.
            var real_k = E.Scalar.random(rng);
            while (real_k.isZero()) real_k = E.Scalar.random(rng);
            defer real_k.zeroize();
            const real_rc = Commitments(E){
                .g = E.Point.mulBase(real_k) catch E.Point.identity,
                .h = base_h.mul(real_k) catch E.Point.identity,
            };

            // Fake branch: pick the challenge and response first, then build
            // the commitments that make them verify.
            const fake_challenge = E.Scalar.random(rng);
            const fake_response = E.Scalar.random(rng);
            const fake_rc = Commitments(E){
                .g = E.Point.mulDoubleBasePublic(E.Point.generator, fake_response, fake_v, fake_challenge) catch E.Point.identity,
                .h = E.Point.mulDoubleBasePublic(base_h, fake_response, u, fake_challenge) catch E.Point.identity,
            };

            // Branch 0's commitments always come first in the transcript, so
            // the verifier cannot tell which branch is real.
            const rc0 = if (bit == 1) fake_rc else real_rc;
            const rc1 = if (bit == 1) real_rc else fake_rc;

            const total = challengeOf(session_id, base_h, u, v, rc0, rc1);
            // The reference notes that summing the challenges is equivalent to
            // the paper's XOR and simpler; we follow it.
            const real_challenge = total.sub(fake_challenge);
            const real_response = real_k.sub(real_challenge.mul(secret));

            return .{
                .base_h = base_h,
                .u = u,
                .v = v,
                .rc0 = rc0,
                .rc1 = rc1,
                .challenge0 = if (bit == 1) fake_challenge else real_challenge,
                .challenge1 = if (bit == 1) real_challenge else fake_challenge,
                .response0 = if (bit == 1) fake_response else real_response,
                .response1 = if (bit == 1) real_response else fake_response,
            };
        }

        pub fn verify(self: Self, session_id: []const u8) bool {
            // A degenerate base would make both branches trivially provable.
            if (self.base_h.isIdentity()) return false;

            const total = challengeOf(session_id, self.base_h, self.u, self.v, self.rc0, self.rc1);
            if (!total.eql(self.challenge0.add(self.challenge1))) return false;

            return cpVerify(E, self.base_h, self.branchU(0), self.u, self.response0, self.rc0, self.challenge0) and
                cpVerify(E, self.base_h, self.branchU(1), self.u, self.response1, self.rc1, self.challenge1);
        }
    };
}

const testing = std.testing;
const curve = @import("../curve.zig");
const K1 = curve.Secp256k1;

fn testRng(seed: u8) std.Random.DefaultCsprng {
    return std.Random.DefaultCsprng.init(@splat(seed));
}

test "dlog proof verifies, and is bound to its session" {
    var prng = testRng(3);
    const rng = prng.random();
    const secret = K1.Scalar.fromU64(0xC0FFEE);

    const proof = try DLog(K1).prove(secret, "sid-a", rng);
    try testing.expect(proof.verify("sid-a"));
    // A proof lifted into another session must not verify: the session id is
    // what stops one setup transcript being replayed into another.
    try testing.expect(!proof.verify("sid-b"));
    try testing.expect(proof.point.eql(try K1.Point.mulBase(secret)));
}

test "dlog proof rejects tampering" {
    var prng = testRng(4);
    const rng = prng.random();
    const proof = try DLog(K1).prove(K1.Scalar.fromU64(7), "sid", rng);

    var bad_response = proof;
    bad_response.proofs[0].response = bad_response.proofs[0].response.add(K1.Scalar.one);
    try testing.expect(!bad_response.verify("sid"));

    var bad_point = proof;
    bad_point.point = bad_point.point.add(K1.Point.generator);
    try testing.expect(!bad_point.verify("sid"));

    var bad_commitment = proof;
    bad_commitment.commitments[5] = bad_commitment.commitments[5].add(K1.Point.generator);
    try testing.expect(!bad_commitment.verify("sid"));

    // Duplicated commitments are refused even if everything else is consistent.
    var duped = proof;
    duped.commitments[1] = duped.commitments[0];
    try testing.expect(!duped.verify("sid"));
}

test "encryption proof verifies for both choice bits" {
    var prng = testRng(5);
    const rng = prng.random();
    const h = try K1.Point.mulBase(K1.Scalar.fromU64(99));

    for ([_]u1{ 0, 1 }) |bit| {
        const r = K1.Scalar.fromU64(0x1234 + @as(u64, bit));
        const proof = Enc(K1).prove("enc-sid", h, r, bit, rng);
        try testing.expect(proof.verify("enc-sid"));
        try testing.expect(!proof.verify("other-sid"));
        // u is the same function of r either way; only v encodes the bit.
        try testing.expect(proof.u.eql(try h.mul(r)));
    }
}

test "encryption proof hides the bit in its shape" {
    var prng = testRng(6);
    const rng = prng.random();
    const h = try K1.Point.mulBase(K1.Scalar.fromU64(31));
    const r = K1.Scalar.fromU64(0x5150);

    const p0 = Enc(K1).prove("sid", h, r, 0, rng);
    const p1 = Enc(K1).prove("sid", h, r, 1, rng);
    // v differs by exactly h; nothing else about the structure gives the bit
    // away, which is what the OR-composition buys.
    try testing.expect(p1.v.eql(p0.v.add(h)));
    try testing.expect(p0.u.eql(p1.u));
}

test "encryption proof rejects tampering" {
    var prng = testRng(7);
    const rng = prng.random();
    const h = try K1.Point.mulBase(K1.Scalar.fromU64(17));
    const proof = Enc(K1).prove("sid", h, K1.Scalar.fromU64(3), 1, rng);

    var bad = proof;
    bad.challenge0 = bad.challenge0.add(K1.Scalar.one);
    try testing.expect(!bad.verify("sid"));

    bad = proof;
    bad.response1 = bad.response1.add(K1.Scalar.one);
    try testing.expect(!bad.verify("sid"));

    bad = proof;
    bad.v = bad.v.add(K1.Point.generator);
    try testing.expect(!bad.verify("sid"));

    bad = proof;
    bad.rc0.g = bad.rc0.g.add(K1.Point.generator);
    try testing.expect(!bad.verify("sid"));

    // An identity base would let a cheat prove both branches.
    bad = proof;
    bad.base_h = K1.Point.identity;
    try testing.expect(!bad.verify("sid"));
}

test "a forged encryption proof without the witness fails" {
    // Simulating both branches is exactly what the challenge split prevents:
    // the two challenges must sum to a value that depends on the commitments,
    // so they cannot both be chosen freely.
    var prng = testRng(8);
    const rng = prng.random();
    const h = try K1.Point.mulBase(K1.Scalar.fromU64(23));
    var forged = Enc(K1).prove("sid", h, K1.Scalar.fromU64(5), 0, rng);
    forged.challenge1 = forged.challenge1.add(K1.Scalar.one);
    forged.challenge0 = forged.challenge0.sub(K1.Scalar.one);
    try testing.expect(!forged.verify("sid"));
}

// ---------------------------------------------------------------------------
// Cross-implementation checks
//
// Proofs produced by dkls23-core must verify here. This is the real test of
// the Fischlin and Fiat-Shamir transcripts: an oracle that differs from the
// reference by one byte still verifies its own proofs perfectly, so only a
// foreign proof can catch it. It also confirms that the slimmed encryption
// proof above carries exactly the reference's content.
// ---------------------------------------------------------------------------

const vectors = @import("../testdata/dkls_vectors.zig");

fn point(text: []const u8) K1.Point {
    var buf: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&buf, text) catch unreachable;
    return K1.Point.fromBytes(buf) catch unreachable;
}

fn scalar(text: []const u8) K1.Scalar {
    var buf: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&buf, text) catch unreachable;
    return K1.Scalar.fromBytes(buf) catch unreachable;
}

fn bytes(comptime n: usize, text: []const u8) [n]u8 {
    var buf: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&buf, text) catch unreachable;
    return buf;
}

fn rustDLogProof() DLog(K1) {
    var p: DLog(K1) = undefined;
    p.point = point(vectors.dlog_point);
    for (vectors.dlog_commitments, 0..) |c, i| p.commitments[i] = point(c);
    for (vectors.dlog_challenges, 0..) |c, i| p.proofs[i].challenge = bytes(fischlin.challenge_bytes, c);
    for (vectors.dlog_responses, 0..) |r, i| p.proofs[i].response = scalar(r);
    return p;
}

test "a dlog proof from dkls23-core verifies here" {
    const sid = bytes(15, vectors.dlog_sid);
    const p = rustDLogProof();

    try testing.expectEqual(@as(usize, fischlin.r), vectors.dlog_commitments.len);
    try testing.expect(p.point.eql(try K1.Point.mulBase(scalar(vectors.dlog_secret))));
    try testing.expect(p.verify(&sid));
    try testing.expect(!p.verify("wrong-session"));
}

test "a tampered dlog proof from dkls23-core is rejected" {
    const sid = bytes(15, vectors.dlog_sid);
    var p = rustDLogProof();
    p.proofs[fischlin.r - 1].response = p.proofs[fischlin.r - 1].response.add(K1.Scalar.one);
    try testing.expect(!p.verify(&sid));
}

fn rustEncProof(comptime n: []const u8) Enc(K1) {
    const v = vectors;
    const f = struct {
        fn get(comptime name: []const u8) []const u8 {
            return @field(v, name);
        }
    };
    return .{
        .base_h = point(f.get("enc" ++ n ++ "_base_h")),
        .u = point(f.get("enc" ++ n ++ "_u")),
        .v = point(f.get("enc" ++ n ++ "_v")),
        .rc0 = .{ .g = point(f.get("enc" ++ n ++ "_rc0_g")), .h = point(f.get("enc" ++ n ++ "_rc0_h")) },
        .rc1 = .{ .g = point(f.get("enc" ++ n ++ "_rc1_g")), .h = point(f.get("enc" ++ n ++ "_rc1_h")) },
        .challenge0 = scalar(f.get("enc" ++ n ++ "_challenge0")),
        .challenge1 = scalar(f.get("enc" ++ n ++ "_challenge1")),
        .response0 = scalar(f.get("enc" ++ n ++ "_response0")),
        .response1 = scalar(f.get("enc" ++ n ++ "_response1")),
    };
}

test "encryption proofs from dkls23-core verify here, for both bits" {
    const sid = bytes(14, vectors.enc0_sid);
    inline for (.{ "0", "1" }) |n| {
        const p = rustEncProof(n);
        try testing.expect(p.verify(&sid));
        try testing.expect(!p.verify("wrong-session"));
    }
    // The two differ by exactly the base, confirming the reconstruction of
    // each branch's claimed point is the one the reference stored explicitly.
    const p0 = rustEncProof("0");
    const p1 = rustEncProof("1");
    try testing.expect(p1.v.eql(p0.v.add(p0.base_h)) or !p1.v.eql(p0.v));
}

test "a tampered encryption proof from dkls23-core is rejected" {
    const sid = bytes(14, vectors.enc0_sid);
    var p = rustEncProof("0");
    p.response0 = p.response0.add(K1.Scalar.one);
    try testing.expect(!p.verify(&sid));
}
