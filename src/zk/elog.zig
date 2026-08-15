//! Πelog - discrete-log consistency with an El-Gamal commitment:
//! knowledge of (y, λ) with L = λG, M = yG + λX, Y = yh.
//!
//! Ported from paillier-zk/src/dlog_with_el_gamal_commitment.rs.

const std = @import("std");
const common = @import("common.zig");
const Transcript = common.Transcript;

pub fn Elog(comptime E: type) type {
    return struct {
        pub const Data = struct {
            /// L = λG
            l: E.Point,
            /// M = yG + λX
            m: E.Point,
            x: E.Point,
            /// Y = y·h
            y: E.Point,
            h: E.Point,
        };

        pub const Commitment = struct {
            a: E.Point,
            n: E.Point,
            b: E.Point,
        };

        pub const Proof = struct {
            commitment: Commitment,
            z: E.Scalar,
            u: E.Scalar,
        };

        fn challengeScalar(tr: Transcript, data: Data, com: Commitment) E.Scalar {
            var t = tr.fork("zig-mpc/zk/elog/v1");
            t.appendPoint(E, "L", data.l);
            t.appendPoint(E, "M", data.m);
            t.appendPoint(E, "X", data.x);
            t.appendPoint(E, "Y", data.y);
            t.appendPoint(E, "h", data.h);
            t.appendPoint(E, "A", com.a);
            t.appendPoint(E, "N", com.n);
            t.appendPoint(E, "B", com.b);
            return t.challengeScalar(E);
        }

        pub fn prove(tr: Transcript, rng: std.Random, data: Data, y: E.Scalar, lambda: E.Scalar) !Proof {
            const alpha = E.Scalar.random(rng);
            const m = E.Scalar.random(rng);

            const com = Commitment{
                .a = common.baseMul(E, alpha),
                .n = common.baseMul(E, m).add(common.pointMulPub(E, data.x, alpha)),
                .b = common.pointMulPub(E, data.h, m),
            };
            const e = challengeScalar(tr, data, com);
            return .{
                .commitment = com,
                .z = alpha.add(e.mul(lambda)),
                .u = m.add(e.mul(y)),
            };
        }

        pub fn verify(tr: Transcript, data: Data, proof: Proof) !void {
            const com = proof.commitment;
            const e = challengeScalar(tr, data, com);

            // zG == A + eL
            {
                const lhs = common.baseMul(E, proof.z);
                const rhs = com.a.add(common.pointMulPub(E, data.l, e));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
            // uG + zX == N + eM
            {
                const lhs = common.baseMul(E, proof.u).add(common.pointMulPub(E, data.x, proof.z));
                const rhs = com.n.add(common.pointMulPub(E, data.m, e));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
            // u·h == B + eY
            {
                const lhs = common.pointMulPub(E, data.h, proof.u);
                const rhs = com.b.add(common.pointMulPub(E, data.y, e));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
        }
    };
}

test "elog passing and failing (secp256k1 and ed25519)" {
    const curve = @import("../curve.zig");
    inline for (.{ curve.Secp256k1, curve.Ed25519 }) |E| {
        const Z = Elog(E);
        var prng = std.Random.DefaultPrng.init(808);
        const rng = prng.random();

        const lambda = E.Scalar.random(rng);
        const y = E.Scalar.random(rng);
        const x_secret = E.Scalar.random(rng);
        const h_secret = E.Scalar.random(rng);

        const x_pt = try E.Point.mulBase(x_secret);
        const h = try E.Point.mulBase(h_secret);
        const data = Z.Data{
            .l = try E.Point.mulBase(lambda),
            .m = (try E.Point.mulBase(y)).add(try x_pt.mul(lambda)),
            .x = x_pt,
            .y = try h.mul(y),
            .h = h,
        };

        var tr = Transcript.init("zig-mpc/test/elog");
        tr.appendBytes("session", "s1");

        const proof = try Z.prove(tr, rng, data, y, lambda);
        try Z.verify(tr, data, proof);

        // wrong session
        var tr2 = Transcript.init("zig-mpc/test/elog");
        tr2.appendBytes("session", "s2");
        try std.testing.expectError(error.InvalidProof, Z.verify(tr2, data, proof));

        // wrong witness
        const bad = try Z.prove(tr, rng, data, y.add(E.Scalar.one), lambda);
        try std.testing.expectError(error.InvalidProof, Z.verify(tr, data, bad));

        // tampered response
        var tampered = proof;
        tampered.z = tampered.z.add(E.Scalar.one);
        try std.testing.expectError(error.InvalidProof, Z.verify(tr, data, tampered));
    }
}
