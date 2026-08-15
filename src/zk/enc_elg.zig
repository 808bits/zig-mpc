//! Πenc-elg - Paillier ciphertext's plaintext is in range ±2^(l+ε), with the
//! plaintext additionally bound to an El-Gamal-style commitment:
//! A = aG, B = bG, X = (ab + x)G.
//!
//! Ported from paillier-zk/src/paillier_encryption_in_range_with_el_gamal.rs.

const std = @import("std");
const common = @import("common.zig");
const Transcript = common.Transcript;

pub fn EncElg(comptime P: type, comptime E: type) type {
    const Aux = common.Aux(P);
    const S = P.S;
    const Pl = common.Pail(P);
    return struct {
        pub const Data = struct {
            ek: Pl.EncryptionKey,
            /// C = Enc(x; ρ)
            c: Pl.Ciphertext,
            a: E.Point,
            b: E.Point,
            x: E.Point,
        };

        pub const Private = struct {
            /// x, |x| < 2^l
            plaintext: S,
            /// ρ
            nonce: Pl.Nonce,
            /// b with B = bG
            b: E.Scalar,
        };

        pub const Commitment = struct {
            s: P.Fn.Bytes,
            t: P.Fn.Bytes,
            d: Pl.Ciphertext,
            y: E.Point,
            z: E.Point,
        };

        pub const Proof = struct {
            commitment: Commitment,
            z1: S,
            z2: P.Fn.Bytes,
            z3: S,
            w: E.Scalar,
        };

        fn challengeScalar(tr: Transcript, aux: Aux, data: Data, com: Commitment) S {
            var t = tr.fork("zig-mpc/zk/enc-elg/v1");
            aux.appendToTranscript(&t);
            t.appendBytes("n0", &data.ek.n);
            t.appendBytes("C", &data.c);
            t.appendPoint(E, "A", data.a);
            t.appendPoint(E, "B", data.b);
            t.appendPoint(E, "X", data.x);
            t.appendBytes("com-s", &com.s);
            t.appendBytes("com-t", &com.t);
            t.appendBytes("com-d", &com.d);
            t.appendPoint(E, "com-y", com.y);
            t.appendPoint(E, "com-z", com.z);
            var hrng = t.challengeRng();
            const rng = hrng.random();
            return S.sampleHalfPm(rng, common.curveOrderWide(P, E));
        }

        pub fn prove(tr: Transcript, rng: std.Random, aux: Aux, data: Data, pdata: Private) !Proof {
            const two_le = P.pow2(P.l + P.epsilon);
            const nhat_l = P.mulBound(P.pow2(P.l), P.lift(P.Fn, aux.n_hat));
            const nhat_le = P.mulBound(two_le, P.lift(P.Fn, aux.n_hat));

            const alpha = S.sampleHalfPm(rng, two_le);
            const mu = S.sampleHalfPm(rng, nhat_l);
            const r = data.ek.randomNonce(rng);
            const beta = E.Scalar.random(rng);
            const gamma = S.sampleHalfPm(rng, nhat_le);

            const com = Commitment{
                .s = try aux.combine(pdata.plaintext, mu),
                .t = try aux.combine(alpha, gamma),
                .d = try common.encryptSigned(P, data.ek, alpha, r),
                .y = common.pointMulPub(E, data.a, beta).add(common.baseMul(E, common.toCurveScalar(P, E, alpha))),
                .z = common.baseMul(E, beta),
            };
            const e = challengeScalar(tr, aux, data, com);
            const e_scalar = common.toCurveScalar(P, E, e);

            return .{
                .commitment = com,
                .z1 = alpha.add(e.mul(pdata.plaintext)),
                .z2 = try common.nonceCombine(P, data.ek, r, pdata.nonce, e),
                .z3 = gamma.add(e.mul(mu)),
                .w = beta.add(e_scalar.mul(pdata.b)),
            };
        }

        pub fn verify(tr: Transcript, aux: Aux, data: Data, proof: Proof) !void {
            const com = proof.commitment;
            if (!data.ek.isValidCiphertext(data.c)) return error.InvalidProof;
            if (!aux.isInMultGroup(com.s) or !aux.isInMultGroup(com.t)) return error.InvalidProof;
            if (!data.ek.isValidCiphertext(com.d)) return error.InvalidProof;

            const e = challengeScalar(tr, aux, data, com);
            const e_scalar = common.toCurveScalar(P, E, e);

            // (5) Enc(z1; z2) == D ⊕ e⊙C
            {
                const lhs = try common.encryptSigned(P, data.ek, proof.z1, proof.z2);
                const e_c = try common.homMulSigned(P, data.ek, data.c, e);
                const rhs = data.ek.homAdd(com.d, e_c);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (6) A·w + G·z1 == Y + X·e
            {
                const lhs = common.pointMulPub(E, data.a, proof.w).add(common.baseMul(E, common.toCurveScalar(P, E, proof.z1)));
                const rhs = com.y.add(common.pointMulPub(E, data.x, e_scalar));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
            // (7) G·w == Z + B·e
            {
                const lhs = common.baseMul(E, proof.w);
                const rhs = com.z.add(common.pointMulPub(E, data.b, e_scalar));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
            // (8) combine(z1, z3) == T · S^e
            {
                const lhs = try aux.combine(proof.z1, proof.z3);
                const s_e = try aux.powModSigned(com.s, e);
                const rhs = aux.mulMod(com.t, s_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (9) |z1| ≤ 2^(l+ε)/2
            if (!proof.z1.inHalfPm(P.pow2(P.l + P.epsilon))) return error.InvalidProof;
        }
    };
}

test "enc-elg passing and failing" {
    const curve = @import("../curve.zig");
    const P = common.TestParamsCurve;
    const E = curve.Secp256k1;
    const Z = EncElg(P, E);
    const Pl = common.Pail(P);
    var prng = std.Random.DefaultPrng.init(9001);
    const rng = prng.random();

    var gen = try common.Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = gen.aux;

    var dk = try Pl.DecryptionKey.generate(rng);
    defer dk.zeroize();
    const ek = dk.ek;

    // x in ±2^l/2, C = Enc(x; ρ); El-Gamal commitment A=aG, B=bG, X=(ab+x)G
    const x = P.S.sampleHalfPm(rng, P.pow2(P.l));
    const rho = ek.randomNonce(rng);
    const c = try common.encryptSigned(P, ek, x, rho);
    const a_sc = E.Scalar.random(rng);
    const b_sc = E.Scalar.random(rng);
    const x_curve = common.toCurveScalar(P, E, x);
    const data = Z.Data{
        .ek = ek,
        .c = c,
        .a = try E.Point.mulBase(a_sc),
        .b = try E.Point.mulBase(b_sc),
        .x = common.baseMul(E, a_sc.mul(b_sc).add(x_curve)),
    };
    const pdata = Z.Private{ .plaintext = x, .nonce = rho, .b = b_sc };

    var tr = Transcript.init("zig-mpc/test/enc-elg");
    tr.appendBytes("session", "s1");

    const proof = try Z.prove(tr, rng, aux, data, pdata);
    try Z.verify(tr, aux, data, proof);

    // wrong session
    var tr2 = Transcript.init("zig-mpc/test/enc-elg");
    tr2.appendBytes("session", "s2");
    try std.testing.expectError(error.InvalidProof, Z.verify(tr2, aux, data, proof));

    // plaintext way out of range: |x| ~ 2^(l+2ε) -> range check must fail
    {
        const huge = P.S.fromMag(P.pow2(P.l + 2 * P.epsilon));
        const rho2 = ek.randomNonce(rng);
        const c2 = try common.encryptSigned(P, ek, huge, rho2);
        const data2 = Z.Data{
            .ek = ek,
            .c = c2,
            .a = data.a,
            .b = data.b,
            .x = common.baseMul(E, a_sc.mul(b_sc).add(common.toCurveScalar(P, E, huge))),
        };
        const pdata2 = Z.Private{ .plaintext = huge, .nonce = rho2, .b = b_sc };
        const bad = try Z.prove(tr, rng, aux, data2, pdata2);
        try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data2, bad));
    }

    // tampered z2 -> rejected
    var tampered = proof;
    _ = P.Fn.addInPlace(&tampered.z2, P.Fn.fromU64(1));
    try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data, tampered));
}
