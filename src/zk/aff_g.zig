//! Πaff-g - Paillier affine operation in range: for D = C^x · Enc_j(y; ρ)
//! with X = xG and Y = Enc_i(y; ρ_y), proves |x| ≤ 2^(l_x) and |y| ≤ 2^(l_y)
//! (soundness slack ε). This is the proof protecting the MtA step of
//! CGGMP24 presigning.
//!
//! Ported from paillier-zk/src/paillier_affine_operation_in_range.rs.
//! `key_j` is the "other" party's key (C, D live under it), `key_i` the
//! prover's own key (Y lives under it).

const std = @import("std");
const common = @import("common.zig");
const Transcript = common.Transcript;

pub fn AffG(comptime P: type, comptime E: type) type {
    const Aux = common.Aux(P);
    const S = P.S;
    const Pl = common.Pail(P);
    return struct {
        pub const Data = struct {
            key_j: Pl.EncryptionKey,
            key_i: Pl.EncryptionKey,
            /// C - a ciphertext under key_j
            c: Pl.Ciphertext,
            /// D = C^x · Enc_j(y; ρ)
            d: Pl.Ciphertext,
            /// Y = Enc_i(y; ρ_y)
            y: Pl.Ciphertext,
            /// X = xG
            x: E.Point,
        };

        pub const Private = struct {
            /// |x| ≤ 2^l
            x: S,
            /// |y| ≤ 2^l_y
            y: S,
            /// ρ
            nonce: Pl.Nonce,
            /// ρ_y
            nonce_y: Pl.Nonce,
        };

        pub const Commitment = struct {
            a: Pl.Ciphertext,
            b_x: E.Point,
            b_y: Pl.Ciphertext,
            e: P.Fn.Bytes,
            s: P.Fn.Bytes,
            f: P.Fn.Bytes,
            t: P.Fn.Bytes,
        };

        pub const Proof = struct {
            commitment: Commitment,
            z1: S,
            z2: S,
            z3: S,
            z4: S,
            w: P.Fn.Bytes,
            w_y: P.Fn.Bytes,
        };

        fn challengeScalar(tr: Transcript, aux: Aux, data: Data, com: Commitment) S {
            var t = tr.fork("zig-mpc/zk/aff-g/v1");
            aux.appendToTranscript(&t);
            t.appendBytes("nj", &data.key_j.n);
            t.appendBytes("ni", &data.key_i.n);
            t.appendBytes("C", &data.c);
            t.appendBytes("D", &data.d);
            t.appendBytes("Y", &data.y);
            t.appendPoint(E, "X", data.x);
            t.appendBytes("com-a", &com.a);
            t.appendPoint(E, "com-bx", com.b_x);
            t.appendBytes("com-by", &com.b_y);
            t.appendBytes("com-e", &com.e);
            t.appendBytes("com-s", &com.s);
            t.appendBytes("com-f", &com.f);
            t.appendBytes("com-t", &com.t);
            var hrng = t.challengeRng();
            const rng = hrng.random();
            return S.sampleHalfPm(rng, common.curveOrderWide(P, E));
        }

        pub fn prove(tr: Transcript, rng: std.Random, aux: Aux, data: Data, pdata: Private) !Proof {
            const two_le = P.pow2(P.l + P.epsilon);
            const two_lye = P.pow2(P.l_y + P.epsilon);
            const nhat = P.lift(P.Fn, aux.n_hat);
            const nhat_le = P.mulBound(nhat, two_le);
            const nhat_l = P.mulBound(nhat, P.pow2(P.l));

            const alpha = S.sampleHalfPm(rng, two_le);
            const beta = S.sampleHalfPm(rng, two_lye);
            const r = data.key_j.randomNonce(rng);
            const r_y = data.key_i.randomNonce(rng);
            const gamma = S.sampleHalfPm(rng, nhat_le);
            const delta = S.sampleHalfPm(rng, nhat_le);
            const m = S.sampleHalfPm(rng, nhat_l);
            const mu = S.sampleHalfPm(rng, nhat_l);

            const com = Commitment{
                .a = blk: {
                    const beta_enc = try common.encryptSigned(P, data.key_j, beta, r);
                    const alpha_c = try common.homMulSigned(P, data.key_j, data.c, alpha);
                    break :blk data.key_j.homAdd(alpha_c, beta_enc);
                },
                .b_x = common.baseMul(E, common.toCurveScalar(P, E, alpha)),
                .b_y = try common.encryptSigned(P, data.key_i, beta, r_y),
                .e = try aux.combine(alpha, gamma),
                .s = try aux.combine(pdata.x, m),
                .f = try aux.combine(beta, delta),
                .t = try aux.combine(pdata.y, mu),
            };
            const e = challengeScalar(tr, aux, data, com);

            return .{
                .commitment = com,
                .z1 = alpha.add(e.mul(pdata.x)),
                .z2 = beta.add(e.mul(pdata.y)),
                .z3 = gamma.add(e.mul(m)),
                .z4 = delta.add(e.mul(mu)),
                .w = try common.nonceCombine(P, data.key_j, r, pdata.nonce, e),
                .w_y = try common.nonceCombine(P, data.key_i, r_y, pdata.nonce_y, e),
            };
        }

        pub fn verify(tr: Transcript, aux: Aux, data: Data, proof: Proof) !void {
            const com = proof.commitment;
            if (!data.key_j.isValidCiphertext(data.c)) return error.InvalidProof;
            if (!data.key_j.isValidCiphertext(data.d)) return error.InvalidProof;
            if (!data.key_i.isValidCiphertext(data.y)) return error.InvalidProof;
            if (!data.key_j.isValidCiphertext(com.a)) return error.InvalidProof;
            if (!data.key_i.isValidCiphertext(com.b_y)) return error.InvalidProof;
            if (!aux.isInMultGroup(com.e) or !aux.isInMultGroup(com.s) or
                !aux.isInMultGroup(com.f) or !aux.isInMultGroup(com.t)) return error.InvalidProof;

            const e = challengeScalar(tr, aux, data, com);
            const e_scalar = common.toCurveScalar(P, E, e);

            // (10) C^z1 ⊕ Enc_j(z2; w) == A ⊕ D^e
            {
                const z1_c = try common.homMulSigned(P, data.key_j, data.c, proof.z1);
                const enc = try common.encryptSigned(P, data.key_j, proof.z2, proof.w);
                const lhs = data.key_j.homAdd(z1_c, enc);
                const e_d = try common.homMulSigned(P, data.key_j, data.d, e);
                const rhs = data.key_j.homAdd(com.a, e_d);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (11) G·z1 == Bx + X·e
            {
                const lhs = common.baseMul(E, common.toCurveScalar(P, E, proof.z1));
                const rhs = com.b_x.add(common.pointMulPub(E, data.x, e_scalar));
                if (!lhs.eql(rhs)) return error.InvalidProof;
            }
            // (12) Enc_i(z2; w_y) == By ⊕ Y^e
            {
                const lhs = try common.encryptSigned(P, data.key_i, proof.z2, proof.w_y);
                const e_y = try common.homMulSigned(P, data.key_i, data.y, e);
                const rhs = data.key_i.homAdd(com.b_y, e_y);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (13) combine(z1, z3) == E · S^e
            {
                const lhs = try aux.combine(proof.z1, proof.z3);
                const s_e = try aux.powModSigned(com.s, e);
                const rhs = aux.mulMod(com.e, s_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (14) combine(z2, z4) == F · T^e
            {
                const lhs = try aux.combine(proof.z2, proof.z4);
                const t_e = try aux.powModSigned(com.t, e);
                const rhs = aux.mulMod(com.f, t_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // (15) |z1| ≤ 2^(l+ε)/2, (16) |z2| ≤ 2^(l_y+ε)/2
            if (!proof.z1.inHalfPm(P.pow2(P.l + P.epsilon))) return error.InvalidProof;
            if (!proof.z2.inHalfPm(P.pow2(P.l_y + P.epsilon))) return error.InvalidProof;
        }
    };
}

test "aff-g passing and failing" {
    const curve = @import("../curve.zig");
    const P = common.TestParamsCurve;
    const E = curve.Secp256k1;
    const Z = AffG(P, E);
    const Pl = common.Pail(P);
    var prng = std.Random.DefaultPrng.init(4242);
    const rng = prng.random();

    var gen = try common.Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = gen.aux;

    var dk_j = try Pl.DecryptionKey.generate(rng);
    defer dk_j.zeroize();
    var dk_i = try Pl.DecryptionKey.generate(rng);
    defer dk_i.zeroize();
    const key_j = dk_j.ek;
    const key_i = dk_i.ek;

    // witness: |x| ≤ 2^l/2, |y| ≤ 2^l_y/2
    const x = P.S.sampleHalfPm(rng, P.pow2(P.l));
    const y = P.S.sampleHalfPm(rng, P.pow2(P.l_y));
    const rho = key_j.randomNonce(rng);
    const rho_y = key_i.randomNonce(rng);

    // C: any ciphertext under key_j
    const c = (try key_j.encrypt(P.Fn.fromU64(123456), rng)).c;
    // D = C^x · Enc_j(y; ρ)
    const d = blk: {
        const cx = try common.homMulSigned(P, key_j, c, x);
        const ey = try common.encryptSigned(P, key_j, y, rho);
        break :blk key_j.homAdd(cx, ey);
    };
    const y_ct = try common.encryptSigned(P, key_i, y, rho_y);

    const data = Z.Data{
        .key_j = key_j,
        .key_i = key_i,
        .c = c,
        .d = d,
        .y = y_ct,
        .x = common.baseMul(E, common.toCurveScalar(P, E, x)),
    };
    const pdata = Z.Private{ .x = x, .y = y, .nonce = rho, .nonce_y = rho_y };

    var tr = Transcript.init("zig-mpc/test/aff-g");
    tr.appendBytes("session", "s1");

    const proof = try Z.prove(tr, rng, aux, data, pdata);
    try Z.verify(tr, aux, data, proof);

    // wrong session
    var tr2 = Transcript.init("zig-mpc/test/aff-g");
    tr2.appendBytes("session", "s2");
    try std.testing.expectError(error.InvalidProof, Z.verify(tr2, aux, data, proof));

    // x far out of range -> range check fails
    {
        const huge = P.S.fromMag(P.pow2(P.l + 2 * P.epsilon));
        const d2 = blk: {
            const cx = try common.homMulSigned(P, key_j, c, huge);
            const ey = try common.encryptSigned(P, key_j, y, rho);
            break :blk key_j.homAdd(cx, ey);
        };
        const data2 = Z.Data{
            .key_j = key_j,
            .key_i = key_i,
            .c = c,
            .d = d2,
            .y = y_ct,
            .x = common.baseMul(E, common.toCurveScalar(P, E, huge)),
        };
        const pdata2 = Z.Private{ .x = huge, .y = y, .nonce = rho, .nonce_y = rho_y };
        const bad = try Z.prove(tr, rng, aux, data2, pdata2);
        try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data2, bad));
    }

    // tampered w -> rejected
    var tampered = proof;
    _ = P.Fn.addInPlace(&tampered.w, P.Fn.fromU64(1));
    try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data, tampered));
}
