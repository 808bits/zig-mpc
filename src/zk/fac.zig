//! Πfac - proof that the Paillier modulus N has no small factors:
//! both p and q are larger than ≈√N / 2^(l+ε). This is the check whose
//! absence enabled CVE-2023-33241 against GG18/GG20 implementations.
//!
//! Ported from paillier-zk/src/no_small_factor.rs. The verifier's
//! ring-Pedersen parameters (`aux`) commit the prover's secrets.

const std = @import("std");
const common = @import("common.zig");
const Transcript = common.Transcript;

pub fn Fac(comptime P: type) type {
    const Aux = common.Aux(P);
    const S = P.S;

    // `verify` rejects any modulus shorter than 4ℓ bits. `generatePrime`
    // forces the top bit, so N = p·q is either 2·prime_bits or one bit short
    // of it - and the short case has to clear the bar too, otherwise roughly
    // half of all generated keys would produce proofs that are correctly
    // formed and always rejected. Catch that at compile time rather than at
    // the end of a three-round protocol.
    comptime {
        if (P.n_bits - 1 < 4 * P.l) @compileError(std.fmt.comptimePrint(
            "zig-mpc: Πfac needs a Paillier modulus of at least 4·l = {d} bits, " ++
                "and p·q can come out as few as {d} bits with prime_bits = {d}. " ++
                "Raise prime_bits to at least {d}, or lower l.",
            .{ 4 * P.l, P.n_bits - 1, P.prime_bits, 2 * P.l + 1 },
        ));
    }

    return struct {
        pub const Data = struct {
            /// The prover's Paillier modulus.
            n: P.Fn.Bytes,
            /// floor(sqrt(N)) - computable by anyone from n.
            n_root: P.Fn.Bytes,

            pub fn fromModulus(n: P.Fn.Bytes) Data {
                return .{ .n = n, .n_root = P.Fn.sqrtFloor(n) };
            }
        };

        pub const Commitment = struct {
            p: P.Fn.Bytes,
            q: P.Fn.Bytes,
            a: P.Fn.Bytes,
            b: P.Fn.Bytes,
            t: P.Fn.Bytes,
        };

        pub const Proof = struct {
            commitment: Commitment,
            z1: S,
            z2: S,
            w1: S,
            w2: S,
            v: S,
        };

        fn bounds(aux: Aux, data: Data) struct {
            root_le: P.FInt.Bytes,
            aux_l: P.FInt.Bytes,
            aux_le: P.FInt.Bytes,
            r_bound: P.FInt.Bytes,
        } {
            const two_l = P.pow2(P.l);
            const two_le = P.pow2(P.l + P.epsilon);
            const root = P.lift(P.Fn, data.n_root);
            const n_hat = P.lift(P.Fn, aux.n_hat);
            const n = P.lift(P.Fn, data.n);
            return .{
                .root_le = P.mulBound(two_le, root),
                .aux_l = P.mulBound(two_l, n_hat),
                .aux_le = P.mulBound(two_le, n_hat),
                .r_bound = P.mulBound(two_le, P.mulBound(n_hat, n)),
            };
        }

        fn challengeScalar(tr: Transcript, aux: Aux, data: Data, com: Commitment) S {
            var t = tr.fork("zig-mpc/zk/fac/v1");
            aux.appendToTranscript(&t);
            t.appendBytes("n", &data.n);
            t.appendBytes("n-root", &data.n_root);
            t.appendBytes("com-p", &com.p);
            t.appendBytes("com-q", &com.q);
            t.appendBytes("com-a", &com.a);
            t.appendBytes("com-b", &com.b);
            t.appendBytes("com-t", &com.t);
            var hrng = t.challengeRng();
            const rng = hrng.random();
            return S.sampleHalfPm(rng, P.pow2(P.l));
        }

        pub fn prove(tr: Transcript, rng: std.Random, aux: Aux, data: Data, p: P.Fp.Bytes, q: P.Fp.Bytes) !Proof {
            const bd = bounds(aux, data);

            const alpha = S.sampleHalfPm(rng, bd.root_le);
            const beta = S.sampleHalfPm(rng, bd.root_le);
            const mu = S.sampleHalfPm(rng, bd.aux_l);
            const nu = S.sampleHalfPm(rng, bd.aux_l);
            const r = S.sampleHalfPm(rng, bd.r_bound);
            const x = S.sampleHalfPm(rng, bd.aux_le);
            const y = S.sampleHalfPm(rng, bd.aux_le);

            const p_s = S.fromMag(P.lift(P.Fp, p));
            const q_s = S.fromMag(P.lift(P.Fp, q));

            const com = Commitment{
                .p = try aux.combine(p_s, mu),
                .q = try aux.combine(q_s, nu),
                .a = try aux.combine(alpha, x),
                .b = try aux.combine(beta, y),
                .t = blk: {
                    const q_com = try aux.combine(q_s, nu);
                    const q_alpha = try aux.powModSigned(q_com, alpha);
                    const t_r = try aux.powModSigned(aux.t, r);
                    break :blk aux.mulMod(q_alpha, t_r);
                },
            };

            const e = challengeScalar(tr, aux, data, com);

            return .{
                .commitment = com,
                .z1 = alpha.add(e.mul(p_s)),
                .z2 = beta.add(e.mul(q_s)),
                .w1 = x.add(e.mul(mu)),
                .w2 = y.add(e.mul(nu)),
                .v = r.sub(e.mul(nu.mul(p_s))),
            };
        }

        pub fn verify(tr: Transcript, aux: Aux, data: Data, proof: Proof) !void {
            const com = proof.commitment;
            if (!aux.isInMultGroup(com.p) or !aux.isInMultGroup(com.q) or
                !aux.isInMultGroup(com.a) or !aux.isInMultGroup(com.b) or
                !aux.isInMultGroup(com.t)) return error.InvalidProof;

            // N must be large enough for the ranges to be meaningful
            if (P.Fn.bitLength(data.n) < 4 * P.l) return error.InvalidProof;
            // n_root must actually be the integer square root of n
            if (!std.mem.eql(u8, &data.n_root, &P.Fn.sqrtFloor(data.n))) return error.InvalidProof;

            const e = challengeScalar(tr, aux, data, com);

            // combine(z1, w1) == A · P^e
            {
                const lhs = try aux.combine(proof.z1, proof.w1);
                const p_e = try aux.powModSigned(com.p, e);
                const rhs = aux.mulMod(com.a, p_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // combine(z2, w2) == B · Q^e
            {
                const lhs = try aux.combine(proof.z2, proof.w2);
                const q_e = try aux.powModSigned(com.q, e);
                const rhs = aux.mulMod(com.b, q_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }
            // Q^z1 · t^v == T · (s^N)^e
            {
                const r_val = try aux.powModSigned(aux.s, S.fromMag(P.lift(P.Fn, data.n)));
                const q_z1 = try aux.powModSigned(com.q, proof.z1);
                const t_v = try aux.powModSigned(aux.t, proof.v);
                const lhs = aux.mulMod(q_z1, t_v);
                const r_e = try aux.powModSigned(r_val, e);
                const rhs = aux.mulMod(com.t, r_e);
                if (!std.mem.eql(u8, &lhs, &rhs)) return error.InvalidProof;
            }

            // range checks: |z1|, |z2| within ±2^(l+ε)·√N / 2
            const bd = bounds(aux, data);
            if (!proof.z1.inHalfPm(bd.root_le)) return error.InvalidProof;
            if (!proof.z2.inHalfPm(bd.root_le)) return error.InvalidProof;
        }
    };
}

test "fac proof passing and failing" {
    const P = common.TestParams;
    const Z = Fac(P);
    var prng = std.Random.DefaultPrng.init(555);
    const rng = prng.random();

    // verifier's pedersen params
    var gen = try common.Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = gen.aux;

    // prover's paillier modulus
    const p = try P.Fp.generatePrime(rng, P.prime_bits, true);
    const q = try P.Fp.generatePrime(rng, P.prime_bits, true);
    const n: P.Fn.Bytes = P.Fp.mulWide(p, q);
    const data = Z.Data.fromModulus(n);

    var tr = Transcript.init("zig-mpc/test/fac");
    tr.appendBytes("session", "s1");

    const proof = try Z.prove(tr, rng, aux, data, p, q);
    try Z.verify(tr, aux, data, proof);

    // different transcript -> rejected
    var tr2 = Transcript.init("zig-mpc/test/fac");
    tr2.appendBytes("session", "s2");
    try std.testing.expectError(error.InvalidProof, Z.verify(tr2, aux, data, proof));

    // tampered response -> rejected
    var tampered = proof;
    tampered.z1 = tampered.z1.add(P.S.fromU64(1));
    try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data, tampered));
}

test "fac rejects modulus with a genuinely small factor" {
    // Soundness bound: factors must exceed sqrt(N) / 2^(l+eps).
    // Pick parameters where 65537 actually violates it:
    // primes up to 240 bits, N = 65537 * q(240bit) ~ 2^256,
    // sqrt(N) ~ 2^128, threshold 2^(128-96) = 2^32 > 65537.
    const P = common.Params(240, 32, 96, 64);
    const Z = Fac(P);
    var prng = std.Random.DefaultPrng.init(556);
    const rng = prng.random();

    var gen = try common.Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = gen.aux;

    const p_small = P.Fp.fromU64(65537);
    const q_big = try P.Fp.generatePrime(rng, 240, true);
    const n_bad: P.Fn.Bytes = P.Fp.mulWide(p_small, q_big);
    const data_bad = Z.Data.fromModulus(n_bad);
    try std.testing.expect(P.Fn.bitLength(n_bad) >= 4 * P.l);

    var tr = Transcript.init("zig-mpc/test/fac-small");
    tr.appendBytes("session", "s1");
    const bad_proof = try Z.prove(tr, rng, aux, data_bad, p_small, q_big);
    try std.testing.expectError(error.InvalidProof, Z.verify(tr, aux, data_bad, bad_proof));
}
