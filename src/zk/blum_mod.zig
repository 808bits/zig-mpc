//! Πmod - proof that N is a Paillier-Blum modulus: N = pq with
//! p ≡ q ≡ 3 (mod 4) and gcd(N, φ(N)) = 1. M parallel repetitions.
//!
//! Ported from paillier-zk/src/paillier_blum_modulus.rs and common/sqrt.rs.

const std = @import("std");
const common = @import("common.zig");
const Transcript = common.Transcript;

pub fn BlumMod(comptime P: type, comptime M: usize) type {
    const Fp = P.Fp;
    const Fn = P.Fn;
    return struct {
        pub const ProofPoint = struct {
            x: Fn.Bytes,
            a: bool,
            b: bool,
            z: Fn.Bytes,
        };

        pub const Proof = struct {
            w: Fn.Bytes,
            points: [M]ProofPoint,
        };

        fn modPrime(y: Fn.Bytes, p: Fp.Bytes) Fp.Bytes {
            const red = Fn.divRem(y, Fp.widen(Fn, p)) catch unreachable;
            return Fn.narrow(Fp, red.r) catch unreachable;
        }

        /// Challenge: M uniform units mod N derived from the transcript.
        fn challengeYs(tr: Transcript, n: Fn.Bytes, w: Fn.Bytes) [M]Fn.Bytes {
            var t = tr.fork("zig-mpc/zk/blum-mod/v1");
            t.appendBytes("n", &n);
            t.appendBytes("w", &w);
            var hrng = t.challengeRng();
            const rng = hrng.random();
            var ys: [M]Fn.Bytes = undefined;
            for (&ys) |*y| {
                while (true) {
                    const c = Fn.sampleBelow(rng, n);
                    if (!Fn.isZero(c) and Fn.isCoprime(c, n)) {
                        y.* = c;
                        break;
                    }
                }
            }
            return ys;
        }

        pub fn prove(tr: Transcript, rng: std.Random, n: Fn.Bytes, p: Fp.Bytes, q: Fp.Bytes) !Proof {
            const mod_n = Fn.Modulus.fromBytes(&n, .big) catch return error.InvalidModulus;

            // w: unit with jacobi(w, N) == -1
            var w: Fn.Bytes = undefined;
            while (true) {
                const c = Fn.sampleBelow(rng, n);
                if (Fn.isZero(c) or !Fn.isCoprime(c, n)) continue;
                if (Fn.jacobi(c, n) == -1) {
                    w = c;
                    break;
                }
            }

            const ys = challengeYs(tr, n, w);

            const phi: Fn.Bytes = Fp.mulWide(Fp.sub(p, Fp.fromU64(1)), Fp.sub(q, Fp.fromU64(1)));
            // N^{-1} mod φ (φ is even -> general inverse)
            const n_red = blk: {
                const red = Fn.divRem(n, phi) catch unreachable;
                break :blk red.r;
            };
            const n_inv = Fn.invertGeneral(n_red, phi) catch return error.NotBlum;
            // 4th-root exponent: e = (φ + 4) / 8
            var e_sqrt = phi;
            _ = Fn.addInPlace(&e_sqrt, Fn.fromU64(4));
            for (0..3) |_| {
                var carry: u8 = 0;
                for (&e_sqrt) |*byte| {
                    const next: u8 = byte.* & 1;
                    byte.* = (carry << 7) | (byte.* >> 1);
                    carry = next;
                }
            }

            var points: [M]ProofPoint = undefined;
            for (&points, ys) |*point, y| {
                // z = y^(N^-1 mod φ) mod N
                const y_fe = Fn.Fe.fromBytes(mod_n, &y, .big) catch unreachable;
                var z: Fn.Bytes = undefined;
                (mod_n.powWithEncodedExponent(y_fe, &n_inv, .big) catch unreachable).toBytes(&z, .big) catch unreachable;

                // find (a, b) such that y' = (-1)^a w^b y is a QR mod N
                var a = false;
                var b = false;
                var y_prime: Fn.Bytes = undefined;
                const jp = Fn.jacobi(Fp.widen(Fn, modPrime(y, p)), Fp.widen(Fn, p));
                const jq = Fn.jacobi(Fp.widen(Fn, modPrime(y, q)), Fp.widen(Fn, q));
                if (jp == 1 and jq == 1) {
                    y_prime = y;
                } else if (jp == -1 and jq == -1) {
                    a = true;
                    y_prime = Fn.sub(n, y);
                } else {
                    const yw = blk: {
                        const w_fe = Fn.Fe.fromBytes(mod_n, &w, .big) catch unreachable;
                        var out: Fn.Bytes = undefined;
                        mod_n.mul(y_fe, w_fe).toBytes(&out, .big) catch unreachable;
                        break :blk out;
                    };
                    const jp2 = Fn.jacobi(Fp.widen(Fn, modPrime(yw, p)), Fp.widen(Fn, p));
                    const jq2 = Fn.jacobi(Fp.widen(Fn, modPrime(yw, q)), Fp.widen(Fn, q));
                    if (jp2 == 1 and jq2 == 1) {
                        b = true;
                        y_prime = yw;
                    } else if (jp2 == -1 and jq2 == -1) {
                        a = true;
                        b = true;
                        y_prime = Fn.sub(n, yw);
                    } else {
                        return error.NotBlum; // w had jacobi +1, or N not Blum
                    }
                }

                // x = (y'^e)^e - the principal 4th root
                const yp_fe = Fn.Fe.fromBytes(mod_n, &y_prime, .big) catch unreachable;
                const sqrt1 = mod_n.powWithEncodedExponent(yp_fe, &e_sqrt, .big) catch unreachable;
                const sqrt2 = mod_n.powWithEncodedExponent(sqrt1, &e_sqrt, .big) catch unreachable;
                var x: Fn.Bytes = undefined;
                sqrt2.toBytes(&x, .big) catch unreachable;

                point.* = .{ .x = x, .a = a, .b = b, .z = z };
            }
            return .{ .w = w, .points = points };
        }

        pub fn verify(tr: Transcript, rng: std.Random, n: Fn.Bytes, proof: Proof) !void {
            // N must be odd and composite
            if (Fn.isEven(n)) return error.InvalidProof;
            if (try Fn.isProbablePrime(n, rng)) return error.InvalidProof;
            const mod_n = Fn.Modulus.fromBytes(&n, .big) catch return error.InvalidProof;

            const inGroup = struct {
                fn f(nn: Fn.Bytes, x: Fn.Bytes) bool {
                    return !Fn.isZero(x) and Fn.cmp(x, nn) == .lt and Fn.isCoprime(x, nn);
                }
            }.f;
            if (!inGroup(n, proof.w)) return error.InvalidProof;

            const ys = challengeYs(tr, n, proof.w);

            for (proof.points, ys) |point, y| {
                if (!inGroup(n, point.x) or !inGroup(n, point.z)) return error.InvalidProof;

                // z^N == y mod N
                const z_fe = Fn.Fe.fromBytes(mod_n, &point.z, .big) catch unreachable;
                var zn: Fn.Bytes = undefined;
                (mod_n.powWithEncodedExponent(z_fe, &n, .big) catch unreachable).toBytes(&zn, .big) catch unreachable;
                if (!std.mem.eql(u8, &zn, &y)) return error.InvalidProof;

                // y' = (-1)^a w^b y
                var y_prime = y;
                if (point.a) y_prime = Fn.sub(n, y_prime);
                if (point.b) {
                    const yp_fe = Fn.Fe.fromBytes(mod_n, &y_prime, .big) catch unreachable;
                    const w_fe = Fn.Fe.fromBytes(mod_n, &proof.w, .big) catch unreachable;
                    mod_n.mul(yp_fe, w_fe).toBytes(&y_prime, .big) catch unreachable;
                }

                // x^4 == y' mod N
                const x_fe = Fn.Fe.fromBytes(mod_n, &point.x, .big) catch unreachable;
                const x2 = mod_n.sq(x_fe);
                var x4: Fn.Bytes = undefined;
                mod_n.sq(x2).toBytes(&x4, .big) catch unreachable;
                if (!std.mem.eql(u8, &x4, &y_prime)) return error.InvalidProof;
            }
        }
    };
}

test "blum modulus proof passing and failing" {
    const P = common.TestParams;
    const Z = BlumMod(P, 16);
    var prng = std.Random.DefaultPrng.init(2001);
    const rng = prng.random();

    const p = try P.Fp.generatePrime(rng, P.prime_bits, true);
    const q = try P.Fp.generatePrime(rng, P.prime_bits, true);
    const n: P.Fn.Bytes = P.Fp.mulWide(p, q);

    var tr = Transcript.init("zig-mpc/test/blum");
    tr.appendBytes("session", "s1");

    const proof = try Z.prove(tr, rng, n, p, q);
    try Z.verify(tr, rng, n, proof);

    // different transcript -> rejected
    var tr2 = Transcript.init("zig-mpc/test/blum");
    tr2.appendBytes("session", "s2");
    try std.testing.expectError(error.InvalidProof, Z.verify(tr2, rng, n, proof));

    // non-Blum modulus (q' == 1 mod 4): prover cannot construct a passing proof
    var q_bad = try P.Fp.generatePrime(rng, P.prime_bits, false);
    while (P.Fp.modU32(q_bad, 4) != 1) q_bad = try P.Fp.generatePrime(rng, P.prime_bits, false);
    const n_bad: P.Fn.Bytes = P.Fp.mulWide(p, q_bad);
    if (Z.prove(tr, rng, n_bad, p, q_bad)) |bad_proof| {
        try std.testing.expectError(error.InvalidProof, Z.verify(tr, rng, n_bad, bad_proof));
    } else |_| {
        // prover already failed to find residues - also acceptable
    }

    // tampered point -> rejected
    var tampered = proof;
    tampered.points[0].a = !tampered.points[0].a;
    try std.testing.expectError(error.InvalidProof, Z.verify(tr, rng, n, tampered));
}
