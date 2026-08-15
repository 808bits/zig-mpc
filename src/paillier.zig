//! Paillier cryptosystem over Blum moduli, as required by CGGMP24.
//!
//! Conventions match the reference stack (dfns fast-paillier):
//!   g = N + 1, so Enc(m, r) = (1 + mN) · r^N (mod N²)
//!   Dec(c) = L(c^φ mod N²) · φ⁻¹ (mod N),  L(x) = (x − 1)/N
//!
//! Timing: encryption is constant-time in m and r (public exponent N);
//! decryption uses ff's secret-exponent pow for c^φ and a fixed-iteration
//! division for L. Nonce sampling's gcd check is variable-time (negligible
//! leak: it virtually never iterates on a non-unit). Keygen is variable-time
//! like all prime generation.

const std = @import("std");
const ffx = @import("ffx.zig");

pub fn Paillier(comptime prime_bits: comptime_int) type {
    return struct {
        /// Byte domains: primes, mod-N values, mod-N² values.
        pub const Fp = ffx.Ffx(prime_bits);
        pub const Fn = ffx.Ffx(2 * prime_bits);
        pub const Fn2 = ffx.Ffx(4 * prime_bits);

        pub const Plaintext = Fn.Bytes;
        pub const Nonce = Fn.Bytes;
        pub const Ciphertext = Fn2.Bytes;

        pub const EncryptionKey = struct {
            n: Fn.Bytes,
            n_wide: Fn2.Bytes,
            mod_n: Fn.Modulus,
            mod_n2: Fn2.Modulus,

            pub fn fromN(n: Fn.Bytes) !EncryptionKey {
                const n2: Fn2.Bytes = Fn.mulWide(n, n);
                return .{
                    .n = n,
                    .n_wide = Fn.widen(Fn2, n),
                    .mod_n = try Fn.Modulus.fromBytes(&n, .big),
                    .mod_n2 = try Fn2.Modulus.fromBytes(&n2, .big),
                };
            }

            /// Uniform unit mod N.
            pub fn randomNonce(self: EncryptionKey, rng: std.Random) Nonce {
                while (true) {
                    const r = Fn.sampleBelow(rng, self.n);
                    if (Fn.isZero(r)) continue;
                    if (Fn.isCoprime(r, self.n)) return r;
                }
            }

            /// Enc(m, r) = (1 + mN) · r^N mod N². m must be < N, r a unit.
            pub fn encryptWithNonce(self: EncryptionKey, m: Plaintext, r: Nonce) !Ciphertext {
                if (Fn.cmp(m, self.n) != .lt) return error.PlaintextTooLarge;
                if (Fn.cmp(r, self.n) != .lt or Fn.isZero(r)) return error.InvalidNonce;

                // 1 + m*N < N², fits the wide domain exactly.
                var one_plus_mn: Fn2.Bytes = Fn.mulWide(m, self.n);
                _ = Fn2.addInPlace(&one_plus_mn, Fn2.fromU64(1));
                const a = Fn2.Fe.fromBytes(self.mod_n2, &one_plus_mn, .big) catch unreachable;

                // r^N mod N², N public: constant-time in r.
                const r_wide = Fn.widen(Fn2, r);
                const r_fe = Fn2.Fe.fromBytes(self.mod_n2, &r_wide, .big) catch unreachable;
                const r_n = try self.mod_n2.powWithEncodedPublicExponent(r_fe, &self.n, .big);

                var out: Ciphertext = undefined;
                try self.mod_n2.mul(a, r_n).toBytes(&out, .big);
                return out;
            }

            pub const Encrypted = struct { c: Ciphertext, r: Nonce };

            pub fn encrypt(self: EncryptionKey, m: Plaintext, rng: std.Random) !Encrypted {
                const r = self.randomNonce(rng);
                return .{ .c = try self.encryptWithNonce(m, r), .r = r };
            }

            /// Ciphertext validity: in [1, N²) and a unit mod N².
            pub fn isValidCiphertext(self: EncryptionKey, c: Ciphertext) bool {
                if (Fn2.isZero(c)) return false;
                var n2: Fn2.Bytes = undefined;
                self.mod_n2.toBytes(&n2, .big) catch return false;
                if (Fn2.cmp(c, n2) != .lt) return false;
                return Fn2.isCoprime(c, n2);
            }

            /// Homomorphic plaintext addition: Enc(a) ⊕ Enc(b) = Enc(a + b).
            pub fn homAdd(self: EncryptionKey, c1: Ciphertext, c2: Ciphertext) Ciphertext {
                const a = Fn2.Fe.fromBytes(self.mod_n2, &c1, .big) catch unreachable;
                const b = Fn2.Fe.fromBytes(self.mod_n2, &c2, .big) catch unreachable;
                var out: Ciphertext = undefined;
                self.mod_n2.mul(a, b).toBytes(&out, .big) catch unreachable;
                return out;
            }

            /// Homomorphic scalar multiplication: Enc(m)^k = Enc(k·m).
            /// Constant-time in both c and k (k may be secret). `k` is a
            /// big-endian byte string of any length (must be nonzero).
            pub fn homMulScalar(self: EncryptionKey, c: Ciphertext, k: []const u8) !Ciphertext {
                const c_fe = Fn2.Fe.fromBytes(self.mod_n2, &c, .big) catch unreachable;
                const out_fe = try self.mod_n2.powWithEncodedExponent(c_fe, k, .big);
                var out: Ciphertext = undefined;
                try out_fe.toBytes(&out, .big);
                return out;
            }

            /// Homomorphic plaintext addition of a known value:
            /// Enc(m) · (1 + kN) = Enc(m + k).
            pub fn homAddPlaintext(self: EncryptionKey, c: Ciphertext, k: Plaintext) !Ciphertext {
                if (Fn.cmp(k, self.n) != .lt) return error.PlaintextTooLarge;
                var one_plus_kn: Fn2.Bytes = Fn.mulWide(k, self.n);
                _ = Fn2.addInPlace(&one_plus_kn, Fn2.fromU64(1));
                const a = Fn2.Fe.fromBytes(self.mod_n2, &one_plus_kn, .big) catch unreachable;
                const c_fe = Fn2.Fe.fromBytes(self.mod_n2, &c, .big) catch unreachable;
                var out: Ciphertext = undefined;
                self.mod_n2.mul(c_fe, a).toBytes(&out, .big) catch unreachable;
                return out;
            }
        };

        pub const DecryptionKey = struct {
            ek: EncryptionKey,
            p: Fp.Bytes,
            q: Fp.Bytes,
            phi: Fn.Bytes,
            /// φ⁻¹ mod N.
            mu: Fn.Bytes,

            /// Generate a fresh key from two `prime_bits` Blum primes.
            pub fn generate(rng: std.Random) !DecryptionKey {
                while (true) {
                    const p = try Fp.generatePrime(rng, prime_bits, true);
                    const q = try Fp.generatePrime(rng, prime_bits, true);
                    if (Fp.cmp(p, q) == .eq) continue;
                    return fromPrimes(p, q);
                }
            }

            pub fn fromPrimes(p: Fp.Bytes, q: Fp.Bytes) !DecryptionKey {
                const n: Fn.Bytes = Fp.mulWide(p, q);
                const ek = try EncryptionKey.fromN(n);

                const p1 = Fp.sub(p, Fp.fromU64(1));
                const q1 = Fp.sub(q, Fp.fromU64(1));
                const phi: Fn.Bytes = Fp.mulWide(p1, q1);

                // µ = φ⁻¹ mod N, constant-time via x^(φ-1)
                const phi_fe = Fn.Fe.fromBytes(ek.mod_n, &phi, .big) catch unreachable;
                const mu_fe = try Fn.invertViaTotient(ek.mod_n, phi_fe, phi);
                var mu: Fn.Bytes = undefined;
                try mu_fe.toBytes(&mu, .big);

                return .{ .ek = ek, .p = p, .q = q, .phi = phi, .mu = mu };
            }

            pub fn zeroize(self: *DecryptionKey) void {
                std.crypto.secureZero(u8, &self.p);
                std.crypto.secureZero(u8, &self.q);
                std.crypto.secureZero(u8, &self.phi);
                std.crypto.secureZero(u8, &self.mu);
            }

            /// Dec(c) = L(c^φ mod N²) · µ mod N.
            pub fn decrypt(self: DecryptionKey, c: Ciphertext) !Plaintext {
                const c_fe = Fn2.Fe.fromBytes(self.ek.mod_n2, &c, .big) catch return error.InvalidCiphertext;

                // c^φ mod N², constant-time in φ
                const x_fe = try self.ek.mod_n2.powWithEncodedExponent(c_fe, &self.phi, .big);
                var x: Fn2.Bytes = undefined;
                try x_fe.toBytes(&x, .big);

                // L(x) = (x - 1) / N - exact division, fixed-iteration
                if (Fn2.isZero(x)) return error.InvalidCiphertext;
                Fn2.subInPlace(&x, Fn2.fromU64(1));
                const dv = try Fn2.divRem(x, self.ek.n_wide);
                if (!Fn2.isZero(dv.r)) return error.InvalidCiphertext;
                const l = try Fn2.narrow(Fn, dv.q);

                // m = L · µ mod N
                const l_fe = Fn.Fe.fromBytes(self.ek.mod_n, &l, .big) catch return error.InvalidCiphertext;
                const mu_fe = Fn.Fe.fromBytes(self.ek.mod_n, &self.mu, .big) catch unreachable;
                var out: Plaintext = undefined;
                self.ek.mod_n.mul(l_fe, mu_fe).toBytes(&out, .big) catch unreachable;
                return out;
            }
        };
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const vectors = @import("testdata/paillier_vectors.zig");

test "paillier vectors from python (byte-exact ciphertexts, 128-bit primes)" {
    const P = Paillier(128);
    for (vectors.enc128) |v| {
        const p = P.Fp.fromHex(v.p);
        const q = P.Fp.fromHex(v.q);
        var dk = try P.DecryptionKey.fromPrimes(p, q);
        defer dk.zeroize();

        const m = P.Fn.fromHex(v.m);
        const r = P.Fn.fromHex(v.r);
        const expected_c = P.Fn2.fromHex(v.c);

        const c = try dk.ek.encryptWithNonce(m, r);
        try std.testing.expectEqualSlices(u8, &expected_c, &c);

        const dec = try dk.decrypt(c);
        try std.testing.expectEqualSlices(u8, &m, &dec);
    }
}

test "roundtrip, homomorphic add and scalar mul" {
    const P = Paillier(128);
    var prng = std.Random.DefaultPrng.init(2718);
    const rng = prng.random();

    var dk = try P.DecryptionKey.generate(rng);
    defer dk.zeroize();
    const ek = dk.ek;

    for (0..4) |_| {
        const a = P.Fn.sampleBelow(rng, ek.n);
        const b = P.Fn.sampleBelow(rng, ek.n);

        const ca = (try ek.encrypt(a, rng)).c;
        const cb = (try ek.encrypt(b, rng)).c;
        try std.testing.expect(ek.isValidCiphertext(ca));

        // Dec(ca ⊕ cb) == a + b mod N
        const sum_c = ek.homAdd(ca, cb);
        const sum = try dk.decrypt(sum_c);
        var expected = a;
        const carry = P.Fn.addInPlace(&expected, b);
        // reduce mod N
        var wide: P.Fn2.Bytes = P.Fn.widen(P.Fn2, expected);
        if (carry == 1) P.Fn2.setBit(&wide, 2 * 128);
        const red = try P.Fn2.divRem(wide, P.Fn.widen(P.Fn2, ek.n));
        const expected_mod = try P.Fn2.narrow(P.Fn, red.r);
        try std.testing.expectEqualSlices(u8, &expected_mod, &sum);

        // Dec(ca^k) == k·a mod N
        const k = P.Fn.fromU64(12345);
        const kc = try ek.homMulScalar(ca, &k);
        const ka = try dk.decrypt(kc);
        const prod_wide = P.Fn.mulWide(a, k);
        const prod_red = try P.Fn2.divRem(prod_wide, P.Fn.widen(P.Fn2, ek.n));
        const expected_ka = try P.Fn2.narrow(P.Fn, prod_red.r);
        try std.testing.expectEqualSlices(u8, &expected_ka, &ka);

        // Dec(ca · (1+kN)) == a + k mod N
        const cak = try ek.homAddPlaintext(ca, k);
        const ak = try dk.decrypt(cak);
        var expected_ak = a;
        const carry2 = P.Fn.addInPlace(&expected_ak, k);
        var wide2: P.Fn2.Bytes = P.Fn.widen(P.Fn2, expected_ak);
        if (carry2 == 1) P.Fn2.setBit(&wide2, 2 * 128);
        const red2 = try P.Fn2.divRem(wide2, P.Fn.widen(P.Fn2, ek.n));
        const expected_ak_mod = try P.Fn2.narrow(P.Fn, red2.r);
        try std.testing.expectEqualSlices(u8, &expected_ak_mod, &ak);
    }
}

test "invalid inputs rejected" {
    const P = Paillier(128);
    var prng = std.Random.DefaultPrng.init(999);
    const rng = prng.random();

    var dk = try P.DecryptionKey.generate(rng);
    defer dk.zeroize();
    const ek = dk.ek;

    // m >= N rejected
    var big = ek.n;
    _ = P.Fn.addInPlace(&big, P.Fn.fromU64(1));
    try std.testing.expectError(error.PlaintextTooLarge, ek.encryptWithNonce(big, P.Fn.fromU64(3)));

    // zero nonce rejected
    try std.testing.expectError(error.InvalidNonce, ek.encryptWithNonce(P.Fn.fromU64(1), P.Fn.zero));

    // zero ciphertext invalid
    try std.testing.expect(!ek.isValidCiphertext(P.Fn2.zero));
}
