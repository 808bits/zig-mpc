//! Shared machinery for the CGGMP24 ZK proofs: security-parameter sets,
//! signed big integers, and ring-Pedersen commitments (the verifier-side
//! "Aux" data).
//!
//! Timing: the ZK layer follows the audited reference implementation in
//! being variable-time (see cggmp24's explicit decision, lib.rs:308) -
//! constant-time hardening here is future work tracked in the roadmap.

const std = @import("std");
const ffx = @import("../ffx.zig");
const transcript = @import("../transcript.zig");
const paillier = @import("../paillier.zig");

pub const Transcript = transcript.Transcript;

/// Security/size parameters for one proof-system instantiation.
/// `prime_bits` is the bit length of each Paillier/Pedersen prime
/// (so moduli are `2*prime_bits`); `l`, `l_y` and `epsilon` are the CGGMP
/// range parameters (ℓ, ℓ', ε).
pub fn Params(comptime prime_bits_: comptime_int, comptime l_: comptime_int, comptime l_y_: comptime_int, comptime epsilon_: comptime_int) type {
    return struct {
        pub const prime_bits = prime_bits_;
        pub const l = l_;
        pub const l_y = l_y_;
        pub const epsilon = epsilon_;
        pub const n_bits = 2 * prime_bits_;
        /// Wide integer domain covering every product the proofs form:
        /// up to 2^(l+ε)·N̂·N for Πfac, curve-order-sized challenges times
        /// N̂·2^(l_y+ε) commitments for Πaff-g, plus slack.
        pub const int_bits = 384 + l_ + l_y_ + epsilon_ + 2 * n_bits + 64;

        pub const Fp = ffx.Ffx(prime_bits);
        pub const Fn = ffx.Ffx(n_bits);
        pub const FInt = ffx.Ffx(int_bits);
        pub const S = Signed(FInt);

        /// Lift narrower bytes into the wide integer domain.
        pub fn lift(comptime F: type, x: F.Bytes) FInt.Bytes {
            return F.widen(FInt, x);
        }

        /// 2^k in the wide domain.
        pub fn pow2(k: usize) FInt.Bytes {
            var out: FInt.Bytes = @splat(0);
            FInt.setBit(&out, k);
            return out;
        }

        /// bound · x in the wide domain (asserts no overflow).
        pub fn mulBound(a: FInt.Bytes, b: FInt.Bytes) FInt.Bytes {
            const wide = FInt.mulWide(a, b);
            return ffx.Ffx(2 * int_bits).narrow(FInt, wide) catch @panic("bound product overflows int domain");
        }
    };
}

/// Signed fixed-width big integer.
pub fn Signed(comptime F: type) type {
    return struct {
        const Self = @This();
        pub const Fx = F;

        neg: bool = false,
        mag: F.Bytes,

        pub const zero = Self{ .neg = false, .mag = @splat(0) };

        pub fn fromMag(mag: F.Bytes) Self {
            return .{ .neg = false, .mag = mag };
        }

        pub fn fromU64(x: u64) Self {
            return .{ .neg = false, .mag = F.fromU64(x) };
        }

        pub fn isZero(self: Self) bool {
            return F.isZero(self.mag);
        }

        /// Canonical: zero is never negative.
        fn canon(self: Self) Self {
            if (self.isZero()) return zero;
            return self;
        }

        /// Public canonicalization (for constructing signed values directly).
        pub fn canonPub(self: Self) Self {
            return self.canon();
        }

        pub fn negate(self: Self) Self {
            return (Self{ .neg = !self.neg, .mag = self.mag }).canon();
        }

        pub fn eql(a: Self, b: Self) bool {
            const ac = a.canon();
            const bc = b.canon();
            return ac.neg == bc.neg and F.cmp(ac.mag, bc.mag) == .eq;
        }

        pub fn add(a: Self, b: Self) Self {
            if (a.neg == b.neg) {
                var mag = a.mag;
                const carry = F.addInPlace(&mag, b.mag);
                std.debug.assert(carry == 0);
                return (Self{ .neg = a.neg, .mag = mag }).canon();
            }
            // opposite signs: result takes the sign of the larger magnitude
            return switch (F.cmp(a.mag, b.mag)) {
                .gt, .eq => (Self{ .neg = a.neg, .mag = F.sub(a.mag, b.mag) }).canon(),
                .lt => (Self{ .neg = b.neg, .mag = F.sub(b.mag, a.mag) }).canon(),
            };
        }

        pub fn sub(a: Self, b: Self) Self {
            return a.add(b.negate());
        }

        pub fn mul(a: Self, b: Self) Self {
            const wide = F.mulWide(a.mag, b.mag);
            const mag = ffx.Ffx(2 * F.bits).narrow(F, wide) catch @panic("signed mul overflows int domain");
            return (Self{ .neg = a.neg != b.neg, .mag = mag }).canon();
        }

        /// |x| <= floor(bound/2) (the reference `is_in_half_pm`).
        pub fn inHalfPm(self: Self, bound: F.Bytes) bool {
            var half = bound;
            var carry: u8 = 0;
            for (&half) |*byte| {
                const next: u8 = byte.* & 1;
                byte.* = (carry << 7) | (byte.* >> 1);
                carry = next;
            }
            return F.cmp(self.mag, half) != .gt;
        }

        /// Uniform in [-floor(bound/2), floor(bound/2)]
        /// (the reference `from_rng_half_pm`).
        pub fn sampleHalfPm(rng: std.Random, bound: F.Bytes) Self {
            var half = bound;
            var carry: u8 = 0;
            for (&half) |*byte| {
                const next: u8 = byte.* & 1;
                byte.* = (carry << 7) | (byte.* >> 1);
                carry = next;
            }
            // sample c in [0, 2*half] then subtract half
            var upper = half;
            const c2 = F.addInPlace(&upper, half);
            std.debug.assert(c2 == 0);
            _ = F.addInPlace(&upper, F.fromU64(1));
            const c = F.sampleBelow(rng, upper);
            return switch (F.cmp(c, half)) {
                .gt => (Self{ .neg = false, .mag = F.sub(c, half) }).canon(),
                .lt => (Self{ .neg = true, .mag = F.sub(half, c) }).canon(),
                .eq => zero,
            };
        }

        /// Reduce into [0, m) as bytes of the modulus' width.
        pub fn toModBytes(self: Self, comptime FM: type, m_bytes: FM.Bytes) FM.Bytes {
            const m_wide = FM.widen(F, m_bytes);
            const red = F.divRem(self.mag, m_wide) catch @panic("zero modulus");
            var r = F.narrow(FM, red.r) catch unreachable;
            if (self.neg and !FM.isZero(r)) {
                r = FM.sub(m_bytes, r);
            }
            return r;
        }

        pub fn appendToTranscript(self: Self, t: *Transcript, label: []const u8) void {
            const c = self.canon();
            var buf: [1 + F.num_bytes]u8 = undefined;
            buf[0] = @intFromBool(c.neg);
            @memcpy(buf[1..], &c.mag);
            t.appendBytes(label, &buf);
        }
    };
}

/// Ring-Pedersen parameters (N̂, s, t): the commitment key each verifier
/// publishes during aux-info generation.
pub fn Aux(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Pp = P;

        n_hat: P.Fn.Bytes,
        s: P.Fn.Bytes,
        t: P.Fn.Bytes,
        mod: P.Fn.Modulus,

        pub const Secret = struct {
            /// φ(N̂)
            phi: P.Fn.Bytes,
            /// λ with s = t^λ mod N̂
            lambda: P.Fn.Bytes,
            pub fn zeroize(self: *Secret) void {
                std.crypto.secureZero(u8, &self.phi);
                std.crypto.secureZero(u8, &self.lambda);
            }
        };

        pub const Generated = struct { aux: Self, secret: Secret };

        /// Generate fresh parameters. `safe_primes = false` uses Blum primes
        /// (fine for tests; production aux-gen should use safe primes).
        pub fn generate(rng: std.Random, comptime safe_primes: bool) !Generated {
            const p = if (safe_primes)
                try P.Fp.generateSafePrime(rng, P.prime_bits)
            else
                try P.Fp.generatePrime(rng, P.prime_bits, true);
            const q = if (safe_primes)
                try P.Fp.generateSafePrime(rng, P.prime_bits)
            else
                try P.Fp.generatePrime(rng, P.prime_bits, true);
            return fromPrimes(rng, p, q);
        }

        /// Build parameters from caller-supplied primes (e.g. pregenerated
        /// safe primes during aux-info generation).
        pub fn fromPrimes(rng: std.Random, p: P.Fp.Bytes, q: P.Fp.Bytes) !Generated {
            const n_hat: P.Fn.Bytes = P.Fp.mulWide(p, q);
            const phi: P.Fn.Bytes = P.Fp.mulWide(P.Fp.sub(p, P.Fp.fromU64(1)), P.Fp.sub(q, P.Fp.fromU64(1)));
            const mod = try P.Fn.Modulus.fromBytes(&n_hat, .big);

            // r unit, t = r² mod N̂, λ < φ, s = t^λ
            var r = P.Fn.sampleBelow(rng, n_hat);
            while (P.Fn.isZero(r) or !P.Fn.isCoprime(r, n_hat)) r = P.Fn.sampleBelow(rng, n_hat);
            const r_fe = P.Fn.Fe.fromBytes(mod, &r, .big) catch unreachable;
            var t_bytes: P.Fn.Bytes = undefined;
            mod.sq(r_fe).toBytes(&t_bytes, .big) catch unreachable;

            var lambda = P.Fn.sampleBelow(rng, phi);
            while (P.Fn.isZero(lambda)) lambda = P.Fn.sampleBelow(rng, phi);
            const t_fe = P.Fn.Fe.fromBytes(mod, &t_bytes, .big) catch unreachable;
            var s_bytes: P.Fn.Bytes = undefined;
            (mod.powWithEncodedExponent(t_fe, &lambda, .big) catch unreachable).toBytes(&s_bytes, .big) catch unreachable;

            return .{
                .aux = .{ .n_hat = n_hat, .s = s_bytes, .t = t_bytes, .mod = mod },
                .secret = .{ .phi = phi, .lambda = lambda },
            };
        }

        pub fn fromParts(n_hat: P.Fn.Bytes, s: P.Fn.Bytes, t: P.Fn.Bytes) !Self {
            const mod = try P.Fn.Modulus.fromBytes(&n_hat, .big);
            const self = Self{ .n_hat = n_hat, .s = s, .t = t, .mod = mod };
            if (!self.isInMultGroup(s) or !self.isInMultGroup(t)) return error.InvalidPedersenParams;
            return self;
        }

        pub fn isInMultGroup(self: Self, x: P.Fn.Bytes) bool {
            if (P.Fn.isZero(x)) return false;
            if (P.Fn.cmp(x, self.n_hat) != .lt) return false;
            return P.Fn.isCoprime(x, self.n_hat);
        }

        pub fn powBytes(self: Self, base: P.Fn.Bytes, e: []const u8) P.Fn.Bytes {
            // ff rejects zero exponents; x^0 = 1
            var all_zero = true;
            for (e) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            var out: P.Fn.Bytes = undefined;
            if (all_zero) {
                self.mod.one().toBytes(&out, .big) catch unreachable;
                return out;
            }
            const base_fe = P.Fn.Fe.fromBytes(self.mod, &base, .big) catch unreachable;
            const r = self.mod.powWithEncodedExponent(base_fe, e, .big) catch unreachable;
            r.toBytes(&out, .big) catch unreachable;
            return out;
        }

        /// base^e mod N̂ for signed e (negative exponents via inversion;
        /// errors if the base is not a unit).
        pub fn powModSigned(self: Self, base: P.Fn.Bytes, e: P.S) !P.Fn.Bytes {
            const pos = self.powBytes(base, &e.mag);
            if (!e.neg or P.FInt.isZero(e.mag)) return pos;
            return P.Fn.invertOdd(pos, self.n_hat) catch return error.NotInvertible;
        }

        /// s^x · t^y mod N̂ (the ring-Pedersen commitment).
        pub fn combine(self: Self, x: P.S, y: P.S) !P.Fn.Bytes {
            const sx = try self.powModSigned(self.s, x);
            const ty = try self.powModSigned(self.t, y);
            const a = P.Fn.Fe.fromBytes(self.mod, &sx, .big) catch unreachable;
            const b = P.Fn.Fe.fromBytes(self.mod, &ty, .big) catch unreachable;
            var out: P.Fn.Bytes = undefined;
            self.mod.mul(a, b).toBytes(&out, .big) catch unreachable;
            return out;
        }

        /// a · b mod N̂ on byte values.
        pub fn mulMod(self: Self, a: P.Fn.Bytes, b: P.Fn.Bytes) P.Fn.Bytes {
            const a_fe = P.Fn.Fe.fromBytes(self.mod, &a, .big) catch unreachable;
            const b_fe = P.Fn.Fe.fromBytes(self.mod, &b, .big) catch unreachable;
            var out: P.Fn.Bytes = undefined;
            self.mod.mul(a_fe, b_fe).toBytes(&out, .big) catch unreachable;
            return out;
        }

        pub fn appendToTranscript(self: Self, t: *Transcript) void {
            t.appendBytes("aux-n-hat", &self.n_hat);
            t.appendBytes("aux-s", &self.s);
            t.appendBytes("aux-t", &self.t);
        }
    };
}

/// The Paillier instantiation matching a parameter set.
pub fn Pail(comptime P: type) type {
    return paillier.Paillier(P.prime_bits);
}

/// Reduce a signed wide integer into a curve scalar (sign-aware).
pub fn toCurveScalar(comptime P: type, comptime E: type, x: P.S) E.Scalar {
    const enc = E.Scalar.encoded_length;
    var order_wide: P.FInt.Bytes = @splat(0);
    @memcpy(order_wide[P.FInt.num_bytes - enc ..], &E.order_be);
    const red = P.FInt.divRem(x.mag, order_wide) catch unreachable;
    var be: [enc]u8 = undefined;
    @memcpy(&be, red.r[P.FInt.num_bytes - enc ..]);
    const s = switch (E.scalar_endian) {
        .big => E.Scalar.fromBytes(be) catch unreachable,
        .little => blk: {
            var le: [enc]u8 = undefined;
            for (0..enc) |i| le[i] = be[enc - 1 - i];
            break :blk E.Scalar.fromBytes(le) catch unreachable;
        },
    };
    return if (x.neg) s.neg() else s;
}

/// The curve order lifted into the wide integer domain (challenge bound).
pub fn curveOrderWide(comptime P: type, comptime E: type) P.FInt.Bytes {
    var out: P.FInt.Bytes = @splat(0);
    @memcpy(out[P.FInt.num_bytes - E.Scalar.encoded_length ..], &E.order_be);
    return out;
}

/// p·s for a point with a possibly-zero public scalar (identity on zero).
pub fn pointMulPub(comptime E: type, p: E.Point, s: E.Scalar) E.Point {
    if (s.isZero()) return E.Point.identity;
    return p.mulPublic(s) catch E.Point.identity;
}

/// G·s with a possibly-zero scalar.
pub fn baseMul(comptime E: type, s: E.Scalar) E.Point {
    if (s.isZero()) return E.Point.identity;
    return E.Point.mulBase(s) catch E.Point.identity;
}

/// Enc(m; r) for signed m (Paillier plaintexts live mod N).
pub fn encryptSigned(comptime P: type, ek: Pail(P).EncryptionKey, m: P.S, r: Pail(P).Nonce) !Pail(P).Ciphertext {
    return ek.encryptWithNonce(m.toModBytes(P.Fn, ek.n), r);
}

/// c^e mod N² for signed e.
pub fn homMulSigned(comptime P: type, ek: Pail(P).EncryptionKey, c: Pail(P).Ciphertext, e: P.S) !Pail(P).Ciphertext {
    if (e.isZero()) {
        var out: Pail(P).Ciphertext = undefined;
        try ek.mod_n2.one().toBytes(&out, .big);
        return out;
    }
    const pos = try ek.homMulScalar(c, &e.mag);
    if (!e.neg) return pos;
    var n2_bytes: [2 * P.Fn.num_bytes]u8 = undefined;
    try ek.mod_n2.toBytes(&n2_bytes, .big);
    return ffx.Ffx(2 * P.n_bits).invertOdd(pos, n2_bytes);
}

/// r · ρ^e mod N for signed e (the nonce-side response).
pub fn nonceCombine(comptime P: type, ek: Pail(P).EncryptionKey, r: Pail(P).Nonce, rho: Pail(P).Nonce, e: P.S) !Pail(P).Nonce {
    var rho_e: P.Fn.Bytes = undefined;
    if (e.isZero()) {
        try ek.mod_n.one().toBytes(&rho_e, .big);
    } else {
        const rho_fe = P.Fn.Fe.fromBytes(ek.mod_n, &rho, .big) catch return error.InvalidNonce;
        try (try ek.mod_n.powWithEncodedExponent(rho_fe, &e.mag, .big)).toBytes(&rho_e, .big);
        if (e.neg) rho_e = try P.Fn.invertOdd(rho_e, ek.n);
    }
    const a = P.Fn.Fe.fromBytes(ek.mod_n, &r, .big) catch return error.InvalidNonce;
    const b = P.Fn.Fe.fromBytes(ek.mod_n, &rho_e, .big) catch unreachable;
    var out: P.Fn.Bytes = undefined;
    try ek.mod_n.mul(a, b).toBytes(&out, .big);
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub const TestParams = Params(128, 32, 96, 64);

/// Test parameters for the curve-linked proofs (Πenc-elg, Πaff-g): their
/// challenges are curve-order sized, so completeness needs
/// ε ≥ bits(q) + l + statistical margin (this is why Level128 pairs
/// ℓ=256 with ε=512).
pub const TestParamsCurve = Params(128, 32, 96, 384);

test "signed arithmetic" {
    const P = TestParams;
    const S = P.S;

    const a = S.fromU64(100);
    const b = S.fromU64(30).negate();
    try std.testing.expect(a.add(b).eql(S.fromU64(70)));
    try std.testing.expect(b.add(a).eql(S.fromU64(70)));
    try std.testing.expect(b.sub(a).eql(S.fromU64(130).negate()));
    try std.testing.expect(a.mul(b).eql(S.fromU64(3000).negate()));
    try std.testing.expect(b.mul(b).eql(S.fromU64(900)));
    try std.testing.expect(S.zero.negate().eql(S.zero));

    // half-pm bounds
    const bound = P.FInt.fromU64(100);
    try std.testing.expect(S.fromU64(50).inHalfPm(bound));
    try std.testing.expect(S.fromU64(50).negate().inHalfPm(bound));
    try std.testing.expect(!S.fromU64(51).inHalfPm(bound));

    var prng = std.Random.DefaultPrng.init(3);
    const rng = prng.random();
    var seen_neg = false;
    var seen_pos = false;
    for (0..200) |_| {
        const x = S.sampleHalfPm(rng, bound);
        try std.testing.expect(x.inHalfPm(bound));
        if (x.neg) seen_neg = true else if (!x.isZero()) seen_pos = true;
    }
    try std.testing.expect(seen_neg and seen_pos);
}

test "signed toModBytes" {
    const P = TestParams;
    const S = P.S;
    const m = P.Fn.fromU64(97);

    // -5 mod 97 == 92
    const neg5 = S.fromU64(5).negate();
    try std.testing.expectEqualSlices(u8, &P.Fn.fromU64(92), &neg5.toModBytes(P.Fn, m));
    // 200 mod 97 == 6
    try std.testing.expectEqualSlices(u8, &P.Fn.fromU64(6), &S.fromU64(200).toModBytes(P.Fn, m));
}

test "ring-pedersen commitment homomorphism" {
    const P = TestParams;
    var prng = std.Random.DefaultPrng.init(41);
    const rng = prng.random();

    var gen = try Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = gen.aux;

    // s^a t^b · s^c t^d == s^(a+c) t^(b+d)
    const a = P.S.sampleHalfPm(rng, P.pow2(40));
    const b = P.S.sampleHalfPm(rng, P.pow2(40));
    const c = P.S.sampleHalfPm(rng, P.pow2(40));
    const d = P.S.sampleHalfPm(rng, P.pow2(40));

    const c1 = try aux.combine(a, b);
    const c2 = try aux.combine(c, d);
    const lhs = aux.mulMod(c1, c2);
    const rhs = try aux.combine(a.add(c), b.add(d));
    try std.testing.expectEqualSlices(u8, &lhs, &rhs);

    // negative exponent roundtrip: s^x · s^(-x) == 1
    const sx = try aux.powModSigned(aux.s, a);
    const sxn = try aux.powModSigned(aux.s, a.negate());
    const one = aux.mulMod(sx, sxn);
    var one_expected: P.Fn.Bytes = undefined;
    try aux.mod.one().toBytes(&one_expected, .big);
    try std.testing.expectEqualSlices(u8, &one, &one_expected);
}
