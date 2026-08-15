//! Extras on top of std.crypto.ff needed for Paillier / CGGMP:
//! modular inversion, GCD, wide multiplication, uniform sampling,
//! Miller-Rabin primality, and Blum/safe-prime generation.
//!
//! Timing notes:
//!  - `invertPrime` / `invertViaTotient` are built on ff's constant-time
//!    `powWithEncodedExponent` and are safe for secret values (the modulus
//!    itself is treated as public, as in all of std.crypto.ff).
//!  - `gcd`, `invertOdd`, `mulWide`, the byte helpers, and prime generation
//!    are VARIABLE-TIME. They are intended for public values and for key
//!    generation, where the candidate values are secret but short-lived;
//!    this matches standard practice (e.g. OpenSSL keygen). Do not use them
//!    on long-lived secrets in signing paths.
//!
//! All big integers at the byte level are fixed-width big-endian arrays.

const std = @import("std");
const ff = std.crypto.ff;

pub fn Ffx(comptime max_bits: comptime_int) type {
    comptime std.debug.assert(max_bits % 8 == 0 and max_bits >= 32);
    return struct {
        pub const bits = max_bits;
        pub const Modulus = ff.Modulus(max_bits);
        pub const Uint = ff.Uint(max_bits);
        pub const Fe = Modulus.Fe;
        pub const num_bytes = max_bits / 8;
        pub const Bytes = [num_bytes]u8;

        pub const zero: Bytes = @splat(0);

        // ------------------------------------------------------------------
        // byte-level primitives (big-endian, fixed width, variable-time)
        // ------------------------------------------------------------------

        pub fn fromHex(hex: []const u8) Bytes {
            var out: Bytes = @splat(0);
            std.debug.assert(hex.len <= 2 * num_bytes);
            const start = num_bytes - hex.len / 2;
            _ = std.fmt.hexToBytes(out[start..], hex) catch unreachable;
            return out;
        }

        pub fn fromU64(x: u64) Bytes {
            var out: Bytes = @splat(0);
            std.mem.writeInt(u64, out[num_bytes - 8 ..][0..8], x, .big);
            return out;
        }

        pub fn cmp(a: Bytes, b: Bytes) std.math.Order {
            return std.mem.order(u8, &a, &b);
        }

        pub fn isZero(a: Bytes) bool {
            for (a) |b| if (b != 0) return false;
            return true;
        }

        pub fn isEven(a: Bytes) bool {
            return a[num_bytes - 1] & 1 == 0;
        }

        pub fn bitLength(a: Bytes) usize {
            for (a, 0..) |b, i| {
                if (b != 0) return (num_bytes - i - 1) * 8 + (8 - @clz(b));
            }
            return 0;
        }

        pub fn bit(a: Bytes, i: usize) u1 {
            return @truncate(a[num_bytes - 1 - i / 8] >> @intCast(i % 8));
        }

        pub fn setBit(a: *Bytes, i: usize) void {
            a[num_bytes - 1 - i / 8] |= @as(u8, 1) << @intCast(i % 8);
        }

        /// a >>= 1, shifting `carry_in` into the top bit.
        fn shr1(a: *Bytes, carry_in: u1) void {
            var carry: u8 = carry_in;
            for (a) |*b| {
                const next: u8 = b.* & 1;
                b.* = (carry << 7) | (b.* >> 1);
                carry = next;
            }
        }

        fn shl1(a: *Bytes) u1 {
            var carry: u8 = 0;
            var i: usize = num_bytes;
            while (i > 0) {
                i -= 1;
                const next: u8 = a[i] >> 7;
                a[i] = (a[i] << 1) | carry;
                carry = next;
            }
            return @truncate(carry);
        }

        pub fn addInPlace(a: *Bytes, b: Bytes) u1 {
            var carry: u16 = 0;
            var i: usize = num_bytes;
            while (i > 0) {
                i -= 1;
                const s: u16 = @as(u16, a[i]) + b[i] + carry;
                a[i] = @truncate(s);
                carry = s >> 8;
            }
            return @truncate(carry);
        }

        /// a -= b; requires a >= b (asserts no final borrow).
        pub fn subInPlace(a: *Bytes, b: Bytes) void {
            var borrow: i16 = 0;
            var i: usize = num_bytes;
            while (i > 0) {
                i -= 1;
                const d: i16 = @as(i16, a[i]) - b[i] - borrow;
                a[i] = @truncate(@as(u16, @bitCast(d)));
                borrow = if (d < 0) 1 else 0;
            }
            std.debug.assert(borrow == 0);
        }

        pub fn sub(a: Bytes, b: Bytes) Bytes {
            var out = a;
            subInPlace(&out, b);
            return out;
        }

        /// a mod m for small m, variable-time.
        pub fn modU32(a: Bytes, m: u32) u32 {
            var r: u64 = 0;
            for (a) |b| r = ((r << 8) | b) % m;
            return @intCast(r);
        }

        /// Schoolbook multiplication, result is double-width.
        pub fn mulWide(a: Bytes, b: Bytes) [2 * num_bytes]u8 {
            var out: [2 * num_bytes]u8 = @splat(0);
            var i: usize = num_bytes;
            while (i > 0) {
                i -= 1;
                if (a[i] == 0) continue;
                var carry: u32 = 0;
                var j: usize = num_bytes;
                while (j > 0) {
                    j -= 1;
                    const pos = i + j + 1;
                    const prod: u32 = @as(u32, a[i]) * b[j] + out[pos] + carry;
                    out[pos] = @truncate(prod);
                    carry = prod >> 8;
                }
                var pos = i;
                while (carry != 0) {
                    const s: u32 = out[pos] + carry;
                    out[pos] = @truncate(s);
                    carry = s >> 8;
                    if (pos == 0) break;
                    pos -= 1;
                }
            }
            return out;
        }

        /// a - b with explicit borrow instead of asserting.
        pub fn trySub(a: Bytes, b: Bytes) struct { diff: Bytes, borrow: u1 } {
            var out = a;
            var borrow: i16 = 0;
            var i: usize = num_bytes;
            while (i > 0) {
                i -= 1;
                const d: i16 = @as(i16, out[i]) - b[i] - borrow;
                out[i] = @truncate(@as(u16, @bitCast(d)));
                borrow = if (d < 0) 1 else 0;
            }
            return .{ .diff = out, .borrow = @intCast(borrow) };
        }

        /// cond ? a : b via byte masking (no data-dependent branch).
        fn ctSelect(cond: u1, a: Bytes, b: Bytes) Bytes {
            const mask: u8 = @as(u8, 0) -% cond;
            var out: Bytes = undefined;
            for (&out, a, b) |*o, x, y| o.* = y ^ (mask & (x ^ y));
            return out;
        }

        /// Fixed-iteration shift-subtract division: a = q*d + r, r < d.
        /// Iteration count and memory access pattern are independent of the
        /// values; the divisor is treated as public.
        pub fn divRem(a: Bytes, d: Bytes) error{DivisionByZero}!struct { q: Bytes, r: Bytes } {
            if (isZero(d)) return error.DivisionByZero;
            var q: Bytes = @splat(0);
            var r: Bytes = @splat(0);
            var i: usize = max_bits;
            while (i > 0) {
                i -= 1;
                _ = shl1(&r);
                r[num_bytes - 1] |= bit(a, i);
                const s = trySub(r, d);
                const fits: u1 = 1 - s.borrow;
                r = ctSelect(fits, s.diff, r);
                q[num_bytes - 1 - i / 8] |= @as(u8, fits) << @intCast(i % 8);
            }
            return .{ .q = q, .r = r };
        }

        /// Narrow to a smaller Ffx size; errors if high bytes are nonzero.
        pub fn narrow(comptime Narrower: type, a: Bytes) error{Overflow}!Narrower.Bytes {
            comptime std.debug.assert(Narrower.num_bytes <= num_bytes);
            for (a[0 .. num_bytes - Narrower.num_bytes]) |b| {
                if (b != 0) return error.Overflow;
            }
            var out: Narrower.Bytes = undefined;
            @memcpy(&out, a[num_bytes - Narrower.num_bytes ..]);
            return out;
        }

        /// Widen to a larger Ffx size (left-pad).
        pub fn widen(comptime Wider: type, a: Bytes) Wider.Bytes {
            comptime std.debug.assert(Wider.num_bytes >= num_bytes);
            var out: Wider.Bytes = @splat(0);
            @memcpy(out[Wider.num_bytes - num_bytes ..], &a);
            return out;
        }

        // ------------------------------------------------------------------
        // gcd / inversion
        // ------------------------------------------------------------------

        /// Binary GCD, variable-time.
        pub fn gcd(a_in: Bytes, b_in: Bytes) Bytes {
            var a = a_in;
            var b = b_in;
            if (isZero(a)) return b;
            if (isZero(b)) return a;

            var shift: usize = 0;
            while (isEven(a) and isEven(b)) {
                shr1(&a, 0);
                shr1(&b, 0);
                shift += 1;
            }
            while (isEven(a)) shr1(&a, 0);
            while (true) {
                while (isEven(b)) shr1(&b, 0);
                if (cmp(a, b) == .gt) std.mem.swap(Bytes, &a, &b);
                subInPlace(&b, a);
                if (isZero(b)) break;
            }
            for (0..shift) |_| _ = shl1(&a);
            return a;
        }

        pub fn isCoprime(a: Bytes, b: Bytes) bool {
            const g = gcd(a, b);
            return cmp(g, fromU64(1)) == .eq;
        }

        fn halveMod(u: *Bytes, m: Bytes) void {
            if (isEven(u.*)) {
                shr1(u, 0);
            } else {
                const carry = addInPlace(u, m);
                shr1(u, carry);
            }
        }

        fn subMod(u: Bytes, v: Bytes, m: Bytes) Bytes {
            if (cmp(u, v) != .lt) {
                return sub(u, v);
            }
            const t = sub(v, u);
            return sub(m, t);
        }

        /// x^-1 mod m for odd m via binary extended GCD. VARIABLE-TIME -
        /// public values only. Errors if gcd(x, m) != 1.
        pub fn invertOdd(x_in: Bytes, m: Bytes) error{ NotInvertible, EvenModulus }!Bytes {
            if (isEven(m)) return error.EvenModulus;
            // reduce x mod m
            var x = x_in;
            while (cmp(x, m) != .lt) subInPlace(&x, m);
            if (isZero(x)) return error.NotInvertible;

            var a = x;
            var b = m;
            var u = fromU64(1); // a == u*x (mod m)
            var v: Bytes = @splat(0); // b == v*x (mod m)

            while (!isZero(a)) {
                while (isEven(a)) {
                    shr1(&a, 0);
                    halveMod(&u, m);
                }
                // a, b both odd here
                if (cmp(a, b) != .lt) {
                    subInPlace(&a, b);
                    u = subMod(u, v, m);
                } else {
                    std.mem.swap(Bytes, &a, &b);
                    std.mem.swap(Bytes, &u, &v);
                }
            }
            // b == gcd(x, m) == v*x (mod m)
            if (cmp(b, fromU64(1)) != .eq) return error.NotInvertible;
            return v;
        }

        /// x^-1 mod p for PRIME p via x^(p-2): constant-time in x
        /// (built on ff's secret-exponent pow).
        pub fn invertPrime(m: Modulus, x: Fe) !Fe {
            var p_bytes: Bytes = undefined;
            try m.toBytes(&p_bytes, .big);
            subInPlace(&p_bytes, fromU64(2));
            return m.powWithEncodedExponent(x, &p_bytes, .big);
        }

        /// x^-1 mod n given the group order phi(n) (e.g. n = p*q with
        /// phi = (p-1)(q-1)): computes x^(phi-1), constant-time in x and phi.
        /// Requires gcd(x, n) == 1 (NOT checked - verify separately).
        pub fn invertViaTotient(m: Modulus, x: Fe, phi: Bytes) !Fe {
            var e = phi;
            subInPlace(&e, fromU64(1));
            return m.powWithEncodedExponent(x, &e, .big);
        }

        /// Jacobi symbol (a/n) for odd n > 0. Variable-time.
        pub fn jacobi(a_in: Bytes, n_in: Bytes) i2 {
            std.debug.assert(!isEven(n_in) and !isZero(n_in));
            var a = a_in;
            var n = n_in;
            // reduce a mod n
            while (cmp(a, n) != .lt) subInPlace(&a, n);

            var result: i2 = 1;
            while (!isZero(a)) {
                while (isEven(a)) {
                    shr1(&a, 0);
                    const r = modU32(n, 8);
                    if (r == 3 or r == 5) result = -result;
                }
                std.mem.swap(Bytes, &a, &n);
                if (modU32(a, 4) == 3 and modU32(n, 4) == 3) result = -result;
                while (cmp(a, n) != .lt) subInPlace(&a, n);
            }
            if (cmp(n, fromU64(1)) == .eq) return result;
            return 0;
        }

        /// x^-1 mod m for arbitrary m >= 2 via extended Euclid (uses divRem).
        /// Variable-time. Errors if gcd(x, m) != 1.
        pub fn invertGeneral(x_in: Bytes, m: Bytes) error{ NotInvertible, DivisionByZero }!Bytes {
            if (isZero(m) or cmp(m, fromU64(1)) == .eq) return error.NotInvertible;
            var x = x_in;
            while (cmp(x, m) != .lt) subInPlace(&x, m);
            if (isZero(x)) return error.NotInvertible;

            // Track Bezout coefficients as residues mod m:
            // r0 = m, r1 = x; t0 = 0, t1 = 1; invariant t_i*x == r_i (mod m).
            var r0 = m;
            var r1 = x;
            var t0: Bytes = @splat(0);
            var t1 = fromU64(1);

            while (!isZero(r1)) {
                const dv = try divRem(r0, r1);
                // t2 = (t0 - q*t1) mod m
                const q_t1 = blk: {
                    const wide = mulWide(dv.q, t1);
                    const m_wide = widen(Ffx(2 * max_bits), m);
                    const red = Ffx(2 * max_bits).divRem(wide, m_wide) catch unreachable;
                    break :blk Ffx(2 * max_bits).narrow(@This(), red.r) catch unreachable;
                };
                const t2 = subMod(t0, q_t1, m);

                r0 = r1;
                r1 = dv.r;
                t0 = t1;
                t1 = t2;
            }
            if (cmp(r0, fromU64(1)) != .eq) return error.NotInvertible;
            return t0;
        }

        /// Integer square root: floor(sqrt(a)). Bitwise algorithm,
        /// variable-time.
        pub fn sqrtFloor(a: Bytes) Bytes {
            var res: Bytes = @splat(0);
            var bit_i: usize = max_bits / 2;
            while (bit_i > 0) {
                bit_i -= 1;
                var candidate = res;
                setBit(&candidate, bit_i);
                // candidate² <= a ?
                const sq = mulWide(candidate, candidate);
                const a_wide = widen(Ffx(2 * max_bits), a);
                if (Ffx(2 * max_bits).cmp(sq, a_wide) != .gt) {
                    res = candidate;
                }
            }
            return res;
        }

        // ------------------------------------------------------------------
        // sampling
        // ------------------------------------------------------------------

        /// Uniform sample with exactly `nbits` significant bits at most
        /// (top bits masked; may be shorter).
        pub fn sampleBits(rng: std.Random, nbits: usize) Bytes {
            std.debug.assert(nbits <= max_bits and nbits > 0);
            var out: Bytes = @splat(0);
            const nb = (nbits + 7) / 8;
            rng.bytes(out[num_bytes - nb ..]);
            const excess: u3 = @intCast((8 - nbits % 8) % 8);
            out[num_bytes - nb] &= @as(u8, 0xff) >> excess;
            return out;
        }

        /// Uniform sample in [0, bound) by rejection.
        pub fn sampleBelow(rng: std.Random, bound: Bytes) Bytes {
            std.debug.assert(!isZero(bound));
            const k = bitLength(bound);
            while (true) {
                const c = sampleBits(rng, k);
                if (cmp(c, bound) == .lt) return c;
            }
        }

        /// Uniform sample in [2, bound).
        pub fn sampleBetween2AndBound(rng: std.Random, bound: Bytes) Bytes {
            while (true) {
                const c = sampleBelow(rng, bound);
                if (cmp(c, fromU64(2)) != .lt) return c;
            }
        }

        // ------------------------------------------------------------------
        // primality
        // ------------------------------------------------------------------

        const small_primes = blk: {
            @setEvalBranchQuota(200_000);
            var primes: []const u32 = &.{};
            var n: u32 = 3;
            while (n < 2000) : (n += 2) {
                var is_p = true;
                var d: u32 = 3;
                while (d * d <= n) : (d += 2) {
                    if (n % d == 0) {
                        is_p = false;
                        break;
                    }
                }
                if (is_p) primes = primes ++ &[_]u32{n};
            }
            break :blk primes;
        };

        /// Miller-Rabin with `rounds` random bases. `n` must be odd and >= 5.
        pub fn millerRabin(n: Bytes, rounds: usize, rng: std.Random) !bool {
            std.debug.assert(!isEven(n));
            const m = Modulus.fromBytes(&n, .big) catch return error.InvalidModulus;

            var n1 = n; // n - 1 = 2^s * d
            subInPlace(&n1, fromU64(1));
            var d = n1;
            var s: usize = 0;
            while (isEven(d)) {
                shr1(&d, 0);
                s += 1;
            }

            const one_fe = m.one();
            const n1_fe = Fe.fromBytes(m, &n1, .big) catch unreachable;

            var round: usize = 0;
            outer: while (round < rounds) : (round += 1) {
                const a_bytes = sampleBetween2AndBound(rng, n1);
                const a = Fe.fromBytes(m, &a_bytes, .big) catch unreachable;
                var x = m.powWithEncodedExponent(a, &d, .big) catch unreachable;
                if (x.eql(one_fe) or x.eql(n1_fe)) continue;
                for (0..s - 1) |_| {
                    x = m.sq(x);
                    if (x.eql(n1_fe)) continue :outer;
                }
                return false;
            }
            return true;
        }

        /// Trial division by small primes, then Miller-Rabin (24 rounds:
        /// error probability <= 4^-24, far below key-failure budgets).
        pub fn isProbablePrime(n: Bytes, rng: std.Random) !bool {
            const bl = bitLength(n);
            if (bl <= 32) {
                const v = modU32(n, 0xffffffff); // n itself fits
                var small: u64 = 0;
                for (n[num_bytes - 4 ..]) |b| small = (small << 8) | b;
                _ = v;
                if (small < 2) return false;
                if (small == 2) return true;
                if (small % 2 == 0) return false;
                var f: u64 = 3;
                while (f * f <= small) : (f += 2) {
                    if (small % f == 0) return false;
                }
                return true;
            }
            if (isEven(n)) return false;
            for (small_primes) |p| {
                if (modU32(n, p) == 0) return false;
            }
            return millerRabin(n, 24, rng);
        }

        /// Generate a random prime of exactly `nbits` bits. When `blum`,
        /// the prime is congruent to 3 mod 4 (as required for Paillier-Blum
        /// moduli in CGGMP).
        pub fn generatePrime(rng: std.Random, nbits: usize, blum: bool) !Bytes {
            std.debug.assert(nbits >= 16 and nbits <= max_bits);
            while (true) {
                var c = sampleBits(rng, nbits);
                setBit(&c, nbits - 1); // exact bit length
                setBit(&c, 0); // odd
                if (blum) setBit(&c, 1); // == 3 (mod 4)
                if (try isProbablePrime(c, rng)) return c;
            }
        }

        /// Generate a safe prime p = 2q + 1 (q prime) of exactly `nbits`
        /// bits. Expensive for large sizes - used for ring-Pedersen setup.
        pub fn generateSafePrime(rng: std.Random, nbits: usize) !Bytes {
            while (true) {
                const q = try generatePrime(rng, nbits - 1, false);
                var p = q;
                _ = shl1(&p);
                setBit(&p, 0);
                if (bitLength(p) != nbits) continue;
                // p == 2q+1; check p prime. q already prime.
                if (try isProbablePrime(p, rng)) return p;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (reference vectors generated independently with python3 + sympy)
// ---------------------------------------------------------------------------

const vectors = @import("testdata/ffx_vectors.zig");

test "modular inverse matches python vectors (256 and 2048 bits)" {
    {
        const F = Ffx(256);
        for (vectors.inv256) |v| {
            const x = F.fromHex(v[0]);
            const m = F.fromHex(v[1]);
            const expected = F.fromHex(v[2]);
            const inv = try F.invertOdd(x, m);
            try std.testing.expectEqualSlices(u8, &expected, &inv);
        }
    }
    {
        const F = Ffx(2048);
        for (vectors.inv2048) |v| {
            const x = F.fromHex(v[0]);
            const m = F.fromHex(v[1]);
            const expected = F.fromHex(v[2]);
            const inv = try F.invertOdd(x, m);
            try std.testing.expectEqualSlices(u8, &expected, &inv);

            // and x * x^-1 == 1 through ff arithmetic
            const mod = try F.Modulus.fromBytes(&m, .big);
            const x_fe = try F.Fe.fromBytes(mod, &x, .big);
            const i_fe = try F.Fe.fromBytes(mod, &inv, .big);
            try std.testing.expect(mod.mul(x_fe, i_fe).eql(mod.one()));
        }
    }
}

test "gcd matches python vectors" {
    const F = Ffx(256);
    for (vectors.gcd256) |v| {
        const a = F.fromHex(v[0]);
        const b = F.fromHex(v[1]);
        const expected = F.fromHex(v[2]);
        try std.testing.expectEqualSlices(u8, &expected, &F.gcd(a, b));
    }
}

test "primality: sympy primes accepted, composites (incl. Carmichael) rejected" {
    const F = Ffx(512);
    var prng = std.Random.DefaultPrng.init(9);
    const rng = prng.random();

    for (vectors.primes512) |hex| {
        try std.testing.expect(try F.isProbablePrime(F.fromHex(hex), rng));
    }
    for (vectors.composites512) |hex| {
        try std.testing.expect(!try F.isProbablePrime(F.fromHex(hex), rng));
    }
}

test "invertPrime (constant-time path) agrees with xgcd on known primes" {
    const F = Ffx(256);
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();

    for (vectors.blum256) |hex| {
        const p = F.fromHex(hex);
        try std.testing.expectEqual(@as(u32, 3), F.modU32(p, 4));
        const m = try F.Modulus.fromBytes(&p, .big);
        for (0..4) |_| {
            const x = F.sampleBetween2AndBound(rng, p);
            const via_xgcd = try F.invertOdd(x, p);
            const x_fe = try F.Fe.fromBytes(m, &x, .big);
            const via_pow = try F.invertPrime(m, x_fe);
            var pow_bytes: F.Bytes = undefined;
            try via_pow.toBytes(&pow_bytes, .big);
            try std.testing.expectEqualSlices(u8, &via_xgcd, &pow_bytes);
        }
    }
}

test "mulWide, totient inversion, and prime generation (Paillier-shaped)" {
    const F128 = Ffx(128);
    const F256 = Ffx(256);
    var prng = std.Random.DefaultPrng.init(123);
    const rng = prng.random();

    const p = try F128.generatePrime(rng, 128, true);
    const q = try F128.generatePrime(rng, 128, true);
    try std.testing.expectEqual(@as(u32, 3), F128.modU32(p, 4));
    try std.testing.expectEqual(@as(usize, 128), F128.bitLength(p));

    // n = p*q, phi = (p-1)(q-1)
    const n: F256.Bytes = F128.mulWide(p, q);
    const p1 = F128.sub(p, F128.fromU64(1));
    const q1 = F128.sub(q, F128.fromU64(1));
    const phi: F256.Bytes = F128.mulWide(p1, q1);

    // sanity: n - phi == p + q - 1
    var pq_sum = F128.widen(F256, p);
    _ = F256.addInPlace(&pq_sum, F128.widen(F256, q));
    F256.subInPlace(&pq_sum, F256.fromU64(1));
    try std.testing.expectEqualSlices(u8, &pq_sum, &F256.sub(n, phi));

    const m = try F256.Modulus.fromBytes(&n, .big);
    for (0..4) |_| {
        const x = F256.sampleBetween2AndBound(rng, n);
        if (!F256.isCoprime(x, n)) continue;
        const via_xgcd = try F256.invertOdd(x, n);
        const x_fe = try F256.Fe.fromBytes(m, &x, .big);
        const via_totient = try F256.invertViaTotient(m, x_fe, phi);
        var tot_bytes: F256.Bytes = undefined;
        try via_totient.toBytes(&tot_bytes, .big);
        try std.testing.expectEqualSlices(u8, &via_xgcd, &tot_bytes);
    }
}

test "safe prime generation (small size)" {
    const F = Ffx(128);
    var prng = std.Random.DefaultPrng.init(55);
    const rng = prng.random();

    const p = try F.generateSafePrime(rng, 96);
    try std.testing.expectEqual(@as(usize, 96), F.bitLength(p));
    try std.testing.expect(try F.isProbablePrime(p, rng));
    // q = (p-1)/2 must be prime
    var q = F.sub(p, F.fromU64(1));
    var carry: u8 = 0;
    for (&q) |*b| {
        const next: u8 = b.* & 1;
        b.* = (carry << 7) | (b.* >> 1);
        carry = next;
    }
    try std.testing.expect(try F.isProbablePrime(q, rng));
}

test "jacobi symbol matches Euler criterion on primes" {
    const F = Ffx(256);
    var prng = std.Random.DefaultPrng.init(6);
    const rng = prng.random();

    for (vectors.blum256) |hex| {
        const p = F.fromHex(hex);
        const m = try F.Modulus.fromBytes(&p, .big);
        // exponent (p-1)/2
        var e = F.sub(p, F.fromU64(1));
        var carry: u8 = 0;
        for (&e) |*b| {
            const next: u8 = b.* & 1;
            b.* = (carry << 7) | (b.* >> 1);
            carry = next;
        }
        for (0..8) |_| {
            const a = F.sampleBetween2AndBound(rng, p);
            const j = F.jacobi(a, p);
            const a_fe = try F.Fe.fromBytes(m, &a, .big);
            const r = try m.powWithEncodedExponent(a_fe, &e, .big);
            var r_bytes: F.Bytes = undefined;
            try r.toBytes(&r_bytes, .big);
            const euler: i2 = if (F.cmp(r_bytes, F.fromU64(1)) == .eq) 1 else -1;
            try std.testing.expectEqual(euler, j);
        }
    }
}

test "invertGeneral agrees with invertOdd and works for even moduli" {
    const F = Ffx(256);
    var prng = std.Random.DefaultPrng.init(17);
    const rng = prng.random();

    // odd moduli: must agree with the binary xgcd
    for (vectors.inv256) |v| {
        const x = F.fromHex(v[0]);
        const m = F.fromHex(v[1]);
        const expected = F.fromHex(v[2]);
        try std.testing.expectEqualSlices(u8, &expected, &(try F.invertGeneral(x, m)));
    }

    // even modulus: x odd, m even, gcd 1 -> x * x^-1 mod m == 1
    for (0..8) |_| {
        var m = F.sampleBits(rng, 200);
        m[F.num_bytes - 1] &= 0xfe; // force even
        if (F.bitLength(m) < 10) continue;
        var x = F.sampleBelow(rng, m);
        x[F.num_bytes - 1] |= 1; // odd
        if (!F.isCoprime(x, m)) continue;
        const inv = try F.invertGeneral(x, m);
        const prod = F.mulWide(x, inv);
        const red = try Ffx(512).divRem(prod, F.widen(Ffx(512), m));
        try std.testing.expectEqualSlices(u8, &Ffx(512).fromU64(1), &red.r);
    }
}

test "sqrtFloor" {
    const F = Ffx(256);
    var prng = std.Random.DefaultPrng.init(23);
    const rng = prng.random();

    try std.testing.expectEqualSlices(u8, &F.fromU64(0), &F.sqrtFloor(F.fromU64(0)));
    try std.testing.expectEqualSlices(u8, &F.fromU64(4), &F.sqrtFloor(F.fromU64(16)));
    try std.testing.expectEqualSlices(u8, &F.fromU64(4), &F.sqrtFloor(F.fromU64(24)));

    for (0..8) |_| {
        const a = F.sampleBits(rng, 250);
        const s = F.sqrtFloor(a);
        // s² <= a < (s+1)²
        const F2 = Ffx(512);
        const s2 = F.mulWide(s, s);
        try std.testing.expect(F2.cmp(s2, F.widen(F2, a)) != .gt);
        var s1 = s;
        _ = F.addInPlace(&s1, F.fromU64(1));
        const s12 = F.mulWide(s1, s1);
        try std.testing.expect(F2.cmp(s12, F.widen(F2, a)) == .gt);
    }
}

test "sampling bounds" {
    const F = Ffx(256);
    var prng = std.Random.DefaultPrng.init(31);
    const rng = prng.random();

    const bound = F.fromU64(1000);
    for (0..100) |_| {
        const s = F.sampleBelow(rng, bound);
        try std.testing.expect(F.cmp(s, bound) == .lt);
    }
    for (0..20) |_| {
        const s = F.sampleBits(rng, 200);
        try std.testing.expect(F.bitLength(s) <= 200);
    }
}
