//! Turning a runtime `--suite` string into the comptime types the library
//! needs.
//!
//! Every protocol in zig-mpc is generic over a curve, and CGGMP24 is
//! additionally generic over a Paillier/ZK parameter set. Those are comptime
//! parameters: `Dkg(E)`, `Frost(Suite)`, `Ecdsa(P, E)` are distinct types, so
//! the CLI cannot pick them at runtime. It instead switches once, at the top
//! of a command, with `inline else` - giving each prong a comptime-known
//! suite - and calls a generic implementation from there.
//!
//! The suite is recorded in every frame header, so two parties running
//! different curves or parameter sets fail immediately with a clear mismatch
//! rather than a length error deep inside a proof.

const std = @import("std");
const mpc = @import("zig_mpc");
const frame = @import("frame.zig");

pub const Suite = frame.Suite;

/// The curve a suite signs on.
pub fn CurveOf(comptime s: Suite) type {
    return switch (s) {
        .ed25519 => mpc.curve.Ed25519,
        .secp256k1, .taproot, .ecdsa_fast, .ecdsa_prod, .dkls => mpc.curve.Secp256k1,
        .p256 => mpc.curve.P256,
        .p384 => mpc.curve.P384,
    };
}

/// The FROST ciphersuite, for the three suites that have one. P-256 and P-384
/// have no published FROST ciphersuite here, so they are keygen-only.
pub fn FrostSuiteOf(comptime s: Suite) ?type {
    return switch (s) {
        .ed25519 => mpc.frost.Ed25519Sha512,
        .secp256k1 => mpc.frost.Secp256k1Sha256,
        .taproot => mpc.bip340.FrostTaprootSuite,
        else => null,
    };
}

/// CGGMP24 parameter presets.
///
/// Three constraints pin these down:
///
///   * ℓ ≥ 256, because signing encrypts full curve scalars (see the note in
///     `src/ecdsa.zig`'s end-to-end test).
///   * ε ≥ bits(q) + ℓ + margin for the curve-linked proofs Πenc-elg and
///     Πaff-g, whose challenges are curve-order sized - hence ε = 384/512
///     rather than something small.
///   * n_bits − 1 ≥ 4ℓ, enforced by Πfac's verifier. p·q can come out one bit
///     short of 2·prime_bits, so with ℓ = 256 the smallest workable prime
///     size is 513 bits; 576 leaves room.
///
/// The last one is why `ecdsa_fast` uses 576-bit primes and not the 320-bit
/// ones in `src/ecdsa.zig`'s own end-to-end test: that test hands each party
/// a locally generated Paillier key and never runs aux-info generation, so it
/// never meets Πfac.
///
/// `ecdsa_fast` is a speed setting for testing and demos, NOT a security
/// level. `ecdsa_prod` is the 2048-bit Paillier modulus a deployment wants.
pub fn ParamsOf(comptime s: Suite) ?type {
    return switch (s) {
        .ecdsa_fast => mpc.zk.common.Params(576, 256, 512, 384),
        .ecdsa_prod => mpc.zk.common.Params(1024, 256, 512, 512),
        else => null,
    };
}

pub fn repetitionsOf(comptime s: Suite) comptime_int {
    return switch (s) {
        .ecdsa_fast => 16,
        .ecdsa_prod => 80,
        else => 0,
    };
}

/// Whether aux-info generation should use safe primes. The reference
/// implementation does; the fast preset skips them because generating four
/// safe primes dominates the runtime.
pub fn safePrimesOf(comptime s: Suite) bool {
    return s == .ecdsa_prod;
}

pub fn isCggmp(s: Suite) bool {
    return s == .ecdsa_fast or s == .ecdsa_prod;
}

/// Whether `zmpc sign` (FROST) applies. DKLs23 and CGGMP24 sign ECDSA through
/// their own commands instead.
pub fn canSign(s: Suite) bool {
    return switch (s) {
        .ed25519, .secp256k1, .taproot => true,
        else => false,
    };
}

pub fn isDkls(s: Suite) bool {
    return s == .dkls;
}

pub fn parse(text: []const u8) ?Suite {
    return std.meta.stringToEnum(Suite, text);
}

pub const names = "ed25519 | secp256k1 | taproot | p256 | p384 | ecdsa_fast | ecdsa_prod | dkls";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "suites map to curves and capabilities" {
    try testing.expectEqual(Suite.taproot, parse("taproot").?);
    try testing.expect(parse("nonsense") == null);

    try testing.expect(CurveOf(.ed25519) == mpc.curve.Ed25519);
    try testing.expect(CurveOf(.taproot) == mpc.curve.Secp256k1);
    try testing.expect(CurveOf(.ecdsa_prod) == mpc.curve.Secp256k1);

    try testing.expect(FrostSuiteOf(.p256) == null);
    try testing.expect(FrostSuiteOf(.secp256k1).? == mpc.frost.Secp256k1Sha256);

    try testing.expect(ParamsOf(.ed25519) == null);
    try testing.expectEqual(@as(comptime_int, 1024), ParamsOf(.ecdsa_prod).?.prime_bits);
    try testing.expectEqual(@as(comptime_int, 2048), ParamsOf(.ecdsa_prod).?.n_bits);

    try testing.expect(isCggmp(.ecdsa_fast));
    try testing.expect(!isCggmp(.secp256k1));
    try testing.expect(canSign(.ed25519) and !canSign(.p384));
    try testing.expect(safePrimesOf(.ecdsa_prod) and !safePrimesOf(.ecdsa_fast));
}

test "every suite resolves through an inline switch" {
    // This is the dispatch pattern the commands use; if any suite failed to
    // monomorphize, this would not compile.
    inline for (comptime std.enums.values(Suite)) |s| {
        const E = CurveOf(s);
        try testing.expect(E.Point.encoded_length >= 32);
    }
}
