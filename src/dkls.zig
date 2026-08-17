//! DKLs23 threshold ECDSA (<https://eprint.iacr.org/2023/765.pdf>).
//!
//! Ported from 0xCarbon's MIT/Apache-licensed `dkls23-core`. Unlike CGGMP24 in
//! `ecdsa.zig`, this route is oblivious-transfer based: no Paillier, no RSA
//! modulus, and no `auxgen` ceremony. What it needs instead is a one-time
//! pairwise setup (`setup.zig`) that establishes base-OT seeds and zero-share
//! seeds between every pair of parties; those are then reused across signings.
//!
//! Layering, bottom up:
//!
//!   hash.zig       the random oracles, and commitments built on them
//!   proofs.zig     Schnorr via randomized Fischlin, and the OR-composed
//!                  encryption proof the base OT needs
//!   ot.zig         endemic base OT (eprint 2022/1525)
//!   ote.zig        KOS OT extension, with SoftSpokenOT's fix
//!   mul.zig        two-party multiplication (random vector OLE)
//!   zeroshare.zig  pairwise-seeded shares of zero
//!   setup.zig      the one-time pairwise setup, run after DKG
//!   sign.zig       the four signing phases of Protocol 3.6

pub const hash = @import("dkls/hash.zig");
pub const proofs = @import("dkls/proofs.zig");
pub const ot = @import("dkls/ot.zig");
pub const ote = @import("dkls/ote.zig");
pub const mul = @import("dkls/mul.zig");
pub const zeroshare = @import("dkls/zeroshare.zig");
pub const sign = @import("dkls/sign.zig");
pub const setup = @import("dkls/setup.zig");

test {
    _ = hash;
    _ = proofs;
    _ = ot;
    _ = ote;
    _ = mul;
    _ = zeroshare;
    _ = sign;
    _ = setup;
}
