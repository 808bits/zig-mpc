//! zig-mpc: threshold signing (ECDSA via CGGMP24, Schnorr/EdDSA via FROST)
//! built on the Zig standard library's cryptographic primitives.

pub const abort = @import("abort.zig");
pub const curve = @import("curve.zig");
pub const dkls = @import("dkls.zig");
pub const transcript = @import("transcript.zig");
pub const message = @import("message.zig");
pub const vss = @import("vss.zig");
pub const frost = @import("frost.zig");
pub const dkg = @import("dkg.zig");
pub const bip340 = @import("bip340.zig");
pub const ffx = @import("ffx.zig");
pub const paillier = @import("paillier.zig");
pub const zk = @import("zk.zig");
pub const auxgen = @import("auxgen.zig");
pub const ecdsa = @import("ecdsa.zig");
pub const refresh = @import("refresh.zig");
pub const hd = @import("hd.zig");
pub const serde = @import("serde.zig");
/// Cross-generated Paillier vectors, exposed so `zmpc selftest` can re-run
/// them against the shipped binary.
pub const testdata_paillier = @import("testdata/paillier_vectors.zig");

test {
    _ = abort;
    // dkls is tested by its own optimized target; see build.zig.
    _ = serde;
    _ = ecdsa;
    _ = refresh;
    _ = hd;
    _ = ffx;
    _ = paillier;
    _ = zk;
    _ = auxgen;
    _ = curve;
    _ = transcript;
    _ = vss;
    _ = frost;
    _ = dkg;
    _ = bip340;
}
