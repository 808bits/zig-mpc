//! CGGMP24 zero-knowledge proof suite.

pub const common = @import("zk/common.zig");
pub const prm = @import("zk/prm.zig");
pub const blum_mod = @import("zk/blum_mod.zig");
pub const fac = @import("zk/fac.zig");
pub const elog = @import("zk/elog.zig");
pub const enc_elg = @import("zk/enc_elg.zig");
pub const aff_g = @import("zk/aff_g.zig");

test {
    _ = common;
    _ = prm;
    _ = blum_mod;
    _ = fac;
    _ = elog;
    _ = enc_elg;
    _ = aff_g;
}
