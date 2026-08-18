//! `zmpc refresh` - proactive re-randomization of the key shares.
//!
//! Every party deals a sharing of zero and adds it to its own share. The
//! secret and the public key are unchanged, but every share is new, so an
//! attacker who collected shares from fewer than t parties before the refresh
//! is left with nothing usable.
//!
//!   round1    commit to a zero-sharing polynomial                [broadcast]
//!   round2    open it; send each peer its piece                 [bc + p2p]
//!   finalize  verify, add the pieces in, rewrite the share
//!
//! On success the key share file is replaced and the previous one is kept
//! alongside it with a `.old` suffix. Deleting that copy is the point of the
//! exercise - keep it only until every party has confirmed success, because
//! a mix of refreshed and stale shares cannot sign.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const dkg_cmd = @import("dkg.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub fn run(ctx: cmd.Ctx, s: *session.Session, step: ?u16, share_override: ?[]const u8) !u8 {
    return switch (s.suite) {
        inline else => |tag| runFor(suite_mod.CurveOf(tag), ctx, s, step, share_override),
    };
}

pub fn runAll(ctx: cmd.Ctx, s: *session.Session, share_override: ?[]const u8) !u8 {
    while (!s.manifest.complete) {
        const code = try run(ctx, s, null, share_override);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

fn runFor(
    comptime E: type,
    ctx: cmd.Ctx,
    s: *session.Session,
    step: ?u16,
    share_override: ?[]const u8,
) !u8 {
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => round1(E, ctx, s, share_override),
        2 => round2(E, ctx, s),
        3 => finalize(E, ctx, s, share_override),
        else => {
            try ctx.warn("refresh has rounds 1 and 2 plus finalize (3); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

fn round1(comptime E: type, ctx: cmd.Ctx, s: *session.Session, share_override: ?[]const u8) !u8 {
    const R = mpc.refresh.Refresh(E);

    const loaded = try cmd.loadKeyShare(E, ctx, s, share_override);
    const result = try R.round1(
        ctx.gpa,
        loaded.share,
        mpc.refresh.ExecutionId.fromBytes(s.id),
        ctx.rng,
    );

    _ = try s.emit(R.Round1Broadcast, result.broadcast, s.msgHeader(1, .broadcast, 0), ctx.armor);
    try s.saveState(R.State1, result.state, 1);
    try s.advance(1);

    try ctx.note("round 1: committed to a zero-sharing\n", .{});
    return cmd.Exit.ok;
}

fn round2(comptime E: type, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const R = mpc.refresh.Refresh(E);

    const gathered = try cmd.gather(ctx, s, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(R.State1, 1);
    const incoming = try cmd.collectFrom(
        ctx,
        R.Round1Broadcast,
        inbox,
        1,
        .broadcast,
        try s.participants(),
        s.manifest.party,
    );

    const result = try R.round2(state, incoming);

    _ = try s.emit(R.Round2Broadcast, result.broadcast, s.msgHeader(2, .broadcast, 0), ctx.armor);
    for (result.p2p) |out| {
        _ = try s.emit(R.Round2P2p, out.msg, s.msgHeader(2, .p2p, out.to), ctx.armor);
    }
    try s.saveState(R.State2, result.state, 2);
    try s.advance(2);

    try ctx.note("round 2: sent {d} zero-share piece(s)\n", .{result.p2p.len});
    return cmd.Exit.ok;
}

fn finalize(comptime E: type, ctx: cmd.Ctx, s: *session.Session, share_override: ?[]const u8) !u8 {
    const D = mpc.dkg.Dkg(E);
    const R = mpc.refresh.Refresh(E);

    const gathered = try cmd.gather(ctx, s, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(R.State2, 2);
    const bc = try cmd.collectFrom(
        ctx,
        R.Round2Broadcast,
        inbox,
        2,
        .broadcast,
        try s.participants(),
        s.manifest.party,
    );
    const p2p = try cmd.collectFrom(
        ctx,
        R.Round2P2p,
        inbox,
        2,
        .p2p,
        try s.participants(),
        s.manifest.party,
    );

    const loaded = try cmd.loadKeyShare(E, ctx, s, share_override);
    var share = loaded.share;
    const pk_before = share.public_key;
    const old_secret = share.secret_share;

    R.finalize(state, &share, bc, p2p) catch |err| {
        const code = try cmd.protocolAbort(ctx, "refresh", err, null);
        try ctx.warn("the key share on disk is unchanged\n", .{});
        return code;
    };

    // The whole point: same key, different share.
    if (!share.public_key.eql(pk_before)) {
        try ctx.warn("BUG: the public key changed during refresh; refusing to write\n", .{});
        return cmd.Exit.internal;
    }
    if (share.secret_share.eql(old_secret)) {
        try ctx.warn("BUG: the share did not change; refusing to write\n", .{});
        return cmd.Exit.internal;
    }

    // Keep the previous share until the operator is sure every party made it
    // through - a mix of refreshed and stale shares cannot sign.
    const backup = try std.fmt.allocPrint(ctx.gpa, "{s}.old", .{loaded.path});
    const previous = try cmd.readFileBytes(ctx, loaded.path);
    // The backup holds a live secret share (t of them still reconstruct the
    // group key until every party refreshes), so it must be 0600 like the
    // original and the new share below, not left world-readable under the
    // default umask.
    try std.Io.Dir.cwd().writeFile(ctx.io, .{
        .sub_path = backup,
        .data = previous,
        .flags = .{ .permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
            .fromMode(0o600)
        else
            .default_file },
    });

    const payload = try mpc.serde.encodeAlloc(D.KeyShare, share, ctx.gpa);
    const bytes = try frame.encodeAlloc(ctx.gpa, .{
        .kind = .key_share,
        .channel = .artifact,
        .protocol = .none,
        .suite = s.suite,
        .from = share.party,
        .n_parties = share.n,
        .threshold = share.threshold,
        .session = s.id,
    }, payload);
    try std.Io.Dir.cwd().writeFile(ctx.io, .{
        .sub_path = loaded.path,
        .data = bytes,
        .flags = .{ .permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
            .fromMode(0o600)
        else
            .default_file },
    });

    try s.advance(3);
    try s.finish();
    for (1..3) |round| try s.consumeState(@intCast(round));

    try ctx.note("share refreshed in place: {s}\n", .{loaded.path});
    try ctx.note("previous share kept at {s}; delete it once every party has\n", .{backup});
    try ctx.note("finished - old and new shares cannot be mixed\n", .{});
    if (ctx.json) {
        try ctx.emit("{{\"public_key\":\"{x}\",\"refreshed\":true,\"backup\":\"{s}\"}}\n", .{
            &share.public_key.toBytes(), backup,
        });
    } else {
        try ctx.emit("{x}\n", .{&share.public_key.toBytes()});
    }
    return cmd.Exit.ok;
}
