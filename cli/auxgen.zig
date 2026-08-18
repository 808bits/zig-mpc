//! `zmpc auxgen` - CGGMP24 auxiliary-info generation.
//!
//! Before any ECDSA presigning can happen, every party needs a Paillier key
//! and ring-Pedersen parameters, and every other party needs to have checked
//! that those are well formed. Three rounds plus a finalize:
//!
//!   round1  commit to (N, N̂, s, t, Πprm, ρ_i)                    [broadcast]
//!   round2  open the commitment                                  [broadcast]
//!   round3  prove N is a Blum modulus (Πmod), and prove to each
//!           peer that N has no small factors (Πfac)                    [p2p]
//!   finalize check every proof, emit the aux-info artifact
//!
//! This runs among *all* parties, indexed by party number, and the result is
//! reusable: any later signing subset selects the entries it needs.
//!
//! Generating the primes is by far the slowest step - at `ecdsa_prod` sizes
//! it means four safe 1024-bit primes, which takes minutes. `zmpc auxgen
//! primes` does that once, offline, so retries never repeat the work.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub const aux_info_file = "auxinfo.zmpc";
pub const primes_file = "primes.zmpc";

pub fn run(ctx: cmd.Ctx, s: *session.Session, step: ?u16, primes_path: ?[]const u8) !u8 {
    return switch (s.suite) {
        inline .ecdsa_fast, .ecdsa_prod => |tag| runFor(tag, ctx, s, step, primes_path),
        else => {
            try ctx.warn(
                "aux-info generation is only for the CGGMP24 suites " ++
                    "(ecdsa_fast, ecdsa_prod); this session uses '{t}'\n",
                .{s.suite},
            );
            return cmd.Exit.usage;
        },
    };
}

pub fn runAll(ctx: cmd.Ctx, s: *session.Session, primes_path: ?[]const u8) !u8 {
    while (!s.manifest.complete) {
        const code = try run(ctx, s, null, primes_path);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

fn AuxOf(comptime tag: suite_mod.Suite) type {
    return mpc.auxgen.AuxGen(suite_mod.ParamsOf(tag).?, suite_mod.repetitionsOf(tag));
}

fn runFor(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    step: ?u16,
    primes_path: ?[]const u8,
) !u8 {
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => round1(tag, ctx, s, primes_path),
        2 => round2(tag, ctx, s),
        3 => round3(tag, ctx, s),
        4 => finalize(tag, ctx, s),
        else => {
            try ctx.warn("auxgen has rounds 1..3 plus finalize (4); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

// ---------------------------------------------------------------------------
// prime generation (offline)
// ---------------------------------------------------------------------------

/// Generate the four primes a party needs, as a standalone artifact.
pub fn generatePrimes(ctx: cmd.Ctx, st: suite_mod.Suite, out_path: []const u8) !u8 {
    return switch (st) {
        inline .ecdsa_fast, .ecdsa_prod => |tag| blk: {
            const A = AuxOf(tag);
            const safe = comptime suite_mod.safePrimesOf(tag);
            const bits = comptime suite_mod.ParamsOf(tag).?.prime_bits;

            try ctx.note(
                "generating four {d}-bit {s} primes; this is the slow part\n",
                .{ bits, if (safe) "safe" else "Blum" },
            );

            var primes = try A.Primes.generate(ctx.rng, safe);
            defer primes.zeroize();

            const payload = try mpc.serde.encodeAlloc(A.Primes, primes, ctx.gpa);
            const bytes = try frame.encodeAlloc(ctx.gpa, .{
                .kind = .primes,
                .channel = .artifact,
                .protocol = .auxgen,
                .suite = st,
                .session = @splat(0),
            }, payload);
            try std.Io.Dir.cwd().writeFile(ctx.io, .{
                .sub_path = out_path,
                .data = bytes,
                .flags = .{ .permissions = secretPermissions() },
            });

            try ctx.note("primes written to {s}\n", .{out_path});
            try ctx.emit("{s}\n", .{out_path});
            break :blk cmd.Exit.ok;
        },
        else => {
            try ctx.warn("--suite must be ecdsa_fast or ecdsa_prod\n", .{});
            return cmd.Exit.usage;
        },
    };
}

fn secretPermissions() std.Io.File.Permissions {
    return if (@hasDecl(std.Io.File.Permissions, "fromMode"))
        .fromMode(0o600)
    else
        .default_file;
}

fn loadOrMakePrimes(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    primes_path: ?[]const u8,
) !AuxOf(tag).Primes {
    const A = AuxOf(tag);

    // An explicitly named file must work. Falling back to generation would
    // silently cost minutes of safe-prime search and use parameters the
    // operator did not choose.
    if (primes_path) |path| {
        const f = cmd.readFrame(ctx, path) catch |e| {
            try ctx.warn("cannot read --primes '{s}': {t}\n", .{ path, e });
            return error.Reported;
        };
        if (f.header.kind != .primes) {
            try ctx.warn("'{s}' is not a primes file\n", .{path});
            return error.Reported;
        }
        if (f.header.suite != s.suite) {
            try ctx.warn(
                "'{s}' holds {t} primes but this session is {t}\n",
                .{ path, f.header.suite, s.suite },
            );
            return error.Reported;
        }
        try ctx.note("using pre-generated primes from {s}\n", .{path});
        return mpc.serde.decodeSlice(A.Primes, f.payload, .{ .gpa = ctx.gpa });
    }

    // Otherwise: reuse what this session cached on an earlier attempt, if any.
    const cached = try s.artifactPath(primes_file);
    if (cmd.readFrame(ctx, cached)) |f| {
        if (f.header.kind == .primes and f.header.suite == s.suite) {
            try ctx.note("reusing the primes cached in {s}\n", .{cached});
            return mpc.serde.decodeSlice(A.Primes, f.payload, .{ .gpa = ctx.gpa });
        }
    } else |_| {}

    const safe = comptime suite_mod.safePrimesOf(tag);
    try ctx.note(
        "generating four {d}-bit {s} primes (run `zmpc auxgen primes` " ++
            "beforehand to avoid repeating this)\n",
        .{ comptime suite_mod.ParamsOf(tag).?.prime_bits, if (safe) "safe" else "Blum" },
    );
    const primes = try A.Primes.generate(ctx.rng, safe);

    // Cache them so a failed round can be retried without paying again.
    const payload = try mpc.serde.encodeAlloc(A.Primes, primes, ctx.gpa);
    const bytes = try frame.encodeAlloc(ctx.gpa, .{
        .kind = .primes,
        .channel = .artifact,
        .protocol = .auxgen,
        .suite = s.suite,
        .session = s.id,
    }, payload);
    try std.Io.Dir.cwd().writeFile(ctx.io, .{
        .sub_path = try s.artifactPath(primes_file),
        .data = bytes,
        .flags = .{ .permissions = secretPermissions() },
    });
    return primes;
}

// ---------------------------------------------------------------------------
// rounds
// ---------------------------------------------------------------------------

fn round1(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    primes_path: ?[]const u8,
) !u8 {
    const A = AuxOf(tag);
    var primes = try loadOrMakePrimes(tag, ctx, s, primes_path);
    defer primes.zeroize();

    const result = try A.round1(
        s.manifest.party,
        s.manifest.n_parties,
        mpc.auxgen.ExecutionId.fromBytes(s.id),
        primes,
        ctx.rng,
    );

    _ = try s.emit(A.Round1Broadcast, result.broadcast, s.msgHeader(1, .broadcast, 0), ctx.armor);
    try s.saveState(A.State1, result.state, 1);
    try s.advance(1);

    try ctx.note("round 1: committed to Paillier and ring-Pedersen parameters\n", .{});
    return cmd.Exit.ok;
}

fn round2(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const A = AuxOf(tag);

    const gathered = try cmd.gather(ctx, s, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(A.State1, 1);
    const incoming = try cmd.collectFrom(
        ctx,
        A.Round1Broadcast,
        inbox,
        1,
        .broadcast,
        try s.participants(),
        s.manifest.party,
    );

    const result = try A.round2(ctx.gpa, state, incoming);

    _ = try s.emit(A.Round2Broadcast, result.broadcast, s.msgHeader(2, .broadcast, 0), ctx.armor);
    try s.saveState(A.State2, result.state, 2);
    try s.advance(2);

    try ctx.note("round 2: opened commitment\n", .{});
    return cmd.Exit.ok;
}

fn round3(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const A = AuxOf(tag);

    const gathered = try cmd.gather(ctx, s, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(A.State2, 2);
    const incoming = try cmd.collectFrom(
        ctx,
        A.Round2Broadcast,
        inbox,
        2,
        .broadcast,
        try s.participants(),
        s.manifest.party,
    );

    const result = A.round3(state, ctx.rng, incoming) catch |err| return cmd.protocolAbort(ctx, "aux-info generation", err, null);

    for (result.p2p) |out| {
        _ = try s.emit(A.Round3P2p, out.msg, s.msgHeader(3, .p2p, out.to), ctx.armor);
    }
    try s.saveState(A.State3, result.state, 3);
    try s.advance(3);

    try ctx.note("round 3: everyone's parameters check out; sent {d} proof set(s)\n", .{result.p2p.len});
    return cmd.Exit.ok;
}

fn finalize(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const A = AuxOf(tag);

    const gathered = try cmd.gather(ctx, s, 4);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(A.State3, 3);
    const incoming = try cmd.collectFrom(
        ctx,
        A.Round3P2p,
        inbox,
        3,
        .p2p,
        try s.participants(),
        s.manifest.party,
    );

    const info = A.finalize(state, ctx.rng, incoming) catch |err| return cmd.protocolAbort(ctx, "aux-info generation", err, null);

    const path = try s.saveArtifact(A.AuxInfo, info, aux_info_file, .aux_info, true);
    try s.advance(4);
    try s.finish();
    for (1..4) |round| try s.consumeState(@intCast(round));

    try ctx.note("aux-info complete; written to {s}\n", .{path});
    if (ctx.json) {
        try ctx.emit("{{\"aux_info\":\"{s}\",\"party\":{d},\"parties\":{d},\"rho\":\"{x}\"}}\n", .{
            path, info.party, info.n_parties, &info.rho,
        });
    } else {
        try ctx.emit("{s}\n", .{path});
    }
    return cmd.Exit.ok;
}
