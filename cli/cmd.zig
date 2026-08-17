//! Shared plumbing for every zmpc command: output streams, RNG, exit codes,
//! and the small helpers commands keep needing.

const std = @import("std");
const mpc = @import("zig_mpc");
const frame = @import("frame.zig");
const help = @import("help.zig");
const session = @import("session.zig");

const Allocator = std.mem.Allocator;

/// Exit codes, chosen so shell scripts can react without parsing messages.
pub const Exit = struct {
    pub const ok: u8 = 0;
    pub const internal: u8 = 1;
    pub const usage: u8 = 2;
    /// A file was missing, unreadable, or not what it claimed to be.
    pub const bad_input: u8 = 64;
    /// The protocol aborted: an invalid proof, share, or signature.
    pub const protocol: u8 = 65;
    /// Not an error - messages from peers have not arrived yet. Retry later.
    pub const waiting: u8 = 75;
};

pub const Ctx = struct {
    io: std.Io,
    gpa: Allocator,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    rng: std.Random,
    /// `ZMPC_DIR`, if it is set to something non-empty: the session directory
    /// to use when `--dir` is absent. Set it once per shell and every command
    /// for that party gets shorter.
    dir_from_env: ?[]const u8 = null,
    /// Write frames as base64 text rather than binary.
    armor: bool = false,
    /// Machine-readable output on stdout; human text goes to stderr.
    json: bool = false,
    quiet: bool = false,
    /// Set when a driver (`zmpc node`) is polling in a loop, so "still
    /// waiting" is the expected state rather than something to act on.
    polling: bool = false,

    pub fn env(self: Ctx) session.Env {
        return .{ .io = self.io, .gpa = self.gpa };
    }

    /// Human-facing progress. Suppressed by `--quiet`, and routed to stderr
    /// under `--json` so stdout stays parseable.
    pub fn note(self: Ctx, comptime fmt: []const u8, args: anytype) !void {
        if (self.quiet) return;
        const w = if (self.json) self.err else self.out;
        try w.print(fmt, args);
    }

    /// The result of a command: the thing a script wants to capture.
    pub fn emit(self: Ctx, comptime fmt: []const u8, args: anytype) !void {
        try self.out.print(fmt, args);
    }

    pub fn warn(self: Ctx, comptime fmt: []const u8, args: anytype) !void {
        try self.err.print(fmt, args);
    }
};

/// Print a command's whole help page and return the usage exit code.
///
/// Reached whenever a command was given too little to act on: no step, or a
/// missing, misspelled or malformed option. Someone in that position wants to
/// see every option, not to rediscover them one error at a time, so this
/// prints the same page `zmpc <command> --help` does. It goes to stderr,
/// because it accompanies a failure and must not land in output a script is
/// capturing.
pub fn usagePage(ctx: Ctx, command: []const u8) !u8 {
    if (help.page(command)) |text| {
        try ctx.err.writeAll(text);
        try ctx.err.writeAll("\n");
    }
    return Exit.usage;
}

/// Decode hex into a fixed-size buffer, requiring exactly `out.len` bytes.
///
/// std.fmt.hexToBytes tolerates short input: it fills only a leading prefix
/// and returns a shorter slice, leaving the tail of `out` uninitialized. For
/// key material and public keys that silently signs under (or verifies
/// against) stack garbage, so every fixed-size hex input must go through here.
pub fn hexExact(out: []u8, text: []const u8) !void {
    const decoded = std.fmt.hexToBytes(out, text) catch return error.InvalidHex;
    if (decoded.len != out.len) return error.InvalidHex;
}

/// Read a message to sign: raw bytes from a file, or hex on the command line.
pub fn readMessage(ctx: Ctx, msg_file: ?[]const u8, msg_hex: ?[]const u8) ![]const u8 {
    if (msg_file) |path| {
        return std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 24));
    }
    if (msg_hex) |text| {
        const out = try ctx.gpa.alloc(u8, text.len / 2);
        return std.fmt.hexToBytes(out, text) catch error.InvalidHex;
    }
    return error.NoMessage;
}

pub fn readFileBytes(ctx: Ctx, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(session.max_file_bytes));
}

/// Load a frame from a path, transparently handling the armored form.
pub fn readFrame(ctx: Ctx, path: []const u8) !frame.Frame {
    const raw = try readFileBytes(ctx, path);
    const bytes = if (frame.isArmored(raw)) try frame.dearmor(ctx.gpa, raw) else raw;
    return frame.parse(bytes);
}

/// Load an artifact (key share, aux info, presignature) and decode it.
pub fn readArtifact(ctx: Ctx, comptime T: type, path: []const u8, kind: frame.Kind) !struct {
    value: T,
    header: frame.Header,
} {
    const f = try readFrame(ctx, path);
    if (f.header.kind != kind) return error.WrongArtifactKind;
    return .{
        .value = try mpc.serde.decodeSlice(T, f.payload, .{ .gpa = ctx.gpa }),
        .header = f.header,
    };
}

pub fn hex(gpa: Allocator, bytes: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{x}", .{bytes});
}

/// Report the frames a round is still waiting for, in a form an operator can
/// act on. Returns the `waiting` exit code.
pub fn reportMissing(ctx: Ctx, missing: []const session.Requirement) !u8 {
    return reportMissingWith(ctx, missing, &.{});
}

/// As `reportMissing`, but also names inbox files that could not be read -
/// otherwise a corrupted frame is indistinguishable from a missing one.
pub fn reportMissingWith(
    ctx: Ctx,
    missing: []const session.Requirement,
    rejected: []const []const u8,
) !u8 {
    if (rejected.len > 0) {
        try ctx.warn("{d} file(s) in in/ could not be read as frames:\n", .{rejected.len});
        for (rejected) |name| try ctx.warn("  {s}  (corrupt, truncated, or a different format)\n", .{name});
        try ctx.warn("ask the sender to resend them\n", .{});
    }
    // Under `zmpc node` this is just the polling loop doing its job; one line
    // is plenty, and the "go copy some files" advice would be wrong.
    if (ctx.polling) {
        if (!ctx.quiet) try ctx.warn("waiting for {d} message(s)...\n", .{missing.len});
        return Exit.waiting;
    }
    try ctx.warn("waiting for {d} message(s):\n", .{missing.len});
    for (missing) |req| {
        switch (req.channel) {
            .broadcast => try ctx.warn(
                "  round {d} broadcast from party {d}\n",
                .{ req.round, req.from },
            ),
            .p2p => try ctx.warn(
                "  round {d} p2p from party {d} to party {d}\n",
                .{ req.round, req.from, req.to },
            ),
            .artifact => {},
        }
    }
    try ctx.warn("copy those parties' out/ files into this session's in/ and run again\n", .{});
    return Exit.waiting;
}

/// Collect one message of type `T` from every participant other than `me`,
/// in ascending party order.
pub fn collectFrom(
    ctx: Ctx,
    comptime T: type,
    inbox: session.Inbox,
    round: u16,
    channel: frame.Channel,
    participants: []const u16,
    me: u16,
) ![]mpc.message.From(T) {
    const out = try ctx.gpa.alloc(mpc.message.From(T), participants.len - 1);
    var k: usize = 0;
    for (participants) |j| {
        if (j == me) continue;
        const req = session.Requirement{
            .round = round,
            .channel = channel,
            .from = j,
            .to = if (channel == .p2p) me else 0,
        };
        out[k] = .{ .from = j, .msg = try inbox.decode(T, req) };
        k += 1;
    }
    return out;
}

/// Seed a userspace CSPRNG from the OS. Kept in one place so every command
/// draws key material the same way.
pub fn seedRng(io: std.Io, csprng: *std.Random.DefaultCsprng) !void {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try io.randomSecure(&seed);
    csprng.* = std.Random.DefaultCsprng.init(seed);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "hex formatting" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualStrings("00ff10", try hex(arena, &.{ 0, 255, 16 }));
}
