//! `zmpc relay`, `zmpc push`, `zmpc pull`, `zmpc node` - the optional network
//! transport.
//!
//! The relay is a dumb store-and-forward spool. It parses only the frame
//! header - enough to know the session, the sender and the recipient - and
//! never looks at a payload. Frames land in a spool directory under the same
//! filenames a session's `out/` uses, so the spool *is* a session directory's
//! worth of frames: you can copy it into a party's `in/` and carry on with the
//! file commands, or copy a file-mode `out/` into the spool and carry on over
//! the network. The transport is genuinely interchangeable.
//!
//! One connection carries one request, then closes. Parties poll. That keeps
//! the relay single-threaded and restartable, and means a party that was
//! offline simply picks up what is waiting when it returns.
//!
//! ## What the relay is not
//!
//! It provides no confidentiality and no authenticity. DKG and refresh send
//! secret VSS shares point-to-point, so a relay that reads them can break the
//! scheme outright, and one that lies about who sent what can equivocate -
//! which the protocols explicitly assume cannot happen. Run it inside a
//! WireGuard/TLS/SSH tunnel, or on a network you already trust with the key.

const std = @import("std");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");

const Dir = std.Io.Dir;
const net = std.Io.net;

/// Wire protocol between a party and the relay. Deliberately tiny: the relay
/// has no opinion about what it is carrying.
const Op = enum(u8) {
    /// party -> relay: here are frames to store and forward.
    push = 1,
    /// party -> relay: send me everything addressed to me.
    pull = 2,
};

const magic = "ZMPCRLY1";
const max_frame_bytes: u32 = 32 * 1024 * 1024;
const max_batch: u32 = 4096;

pub fn parseAddress(ctx: cmd.Ctx, text: []const u8) !net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse {
        try ctx.warn("--relay looks like HOST:PORT\n", .{});
        return error.Reported;
    };
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch {
        try ctx.warn("'{s}' is not a port number\n", .{text[colon + 1 ..]});
        return error.Reported;
    };
    var host = text[0..colon];
    // Allow [::1]:7000 for IPv6.
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    return net.IpAddress.parse(host, port) catch {
        try ctx.warn("cannot parse address '{s}'\n", .{text});
        return error.Reported;
    };
}

fn writeU32(w: *std.Io.Writer, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try w.writeAll(&buf);
}

fn readU32(r: *std.Io.Reader) !u32 {
    return std.mem.readInt(u32, try r.takeArray(4), .little);
}

// ---------------------------------------------------------------------------
// relay server
// ---------------------------------------------------------------------------

pub fn serve(ctx: cmd.Ctx, listen_text: []const u8, spool: []const u8) !u8 {
    const address = try parseAddress(ctx, listen_text);

    var server = address.listen(ctx.io, .{ .reuse_address = true }) catch |e| {
        try ctx.warn("cannot listen on {s}: {t}\n", .{ listen_text, e });
        return cmd.Exit.internal;
    };
    defer server.deinit(ctx.io);

    try Dir.cwd().createDirPath(ctx.io, spool);

    try ctx.warn("zmpc relay listening on {s}, spooling to {s}/\n", .{ listen_text, spool });
    try ctx.warn(
        "this relay sees every message in the clear and is trusted for delivery;\n" ++
            "run it over a tunnel you trust\n",
        .{},
    );
    try ctx.err.flush();

    while (true) {
        const stream = server.accept(ctx.io) catch |e| {
            try ctx.warn("accept failed: {t}\n", .{e});
            try ctx.err.flush();
            continue;
        };

        // Each connection gets its own arena, freed when it closes. The
        // process-wide arena the commands use is never reset, which is fine
        // for a one-shot command and a slow memory leak for a daemon that
        // buffers whole frames per request.
        var conn_arena = std.heap.ArenaAllocator.init(ctx.gpa);
        var conn_ctx = ctx;
        conn_ctx.gpa = conn_arena.allocator();

        handle(conn_ctx, stream, spool) catch |e| {
            try ctx.warn("connection error: {t}\n", .{e});
        };
        stream.close(ctx.io);
        conn_arena.deinit();
        try ctx.err.flush();
    }
}

fn handle(ctx: cmd.Ctx, stream: net.Stream, spool: []const u8) !void {
    var read_buf: [64 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var reader = stream.reader(ctx.io, &read_buf);
    var writer = stream.writer(ctx.io, &write_buf);
    const r = &reader.interface;
    const w = &writer.interface;

    if (!std.mem.eql(u8, magic, try r.takeArray(magic.len))) return error.NotARelayClient;
    const op = std.enums.fromInt(Op, try r.takeByte()) orelse return error.BadOp;
    const sid = (try r.takeArray(32)).*;
    const party = std.mem.readInt(u16, try r.takeArray(2), .little);

    const sid_hex = try session.hexId(ctx.gpa, sid);
    const dir = try session.join(ctx.gpa, &.{ spool, sid_hex });

    switch (op) {
        .push => {
            const count = try readU32(r);
            if (count > max_batch) return error.TooManyFrames;
            try Dir.cwd().createDirPath(ctx.io, dir);

            var stored: u32 = 0;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const len = try readU32(r);
                if (len > max_frame_bytes) return error.FrameTooLarge;
                const bytes = try ctx.gpa.alloc(u8, len);
                try r.readSliceAll(bytes);

                // Parse only the header: enough to route the frame, not
                // enough to learn anything about the payload.
                const peek = frame.peekHeader(bytes) catch continue;
                if (!std.mem.eql(u8, &peek.header.session, &sid)) continue;

                // A client may only push frames it claims to have sent. This
                // is not authentication - anyone can open a connection and
                // announce any party number - but it stops a client from
                // overwriting *another* party's frame in the spool, which
                // would replace a message the recipient had not yet fetched
                // and leave no trace for the equivocation check to find.
                if (peek.header.from != party) {
                    try ctx.warn(
                        "rejected a frame from party {d} pushed by party {d}\n",
                        .{ peek.header.from, party },
                    );
                    continue;
                }

                var name_buf: [128]u8 = undefined;
                const name = try frame.fileName(&name_buf, peek.header, frame.isArmored(bytes));
                const target = try session.join(ctx.gpa, &.{ dir, name });

                // Never silently replace a spooled frame with different
                // content: keep both so the recipient's consistency check can
                // see the contradiction.
                if (Dir.cwd().readFileAlloc(ctx.io, target, ctx.gpa, .limited(max_frame_bytes))) |existing| {
                    if (!std.mem.eql(u8, existing, bytes)) {
                        const alt = try std.fmt.allocPrint(
                            ctx.gpa,
                            "{s}/conflict{d}-{s}",
                            .{ dir, stored, name },
                        );
                        try Dir.cwd().writeFile(ctx.io, .{ .sub_path = alt, .data = bytes });
                        try ctx.warn(
                            "party {d} pushed a second, different frame for {s}\n",
                            .{ party, name },
                        );
                        stored += 1;
                        continue;
                    }
                    // Identical resend: nothing to do.
                    stored += 1;
                    continue;
                } else |_| {}

                try Dir.cwd().writeFile(ctx.io, .{ .sub_path = target, .data = bytes });
                stored += 1;
            }

            try writeU32(w, stored);
            try w.flush();
            try ctx.warn("push  session {s} party {d}: {d} frame(s)\n", .{ sid_hex[0..8], party, stored });
        },

        .pull => {
            var matches: std.ArrayList([]u8) = .empty;

            var d = Dir.cwd().openDir(ctx.io, dir, .{ .iterate = true }) catch |e| switch (e) {
                error.FileNotFound => {
                    try writeU32(w, 0);
                    try w.flush();
                    return;
                },
                else => return e,
            };
            defer d.close(ctx.io);

            var it = d.iterate();
            while (try it.next(ctx.io)) |entry| {
                if (entry.kind != .file) continue;
                const path = try session.join(ctx.gpa, &.{ dir, entry.name });
                const bytes = Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(max_frame_bytes)) catch continue;
                const peek = frame.peekHeader(bytes) catch continue;
                if (peek.header.from == party) continue; // never echo a party's own frames
                const addressed = peek.header.to == party or
                    (peek.header.channel == .broadcast and peek.header.to == 0);
                if (!addressed) continue;
                try matches.append(ctx.gpa, bytes);
            }

            try writeU32(w, @intCast(matches.items.len));
            for (matches.items) |bytes| {
                try writeU32(w, @intCast(bytes.len));
                try w.writeAll(bytes);
            }
            try w.flush();
            try ctx.warn(
                "pull  session {s} party {d}: {d} frame(s)\n",
                .{ sid_hex[0..8], party, matches.items.len },
            );
        },
    }
}

// ---------------------------------------------------------------------------
// client: push / pull
// ---------------------------------------------------------------------------

fn connect(ctx: cmd.Ctx, relay: []const u8) !net.Stream {
    const address = try parseAddress(ctx, relay);
    return address.connect(ctx.io, .{ .mode = .stream }) catch |e| {
        try ctx.warn("cannot reach relay {s}: {t}\n", .{ relay, e });
        return error.Reported;
    };
}

fn sendPreamble(w: *std.Io.Writer, op: Op, sid: [32]u8, party: u16) !void {
    try w.writeAll(magic);
    try w.writeByte(@intFromEnum(op));
    try w.writeAll(&sid);
    var pb: [2]u8 = undefined;
    std.mem.writeInt(u16, &pb, party, .little);
    try w.writeAll(&pb);
}

/// Upload everything in the session's `out/` directory.
pub fn push(ctx: cmd.Ctx, s: *session.Session, relay: []const u8) !u32 {
    const out_path = try session.join(ctx.gpa, &.{ s.path, session.out_dir });

    var files: std.ArrayList([]u8) = .empty;
    var d = Dir.cwd().openDir(ctx.io, out_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return 0,
        else => return e,
    };
    defer d.close(ctx.io);

    var it = d.iterate();
    while (try it.next(ctx.io)) |entry| {
        if (entry.kind != .file) continue;
        const path = try session.join(ctx.gpa, &.{ out_path, entry.name });
        const bytes = try Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(max_frame_bytes));
        try files.append(ctx.gpa, bytes);
    }
    if (files.items.len == 0) return 0;

    const stream = try connect(ctx, relay);
    defer stream.close(ctx.io);

    var read_buf: [4096]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var reader = stream.reader(ctx.io, &read_buf);
    var writer = stream.writer(ctx.io, &write_buf);
    const r = &reader.interface;
    const w = &writer.interface;

    try sendPreamble(w, .push, s.id, s.manifest.party);
    try writeU32(w, @intCast(files.items.len));
    for (files.items) |bytes| {
        try writeU32(w, @intCast(bytes.len));
        try w.writeAll(bytes);
    }
    try w.flush();

    return readU32(r);
}

/// Download everything addressed to this party into the session's `in/`.
pub fn pull(ctx: cmd.Ctx, s: *session.Session, relay: []const u8) !u32 {
    const stream = try connect(ctx, relay);
    defer stream.close(ctx.io);

    var read_buf: [64 * 1024]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var reader = stream.reader(ctx.io, &read_buf);
    var writer = stream.writer(ctx.io, &write_buf);
    const r = &reader.interface;
    const w = &writer.interface;

    try sendPreamble(w, .pull, s.id, s.manifest.party);
    try w.flush();

    const in_path = try session.join(ctx.gpa, &.{ s.path, session.in_dir });
    try Dir.cwd().createDirPath(ctx.io, in_path);

    const count = try readU32(r);
    if (count > max_batch) return error.TooManyFrames;

    var written: u32 = 0;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const len = try readU32(r);
        if (len > max_frame_bytes) return error.FrameTooLarge;
        const bytes = try ctx.gpa.alloc(u8, len);
        try r.readSliceAll(bytes);

        // The relay is untrusted, so re-derive the filename from the frame's
        // own header rather than believing anything it says.
        const peek = frame.peekHeader(bytes) catch continue;
        if (!std.mem.eql(u8, &peek.header.session, &s.id)) continue;
        var name_buf: [128]u8 = undefined;
        const name = try frame.fileName(&name_buf, peek.header, frame.isArmored(bytes));
        const target = try session.join(ctx.gpa, &.{ in_path, name });

        // A frame already in the inbox is never replaced by different bytes.
        // Overwriting would let a relay swap a peer's message after it had
        // been delivered - and because the name is derived from the header,
        // the substitution would be invisible to the equivocation check.
        // Keeping both makes the contradiction visible instead.
        if (Dir.cwd().readFileAlloc(ctx.io, target, ctx.gpa, .limited(max_frame_bytes))) |existing| {
            if (std.mem.eql(u8, existing, bytes)) continue;
            const alt = try std.fmt.allocPrint(
                ctx.gpa,
                "{s}/conflict{d}-{s}",
                .{ in_path, i, name },
            );
            try Dir.cwd().writeFile(ctx.io, .{ .sub_path = alt, .data = bytes });
            written += 1;
            continue;
        } else |_| {}

        try Dir.cwd().writeFile(ctx.io, .{ .sub_path = target, .data = bytes });
        written += 1;
    }
    return written;
}
