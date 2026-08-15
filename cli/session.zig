//! The session directory: one per party, per protocol run.
//!
//! ```
//! <dir>/
//!   session.json   who this party is, which run this is  (informational)
//!   in/            frames received from peers
//!   out/           frames this party produced
//!   state/         round state carried between process invocations  (SECRET)
//!   artifacts/     key share, aux info, presignatures, signatures
//! ```
//!
//! A round is one process invocation: read `state/` and `in/`, run the round,
//! write `out/` and the next `state/`. Getting `out/` to the peers' `in/` is
//! someone else's job - `cp`, `scp`, a shared mount, a USB stick, or the
//! relay. Frames are named identically on both sides, so delivery never needs
//! to rename anything.
//!
//! Filenames are a convenience for humans and shell globs. The frame header
//! is authoritative: a file named `-f2-` whose header says it came from party
//! 5 is treated as coming from party 5.
//!
//! `state/` holds secrets - DKG polynomial coefficients, Paillier decryption
//! keys, FROST nonces - and is created 0700 with 0600 files. That is a
//! speed bump, not encryption at rest.

const std = @import("std");
const mpc = @import("zig_mpc");
const frame = @import("frame.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

pub const manifest_name = "session.json";
pub const in_dir = "in";
pub const out_dir = "out";
pub const state_dir = "state";
pub const artifacts_dir = "artifacts";

/// Generous cap; the largest real frame is a CGGMP round-2 p2p message.
pub const max_file_bytes = 64 * 1024 * 1024;

const secret_file: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

const secret_dir: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o700)
else
    .default_dir;

pub const Env = struct {
    io: std.Io,
    /// An arena: nothing here frees individual allocations.
    gpa: Allocator,
};

pub const Manifest = struct {
    format: u32 = 1,
    /// 64 hex characters.
    session: []const u8,
    protocol: []const u8,
    suite: []const u8,
    party: u16,
    n_parties: u16,
    threshold: u16,
    /// Highest round whose state has been written. 0 = nothing run yet.
    round: u16 = 0,
    /// Set once the protocol has produced its artifact.
    complete: bool = false,
    /// For protocols that run among a subset of the parties (signing,
    /// presigning): the participating party indices, ascending. Null means
    /// every party from 1 to `n_parties` takes part.
    signers: ?[]const u16 = null,
    /// Where to find the key share this session signs with.
    share_path: ?[]const u8 = null,
    /// Where to find the CGGMP24 aux info, for presigning sessions.
    aux_path: ?[]const u8 = null,
};

pub const Error = error{
    SessionExists,
    SessionNotFound,
    BadSessionId,
    UnknownProtocol,
    UnknownSuite,
    /// Two frames claiming the same (round, channel, sender, recipient) with
    /// different contents. Someone is equivocating, or two runs were mixed.
    Equivocation,
};

pub const Session = struct {
    env: Env,
    path: []const u8,
    manifest: Manifest,
    id: [32]u8,
    protocol: frame.Protocol,
    suite: frame.Suite,

    pub fn create(env: Env, path: []const u8, m: Manifest) !Session {
        const cwd = Dir.cwd();
        const manifest_path = try join(env.gpa, &.{ path, manifest_name });
        if (cwd.statFile(env.io, manifest_path, .{})) |_| {
            return error.SessionExists;
        } else |_| {}

        try cwd.createDirPath(env.io, path);
        for ([_][]const u8{ in_dir, out_dir, artifacts_dir }) |sub| {
            try cwd.createDirPath(env.io, try join(env.gpa, &.{ path, sub }));
        }
        // State is secret; create it restrictively rather than by default.
        const state_path = try join(env.gpa, &.{ path, state_dir });
        cwd.createDir(env.io, state_path, secret_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var self = try build(env, path, m);
        try self.saveManifest();
        return self;
    }

    pub fn open(env: Env, path: []const u8) !Session {
        const cwd = Dir.cwd();
        const manifest_path = try join(env.gpa, &.{ path, manifest_name });
        const text = cwd.readFileAlloc(env.io, manifest_path, env.gpa, .limited(1 << 20)) catch
            return error.SessionNotFound;
        const parsed = std.json.parseFromSliceLeaky(Manifest, env.gpa, text, .{
            .allocate = .alloc_always,
        }) catch return error.SessionNotFound;
        return build(env, path, parsed);
    }

    fn build(env: Env, path: []const u8, m: Manifest) !Session {
        if (m.session.len != 64) return error.BadSessionId;
        var id: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&id, m.session) catch return error.BadSessionId;
        return .{
            .env = env,
            .path = path,
            .manifest = m,
            .id = id,
            .protocol = std.meta.stringToEnum(frame.Protocol, m.protocol) orelse
                return error.UnknownProtocol,
            .suite = std.meta.stringToEnum(frame.Suite, m.suite) orelse
                return error.UnknownSuite,
        };
    }

    pub fn saveManifest(self: *Session) !void {
        const text = try std.json.Stringify.valueAlloc(self.env.gpa, self.manifest, .{
            .whitespace = .indent_2,
        });
        try Dir.cwd().writeFile(self.env.io, .{
            .sub_path = try join(self.env.gpa, &.{ self.path, manifest_name }),
            .data = text,
        });
    }

    /// Record that `round` finished, so `status` and `run` know where we are.
    pub fn advance(self: *Session, round: u16) !void {
        self.manifest.round = round;
        try self.saveManifest();
    }

    pub fn finish(self: *Session) !void {
        self.manifest.complete = true;
        try self.saveManifest();
    }

    // -----------------------------------------------------------------
    // outbound frames
    // -----------------------------------------------------------------

    /// Serialize `value`, wrap it in a frame, and drop it in `out/`.
    /// Returns the file name written, for logging.
    pub fn emit(
        self: *Session,
        comptime T: type,
        value: T,
        header: frame.Header,
        armored: bool,
    ) ![]const u8 {
        const payload = try mpc.serde.encodeAlloc(T, value, self.env.gpa);
        return self.emitRaw(payload, header, armored);
    }

    pub fn emitRaw(self: *Session, payload: []const u8, header: frame.Header, armored: bool) ![]const u8 {
        var h = header;
        h.session = self.id;

        const bytes = try frame.encodeAlloc(self.env.gpa, h, payload);
        const data = if (armored) try frame.armor(self.env.gpa, bytes) else bytes;

        var name_buf: [128]u8 = undefined;
        const name = try frame.fileName(&name_buf, h, armored);
        const owned = try self.env.gpa.dupe(u8, name);

        try Dir.cwd().writeFile(self.env.io, .{
            .sub_path = try join(self.env.gpa, &.{ self.path, out_dir, owned }),
            .data = data,
        });
        return owned;
    }

    // -----------------------------------------------------------------
    // round state
    // -----------------------------------------------------------------

    fn statePath(self: *Session, round: u16) ![]const u8 {
        var buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "{t}-r{d}.state", .{ self.protocol, round });
        return join(self.env.gpa, &.{ self.path, state_dir, name });
    }

    pub fn saveState(self: *Session, comptime T: type, value: T, round: u16) !void {
        const payload = try mpc.serde.encodeAlloc(T, value, self.env.gpa);
        const bytes = try frame.encodeAlloc(self.env.gpa, .{
            .kind = .state,
            .channel = .artifact,
            .protocol = self.protocol,
            .suite = self.suite,
            .round = round,
            .from = self.manifest.party,
            .n_parties = self.manifest.n_parties,
            .threshold = self.manifest.threshold,
            .session = self.id,
        }, payload);

        try Dir.cwd().writeFile(self.env.io, .{
            .sub_path = try self.statePath(round),
            .data = bytes,
            .flags = .{ .permissions = secret_file },
        });
    }

    pub fn loadState(self: *Session, comptime T: type, round: u16) !T {
        const path = try self.statePath(round);
        const bytes = Dir.cwd().readFileAlloc(self.env.io, path, self.env.gpa, .limited(max_file_bytes)) catch
            return error.MissingState;
        const f = try frame.parse(bytes);
        if (!std.mem.eql(u8, &f.header.session, &self.id)) return error.WrongSession;
        if (f.header.round != round or f.header.protocol != self.protocol) return error.WrongState;
        if (f.header.suite != self.suite) return error.SuiteMismatch;
        return mpc.serde.decodeSlice(T, f.payload, .{ .gpa = self.env.gpa });
    }

    /// Delete a state file. Used to enforce single-use of FROST nonces: a
    /// nonce reused across two messages leaks the signing share.
    pub fn consumeState(self: *Session, round: u16) !void {
        const path = try self.statePath(round);
        Dir.cwd().deleteFile(self.env.io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    // -----------------------------------------------------------------
    // artifacts
    // -----------------------------------------------------------------

    pub fn artifactPath(self: *Session, name: []const u8) ![]const u8 {
        return join(self.env.gpa, &.{ self.path, artifacts_dir, name });
    }

    pub fn saveArtifact(
        self: *Session,
        comptime T: type,
        value: T,
        name: []const u8,
        kind: frame.Kind,
        secret: bool,
    ) ![]const u8 {
        const payload = try mpc.serde.encodeAlloc(T, value, self.env.gpa);
        const bytes = try frame.encodeAlloc(self.env.gpa, .{
            .kind = kind,
            .channel = .artifact,
            .protocol = .none,
            .suite = self.suite,
            .from = self.manifest.party,
            .n_parties = self.manifest.n_parties,
            .threshold = self.manifest.threshold,
            .session = self.id,
        }, payload);

        const path = try self.artifactPath(name);
        try Dir.cwd().writeFile(self.env.io, .{
            .sub_path = path,
            .data = bytes,
            .flags = if (secret) .{ .permissions = secret_file } else .{},
        });
        return path;
    }

    // -----------------------------------------------------------------
    // inbound frames
    // -----------------------------------------------------------------

    pub fn scanInbox(self: *Session) !Inbox {
        return Inbox.scan(
            self.env,
            try join(self.env.gpa, &.{ self.path, in_dir }),
            self.id,
            self.protocol,
            self.suite,
        );
    }

    /// The parties taking part in this session: the chosen signer set, or
    /// everyone if the protocol involves all of them.
    pub fn participants(self: *Session) ![]const u16 {
        if (self.manifest.signers) |list| return list;
        const all = try self.env.gpa.alloc(u16, self.manifest.n_parties);
        for (all, 0..) |*p, i| p.* = @intCast(i + 1);
        return all;
    }

    /// Position of this party within `participants` - the index the Lagrange
    /// coefficients are computed against.
    pub fn myPosition(self: *Session) !usize {
        for (try self.participants(), 0..) |p, i| {
            if (p == self.manifest.party) return i;
        }
        return error.NotAParticipant;
    }
};

/// One inbound frame, with the file it came from so errors can name it.
pub const Received = struct {
    header: frame.Header,
    payload: []const u8,
    source: []const u8,
};

pub const Requirement = struct {
    round: u16,
    channel: frame.Channel,
    /// The sending party.
    from: u16,
    /// The recipient; 0 for broadcast.
    to: u16 = 0,
};

pub const Inbox = struct {
    env: Env,
    frames: []Received,
    /// Files that looked like frames for this session but could not be used:
    /// corrupted, truncated, or from a different format version. Without this
    /// a bit-flipped frame is indistinguishable from one that never arrived,
    /// and the round just waits forever with nothing to say.
    rejected: [][]const u8 = &.{},

    /// Read every frame in `path` belonging to this exact run: same session
    /// id, same protocol, same suite. Files that are not zmpc frames, or that
    /// belong to another run, are ignored - so one shared directory can serve
    /// several concurrent sessions.
    ///
    /// Matching on all three matters. The session id alone is not enough: two
    /// sessions can share one (an operator reusing the id, or a `sign` and a
    /// `presign` run over one relay spool), and then round-1 broadcasts from
    /// the two protocols collide on `(round, channel, from, to)` and look like
    /// equivocation, wedging both runs.
    pub fn scan(
        env: Env,
        path: []const u8,
        id: [32]u8,
        protocol: frame.Protocol,
        suite: frame.Suite,
    ) !Inbox {
        var out: std.ArrayList(Received) = .empty;
        var bad: std.ArrayList([]const u8) = .empty;

        var dir = Dir.cwd().openDir(env.io, path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return .{ .env = env, .frames = &.{} },
            else => return err,
        };
        defer dir.close(env.io);

        var it = dir.iterate();
        while (try it.next(env.io)) |entry| {
            if (entry.kind != .file) continue;

            // Only files named like our frames are candidates; anything else
            // is somebody's notes and is ignored without comment, so one
            // shared directory can serve several concurrent runs.
            const looks_like_ours = std.mem.endsWith(u8, entry.name, ".zmpc") or
                std.mem.endsWith(u8, entry.name, ".zmpc.asc");

            const file_path = try join(env.gpa, &.{ path, entry.name });
            const raw = Dir.cwd().readFileAlloc(env.io, file_path, env.gpa, .limited(max_file_bytes)) catch {
                if (looks_like_ours) try bad.append(env.gpa, try env.gpa.dupe(u8, entry.name));
                continue;
            };

            const bytes = if (frame.isArmored(raw))
                frame.dearmor(env.gpa, raw) catch {
                    try bad.append(env.gpa, try env.gpa.dupe(u8, entry.name));
                    continue;
                }
            else
                raw;

            const f = frame.parse(bytes) catch {
                if (looks_like_ours) try bad.append(env.gpa, try env.gpa.dupe(u8, entry.name));
                continue;
            };
            // A frame for a different run is not an error, just not ours.
            if (!std.mem.eql(u8, &f.header.session, &id)) continue;
            if (f.header.protocol != protocol or f.header.suite != suite) continue;

            try out.append(env.gpa, .{
                .header = f.header,
                .payload = f.payload,
                .source = try env.gpa.dupe(u8, entry.name),
            });
        }

        const inbox = Inbox{
            .env = env,
            .frames = try out.toOwnedSlice(env.gpa),
            .rejected = try bad.toOwnedSlice(env.gpa),
        };
        try inbox.checkConsistency();
        return inbox;
    }

    /// Two frames addressed the same way but carrying different payloads mean
    /// a peer sent one thing to us and another to someone else, or that two
    /// runs got mixed in one directory. Either way, refuse to proceed: the
    /// protocols assume a consistent broadcast this transport cannot provide,
    /// and this is the part of that gap we can actually detect.
    fn checkConsistency(self: Inbox) !void {
        for (self.frames, 0..) |a, i| {
            for (self.frames[i + 1 ..]) |b| {
                if (a.header.round != b.header.round) continue;
                if (a.header.channel != b.header.channel) continue;
                if (a.header.from != b.header.from) continue;
                if (a.header.to != b.header.to) continue;
                if (!std.mem.eql(u8, a.payload, b.payload)) return error.Equivocation;
            }
        }
    }

    pub fn find(self: Inbox, req: Requirement) ?Received {
        for (self.frames) |f| {
            if (f.header.round == req.round and
                f.header.channel == req.channel and
                f.header.from == req.from and
                f.header.to == req.to) return f;
        }
        return null;
    }

    /// Requirements with no matching frame yet.
    pub fn missing(self: Inbox, reqs: []const Requirement) ![]Requirement {
        var out: std.ArrayList(Requirement) = .empty;
        for (reqs) |req| {
            if (self.find(req) == null) try out.append(self.env.gpa, req);
        }
        return out.toOwnedSlice(self.env.gpa);
    }

    /// Decode the frame satisfying `req` as a `T`.
    pub fn decode(self: Inbox, comptime T: type, req: Requirement) !T {
        const got = self.find(req) orelse return error.MissingMessage;
        return mpc.serde.decodeSlice(T, got.payload, .{ .gpa = self.env.gpa });
    }
};

/// Every frame party `me` must have received before it can run `round`.
/// Pure and deterministic - the same table drives `status`, `run`, and the
/// "still waiting on party 3" message.
///
/// `participants` is the set taking part: all parties for keygen and refresh,
/// the chosen signer set for signing and presigning.
pub fn requirements(
    gpa: Allocator,
    protocol: frame.Protocol,
    round: u16,
    participants: []const u16,
    me: u16,
) ![]Requirement {
    var out: std.ArrayList(Requirement) = .empty;

    // Rounds consume the *previous* round's messages.
    const prev = if (round == 0) 0 else round - 1;
    if (prev == 0) return out.toOwnedSlice(gpa);

    for (participants) |j| {
        if (j == me) continue;
        switch (protocol) {
            .dkg, .refresh => {
                // round 1 broadcasts a commitment; round 2 decommits and
                // sends a p2p share; round 3 broadcasts a proof.
                try out.append(gpa, .{ .round = prev, .channel = .broadcast, .from = j });
                if (prev == 2) try out.append(gpa, .{ .round = prev, .channel = .p2p, .from = j, .to = me });
            },
            .auxgen => {
                if (prev == 3) {
                    try out.append(gpa, .{ .round = prev, .channel = .p2p, .from = j, .to = me });
                } else {
                    try out.append(gpa, .{ .round = prev, .channel = .broadcast, .from = j });
                }
            },
            .presign => {
                switch (prev) {
                    1 => {
                        try out.append(gpa, .{ .round = prev, .channel = .broadcast, .from = j });
                        try out.append(gpa, .{ .round = prev, .channel = .p2p, .from = j, .to = me });
                    },
                    2 => try out.append(gpa, .{ .round = prev, .channel = .p2p, .from = j, .to = me }),
                    else => try out.append(gpa, .{ .round = prev, .channel = .broadcast, .from = j }),
                }
            },
            .sign => try out.append(gpa, .{ .round = prev, .channel = .broadcast, .from = j }),
            .none => {},
        }
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn join(gpa: Allocator, parts: []const []const u8) ![]u8 {
    return std.fs.path.join(gpa, parts);
}

pub fn hexId(gpa: Allocator, id: [32]u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{x}", .{&id});
}

pub fn parseId(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.BadSessionId;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return error.BadSessionId;
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "requirements describe who we are waiting for" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const three: []const u16 = &.{ 1, 2, 3 };

    // Nothing is needed to start.
    try testing.expectEqual(@as(usize, 0), (try requirements(arena, .dkg, 1, three, 1)).len);

    // DKG round 2 waits on every other party's round-1 broadcast.
    const r2 = try requirements(arena, .dkg, 2, three, 1);
    try testing.expectEqual(@as(usize, 2), r2.len);
    try testing.expectEqual(frame.Channel.broadcast, r2[0].channel);
    try testing.expectEqual(@as(u16, 2), r2[0].from);
    try testing.expectEqual(@as(u16, 3), r2[1].from);

    // Round 3 additionally waits on the p2p share addressed to us.
    const r3 = try requirements(arena, .dkg, 3, three, 1);
    try testing.expectEqual(@as(usize, 4), r3.len);
    try testing.expectEqual(frame.Channel.p2p, r3[1].channel);
    try testing.expectEqual(@as(u16, 1), r3[1].to);

    // CGGMP presigning round 2 needs both the broadcast and the p2p proofs.
    const p2 = try requirements(arena, .presign, 2, &.{ 1, 2 }, 2);
    try testing.expectEqual(@as(usize, 2), p2.len);
    try testing.expectEqual(@as(u16, 1), p2[0].from);
    try testing.expectEqual(frame.Channel.p2p, p2[1].channel);

    // A signing session runs among a subset, and waits only on that subset.
    // Party 2 sat this one out, so nobody waits for it.
    const signers: []const u16 = &.{ 1, 3 };
    const s2 = try requirements(arena, .sign, 2, signers, 1);
    try testing.expectEqual(@as(usize, 1), s2.len);
    try testing.expectEqual(@as(u16, 3), s2[0].from);
}

test "participants default to everyone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var s = Session{
        .env = .{ .io = undefined, .gpa = arena },
        .path = "unused",
        .manifest = .{
            .session = &@as([64]u8, @splat('0')),
            .protocol = "dkg",
            .suite = "ed25519",
            .party = 2,
            .n_parties = 3,
            .threshold = 2,
        },
        .id = @splat(0),
        .protocol = .dkg,
        .suite = .ed25519,
    };
    try testing.expectEqualSlices(u16, &.{ 1, 2, 3 }, try s.participants());
    try testing.expectEqual(@as(usize, 1), try s.myPosition());

    s.manifest.signers = &.{ 1, 3 };
    s.manifest.party = 3;
    try testing.expectEqual(@as(usize, 1), try s.myPosition());
    s.manifest.party = 2;
    try testing.expectError(error.NotAParticipant, s.myPosition());
}
