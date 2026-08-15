//! zmpc - command-line interface to zig-mpc.
//!
//! Every party runs in its own process, on its own machine. Protocol messages
//! are exchanged as self-describing frames (`frame.zig`) through a session
//! directory (`session.zig`); how those frames travel between parties is
//! deliberately not this tool's concern - copy them with anything you like,
//! or use `zmpc relay`.

const std = @import("std");
const mpc = @import("zig_mpc");

pub const args_mod = @import("args.zig");
pub const auxgen = @import("auxgen.zig");
pub const cmd = @import("cmd.zig");
pub const dkg = @import("dkg.zig");
pub const ecdsa = @import("ecdsa.zig");
pub const frame = @import("frame.zig");
pub const hd = @import("hd.zig");
pub const prim = @import("prim.zig");
pub const selftest_mod = @import("selftest.zig");
pub const refresh = @import("refresh.zig");
pub const relay = @import("relay.zig");
pub const session = @import("session.zig");
pub const sign = @import("sign.zig");
pub const suite_mod = @import("suite.zig");

const Args = args_mod.Args;

/// Set by the build (`-Dversion=`); release tags stamp their own value in.
pub const version = @import("build_options").version;

const usage =
    \\zmpc - threshold signing (FROST, CGGMP24) across processes and machines
    \\
    \\usage: zmpc <command> [options]
    \\
    \\sessions
    \\  init          create a session directory for one party
    \\  status        what this session has done and is waiting for
    \\
    \\protocols            (each: init? round1 round2 [round3] finalize | run)
    \\  dkg           distributed key generation, any curve
    \\  refresh       re-randomize shares; same public key, old shares dead
    \\  auxgen        CGGMP24 aux info; also `auxgen primes` to pre-generate
    \\  presign       CGGMP24 presigning, message-independent
    \\  sign          FROST: commit | share | aggregate
    \\
    \\signing and keys
    \\  ecdsa         sign | combine | verify     (uses a presignature)
    \\  verify        check a FROST/Taproot signature against a public key
    \\  share         info | pubkey | verify
    \\  hd            pubkey | derive             (BIP-32/SLIP-10, non-hardened)
    \\
    \\primitives
    \\  bip340        pubkey | sign | verify
    \\  paillier      keygen | encrypt | decrypt | add | mul | addplain
    \\  vss           split | reconstruct | verify
    \\  ffx           prime | isprime | jacobi | gcd | inverse | sqrt | divrem
    \\  transcript    hash
    \\
    \\relay transport (optional)
    \\  relay         store-and-forward hub: --listen HOST:PORT [--spool DIR]
    \\  push          upload this session's out/ to a relay
    \\  pull          download frames addressed to this party into in/
    \\  node          run a whole protocol to completion over a relay
    \\
    \\tools
    \\  simulate      run whole protocols in one process
    \\  selftest      known-answer tests against this binary
    \\  inspect       decode any frame file
    \\  version
    \\
    \\suites: ed25519 | secp256k1 | taproot | p256 | p384 | ecdsa_fast | ecdsa_prod
    \\
    \\common options
    \\  --dir DIR     session directory (default: .)
    \\  --armor       write frames as base64 text instead of binary
    \\  --json        machine-readable result on stdout, human text on stderr
    \\  --quiet       suppress progress notes
    \\
    \\A round reads in/ and state/, then writes out/ and state/. Deliver a
    \\party's out/ files into its peers' in/ directories by any means you
    \\trust - the frames are inert and named identically on both sides.
    \\Exit 75 means "still waiting for messages", not failure.
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;

    var stdout_buf: [16 * 1024]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    var stderr = std.Io.File.stderr().writerStreaming(io, &stderr_buf);
    const out = &stdout.interface;
    const err = &stderr.interface;
    defer out.flush() catch {};
    defer err.flush() catch {};

    var csprng: std.Random.DefaultCsprng = undefined;
    try cmd.seedRng(io, &csprng);

    const argv = try init.minimal.args.toSlice(gpa);
    var args = Args.parse(gpa, argv[@min(1, argv.len)..]) catch |e| {
        try err.print("bad arguments: {t}\n", .{e});
        return cmd.Exit.usage;
    };

    var ctx = cmd.Ctx{
        .io = io,
        .gpa = gpa,
        .out = out,
        .err = err,
        .rng = csprng.random(),
        .armor = args.has("armor"),
        .json = args.has("json"),
        .quiet = args.has("quiet"),
    };

    const code = dispatch(&ctx, &args) catch |e| {
        try reportError(ctx, &args, e);
        return errorExit(e);
    };
    return code;
}

fn dispatch(ctx: *cmd.Ctx, args: *Args) !u8 {
    const command = args.word(0) orelse {
        try ctx.out.writeAll(usage);
        return cmd.Exit.usage;
    };

    if (eql(command, "version")) {
        try ctx.emit("zmpc {s}\n", .{version});
        return cmd.Exit.ok;
    }
    if (eql(command, "help") or eql(command, "--help")) {
        try ctx.out.writeAll(usage);
        return cmd.Exit.ok;
    }
    if (eql(command, "init")) return cmdInit(ctx, args);
    if (eql(command, "status")) return cmdStatus(ctx, args);
    if (eql(command, "inspect")) return cmdInspect(ctx, args);
    if (eql(command, "dkg")) return cmdDkg(ctx, args);
    if (eql(command, "auxgen")) return cmdAuxgen(ctx, args);
    if (eql(command, "presign")) return cmdPresign(ctx, args);
    if (eql(command, "ecdsa")) return cmdEcdsa(ctx, args);
    if (eql(command, "refresh")) return cmdRefresh(ctx, args);
    if (eql(command, "hd")) return cmdHd(ctx, args);
    if (eql(command, "sign")) return cmdSign(ctx, args);
    if (eql(command, "verify")) return cmdVerify(ctx, args);
    if (eql(command, "share")) return cmdShare(ctx, args);
    if (eql(command, "bip340")) return prim.bip340(ctx.*, args);
    if (eql(command, "paillier")) return prim.paillier(ctx.*, args);
    if (eql(command, "vss")) return prim.vss(ctx.*, args);
    if (eql(command, "ffx")) return prim.ffx(ctx.*, args);
    if (eql(command, "transcript")) return prim.transcript(ctx.*, args);
    if (eql(command, "relay")) return cmdRelay(ctx, args);
    if (eql(command, "push")) return cmdPush(ctx, args);
    if (eql(command, "pull")) return cmdPull(ctx, args);
    if (eql(command, "node")) return cmdNode(ctx, args);
    if (eql(command, "selftest")) return selftest_mod.selftest(ctx.*, args);
    if (eql(command, "simulate")) return selftest_mod.simulate(ctx.*, args);

    try ctx.warn("unknown command '{s}'\n\n", .{command});
    try ctx.out.writeAll(usage);
    return cmd.Exit.usage;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn sessionDir(args: *Args) []const u8 {
    return args.valueOr("dir", ".");
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmdInit(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{
        "dir", "protocol", "suite", "party", "n", "threshold", "session", "armor", "json", "quiet",
    });

    const protocol_name = args.valueOr("protocol", "dkg");
    const protocol = std.meta.stringToEnum(frame.Protocol, protocol_name) orelse {
        try ctx.warn("unknown protocol '{s}'\n", .{protocol_name});
        return cmd.Exit.usage;
    };
    const suite_name = try args.require("suite");
    if (suite_mod.parse(suite_name) == null) {
        try ctx.warn("unknown suite '{s}'; choose one of: {s}\n", .{ suite_name, suite_mod.names });
        return cmd.Exit.usage;
    }

    const party = try args.intRequired(u16, "party");
    const n = try args.intRequired(u16, "n");
    const threshold = try args.intRequired(u16, "threshold");
    if (party < 1 or party > n or threshold < 1 or threshold > n or n < 2) {
        try ctx.warn("need 2 <= n, 1 <= threshold <= n, 1 <= party <= n\n", .{});
        return cmd.Exit.usage;
    }

    // Every party must use the same execution id: it binds each frame to one
    // run and is mixed into every transcript, so a mismatch is a hard failure
    // rather than a subtle one.
    const id_hex = if (args.value("session")) |given| blk: {
        _ = session.parseId(given) catch {
            try ctx.warn("--session must be 64 hex characters\n", .{});
            return cmd.Exit.usage;
        };
        break :blk given;
    } else blk: {
        var id: [32]u8 = undefined;
        ctx.rng.bytes(&id);
        break :blk try session.hexId(ctx.gpa, id);
    };

    const s = session.Session.create(ctx.env(), sessionDir(args), .{
        .session = id_hex,
        .protocol = @tagName(protocol),
        .suite = suite_name,
        .party = party,
        .n_parties = n,
        .threshold = threshold,
    }) catch |e| switch (e) {
        error.SessionExists => {
            try ctx.warn("a session already exists in '{s}'\n", .{sessionDir(args)});
            return cmd.Exit.usage;
        },
        else => return e,
    };

    try ctx.note(
        "session for party {d} of {d} ({d}-of-{d} {s}) created in {s}\n",
        .{ party, n, threshold, n, suite_name, s.path },
    );
    if (!args.has("session")) {
        try ctx.note("give every other party this session id:\n", .{});
    }
    try ctx.emit("{s}\n", .{id_hex});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmdStatus(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "json", "quiet", "armor" });
    var s = try openSession(ctx, args);
    const m = s.manifest;

    const inbox = try s.scanInbox();
    const next_round = m.round + 1;
    const reqs = try session.requirements(ctx.gpa, s.protocol, next_round, try s.participants(), m.party);
    const missing = try inbox.missing(reqs);

    if (ctx.json) {
        try ctx.emit(
            "{{\"session\":\"{s}\",\"protocol\":\"{s}\",\"suite\":\"{s}\",\"party\":{d}," ++
                "\"threshold\":{d},\"parties\":{d},\"round\":{d},\"complete\":{},\"waiting_on\":{d}}}\n",
            .{ m.session, m.protocol, m.suite, m.party, m.threshold, m.n_parties, m.round, m.complete, missing.len },
        );
        return cmd.Exit.ok;
    }

    try ctx.emit("session   {s}\n", .{m.session});
    try ctx.emit("protocol  {s} ({s})\n", .{ m.protocol, m.suite });
    try ctx.emit("party     {d} of {d}, threshold {d}\n", .{ m.party, m.n_parties, m.threshold });
    try ctx.emit("inbox     {d} frame(s)\n", .{inbox.frames.len});
    if (m.complete) {
        try ctx.emit("state     complete\n", .{});
        return cmd.Exit.ok;
    }
    try ctx.emit("state     {d} round(s) done; next is round {d}\n", .{ m.round, next_round });
    if (missing.len == 0) {
        try ctx.emit("ready     yes - run the next round\n", .{});
        return cmd.Exit.ok;
    }
    try ctx.emit("ready     no\n", .{});
    _ = try cmd.reportMissingWith(ctx.*, missing, inbox.rejected);
    return cmd.Exit.ok;
}

/// Read a key share's shape from its *payload*, and cross-check the header
/// against it.
///
/// The header is convenient - it lets a caller learn the threshold without
/// instantiating a curve - but it is not authoritative. A share whose header
/// claimed `threshold: 1` over a payload saying 2 would otherwise create a
/// session that thinks one signer is enough for a 2-of-n key.
const ShareShape = struct { party: u16, n_parties: u16, threshold: u16 };

fn shareShape(ctx: *cmd.Ctx, f: frame.Frame) !ShareShape {
    return switch (f.header.suite) {
        inline else => |tag| blk: {
            const KeyShare = mpc.dkg.Dkg(suite_mod.CurveOf(tag)).KeyShare;
            const ks = try mpc.serde.decodeSlice(KeyShare, f.payload, .{ .gpa = ctx.gpa });
            ks.validate() catch |e| {
                try ctx.warn("this key share is not well formed: {t}\n", .{e});
                return error.Reported;
            };
            if (f.header.n_parties != ks.n or f.header.threshold != ks.threshold) {
                try ctx.warn(
                    "this key share's header disagrees with its contents: header says " ++
                        "{d}-of-{d}, the share itself says {d}-of-{d}\n",
                    .{ f.header.threshold, f.header.n_parties, ks.threshold, ks.n },
                );
                return error.Reported;
            }
            break :blk ShareShape{ .party = ks.party, .n_parties = ks.n, .threshold = ks.threshold };
        },
    };
}

/// Sort and sanity-check a `--signers` list against the key it will sign for.
/// Returns an exit code if the command should stop.
fn rejectBadSignerSet(ctx: *cmd.Ctx, signers: []u16, shape: ShareShape) !?u8 {
    std.mem.sort(u16, signers, {}, std.sort.asc(u16));
    for (signers[1..], 0..) |sgn, i| {
        if (sgn == signers[i]) {
            // A repeated index makes the Lagrange interpolation singular; the
            // protocol would abort several rounds later with a much less
            // helpful message.
            try ctx.warn("--signers lists party {d} twice\n", .{sgn});
            return cmd.Exit.usage;
        }
    }
    for (signers) |sgn| {
        if (sgn < 1 or sgn > shape.n_parties) {
            try ctx.warn(
                "--signers names party {d}, but this key has parties 1..{d}\n",
                .{ sgn, shape.n_parties },
            );
            return cmd.Exit.usage;
        }
    }
    if (signers.len < shape.threshold) {
        try ctx.warn(
            "need at least {d} signers for this key; got {d}\n",
            .{ shape.threshold, signers.len },
        );
        return cmd.Exit.usage;
    }
    return null;
}

fn openSession(ctx: *cmd.Ctx, args: *Args) !session.Session {
    return session.Session.open(ctx.env(), sessionDir(args)) catch |e| switch (e) {
        error.SessionNotFound => {
            try ctx.warn(
                "no session in '{s}' - run `zmpc init` there first\n",
                .{sessionDir(args)},
            );
            return error.Reported;
        },
        else => e,
    };
}

// ---------------------------------------------------------------------------
// dkg
// ---------------------------------------------------------------------------

fn cmdDkg(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "armor", "json", "quiet" });
    const step = args.word(1) orelse {
        try ctx.warn("usage: zmpc dkg <round1|round2|round3|finalize|run> [--dir DIR]\n", .{});
        return cmd.Exit.usage;
    };

    var s = try openSession(ctx, args);
    if (s.protocol != .dkg) {
        try ctx.warn("this session runs '{s}', not dkg\n", .{s.manifest.protocol});
        return cmd.Exit.usage;
    }

    if (eql(step, "run")) return dkg.runAll(ctx.*, &s);
    const round: u16 = if (eql(step, "round1"))
        1
    else if (eql(step, "round2"))
        2
    else if (eql(step, "round3"))
        3
    else if (eql(step, "finalize"))
        4
    else {
        try ctx.warn("unknown dkg step '{s}'\n", .{step});
        return cmd.Exit.usage;
    };

    if (s.manifest.complete) {
        try ctx.warn("this session is already complete\n", .{});
        return cmd.Exit.usage;
    }
    if (round <= s.manifest.round) {
        try ctx.warn(
            "round {d} already ran; re-running it would reuse committed randomness\n",
            .{round},
        );
        return cmd.Exit.usage;
    }
    if (round > s.manifest.round + 1) {
        try ctx.warn(
            "round {d} cannot run yet; the next round is {d}\n",
            .{ round, s.manifest.round + 1 },
        );
        return cmd.Exit.usage;
    }
    return dkg.run(ctx.*, &s, round);
}

// ---------------------------------------------------------------------------
// auxgen
// ---------------------------------------------------------------------------

fn cmdAuxgen(ctx: *cmd.Ctx, args: *Args) !u8 {
    const step = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc auxgen <primes|round1|round2|round3|finalize|run> [--dir DIR]\n",
            .{},
        );
        return cmd.Exit.usage;
    };

    if (eql(step, "primes")) {
        try args.rejectUnknown(&.{ "suite", "out", "json", "quiet", "armor", "dir" });
        const suite_name = try args.require("suite");
        const st = suite_mod.parse(suite_name) orelse {
            try ctx.warn("unknown suite '{s}'\n", .{suite_name});
            return cmd.Exit.usage;
        };
        return auxgen.generatePrimes(ctx.*, st, args.valueOr("out", "primes.zmpc"));
    }

    try args.rejectUnknown(&.{ "dir", "primes", "armor", "json", "quiet" });
    var s = try openSession(ctx, args);
    if (s.protocol != .auxgen) {
        try ctx.warn("this session runs '{s}', not auxgen\n", .{s.manifest.protocol});
        return cmd.Exit.usage;
    }
    const primes_path = args.value("primes");
    if (eql(step, "run")) return auxgen.runAll(ctx.*, &s, primes_path);

    const round = roundOf(step, "round1", "round2", "round3", "finalize") orelse {
        try ctx.warn("unknown auxgen step '{s}'\n", .{step});
        return cmd.Exit.usage;
    };
    if (try guardRound(ctx, &s, round, step)) |code| return code;
    return auxgen.run(ctx.*, &s, round, primes_path);
}

// ---------------------------------------------------------------------------
// presign
// ---------------------------------------------------------------------------

fn cmdPresign(ctx: *cmd.Ctx, args: *Args) !u8 {
    const step = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc presign <init|round1|round2|round3|finalize|run> [--dir DIR]\n",
            .{},
        );
        return cmd.Exit.usage;
    };

    if (eql(step, "init")) return cmdPresignInit(ctx, args);

    try args.rejectUnknown(&.{ "dir", "share", "aux", "armor", "json", "quiet" });
    var s = try openSession(ctx, args);
    if (s.protocol != .presign) {
        try ctx.warn("this session runs '{s}', not presign\n", .{s.manifest.protocol});
        return cmd.Exit.usage;
    }
    const paths = ecdsa.Paths{ .share = args.value("share"), .aux = args.value("aux") };
    if (eql(step, "run")) return ecdsa.runAll(ctx.*, &s, paths);

    const round = roundOf(step, "round1", "round2", "round3", "finalize") orelse {
        try ctx.warn("unknown presign step '{s}'\n", .{step});
        return cmd.Exit.usage;
    };
    if (try guardRound(ctx, &s, round, step)) |code| return code;
    return ecdsa.run(ctx.*, &s, round, paths);
}

fn cmdPresignInit(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{
        "dir", "share", "aux", "signers", "session", "armor", "json", "quiet",
    });

    const share_path = try args.require("share");
    const aux_path = try args.require("aux");
    const f = cmd.readFrame(ctx.*, share_path) catch |e| {
        try ctx.warn("cannot read key share '{s}': {t}\n", .{ share_path, e });
        return cmd.Exit.bad_input;
    };
    if (f.header.kind != .key_share) {
        try ctx.warn("'{s}' is not a key share\n", .{share_path});
        return cmd.Exit.bad_input;
    }
    if (!suite_mod.isCggmp(f.header.suite)) {
        try ctx.warn(
            "presigning needs an ecdsa_fast or ecdsa_prod key share; '{s}' is {t}\n",
            .{ share_path, f.header.suite },
        );
        return cmd.Exit.usage;
    }

    const shape = try shareShape(ctx, f);
    const party = shape.party;

    const signers = try args.intList(u16, ctx.gpa, "signers");
    if (try rejectBadSignerSet(ctx, signers, shape)) |code| return code;

    const id_hex = if (args.value("session")) |given| blk: {
        _ = session.parseId(given) catch {
            try ctx.warn("--session must be 64 hex characters\n", .{});
            return cmd.Exit.usage;
        };
        break :blk given;
    } else blk: {
        var id: [32]u8 = undefined;
        ctx.rng.bytes(&id);
        break :blk try session.hexId(ctx.gpa, id);
    };

    var in_set = false;
    for (signers) |sgn| {
        if (sgn == party) in_set = true;
    }
    if (!in_set) {
        try ctx.warn("this share belongs to party {d}, which is not in --signers\n", .{party});
        return cmd.Exit.usage;
    }

    const s = session.Session.create(ctx.env(), sessionDir(args), .{
        .session = id_hex,
        .protocol = "presign",
        .suite = @tagName(f.header.suite),
        .party = party,
        .n_parties = shape.n_parties,
        .threshold = shape.threshold,
        .signers = signers,
        .share_path = share_path,
        .aux_path = aux_path,
    }) catch |e| switch (e) {
        error.SessionExists => {
            try ctx.warn("a session already exists in '{s}'\n", .{sessionDir(args)});
            return cmd.Exit.usage;
        },
        else => return e,
    };

    try ctx.note(
        "presigning session for party {d} with {d} signers\n",
        .{ party, signers.len },
    );
    try ctx.emit("{s}\n", .{s.manifest.session});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// ecdsa sign / combine / verify
// ---------------------------------------------------------------------------

fn cmdEcdsa(ctx: *cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse {
        try ctx.warn("usage: zmpc ecdsa <sign|combine|verify> [options]\n", .{});
        return cmd.Exit.usage;
    };

    if (eql(action, "sign")) {
        try args.rejectUnknown(&.{
            "presig", "msg-file", "msg-hex", "digest", "out", "keep", "json", "quiet", "armor", "dir",
        });
        const presig = try args.require("presig");
        const digest = try digestFromArgs(ctx, args);
        return ecdsa.signPartial(
            ctx.*,
            presig,
            digest,
            args.valueOr("out", "partial.zmpc"),
            args.has("keep"),
        );
    }

    if (eql(action, "combine")) {
        try args.rejectUnknown(&.{
            "partials", "msg-file", "msg-hex", "digest", "pubkey-share",
            "out",      "json",     "quiet",   "armor",  "dir",
        });
        const digest = try digestFromArgs(ctx, args);
        const list = try args.require("partials");

        var paths: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, list, ',');
        while (it.next()) |piece| {
            const trimmed = std.mem.trim(u8, piece, " ");
            if (trimmed.len > 0) try paths.append(ctx.gpa, trimmed);
        }
        if (paths.items.len == 0) {
            try ctx.warn("--partials needs at least one file\n", .{});
            return cmd.Exit.usage;
        }

        return ecdsa.combine(
            ctx.*,
            paths.items,
            digest,
            args.value("pubkey-share"),
            args.valueOr("out", "signature.bin"),
        );
    }

    if (eql(action, "verify")) {
        try args.rejectUnknown(&.{
            "pubkey", "msg-file", "msg-hex", "digest", "sig", "json", "quiet", "armor", "dir",
        });
        const pubkey = try args.require("pubkey");
        const digest = try digestFromArgs(ctx, args);
        const sig_path = try args.require("sig");
        const sig_bytes = cmd.readFileBytes(ctx.*, sig_path) catch |e| {
            try ctx.warn("cannot read signature '{s}': {t}\n", .{ sig_path, e });
            return cmd.Exit.bad_input;
        };
        return ecdsa.verify(ctx.*, pubkey, digest, sig_bytes);
    }

    try ctx.warn("unknown ecdsa action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

fn digestFromArgs(ctx: *cmd.Ctx, args: *Args) ![32]u8 {
    if (args.value("digest")) |hex_text| {
        return ecdsa.digestOf(ctx.*, null, hex_text) catch |e| {
            try ctx.warn("--digest must be 32 bytes of hex: {t}\n", .{e});
            return error.Reported;
        };
    }
    const msg = cmd.readMessage(ctx.*, args.value("msg-file"), args.value("msg-hex")) catch {
        try ctx.warn("give the message with --msg-file/--msg-hex, or a --digest\n", .{});
        return error.Reported;
    };
    return ecdsa.digestOf(ctx.*, msg, null);
}

/// Shared "which round is this" mapping and ordering guard.
fn roundOf(
    step: []const u8,
    comptime a: []const u8,
    comptime b: []const u8,
    comptime c: []const u8,
    comptime d: []const u8,
) ?u16 {
    if (eql(step, a)) return 1;
    if (eql(step, b)) return 2;
    if (eql(step, c)) return 3;
    if (eql(step, d)) return 4;
    return null;
}

/// Refuse to re-run or skip a round. Returns an exit code if the command
/// should stop, or null to proceed.
fn guardRound(ctx: *cmd.Ctx, s: *session.Session, round: u16, step: []const u8) !?u8 {
    if (s.manifest.complete) {
        try ctx.warn("this session is already complete\n", .{});
        return cmd.Exit.usage;
    }
    if (round <= s.manifest.round) {
        try ctx.warn(
            "'{s}' already ran; re-running it would reuse committed randomness\n",
            .{step},
        );
        return cmd.Exit.usage;
    }
    if (round > s.manifest.round + 1) {
        try ctx.warn(
            "'{s}' cannot run yet; the next round is {d}\n",
            .{ step, s.manifest.round + 1 },
        );
        return cmd.Exit.usage;
    }
    return null;
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn cmdSign(ctx: *cmd.Ctx, args: *Args) !u8 {
    const step = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc sign <init|commit|share|aggregate|run> [--dir DIR]\n",
            .{},
        );
        return cmd.Exit.usage;
    };

    if (eql(step, "init")) return cmdSignInit(ctx, args);

    try args.rejectUnknown(&.{ "dir", "share", "armor", "json", "quiet" });
    var s = try openSession(ctx, args);
    if (s.protocol != .sign) {
        try ctx.warn("this session runs '{s}', not sign\n", .{s.manifest.protocol});
        return cmd.Exit.usage;
    }
    const share_override = args.value("share");
    if (eql(step, "run")) return sign.runAll(ctx.*, &s, share_override);

    const round: u16 = if (eql(step, "commit"))
        1
    else if (eql(step, "share"))
        2
    else if (eql(step, "aggregate"))
        3
    else {
        try ctx.warn("unknown sign step '{s}'\n", .{step});
        return cmd.Exit.usage;
    };

    if (s.manifest.complete) {
        try ctx.warn("this signing session is already complete\n", .{});
        return cmd.Exit.usage;
    }
    if (round <= s.manifest.round) {
        try ctx.warn(
            "'{s}' already ran in this session; start a new one rather than\n" ++
                "reusing nonces\n",
            .{step},
        );
        return cmd.Exit.usage;
    }
    return sign.run(ctx.*, &s, round, share_override);
}

fn cmdSignInit(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{
        "dir",     "share", "signers", "msg-file", "msg-hex",
        "session", "armor", "json",    "quiet",
    });

    const share_path = try args.require("share");
    const f = cmd.readFrame(ctx.*, share_path) catch |e| {
        try ctx.warn("cannot read key share '{s}': {t}\n", .{ share_path, e });
        return cmd.Exit.bad_input;
    };
    if (f.header.kind != .key_share) {
        try ctx.warn("'{s}' is not a key share\n", .{share_path});
        return cmd.Exit.bad_input;
    }
    if (!suite_mod.canSign(f.header.suite)) {
        try ctx.warn(
            "'{t}' key shares have no FROST ciphersuite here; use ed25519, " ++
                "secp256k1 or taproot (or `zmpc presign` for ECDSA)\n",
            .{f.header.suite},
        );
        return cmd.Exit.usage;
    }

    const shape = try shareShape(ctx, f);
    const signers = try args.intList(u16, ctx.gpa, "signers");
    if (try rejectBadSignerSet(ctx, signers, shape)) |code| return code;

    const msg = cmd.readMessage(ctx.*, args.value("msg-file"), args.value("msg-hex")) catch |e| {
        switch (e) {
            error.NoMessage => try ctx.warn("give the message with --msg-file or --msg-hex\n", .{}),
            error.InvalidHex => try ctx.warn("--msg-hex is not valid hex\n", .{}),
            else => try ctx.warn("cannot read the message: {t}\n", .{e}),
        }
        return cmd.Exit.bad_input;
    };

    // Every signer must sign the same bytes under the same session id. The
    // session id is what stops two concurrent signings from crossing over.
    const id_hex = if (args.value("session")) |given| blk: {
        _ = session.parseId(given) catch {
            try ctx.warn("--session must be 64 hex characters\n", .{});
            return cmd.Exit.usage;
        };
        break :blk given;
    } else blk: {
        var id: [32]u8 = undefined;
        ctx.rng.bytes(&id);
        break :blk try session.hexId(ctx.gpa, id);
    };

    // Which party are we? Read it from the share rather than asking.
    const party = shape.party;

    var found = false;
    for (signers) |sgn| {
        if (sgn == party) found = true;
    }
    if (!found) {
        try ctx.warn(
            "this share belongs to party {d}, which is not in --signers\n",
            .{party},
        );
        return cmd.Exit.usage;
    }

    var s = session.Session.create(ctx.env(), sessionDir(args), .{
        .session = id_hex,
        .protocol = "sign",
        .suite = @tagName(f.header.suite),
        .party = party,
        .n_parties = shape.n_parties,
        .threshold = shape.threshold,
        .signers = signers,
        .share_path = share_path,
    }) catch |e| switch (e) {
        error.SessionExists => {
            try ctx.warn("a session already exists in '{s}'\n", .{sessionDir(args)});
            return cmd.Exit.usage;
        },
        else => return e,
    };

    try std.Io.Dir.cwd().writeFile(ctx.io, .{
        .sub_path = try s.artifactPath(sign.message_file),
        .data = msg,
    });

    try ctx.note(
        "signing session for party {d} ({d} signers, {d} bytes to sign)\n",
        .{ party, signers.len, msg.len },
    );
    try ctx.emit("{s}\n", .{id_hex});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn cmdVerify(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{
        "suite", "pubkey", "msg-file", "msg-hex", "sig", "json", "quiet", "armor", "dir",
    });

    const suite_name = try args.require("suite");
    const st = suite_mod.parse(suite_name) orelse {
        try ctx.warn("unknown suite '{s}'; choose one of: {s}\n", .{ suite_name, suite_mod.names });
        return cmd.Exit.usage;
    };
    const pubkey = try args.require("pubkey");
    const msg = cmd.readMessage(ctx.*, args.value("msg-file"), args.value("msg-hex")) catch {
        try ctx.warn("give the message with --msg-file or --msg-hex\n", .{});
        return cmd.Exit.bad_input;
    };
    const sig_path = try args.require("sig");
    const sig_bytes = cmd.readFileBytes(ctx.*, sig_path) catch |e| {
        try ctx.warn("cannot read signature '{s}': {t}\n", .{ sig_path, e });
        return cmd.Exit.bad_input;
    };

    return sign.verify(ctx.*, st, pubkey, msg, sig_bytes);
}

// ---------------------------------------------------------------------------
// relay transport
// ---------------------------------------------------------------------------

fn cmdRelay(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "listen", "spool", "json", "quiet", "armor", "dir" });
    return relay.serve(
        ctx.*,
        args.valueOr("listen", "127.0.0.1:7000"),
        args.valueOr("spool", "zmpc-spool"),
    );
}

fn cmdPush(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "relay", "json", "quiet", "armor" });
    var s = try openSession(ctx, args);
    const count = try relay.push(ctx.*, &s, try args.require("relay"));
    try ctx.note("pushed {d} frame(s)\n", .{count});
    if (ctx.json) try ctx.emit("{{\"pushed\":{d}}}\n", .{count});
    return cmd.Exit.ok;
}

fn cmdPull(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "relay", "json", "quiet", "armor" });
    var s = try openSession(ctx, args);
    const count = try relay.pull(ctx.*, &s, try args.require("relay"));
    try ctx.note("pulled {d} frame(s)\n", .{count});
    if (ctx.json) try ctx.emit("{{\"pulled\":{d}}}\n", .{count});
    return cmd.Exit.ok;
}

/// Drive a whole protocol to completion over the relay: run what we can, push
/// what we produced, pull what arrived, repeat.
fn cmdNode(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{
        "dir",  "relay", "share", "aux", "primes", "poll-ms", "timeout-s",
        "json", "quiet", "armor",
    });
    var s = try openSession(ctx, args);
    const relay_addr = try args.require("relay");
    ctx.polling = true;
    const poll_ms = (try args.int(u32, "poll-ms")) orelse 500;
    const timeout_s = (try args.int(u32, "timeout-s")) orelse 600;

    const paths = ecdsa.Paths{ .share = args.value("share"), .aux = args.value("aux") };
    var waited_ms: u64 = 0;

    while (!s.manifest.complete) {
        const before = s.manifest.round;

        const code = switch (s.protocol) {
            .dkg => try dkg.run(ctx.*, &s, null),
            .refresh => try refresh.run(ctx.*, &s, null, args.value("share")),
            .auxgen => try auxgen.run(ctx.*, &s, null, args.value("primes")),
            .presign => try ecdsa.run(ctx.*, &s, null, paths),
            .sign => try sign.run(ctx.*, &s, null, args.value("share")),
            .none => {
                try ctx.warn("this session has no protocol to run\n", .{});
                return cmd.Exit.usage;
            },
        };

        if (code == cmd.Exit.ok) {
            _ = try relay.push(ctx.*, &s, relay_addr);
            waited_ms = 0;
            continue;
        }
        if (code != cmd.Exit.waiting) return code;

        // Waiting on peers: fetch and retry.
        _ = try relay.pull(ctx.*, &s, relay_addr);
        if (s.manifest.round != before) continue;

        if (waited_ms >= @as(u64, timeout_s) * 1000) {
            try ctx.warn("gave up after {d}s waiting for peers\n", .{timeout_s});
            return cmd.Exit.waiting;
        }
        std.Io.sleep(ctx.io, .fromMilliseconds(poll_ms), .awake) catch {};
        waited_ms += poll_ms;
    }

    try ctx.note("protocol complete\n", .{});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// refresh
// ---------------------------------------------------------------------------

fn cmdRefresh(ctx: *cmd.Ctx, args: *Args) !u8 {
    const step = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc refresh <init|round1|round2|finalize|run> [--dir DIR]\n",
            .{},
        );
        return cmd.Exit.usage;
    };

    if (eql(step, "init")) return cmdRefreshInit(ctx, args);

    try args.rejectUnknown(&.{ "dir", "share", "armor", "json", "quiet" });
    var s = try openSession(ctx, args);
    if (s.protocol != .refresh) {
        try ctx.warn("this session runs '{s}', not refresh\n", .{s.manifest.protocol});
        return cmd.Exit.usage;
    }
    const share_override = args.value("share");
    if (eql(step, "run")) return refresh.runAll(ctx.*, &s, share_override);

    const round: u16 = if (eql(step, "round1"))
        1
    else if (eql(step, "round2"))
        2
    else if (eql(step, "finalize"))
        3
    else {
        try ctx.warn("unknown refresh step '{s}'\n", .{step});
        return cmd.Exit.usage;
    };
    if (try guardRound(ctx, &s, round, step)) |code| return code;
    return refresh.run(ctx.*, &s, round, share_override);
}

fn cmdRefreshInit(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "share", "session", "armor", "json", "quiet" });

    const share_path = try args.require("share");
    const f = cmd.readFrame(ctx.*, share_path) catch |e| {
        try ctx.warn("cannot read key share '{s}': {t}\n", .{ share_path, e });
        return cmd.Exit.bad_input;
    };
    if (f.header.kind != .key_share) {
        try ctx.warn("'{s}' is not a key share\n", .{share_path});
        return cmd.Exit.bad_input;
    }

    const id_hex = if (args.value("session")) |given| blk: {
        _ = session.parseId(given) catch {
            try ctx.warn("--session must be 64 hex characters\n", .{});
            return cmd.Exit.usage;
        };
        break :blk given;
    } else blk: {
        var id: [32]u8 = undefined;
        ctx.rng.bytes(&id);
        break :blk try session.hexId(ctx.gpa, id);
    };

    const shape = try shareShape(ctx, f);
    const party = shape.party;

    const s = session.Session.create(ctx.env(), sessionDir(args), .{
        .session = id_hex,
        .protocol = "refresh",
        .suite = @tagName(f.header.suite),
        .party = party,
        .n_parties = shape.n_parties,
        .threshold = shape.threshold,
        .share_path = share_path,
    }) catch |e| switch (e) {
        error.SessionExists => {
            try ctx.warn("a session already exists in '{s}'\n", .{sessionDir(args)});
            return cmd.Exit.usage;
        },
        else => return e,
    };

    try ctx.note(
        "refresh session for party {d} of {d}; every party must take part\n",
        .{ party, shape.n_parties },
    );
    try ctx.emit("{s}\n", .{s.manifest.session});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// hd
// ---------------------------------------------------------------------------

fn cmdHd(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "share", "path", "out", "dir", "json", "quiet", "armor" });
    const action = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc hd <pubkey|derive> --share FILE --path m/44/0/7 [--out FILE]\n",
            .{},
        );
        return cmd.Exit.usage;
    };

    const share_path = if (args.value("share")) |p| p else blk: {
        var s = try openSession(ctx, args);
        break :blk try s.artifactPath(dkg.key_share_file);
    };
    const path_text = try args.require("path");

    if (eql(action, "pubkey")) return hd.derive(ctx.*, share_path, path_text, null);
    if (eql(action, "derive")) {
        const out = args.value("out") orelse {
            try ctx.warn("`hd derive` needs --out for the child share\n", .{});
            return cmd.Exit.usage;
        };
        return hd.derive(ctx.*, share_path, path_text, out);
    }

    try ctx.warn("unknown hd action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// share
// ---------------------------------------------------------------------------

fn cmdShare(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "dir", "share", "json", "quiet", "armor" });
    const action = args.word(1) orelse {
        try ctx.warn("usage: zmpc share <info|pubkey|verify> [--share FILE | --dir DIR]\n", .{});
        return cmd.Exit.usage;
    };

    const path = if (args.value("share")) |p| p else blk: {
        var s = try openSession(ctx, args);
        break :blk try s.artifactPath(dkg.key_share_file);
    };

    const f = cmd.readFrame(ctx.*, path) catch |e| {
        try ctx.warn("cannot read key share '{s}': {t}\n", .{ path, e });
        return cmd.Exit.bad_input;
    };
    if (f.header.kind != .key_share) {
        try ctx.warn("'{s}' is a {t} frame, not a key share\n", .{ path, f.header.kind });
        return cmd.Exit.bad_input;
    }

    return switch (f.header.suite) {
        inline else => |tag| shareFor(suite_mod.CurveOf(tag), ctx, f, action),
    };
}

fn shareFor(comptime E: type, ctx: *cmd.Ctx, f: frame.Frame, action: []const u8) !u8 {
    const KeyShare = mpc.dkg.Dkg(E).KeyShare;
    const share = try mpc.serde.decodeSlice(KeyShare, f.payload, .{ .gpa = ctx.gpa });
    share.validate() catch |e| {
        try ctx.warn("this key share is not well formed: {t}\n", .{e});
        return cmd.Exit.bad_input;
    };

    if (eql(action, "pubkey")) {
        // Taproot keys are x-only: print the 32 bytes that actually appear in
        // an output script and that `zmpc verify --suite taproot` expects.
        if (comptime E == mpc.bip340.E) {
            if (f.header.suite == .taproot) {
                try ctx.emit("{x}\n", .{&share.public_key.xOnly()});
                return cmd.Exit.ok;
            }
        }
        try ctx.emit("{x}\n", .{&share.public_key.toBytes()});
        return cmd.Exit.ok;
    }

    if (eql(action, "verify")) {
        const com = mpc.vss.Commitment(E){ .points = share.vss_commitment, .allocator = ctx.gpa };
        if (!com.verifyShare(share.party, share.secret_share)) {
            try ctx.warn("share is INCONSISTENT with its own commitment\n", .{});
            return cmd.Exit.protocol;
        }
        if (!com.publicKey().eql(share.public_key)) {
            try ctx.warn("public key does not match the commitment's constant term\n", .{});
            return cmd.Exit.protocol;
        }
        try ctx.note("share is consistent with its commitment\n", .{});
        return cmd.Exit.ok;
    }

    if (eql(action, "info")) {
        if (ctx.json) {
            try ctx.emit(
                "{{\"suite\":\"{t}\",\"party\":{d},\"threshold\":{d},\"parties\":{d}," ++
                    "\"public_key\":\"{x}\",\"chain_code\":\"{x}\",\"session\":\"{x}\"}}\n",
                .{
                    f.header.suite,    share.party,                 share.threshold,
                    share.n,           &share.public_key.toBytes(), &share.chain_code,
                    &f.header.session,
                },
            );
            return cmd.Exit.ok;
        }
        try ctx.emit("suite       {t}\n", .{f.header.suite});
        try ctx.emit("party       {d} of {d}\n", .{ share.party, share.n });
        try ctx.emit("threshold   {d}\n", .{share.threshold});
        try ctx.emit("public key  {x}\n", .{&share.public_key.toBytes()});
        if (comptime E == mpc.bip340.E) {
            if (f.header.suite == .taproot) {
                try ctx.emit("x-only key  {x}\n", .{&share.public_key.xOnly()});
            }
        }
        try ctx.emit("chain code  {x}\n", .{&share.chain_code});
        try ctx.emit("session     {x}\n", .{&f.header.session});
        try ctx.emit("rid         {x}\n", .{&share.rid});
        return cmd.Exit.ok;
    }

    try ctx.warn("unknown share action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

fn cmdInspect(ctx: *cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "json", "quiet", "armor", "dir" });
    const path = args.word(1) orelse {
        try ctx.warn("usage: zmpc inspect <file>\n", .{});
        return cmd.Exit.usage;
    };

    const f = cmd.readFrame(ctx.*, path) catch |e| {
        try ctx.warn("cannot read frame '{s}': {t}\n", .{ path, e });
        return cmd.Exit.bad_input;
    };
    const h = f.header;

    if (ctx.json) {
        try ctx.emit(
            "{{\"kind\":\"{t}\",\"channel\":\"{t}\",\"protocol\":\"{t}\",\"suite\":\"{t}\"," ++
                "\"round\":{d},\"from\":{d},\"to\":{d},\"parties\":{d},\"threshold\":{d}," ++
                "\"session\":\"{x}\",\"payload_bytes\":{d}}}\n",
            .{
                h.kind,        h.channel, h.protocol,  h.suite,     h.round,
                h.from,        h.to,      h.n_parties, h.threshold, &h.session,
                f.payload.len,
            },
        );
        return cmd.Exit.ok;
    }

    try ctx.emit("kind      {t}\n", .{h.kind});
    try ctx.emit("protocol  {t} round {d}\n", .{ h.protocol, h.round });
    try ctx.emit("suite     {t}\n", .{h.suite});
    try ctx.emit("channel   {t}\n", .{h.channel});
    try ctx.emit("from      {d}\n", .{h.from});
    if (h.channel == .p2p) try ctx.emit("to        {d}\n", .{h.to});
    try ctx.emit("parties   {d}, threshold {d}\n", .{ h.n_parties, h.threshold });
    try ctx.emit("session   {x}\n", .{&h.session});
    try ctx.emit("payload   {d} bytes\n", .{f.payload.len});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

fn reportError(ctx: cmd.Ctx, args: *Args, e: anyerror) !void {
    switch (e) {
        error.Reported => {},
        error.UnknownFlag => try ctx.warn("unknown option '--{s}'\n", .{args.bad_flag}),
        error.MissingRequiredFlag => try ctx.warn("missing required option '--{s}'\n", .{args.bad_flag}),
        error.MissingValue => try ctx.warn("option '--{s}' needs a value\n", .{args.bad_flag}),
        error.InvalidValue => try ctx.warn("bad value for '--{s}'\n", .{args.bad_value_for}),
        error.MissingState => try ctx.warn(
            "no saved state for this round - run the previous round first\n",
            .{},
        ),
        error.WrongSession, error.SuiteMismatch => try ctx.warn(
            "this session's files belong to a different run or suite\n",
            .{},
        ),
        else => try ctx.warn("error: {t}\n", .{e}),
    }
}

fn errorExit(e: anyerror) u8 {
    return switch (e) {
        error.UnknownFlag,
        error.MissingRequiredFlag,
        error.MissingValue,
        error.InvalidValue,
        => cmd.Exit.usage,
        error.MissingState,
        error.WrongSession,
        error.SuiteMismatch,
        error.MissingMessage,
        => cmd.Exit.bad_input,
        else => cmd.Exit.internal,
    };
}

test {
    _ = args_mod;
    _ = cmd;
    _ = frame;
    _ = hd;
    _ = session;
    _ = suite_mod;
}
