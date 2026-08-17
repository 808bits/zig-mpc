//! `zmpc dkls` - DKLs23 threshold ECDSA.
//!
//! The other ECDSA route in this tool. Where `zmpc auxgen` + `zmpc presign`
//! run CGGMP24 on Paillier encryption, this runs DKLs23 on oblivious transfer:
//! no safe primes, no aux-info ceremony, and nothing per signature but curve
//! and hash work. It signs on secp256k1 under the `dkls` suite.
//!
//! Two commands, after a normal `zmpc dkg`:
//!
//!   dkls setup   round1, round2, finalize                          [p2p]
//!   dkls sign    phase1, phase2, phase3, finalize            [p2p, p2p, bc]
//!
//! Setup runs once among *all* parties and its artifact is reusable: any later
//! quorum picks out the entries it needs, exactly as aux-info does for CGGMP24.
//! It is the expensive step, because each ordered pair costs 256 endemic
//! oblivious transfers and a Fischlin proof of work, so its messages are large
//! (on the order of 90 kB per counterparty). Signing afterwards is cheap.
//!
//! The setup artifact holds base-OT correlations, which are secret and are
//! *not* safe to reuse across a fork of the session: two signings that reuse
//! one correlation against different inputs leak. Each `dkls sign` session
//! derives fresh per-signature values from the session id, so distinct
//! sessions are fine; copying a session directory and running both is not.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub const setup_file = "dkls-setup.zmpc";
pub const signature_file = "signature.bin";

const E = mpc.curve.Secp256k1;
const Setup = mpc.dkls.setup.Setup(E);
const Signer = mpc.dkls.sign.Signer(E);

/// Where signing finds the material it needs. Both default to what the session
/// recorded at init.
pub const Paths = struct {
    share: ?[]const u8 = null,
    setup: ?[]const u8 = null,
};

fn requireDkls(ctx: cmd.Ctx, s: *session.Session) !bool {
    if (s.suite == .dkls) return true;
    try ctx.warn(
        "DKLs23 needs the 'dkls' suite; this session uses '{t}'\n",
        .{s.suite},
    );
    return false;
}

fn header(s: *session.Session, protocol: frame.Protocol, round: u16, channel: frame.Channel, to: u16) frame.Header {
    return .{
        .kind = .message,
        .channel = channel,
        .protocol = protocol,
        .suite = s.suite,
        .round = round,
        .from = s.manifest.party,
        .to = to,
        .n_parties = s.manifest.n_parties,
        .threshold = s.manifest.threshold,
        .session = s.id,
    };
}

fn gather(ctx: cmd.Ctx, s: *session.Session, protocol: frame.Protocol, round: u16) !union(enum) {
    ready: session.Inbox,
    waiting: u8,
} {
    const inbox = s.scanInbox() catch |err| switch (err) {
        error.Equivocation => {
            try ctx.warn("refusing to continue: a peer sent contradictory messages\n", .{});
            return .{ .waiting = cmd.Exit.protocol };
        },
        else => return err,
    };
    const reqs = try session.requirements(ctx.gpa, protocol, round, try s.participants(), s.manifest.party);
    const missing = try inbox.missing(reqs);
    if (missing.len > 0) return .{ .waiting = try cmd.reportMissingWith(ctx, missing, inbox.rejected) };
    return .{ .ready = inbox };
}

/// The counterparties of this party within `participants`, ascending.
fn counterpartiesOf(ctx: cmd.Ctx, s: *session.Session) ![]u16 {
    const all = try s.participants();
    const out = try ctx.gpa.alloc(u16, all.len - 1);
    var k: usize = 0;
    for (all) |j| {
        if (j == s.manifest.party) continue;
        out[k] = j;
        k += 1;
    }
    return out;
}

fn loadShare(ctx: cmd.Ctx, s: *session.Session, override: ?[]const u8) !mpc.dkg.Dkg(E).KeyShare {
    const path = override orelse s.manifest.share_path orelse return error.NoKeyShare;
    const f = try cmd.readFrame(ctx, path);
    if (f.header.kind != .key_share) return error.WrongArtifactKind;
    if (f.header.suite != s.suite) return error.SuiteMismatch;
    const share = try mpc.serde.decodeSlice(mpc.dkg.Dkg(E).KeyShare, f.payload, .{ .gpa = ctx.gpa });
    try share.validate();
    return share;
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

/// A party's finished setup, as written to disk.
///
/// The peers are stored in ascending index order, matching what the signing
/// phases expect.
pub const StoredSetup = struct {
    execution_id: [32]u8,
    chain_code: [32]u8,
    zero_pairs: []mpc.dkls.zeroshare.SeedPair,
    peers: []StoredPeer,
};

pub const StoredPeer = struct {
    index: u16,
    sender_correlation: [mpc.dkls.ote.row_len]u8,
    sender_seeds: [mpc.dkls.ote.kappa][32]u8,
    sender_gadget: []E.Scalar,
    receiver_seeds0: [mpc.dkls.ote.kappa][32]u8,
    receiver_seeds1: [mpc.dkls.ote.kappa][32]u8,
    receiver_gadget: []E.Scalar,
};

fn storeParty(gpa: std.mem.Allocator, p: mpc.dkls.sign.Party(E)) !StoredSetup {
    const peers = try gpa.alloc(StoredPeer, p.peers.len);
    for (p.peers, 0..) |peer, i| {
        peers[i] = .{
            .index = peer.index,
            .sender_correlation = peer.as_sender.ote_sender.correlation,
            .sender_seeds = peer.as_sender.ote_sender.seeds,
            .sender_gadget = peer.as_sender.gadget,
            .receiver_seeds0 = peer.as_receiver.ote_receiver.seeds0,
            .receiver_seeds1 = peer.as_receiver.ote_receiver.seeds1,
            .receiver_gadget = peer.as_receiver.gadget,
        };
    }
    return .{
        .execution_id = p.execution_id,
        .chain_code = p.chain_code,
        .zero_pairs = p.zero.pairs,
        .peers = peers,
    };
}

fn restoreParty(
    gpa: std.mem.Allocator,
    stored: StoredSetup,
    params: mpc.dkls.sign.Params,
    key_share: E.Scalar,
    public_key: E.Point,
) !mpc.dkls.sign.Party(E) {
    const peers = try gpa.alloc(mpc.dkls.sign.Peer(E), stored.peers.len);
    for (stored.peers, 0..) |sp, i| {
        peers[i] = .{
            .index = sp.index,
            .as_sender = .{
                .ote_sender = .{ .correlation = sp.sender_correlation, .seeds = sp.sender_seeds },
                .gadget = sp.sender_gadget,
            },
            .as_receiver = .{
                .ote_receiver = .{ .seeds0 = sp.receiver_seeds0, .seeds1 = sp.receiver_seeds1 },
                .gadget = sp.receiver_gadget,
            },
        };
    }
    return .{
        .params = params,
        .execution_id = stored.execution_id,
        .chain_code = stored.chain_code,
        .key_share = key_share,
        .public_key = public_key,
        .zero = .{ .pairs = stored.zero_pairs },
        .peers = peers,
    };
}

pub fn setupRun(ctx: cmd.Ctx, s: *session.Session, step: ?u16, share_override: ?[]const u8) !u8 {
    if (!try requireDkls(ctx, s)) return cmd.Exit.usage;
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => setupRound1(ctx, s),
        2 => setupRound2(ctx, s),
        3 => setupFinalize(ctx, s, share_override),
        else => {
            try ctx.warn("dkls setup has rounds 1 and 2 plus finalize (3); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

pub fn setupRunAll(ctx: cmd.Ctx, s: *session.Session, share_override: ?[]const u8) !u8 {
    while (!s.manifest.complete) {
        const code = try setupRun(ctx, s, null, share_override);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

fn setupRound1(ctx: cmd.Ctx, s: *session.Session) !u8 {
    const params = mpc.dkls.sign.Params{
        .party = s.manifest.party,
        .n = s.manifest.n_parties,
        .threshold = s.manifest.threshold,
    };
    try ctx.note("running {d} base-OT setups; this is the slow step\n", .{params.n - 1});

    const out = Setup.round1(ctx.gpa, params, s.id, ctx.rng) catch |err|
        return cmd.protocolAbort(ctx, "dkls setup", err, null);
    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);

    for (cps, 0..) |cp, i| {
        _ = try s.emit(mpc.dkls.setup.Round1(E), out.messages[i], header(s, .dkls_setup, 1, .p2p, cp), ctx.armor);
    }
    try s.saveState(Setup.State1, out.state, 1);
    try s.advance(1);

    try ctx.note("round 1: base-OT material sent to {d} peer(s)\n", .{cps.len});
    return cmd.Exit.ok;
}

fn setupRound2(ctx: cmd.Ctx, s: *session.Session) !u8 {
    const state = try s.loadState(Setup.State1, 1);
    const out = try Setup.round2(ctx.gpa, state);
    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);

    for (cps, 0..) |cp, i| {
        _ = try s.emit(mpc.dkls.setup.Round2(E), out.messages[i], header(s, .dkls_setup, 2, .p2p, cp), ctx.armor);
    }
    try s.advance(2);

    try ctx.note("round 2: zero-share seeds opened\n", .{});
    return cmd.Exit.ok;
}

fn setupFinalize(ctx: cmd.Ctx, s: *session.Session, share_override: ?[]const u8) !u8 {
    const gathered = try gather(ctx, s, .dkls_setup, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);

    const r1 = try ctx.gpa.alloc(mpc.dkls.setup.Round1(E), cps.len);
    defer ctx.gpa.free(r1);
    const r2 = try ctx.gpa.alloc(mpc.dkls.setup.Round2(E), cps.len);
    defer ctx.gpa.free(r2);
    for (cps, 0..) |cp, i| {
        r1[i] = try inbox.decode(mpc.dkls.setup.Round1(E), .{ .round = 1, .channel = .p2p, .from = cp, .to = s.manifest.party });
        r2[i] = try inbox.decode(mpc.dkls.setup.Round2(E), .{ .round = 2, .channel = .p2p, .from = cp, .to = s.manifest.party });
    }

    const key = try loadShare(ctx, s, share_override);
    const params = mpc.dkls.sign.Params{
        .party = s.manifest.party,
        .n = s.manifest.n_parties,
        .threshold = s.manifest.threshold,
    };
    const state = try s.loadState(Setup.State1, 1);

    const party = Setup.finalize(
        ctx.gpa,
        params,
        s.id,
        key.chain_code,
        key.secret_share,
        key.public_key,
        state,
        cps,
        r1,
        r2,
    ) catch |err| return cmd.protocolAbort(ctx, "dkls setup", err, null);

    const stored = try storeParty(ctx.gpa, party);
    const path = try s.saveArtifact(StoredSetup, stored, setup_file, .dkls_setup, true);
    try s.advance(3);
    for (1..3) |round| try s.consumeState(@intCast(round));

    try ctx.note("dkls setup complete; written to {s}\n", .{path});
    if (ctx.json) {
        try ctx.emit("{{\"setup\":\"{s}\",\"party\":{d},\"peers\":{d}}}\n", .{ path, params.party, cps.len });
    } else {
        try ctx.emit("{s}\n", .{path});
    }
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

pub fn signRun(ctx: cmd.Ctx, s: *session.Session, step: ?u16, paths: Paths) !u8 {
    if (!try requireDkls(ctx, s)) return cmd.Exit.usage;
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => signPhase1(ctx, s, paths),
        2 => signPhase2(ctx, s, paths),
        3 => signPhase3(ctx, s, paths),
        4 => signFinalize(ctx, s, paths),
        else => {
            try ctx.warn("dkls sign has phases 1..3 plus finalize (4); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

pub fn signRunAll(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    while (!s.manifest.complete) {
        const code = try signRun(ctx, s, null, paths);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

fn loadParty(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !mpc.dkls.sign.Party(E) {
    const key = try loadShare(ctx, s, paths.share);
    const path = paths.setup orelse s.manifest.aux_path orelse return error.NoSetup;
    const loaded = try cmd.readArtifact(ctx, StoredSetup, path, .dkls_setup);
    return restoreParty(ctx.gpa, loaded.value, .{
        .party = s.manifest.party,
        .n = s.manifest.n_parties,
        .threshold = s.manifest.threshold,
    }, key.secret_share, key.public_key);
}

fn signData(ctx: cmd.Ctx, s: *session.Session) !mpc.dkls.sign.SignData {
    const digest = try cmd.readFileBytes(ctx, try s.artifactPath("message.bin"));
    var h: [32]u8 = undefined;
    if (digest.len == 32) {
        @memcpy(&h, digest);
    } else {
        std.crypto.hash.sha2.Sha256.hash(digest, &h, .{});
    }
    return .{ .sign_id = s.id, .quorum = try s.participants(), .message_hash = h };
}

fn signPhase1(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    const party = try loadParty(ctx, s, paths);
    const data = try signData(ctx, s);

    const out = Signer.phase1(ctx.gpa, party, data, ctx.rng) catch |err|
        return cmd.protocolAbort(ctx, "dkls signing", err, null);

    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);
    for (cps, 0..) |cp, i| {
        _ = try s.emit(mpc.dkls.sign.Round1(E), out.messages[i], header(s, .dkls_sign, 1, .p2p, cp), ctx.armor);
    }
    try s.saveState(Signer.State1, out.state, 1);
    try s.advance(1);

    try ctx.note("phase 1: instance key committed, multiplications opened\n", .{});
    return cmd.Exit.ok;
}

fn signPhase2(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    const gathered = try gather(ctx, s, .dkls_sign, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const party = try loadParty(ctx, s, paths);
    const data = try signData(ctx, s);
    var state = try s.loadState(Signer.State1, 1);

    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);
    const msgs = try ctx.gpa.alloc(mpc.dkls.sign.Round1(E), cps.len);
    defer ctx.gpa.free(msgs);
    for (cps, 0..) |cp, i| {
        msgs[i] = try inbox.decode(mpc.dkls.sign.Round1(E), .{ .round = 1, .channel = .p2p, .from = cp, .to = s.manifest.party });
    }

    const out = Signer.phase2(ctx.gpa, party, data, &state, cps, msgs, ctx.rng) catch |err|
        return cmd.protocolAbort(ctx, "dkls signing", err, null);

    for (cps, 0..) |cp, i| {
        _ = try s.emit(mpc.dkls.sign.Round2(E), out.messages[i], header(s, .dkls_sign, 2, .p2p, cp), ctx.armor);
    }
    try s.saveState(Signer.State2, out.state, 2);
    try s.advance(2);

    try ctx.note("phase 2: key share converted, multiplications answered\n", .{});
    return cmd.Exit.ok;
}

fn signPhase3(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    const gathered = try gather(ctx, s, .dkls_sign, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const party = try loadParty(ctx, s, paths);
    const data = try signData(ctx, s);
    var state = try s.loadState(Signer.State2, 2);

    const cps = try counterpartiesOf(ctx, s);
    defer ctx.gpa.free(cps);
    const msgs = try ctx.gpa.alloc(mpc.dkls.sign.Round2(E), cps.len);
    defer ctx.gpa.free(msgs);
    for (cps, 0..) |cp, i| {
        msgs[i] = try inbox.decode(mpc.dkls.sign.Round2(E), .{ .round = 2, .channel = .p2p, .from = cp, .to = s.manifest.party });
    }

    const out = Signer.phase3(ctx.gpa, party, data, &state, cps, msgs) catch |err|
        return cmd.protocolAbort(ctx, "dkls signing", err, null);

    _ = try s.emit(mpc.dkls.sign.Round3(E), out.broadcast, header(s, .dkls_sign, 3, .broadcast, 0), ctx.armor);
    try s.saveState(Signer.Out3, out, 3);
    try s.advance(3);

    try ctx.note("phase 3: counterparties checked, components published\n", .{});
    return cmd.Exit.ok;
}

fn signFinalize(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    const gathered = try gather(ctx, s, .dkls_sign, 4);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const party = try loadParty(ctx, s, paths);
    const data = try signData(ctx, s);
    const out3 = try s.loadState(Signer.Out3, 3);

    // Phase 3 is a broadcast including this party's own component, so the
    // combination covers the whole quorum.
    const quorum = try s.participants();
    const bcast = try ctx.gpa.alloc(mpc.dkls.sign.Round3(E), quorum.len);
    defer ctx.gpa.free(bcast);
    for (quorum, 0..) |p, i| {
        bcast[i] = if (p == s.manifest.party)
            out3.broadcast
        else
            try inbox.decode(mpc.dkls.sign.Round3(E), .{ .round = 3, .channel = .broadcast, .from = p });
    }

    const sig = Signer.phase4(party, data, out3, bcast) catch |err|
        return cmd.protocolAbort(ctx, "dkls signing", err, null);

    const bytes = sig.toBytes();
    const path = try s.artifactPath(signature_file);
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = &bytes });
    try s.advance(4);
    for (1..4) |round| try s.consumeState(@intCast(round));

    try ctx.note("signature written to {s}\n", .{path});
    if (ctx.json) {
        try ctx.emit("{{\"signature\":\"{x}\",\"recovery_id\":{d},\"file\":\"{s}\"}}\n", .{ &bytes, sig.recovery_id, path });
    } else {
        try ctx.emit("{x}\n", .{&bytes});
    }
    return cmd.Exit.ok;
}
