//! `zmpc dkg` - distributed key generation across processes.
//!
//! Three rounds plus a finalize, each a separate invocation:
//!
//!   round1  commit to a polynomial, a share of the session randomness, and a
//!           Schnorr proof-of-knowledge nonce                     [broadcast]
//!   round2  open the commitment; send every peer its VSS share  [bc + p2p]
//!   round3  verify all commitments and shares; prove knowledge   [broadcast]
//!   finalize verify every proof, emit the key share
//!
//! The resulting share is protocol-agnostic: the same artifact feeds FROST
//! signing and CGGMP24 ECDSA.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub const key_share_file = "keyshare.zmpc";

/// Run the next pending round, or the specific one named.
pub fn run(ctx: cmd.Ctx, s: *session.Session, step: ?u16) !u8 {
    return switch (s.suite) {
        inline else => |tag| runFor(suite_mod.CurveOf(tag), ctx, s, step),
    };
}

fn runFor(comptime E: type, ctx: cmd.Ctx, s: *session.Session, step: ?u16) !u8 {
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => round1(E, ctx, s),
        2 => round2(E, ctx, s),
        3 => round3(E, ctx, s),
        4 => finalize(E, ctx, s),
        else => {
            try ctx.warn("dkg has rounds 1..3 plus finalize (4); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

/// Advance as far as the messages on hand allow.
pub fn runAll(ctx: cmd.Ctx, s: *session.Session) !u8 {
    while (!s.manifest.complete) {
        const code = try run(ctx, s, null);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

/// Fetch this round's inputs, or explain what is still missing.
fn round1(comptime E: type, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const D = mpc.dkg.Dkg(E);
    const m = s.manifest;

    const result = try D.round1(ctx.gpa, .{
        .party = m.party,
        .threshold = m.threshold,
        .n = m.n_parties,
    }, mpc.dkg.ExecutionId.fromBytes(s.id), ctx.rng);

    const name = try s.emit(D.Round1Broadcast, result.broadcast, s.msgHeader(1, .broadcast, 0), ctx.armor);
    try s.saveState(D.State1, result.state, 1);
    try s.advance(1);

    try ctx.note("round 1: committed; wrote out/{s}\n", .{name});
    return cmd.Exit.ok;
}

fn round2(comptime E: type, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const D = mpc.dkg.Dkg(E);
    const m = s.manifest;

    const gathered = try cmd.gather(ctx, s, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(D.State1, 1);
    const incoming = try cmd.collectFrom(ctx, D.Round1Broadcast, inbox, 1, .broadcast, try s.participants(), m.party);

    const result = try D.round2(state, incoming);

    _ = try s.emit(D.Round2Broadcast, result.broadcast, s.msgHeader(2, .broadcast, 0), ctx.armor);
    for (result.p2p) |out| {
        _ = try s.emit(D.Round2P2p, out.msg, s.msgHeader(2, .p2p, out.to), ctx.armor);
    }
    try s.saveState(D.State2, result.state, 2);
    try s.advance(2);

    try ctx.note("round 2: opened commitment, sent {d} share(s)\n", .{result.p2p.len});
    return cmd.Exit.ok;
}

fn round3(comptime E: type, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const D = mpc.dkg.Dkg(E);
    const m = s.manifest;

    const gathered = try cmd.gather(ctx, s, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(D.State2, 2);
    const bc = try cmd.collectFrom(ctx, D.Round2Broadcast, inbox, 2, .broadcast, try s.participants(), m.party);
    const p2p = try cmd.collectFrom(ctx, D.Round2P2p, inbox, 2, .p2p, try s.participants(), m.party);

    const result = D.round3(state, bc, p2p) catch |err| return cmd.protocolAbort(ctx, "key generation", err, null);

    _ = try s.emit(D.Round3Broadcast, result.broadcast, s.msgHeader(3, .broadcast, 0), ctx.armor);
    try s.saveState(D.State3, result.state, 3);
    try s.advance(3);

    try ctx.note("round 3: all commitments and shares verified\n", .{});
    return cmd.Exit.ok;
}

fn finalize(comptime E: type, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const D = mpc.dkg.Dkg(E);
    const m = s.manifest;

    const gathered = try cmd.gather(ctx, s, 4);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(D.State3, 3);
    const bc = try cmd.collectFrom(ctx, D.Round3Broadcast, inbox, 3, .broadcast, try s.participants(), m.party);

    var share = D.finalize(state, bc) catch |err| return cmd.protocolAbort(ctx, "key generation", err, null);

    // BIP-340 keys are x-only with an implicit even Y. If the DKG landed on an
    // odd-Y group key, every party negates its own key material now, so that
    // what lands on disk is already Taproot-ready and `share pubkey` shows the
    // key that will actually be spent from.
    if (comptime E == mpc.bip340.E) {
        if (s.suite == .taproot) {
            var pk = share.public_key;
            if (mpc.bip340.normalizeKeyMaterial(&share.secret_share, &pk, share.vss_commitment)) {
                try ctx.note("group key had odd Y; negated key material for BIP-340\n", .{});
            }
            share.public_key = pk;
        }
    }

    const path = try s.saveArtifact(D.KeyShare, share, key_share_file, .key_share, true);
    try s.advance(4);
    try s.finish();

    // The round state held the polynomial and the accumulating share; it has
    // served its purpose and is secret, so drop it.
    for (1..4) |round| try s.consumeState(@intCast(round));

    try ctx.note("key generation complete; share written to {s}\n", .{path});
    if (ctx.json) {
        try ctx.emit("{{\"public_key\":\"{x}\",\"party\":{d},\"threshold\":{d},\"parties\":{d}," ++
            "\"chain_code\":\"{x}\"}}\n", .{
            &share.public_key.toBytes(), share.party, share.threshold, share.n, &share.chain_code,
        });
    } else {
        try ctx.emit("{x}\n", .{&share.public_key.toBytes()});
    }
    return cmd.Exit.ok;
}
