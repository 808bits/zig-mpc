//! WebAssembly interface to zig-mpc: everything a browser (or Node) needs to
//! run the full ceremony - trustless DKG, FROST signing, verification - plus
//! the CGGMP24 ECDSA signing half. There is no separate C ABI; this is the
//! module's only foreign interface.
//!
//! ## Conventions
//!
//! Byte buffers are staged in linear memory with `zmpc_alloc`/`zmpc_free`.
//! Protocol messages and artifacts are **wire frames** - the same
//! self-describing format the `zmpc` CLI reads and writes (`cli/frame.zig`),
//! so a key share generated in the browser works with `zmpc sign init` and
//! vice versa. Round *state* is an opaque serde blob: it never travels
//! between parties, the caller just holds it and hands it to the next round.
//! It contains secrets; treat it like one.
//!
//! Calls that produce a variable number of outputs (a round can emit a state
//! blob, a broadcast frame, and several p2p frames) stage them in an output
//! registry read back via `zmpc_out_count`/`zmpc_out_ptr`/`zmpc_out_len`.
//! The registry is cleared at the start of the next staging call - copy what
//! you need first. Use `zmpc_frame_meta` to route a frame (who it is from,
//! who it is for, broadcast or p2p) and `zmpc_frame_name` for the canonical
//! file name the CLI would give it.
//!
//! All randomness is caller-supplied (32 bytes per call that needs it) and
//! MUST come from a CSPRNG, e.g. `crypto.getRandomValues`.
//!
//! `suite` parameters take the frame-header suite id: ed25519=1, secp256k1=2,
//! taproot=5 (and for the ECDSA calls, ecdsa_fast=0x101, ecdsa_prod=0x102).
//!
//! Return codes: 0 success; -1 bad argument or malformed input; -2 internal
//! failure; -3 verification failed; -4 the protocol aborted (a peer's
//! commitment, share, or proof did not check out).

const std = @import("std");
const bip340 = @import("bip340.zig");
const curve = @import("curve.zig");
const dkg = @import("dkg.zig");
const ecdsa = @import("ecdsa.zig");
const frost = @import("frost.zig");
const serde = @import("serde.zig");
const zk = @import("zk.zig");
const frame = @import("frame");

pub const ZMPC_OK: c_int = 0;
pub const ZMPC_ERR_INVALID_ARG: c_int = -1;
pub const ZMPC_ERR_CRYPTO: c_int = -2;
pub const ZMPC_ERR_VERIFY: c_int = -3;
pub const ZMPC_ERR_PROTOCOL: c_int = -4;

const allocator = std.heap.wasm_allocator;
const max_parties = 16;

export fn zmpc_alloc(len: usize) ?[*]u8 {
    const mem = allocator.alloc(u8, len) catch return null;
    return mem.ptr;
}

export fn zmpc_free(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}

// ---------------------------------------------------------------------------
// output registry
// ---------------------------------------------------------------------------

var staged: [max_parties + 2][]u8 = undefined;
var staged_count: usize = 0;

fn stageClear() void {
    for (staged[0..staged_count]) |b| allocator.free(b);
    staged_count = 0;
}

/// Copy `bytes` (typically arena-allocated) into the registry.
fn stage(bytes: []const u8) !void {
    if (staged_count == staged.len) return error.TooManyOutputs;
    staged[staged_count] = try allocator.dupe(u8, bytes);
    staged_count += 1;
}

export fn zmpc_out_count() usize {
    return staged_count;
}

export fn zmpc_out_ptr(i: usize) ?[*]u8 {
    return if (i < staged_count) staged[i].ptr else null;
}

export fn zmpc_out_len(i: usize) usize {
    return if (i < staged_count) staged[i].len else 0;
}

export fn zmpc_out_clear() void {
    stageClear();
}

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

const FrostSuiteTag = enum { ed25519, secp256k1, taproot };

fn frostTagOf(raw: u32) ?FrostSuiteTag {
    const s = std.enums.fromInt(frame.Suite, raw) orelse return null;
    return switch (s) {
        .ed25519 => .ed25519,
        .secp256k1 => .secp256k1,
        .taproot => .taproot,
        else => null,
    };
}

fn FrostSuiteOf(comptime tag: FrostSuiteTag) type {
    return switch (tag) {
        .ed25519 => frost.Ed25519Sha512,
        .secp256k1 => frost.Secp256k1Sha256,
        .taproot => bip340.FrostTaprootSuite,
    };
}

fn CurveOf(comptime tag: FrostSuiteTag) type {
    return FrostSuiteOf(tag).E;
}

fn frameSuiteOf(comptime tag: FrostSuiteTag) frame.Suite {
    return switch (tag) {
        .ed25519 => .ed25519,
        .secp256k1 => .secp256k1,
        .taproot => .taproot,
    };
}

fn chachaFrom(seed: *const [32]u8) std.Random.ChaCha {
    return std.Random.ChaCha.init(seed.*);
}

fn digestOf(msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &out, .{});
    return out;
}

/// Serde-encode a value and wrap it in a frame, in `arena`.
fn encodeFrame(arena: std.mem.Allocator, comptime T: type, value: T, h: frame.Header) ![]u8 {
    const payload = try serde.encodeAlloc(T, value, arena);
    return frame.encodeAlloc(arena, h, payload);
}

const ParsedFrame = struct { header: frame.Header, payload: []const u8 };

/// Parse one incoming round-message frame and check it belongs to this
/// round of this run.
fn expectMsg(
    bytes: []const u8,
    suite: frame.Suite,
    protocol: frame.Protocol,
    round: u16,
    session: [32]u8,
) !ParsedFrame {
    const f = frame.parse(bytes) catch return error.Malformed;
    const h = f.header;
    if (h.kind != .message or h.protocol != protocol or h.suite != suite or h.round != round)
        return error.Malformed;
    if (!std.mem.eql(u8, &h.session, &session)) return error.Malformed;
    return .{ .header = h, .payload = f.payload };
}

// ---------------------------------------------------------------------------
// DKG - trustless distributed key generation, 3 rounds + finalize
// ---------------------------------------------------------------------------

/// Round 1: commit to a random polynomial. Stages [0] the round state
/// (secret, keep for round 2) and [1] one broadcast frame for every peer.
export fn zmpc_dkg_round1(
    suite: u32,
    party: u32,
    n: u32,
    threshold: u32,
    session: *const [32]u8,
    entropy: *const [32]u8,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    if (n < 2 or n > max_parties or party < 1 or party > n or threshold < 1 or threshold > n)
        return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| dkgRound1(t, @intCast(party), @intCast(n), @intCast(threshold), session, entropy),
    };
}

fn dkgRound1(
    comptime tag: FrostSuiteTag,
    party: u16,
    n: u16,
    threshold: u16,
    session: *const [32]u8,
    entropy: *const [32]u8,
) c_int {
    const D = dkg.Dkg(CurveOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var rng_state = chachaFrom(entropy);

    const result = D.round1(
        arena,
        .{ .party = party, .threshold = threshold, .n = n },
        dkg.ExecutionId.fromBytes(session.*),
        rng_state.random(),
    ) catch return ZMPC_ERR_CRYPTO;

    const state = serde.encodeAlloc(D.State1, result.state, arena) catch return ZMPC_ERR_CRYPTO;
    stage(state) catch return ZMPC_ERR_CRYPTO;
    const bc = encodeFrame(arena, D.Round1Broadcast, result.broadcast, .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .dkg,
        .suite = frameSuiteOf(tag),
        .round = 1,
        .from = party,
        .n_parties = n,
        .threshold = threshold,
        .session = session.*,
    }) catch return ZMPC_ERR_CRYPTO;
    stage(bc) catch return ZMPC_ERR_CRYPTO;
    return ZMPC_OK;
}

/// Round 2: open the commitment, send every peer its VSS share. Takes the
/// round-1 state and the n-1 round-1 broadcast frames received from peers.
/// Stages [0] the new state, [1] a broadcast frame, [2..] one p2p frame per
/// peer - deliver each p2p frame ONLY to the party named in its header (it
/// carries that party's secret share).
export fn zmpc_dkg_round2(
    suite: u32,
    state_ptr: [*]const u8,
    state_len: usize,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| dkgRound2(t, state_ptr[0..state_len], ptrs, lens, count),
    };
}

fn dkgRound2(
    comptime tag: FrostSuiteTag,
    state_bytes: []const u8,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    const D = dkg.Dkg(CurveOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const state = serde.decodeSlice(D.State1, state_bytes, .{ .gpa = arena }) catch
        return ZMPC_ERR_INVALID_ARG;
    const p = state.params;
    const session = state.eid.bytes;
    const suite = frameSuiteOf(tag);

    if (count != p.n - 1) return ZMPC_ERR_INVALID_ARG;
    const incoming = arena.alloc(D.From(D.Round1Broadcast), count) catch return ZMPC_ERR_CRYPTO;
    for (0..count) |i| {
        const pf = expectMsg(ptrs[i][0..lens[i]], suite, .dkg, 1, session) catch
            return ZMPC_ERR_INVALID_ARG;
        if (pf.header.channel != .broadcast or pf.header.from == p.party)
            return ZMPC_ERR_INVALID_ARG;
        incoming[i] = .{
            .from = pf.header.from,
            .msg = serde.decodeSlice(D.Round1Broadcast, pf.payload, .{ .gpa = arena }) catch
                return ZMPC_ERR_INVALID_ARG,
        };
    }

    const result = D.round2(state, incoming) catch return ZMPC_ERR_PROTOCOL;

    const state2 = serde.encodeAlloc(D.State2, result.state, arena) catch return ZMPC_ERR_CRYPTO;
    stage(state2) catch return ZMPC_ERR_CRYPTO;

    var h = frame.Header{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .dkg,
        .suite = suite,
        .round = 2,
        .from = p.party,
        .n_parties = p.n,
        .threshold = p.threshold,
        .session = session,
    };
    const bc = encodeFrame(arena, D.Round2Broadcast, result.broadcast, h) catch
        return ZMPC_ERR_CRYPTO;
    stage(bc) catch return ZMPC_ERR_CRYPTO;

    for (result.p2p) |out| {
        h.channel = .p2p;
        h.to = out.to;
        const pf = encodeFrame(arena, D.Round2P2p, out.msg, h) catch return ZMPC_ERR_CRYPTO;
        stage(pf) catch return ZMPC_ERR_CRYPTO;
    }
    return ZMPC_OK;
}

/// Round 3: verify every commitment and share. Takes the round-2 state and
/// ALL round-2 frames addressed to this party - the n-1 broadcasts plus the
/// n-1 p2p frames whose `to` is this party. Stages [0] the new state and
/// [1] a broadcast frame.
export fn zmpc_dkg_round3(
    suite: u32,
    state_ptr: [*]const u8,
    state_len: usize,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| dkgRound3(t, state_ptr[0..state_len], ptrs, lens, count),
    };
}

fn dkgRound3(
    comptime tag: FrostSuiteTag,
    state_bytes: []const u8,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    const D = dkg.Dkg(CurveOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const state = serde.decodeSlice(D.State2, state_bytes, .{ .gpa = arena }) catch
        return ZMPC_ERR_INVALID_ARG;
    const p = state.s1.params;
    const session = state.s1.eid.bytes;
    const suite = frameSuiteOf(tag);

    if (count != 2 * (@as(usize, p.n) - 1)) return ZMPC_ERR_INVALID_ARG;
    const bc = arena.alloc(D.From(D.Round2Broadcast), p.n - 1) catch return ZMPC_ERR_CRYPTO;
    const p2p = arena.alloc(D.From(D.Round2P2p), p.n - 1) catch return ZMPC_ERR_CRYPTO;
    var bc_n: usize = 0;
    var p2p_n: usize = 0;
    for (0..count) |i| {
        const pf = expectMsg(ptrs[i][0..lens[i]], suite, .dkg, 2, session) catch
            return ZMPC_ERR_INVALID_ARG;
        if (pf.header.from == p.party) return ZMPC_ERR_INVALID_ARG;
        switch (pf.header.channel) {
            .broadcast => {
                if (bc_n == bc.len) return ZMPC_ERR_INVALID_ARG;
                bc[bc_n] = .{
                    .from = pf.header.from,
                    .msg = serde.decodeSlice(D.Round2Broadcast, pf.payload, .{ .gpa = arena }) catch
                        return ZMPC_ERR_INVALID_ARG,
                };
                bc_n += 1;
            },
            .p2p => {
                // A p2p frame for someone else holds their secret share; its
                // presence here means misrouting. Refuse rather than ignore.
                if (pf.header.to != p.party or p2p_n == p2p.len) return ZMPC_ERR_INVALID_ARG;
                p2p[p2p_n] = .{
                    .from = pf.header.from,
                    .msg = serde.decodeSlice(D.Round2P2p, pf.payload, .{ .gpa = arena }) catch
                        return ZMPC_ERR_INVALID_ARG,
                };
                p2p_n += 1;
            },
            else => return ZMPC_ERR_INVALID_ARG,
        }
    }
    if (bc_n != bc.len or p2p_n != p2p.len) return ZMPC_ERR_INVALID_ARG;

    const result = D.round3(state, bc, p2p) catch return ZMPC_ERR_PROTOCOL;

    const state3 = serde.encodeAlloc(D.State3, result.state, arena) catch return ZMPC_ERR_CRYPTO;
    stage(state3) catch return ZMPC_ERR_CRYPTO;
    const out = encodeFrame(arena, D.Round3Broadcast, result.broadcast, .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .dkg,
        .suite = suite,
        .round = 3,
        .from = p.party,
        .n_parties = p.n,
        .threshold = p.threshold,
        .session = session,
    }) catch return ZMPC_ERR_CRYPTO;
    stage(out) catch return ZMPC_ERR_CRYPTO;
    return ZMPC_OK;
}

/// Finalize: check every proof and emit the key share. Takes the round-3
/// state and the n-1 round-3 broadcast frames. Stages [0] the key-share
/// frame - SECRET, this party's long-term share, the CLI's
/// `artifacts/keyshare.zmpc` - and writes the group public key (33 bytes
/// SEC1 for secp256k1, 32 for ed25519, 32 x-only for taproot) to `out_pk`.
export fn zmpc_dkg_finalize(
    suite: u32,
    state_ptr: [*]const u8,
    state_len: usize,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
    out_pk: *[33]u8,
    out_pk_len: *usize,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| dkgFinalize(t, state_ptr[0..state_len], ptrs, lens, count, out_pk, out_pk_len),
    };
}

fn dkgFinalize(
    comptime tag: FrostSuiteTag,
    state_bytes: []const u8,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
    out_pk: *[33]u8,
    out_pk_len: *usize,
) c_int {
    const D = dkg.Dkg(CurveOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const state = serde.decodeSlice(D.State3, state_bytes, .{ .gpa = arena }) catch
        return ZMPC_ERR_INVALID_ARG;
    const p = state.params;
    const session = state.eid.bytes;
    const suite = frameSuiteOf(tag);

    if (count != p.n - 1) return ZMPC_ERR_INVALID_ARG;
    const bc = arena.alloc(D.From(D.Round3Broadcast), count) catch return ZMPC_ERR_CRYPTO;
    for (0..count) |i| {
        const pf = expectMsg(ptrs[i][0..lens[i]], suite, .dkg, 3, session) catch
            return ZMPC_ERR_INVALID_ARG;
        if (pf.header.channel != .broadcast or pf.header.from == p.party)
            return ZMPC_ERR_INVALID_ARG;
        bc[i] = .{
            .from = pf.header.from,
            .msg = serde.decodeSlice(D.Round3Broadcast, pf.payload, .{ .gpa = arena }) catch
                return ZMPC_ERR_INVALID_ARG,
        };
    }

    var share = D.finalize(state, bc) catch return ZMPC_ERR_PROTOCOL;

    // BIP-340 keys are x-only with an implicit even Y: if the DKG landed on
    // an odd-Y group key, negate the key material now so the share is
    // Taproot-ready, exactly as the CLI does.
    if (comptime tag == .taproot) {
        var pk = share.public_key;
        _ = bip340.normalizeKeyMaterial(&share.secret_share, &pk, share.vss_commitment);
        share.public_key = pk;
    }

    const ks = encodeFrame(arena, D.KeyShare, share, .{
        .kind = .key_share,
        .channel = .artifact,
        .protocol = .none,
        .suite = suite,
        .from = p.party,
        .n_parties = p.n,
        .threshold = p.threshold,
        .session = session,
    }) catch return ZMPC_ERR_CRYPTO;
    stage(ks) catch return ZMPC_ERR_CRYPTO;

    if (comptime tag == .taproot) {
        out_pk[0..32].* = share.public_key.xOnly();
        out_pk_len.* = 32;
    } else {
        const bytes = share.public_key.toBytes();
        out_pk[0..bytes.len].* = bytes;
        out_pk_len.* = bytes.len;
    }
    return ZMPC_OK;
}

// ---------------------------------------------------------------------------
// FROST signing - commit, share, aggregate
// ---------------------------------------------------------------------------

/// What `commit` stages for `share`: the secret nonces, the public
/// commitment, and the digest of the message this signing run was created
/// for - nonce reuse across messages is refused, not just discouraged.
fn CommitState(comptime F: type) type {
    return struct {
        nonces: F.SecretNonces,
        commitment: F.Commitment,
        msg_digest: [32]u8,
        session: [32]u8,
    };
}

/// Signing round 1: commit to fresh nonces. Takes this signer's key-share
/// frame, the message, a signing-session id shared by all signers, and
/// entropy. Stages [0] the commit state (SECRET, single-use) and [1] a
/// broadcast frame for the other signers.
export fn zmpc_sign_commit(
    suite: u32,
    share_ptr: [*]const u8,
    share_len: usize,
    msg_ptr: [*]const u8,
    msg_len: usize,
    session: *const [32]u8,
    entropy: *const [32]u8,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| signCommit(t, share_ptr[0..share_len], msg_ptr[0..msg_len], session, entropy),
    };
}

fn loadKeyShare(
    comptime tag: FrostSuiteTag,
    arena: std.mem.Allocator,
    bytes: []const u8,
) !dkg.Dkg(CurveOf(tag)).KeyShare {
    const f = frame.parse(bytes) catch return error.Malformed;
    if (f.header.kind != .key_share or f.header.suite != frameSuiteOf(tag)) return error.Malformed;
    const key = try serde.decodeSlice(dkg.Dkg(CurveOf(tag)).KeyShare, f.payload, .{ .gpa = arena });
    try key.validate();
    return key;
}

fn signCommit(
    comptime tag: FrostSuiteTag,
    share_bytes: []const u8,
    msg: []const u8,
    session: *const [32]u8,
    entropy: *const [32]u8,
) c_int {
    const F = frost.Frost(FrostSuiteOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var rng_state = chachaFrom(entropy);

    const key = loadKeyShare(tag, arena, share_bytes) catch return ZMPC_ERR_INVALID_ARG;
    const result = F.commit(key.party, key.secret_share, rng_state.random()) catch
        return ZMPC_ERR_CRYPTO;

    const state = serde.encodeAlloc(CommitState(F), .{
        .nonces = result.nonces,
        .commitment = result.commitment,
        .msg_digest = digestOf(msg),
        .session = session.*,
    }, arena) catch return ZMPC_ERR_CRYPTO;
    stage(state) catch return ZMPC_ERR_CRYPTO;

    const bc = encodeFrame(arena, F.Commitment, result.commitment, .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .sign,
        .suite = frameSuiteOf(tag),
        .round = 1,
        .from = key.party,
        .n_parties = key.n,
        .threshold = key.threshold,
        .session = session.*,
    }) catch return ZMPC_ERR_CRYPTO;
    stage(bc) catch return ZMPC_ERR_CRYPTO;
    return ZMPC_OK;
}

/// Decode commit frames into the commitment list every signer must agree
/// on: ascending by identifier, one entry per signer.
fn commitmentList(
    comptime F: type,
    arena: std.mem.Allocator,
    suite: frame.Suite,
    session: [32]u8,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) ![]F.Commitment {
    if (count < 1 or count > max_parties) return error.Malformed;
    const list = try arena.alloc(F.Commitment, count);
    for (0..count) |i| {
        const pf = try expectMsg(ptrs[i][0..lens[i]], suite, .sign, 1, session);
        if (pf.header.channel != .broadcast) return error.Malformed;
        list[i] = try serde.decodeSlice(F.Commitment, pf.payload, .{ .gpa = arena });
        if (list[i].identifier != pf.header.from) return error.Malformed;
    }
    std.mem.sort(F.Commitment, list, {}, struct {
        fn lt(_: void, a: F.Commitment, b: F.Commitment) bool {
            return a.identifier < b.identifier;
        }
    }.lt);
    for (list[1..], 0..) |c, i| {
        if (c.identifier <= list[i].identifier) return error.Malformed;
    }
    return list;
}

/// Signing round 2: produce this signer's signature share. Takes the commit
/// state, the key-share frame, the message, and ALL signers' commit frames
/// (this signer's included). Stages [0] the signature-share broadcast frame,
/// and **zeroes the input state buffer** - FROST nonces are single-use, and
/// a second share over the same nonces would reveal this signer's key share.
export fn zmpc_sign_share(
    suite: u32,
    state_ptr: [*]u8,
    state_len: usize,
    share_ptr: [*]const u8,
    share_len: usize,
    msg_ptr: [*]const u8,
    msg_len: usize,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| signShare(
            t,
            state_ptr[0..state_len],
            share_ptr[0..share_len],
            msg_ptr[0..msg_len],
            ptrs,
            lens,
            count,
        ),
    };
}

fn signShare(
    comptime tag: FrostSuiteTag,
    state_bytes: []u8,
    share_bytes: []const u8,
    msg: []const u8,
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
) c_int {
    const F = frost.Frost(FrostSuiteOf(tag));
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const state = serde.decodeSlice(CommitState(F), state_bytes, .{ .gpa = arena }) catch
        return ZMPC_ERR_INVALID_ARG;
    // The nonces were committed for one specific message; signing different
    // bytes with them would reveal the key share.
    if (!std.crypto.timing_safe.eql([32]u8, digestOf(msg), state.msg_digest))
        return ZMPC_ERR_VERIFY;

    const key = loadKeyShare(tag, arena, share_bytes) catch return ZMPC_ERR_INVALID_ARG;
    const list = commitmentList(F, arena, frameSuiteOf(tag), state.session, ptrs, lens, count) catch
        return ZMPC_ERR_INVALID_ARG;

    // Our own entry must be the commitment these nonces belong to.
    const own = for (list) |c| {
        if (c.identifier == key.party) break c;
    } else return ZMPC_ERR_INVALID_ARG;
    if (!own.hiding.eql(state.commitment.hiding) or !own.binding.eql(state.commitment.binding))
        return ZMPC_ERR_INVALID_ARG;

    const sig_share = F.sign(key.party, key.secret_share, key.public_key, state.nonces, msg, list) catch
        return ZMPC_ERR_CRYPTO;

    // Destroy the nonces before the share exists anywhere.
    @memset(state_bytes, 0);

    const out = encodeFrame(arena, CurveOf(tag).Scalar, sig_share, .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .sign,
        .suite = frameSuiteOf(tag),
        .round = 2,
        .from = key.party,
        .n_parties = key.n,
        .threshold = key.threshold,
        .session = state.session,
    }) catch return ZMPC_ERR_CRYPTO;
    stage(out) catch return ZMPC_ERR_CRYPTO;
    return ZMPC_OK;
}

/// Aggregate: combine the signature shares into one ordinary signature.
/// Takes the key-share frame, the message, ALL commit frames and ALL
/// signature-share frames (one of each per signer). Each share is checked
/// individually first - a bad one names its author (-4) instead of just
/// producing garbage. Writes the signature to `out_sig`: 64 bytes for
/// ed25519 (RFC 8032) and taproot (BIP-340), 65 for secp256k1 (R ‖ z).
export fn zmpc_sign_aggregate(
    suite: u32,
    share_ptr: [*]const u8,
    share_len: usize,
    msg_ptr: [*]const u8,
    msg_len: usize,
    commit_ptrs: [*]const [*]const u8,
    commit_lens: [*]const usize,
    sig_ptrs: [*]const [*]const u8,
    sig_lens: [*]const usize,
    count: usize,
    out_sig: *[65]u8,
    out_sig_len: *usize,
) c_int {
    stageClear();
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    return switch (tag) {
        inline else => |t| signAggregate(
            t,
            share_ptr[0..share_len],
            msg_ptr[0..msg_len],
            commit_ptrs,
            commit_lens,
            sig_ptrs,
            sig_lens,
            count,
            out_sig,
            out_sig_len,
        ),
    };
}

fn signAggregate(
    comptime tag: FrostSuiteTag,
    share_bytes: []const u8,
    msg: []const u8,
    commit_ptrs: [*]const [*]const u8,
    commit_lens: [*]const usize,
    sig_ptrs: [*]const [*]const u8,
    sig_lens: [*]const usize,
    count: usize,
    out_sig: *[65]u8,
    out_sig_len: *usize,
) c_int {
    const F = frost.Frost(FrostSuiteOf(tag));
    const E = CurveOf(tag);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const key = loadKeyShare(tag, arena, share_bytes) catch return ZMPC_ERR_INVALID_ARG;

    // The session id comes from the frames themselves; commitmentList checks
    // that every frame carries the same one.
    const first = frame.parse(commit_ptrs[0][0..commit_lens[0]]) catch return ZMPC_ERR_INVALID_ARG;
    const session = first.header.session;
    const list = commitmentList(F, arena, frameSuiteOf(tag), session, commit_ptrs, commit_lens, count) catch
        return ZMPC_ERR_INVALID_ARG;

    // One signature share per signer, aligned with the commitment list.
    const shares = arena.alloc(E.Scalar, count) catch return ZMPC_ERR_CRYPTO;
    const seen = arena.alloc(bool, count) catch return ZMPC_ERR_CRYPTO;
    @memset(seen, false);
    for (0..count) |i| {
        const pf = expectMsg(sig_ptrs[i][0..sig_lens[i]], frameSuiteOf(tag), .sign, 2, session) catch
            return ZMPC_ERR_INVALID_ARG;
        const pos = for (list, 0..) |c, j| {
            if (c.identifier == pf.header.from) break j;
        } else return ZMPC_ERR_INVALID_ARG;
        if (seen[pos]) return ZMPC_ERR_INVALID_ARG;
        seen[pos] = true;
        shares[pos] = serde.decodeSlice(E.Scalar, pf.payload, .{ .gpa = arena }) catch
            return ZMPC_ERR_INVALID_ARG;
    }

    // Check each share before combining - RFC 9591's identifiable abort.
    for (list, shares) |c, sig_share| {
        const pk_i = key.publicShareOf(c.identifier) catch return ZMPC_ERR_INVALID_ARG;
        const ok = F.verifySigShare(c.identifier, pk_i, sig_share, key.public_key, msg, list) catch false;
        if (!ok) return ZMPC_ERR_PROTOCOL;
    }

    const sig = F.aggregate(list, msg, key.public_key, shares) catch return ZMPC_ERR_CRYPTO;
    if (!F.verify(msg, key.public_key, sig)) return ZMPC_ERR_VERIFY;

    if (comptime tag == .taproot) {
        out_sig[0..64].* = bip340.signatureToBytes(sig);
        out_sig_len.* = 64;
    } else {
        const bytes = sig.toBytes();
        out_sig[0..bytes.len].* = bytes;
        out_sig_len.* = bytes.len;
    }
    return ZMPC_OK;
}

/// Verify a signature with nothing but the public key - the check any
/// outside party would perform. Public keys and signatures use the formats
/// `zmpc_dkg_finalize` and `zmpc_sign_aggregate` emit.
export fn zmpc_verify(
    suite: u32,
    pk_ptr: [*]const u8,
    pk_len: usize,
    msg_ptr: [*]const u8,
    msg_len: usize,
    sig_ptr: [*]const u8,
    sig_len: usize,
) c_int {
    const tag = frostTagOf(suite) orelse return ZMPC_ERR_INVALID_ARG;
    const pk = pk_ptr[0..pk_len];
    const msg = msg_ptr[0..msg_len];
    const sig = sig_ptr[0..sig_len];
    return switch (tag) {
        inline else => |t| verifyFor(t, pk, msg, sig),
    };
}

fn verifyFor(comptime tag: FrostSuiteTag, pk: []const u8, msg: []const u8, sig: []const u8) c_int {
    if (comptime tag == .taproot) {
        if (pk.len != 32 or sig.len != 64) return ZMPC_ERR_INVALID_ARG;
        if (!bip340.verify(pk[0..32].*, msg, sig[0..64].*)) return ZMPC_ERR_VERIFY;
        return ZMPC_OK;
    }
    const F = frost.Frost(FrostSuiteOf(tag));
    const E = CurveOf(tag);
    if (pk.len != E.Point.encoded_length or sig.len != F.Signature.encoded_length)
        return ZMPC_ERR_INVALID_ARG;
    const point = E.Point.fromBytes(pk[0..E.Point.encoded_length].*) catch
        return ZMPC_ERR_INVALID_ARG;
    const s = F.Signature.fromBytes(sig[0..F.Signature.encoded_length].*) catch
        return ZMPC_ERR_INVALID_ARG;
    if (!F.verify(msg, point, s)) return ZMPC_ERR_VERIFY;
    return ZMPC_OK;
}

// ---------------------------------------------------------------------------
// frame and key-share introspection
// ---------------------------------------------------------------------------

/// Decode a frame's routing header into nine u16s:
/// [kind, channel, protocol, suite, round, from, to, n_parties, threshold].
/// `to` = 0 means broadcast: deliver to every other party. `to` = N means
/// p2p: deliver to party N only.
export fn zmpc_frame_meta(ptr: [*]const u8, len: usize, out: *[9]u16) c_int {
    const f = frame.parse(ptr[0..len]) catch return ZMPC_ERR_INVALID_ARG;
    const h = f.header;
    out.* = .{
        @intFromEnum(h.kind),  @intFromEnum(h.channel), @intFromEnum(h.protocol),
        @intFromEnum(h.suite), h.round,                 h.from,
        h.to,                  h.n_parties,             h.threshold,
    };
    return ZMPC_OK;
}

/// The canonical file name the CLI would give this frame
/// (`<session8>-<protocol>-r<round>-<b|p|a>-f<from>-t<to>.zmpc`).
export fn zmpc_frame_name(ptr: [*]const u8, len: usize, out: *[64]u8, out_len: *usize) c_int {
    const f = frame.parse(ptr[0..len]) catch return ZMPC_ERR_INVALID_ARG;
    const name = frame.fileName(out, f.header, false) catch return ZMPC_ERR_CRYPTO;
    out_len.* = name.len;
    return ZMPC_OK;
}

/// The public key inside a key-share frame, in the suite's verification
/// format (x-only for taproot).
export fn zmpc_share_pubkey(ptr: [*]const u8, len: usize, out: *[33]u8, out_len: *usize) c_int {
    const f = frame.parse(ptr[0..len]) catch return ZMPC_ERR_INVALID_ARG;
    if (f.header.kind != .key_share) return ZMPC_ERR_INVALID_ARG;
    switch (f.header.suite) {
        .ed25519, .secp256k1, .taproot => {},
        .ecdsa_fast, .ecdsa_prod => {
            var arena_state = std.heap.ArenaAllocator.init(allocator);
            defer arena_state.deinit();
            const key = serde.decodeSlice(
                dkg.Dkg(curve.Secp256k1).KeyShare,
                f.payload,
                .{ .gpa = arena_state.allocator() },
            ) catch return ZMPC_ERR_INVALID_ARG;
            out[0..33].* = key.public_key.toBytes();
            out_len.* = 33;
            return ZMPC_OK;
        },
        else => return ZMPC_ERR_INVALID_ARG,
    }
    const tag: FrostSuiteTag = switch (f.header.suite) {
        .ed25519 => .ed25519,
        .secp256k1 => .secp256k1,
        .taproot => .taproot,
        else => unreachable,
    };
    return switch (tag) {
        inline else => |t| blk: {
            var arena_state = std.heap.ArenaAllocator.init(allocator);
            defer arena_state.deinit();
            const key = serde.decodeSlice(
                dkg.Dkg(CurveOf(t)).KeyShare,
                f.payload,
                .{ .gpa = arena_state.allocator() },
            ) catch break :blk ZMPC_ERR_INVALID_ARG;
            if (comptime t == .taproot) {
                out[0..32].* = key.public_key.xOnly();
                out_len.* = 32;
            } else {
                const bytes = key.public_key.toBytes();
                out[0..bytes.len].* = bytes;
                out_len.* = bytes.len;
            }
            break :blk ZMPC_OK;
        },
    };
}

// ---------------------------------------------------------------------------
// CGGMP24 ECDSA: signing with a presignature
// ---------------------------------------------------------------------------

const Secp = curve.Secp256k1;
/// `partialSign`, `combine` and `verify` never touch the Paillier/ZK
/// parameters - the presignature is two curve scalars and a point - so one
/// instantiation serves frames from both `ecdsa_fast` and `ecdsa_prod`.
const Ecdsa = ecdsa.Ecdsa(zk.common.Params(576, 256, 512, 384), Secp);

fn scalarFromDigest(digest: *const [32]u8) Secp.Scalar {
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], digest);
    return Secp.Scalar.fromWideBytes(wide);
}

fn isCggmp(s: frame.Suite) bool {
    return s == .ecdsa_fast or s == .ecdsa_prod;
}

/// Produce this signer's partial signature from a `presignature.zmpc` frame
/// and a 32-byte message digest.
///
/// On success, writes a partial-signature frame (allocated with the module
/// allocator; release it with `zmpc_free`) to `out_ptr`/`out_len`, and
/// **zeroes the input presignature buffer**: a presignature signs at most one
/// message - using it twice reveals the private key - and the caller must
/// also destroy any other copy it holds.
export fn zmpc_ecdsa_partial_sign(
    presig: [*]u8,
    presig_len: usize,
    digest: *const [32]u8,
    out_ptr: *[*]u8,
    out_len: *usize,
) c_int {
    const bytes = presig[0..presig_len];
    const f = frame.parse(bytes) catch return ZMPC_ERR_INVALID_ARG;
    if (f.header.kind != .presignature or !isCggmp(f.header.suite))
        return ZMPC_ERR_INVALID_ARG;

    var p = serde.decodeSlice(Ecdsa.Presignature, f.payload, .{ .gpa = allocator }) catch
        return ZMPC_ERR_INVALID_ARG;
    const partial = Ecdsa.PartialSig{
        .gamma = p.gamma,
        .sigma = Ecdsa.partialSign(p, scalarFromDigest(digest)),
    };
    p.zeroize();

    const payload = serde.encodeAlloc(Ecdsa.PartialSig, partial, allocator) catch
        return ZMPC_ERR_CRYPTO;
    defer allocator.free(payload);
    var h = f.header;
    h.kind = .signature;
    h.protocol = .sign;
    h.channel = .broadcast;
    h.round = 1;
    const out = frame.encodeAlloc(allocator, h, payload) catch return ZMPC_ERR_CRYPTO;

    @memset(bytes, 0);
    out_ptr.* = out.ptr;
    out_len.* = out.len;
    return ZMPC_OK;
}

/// Combine partial-signature frames into a 64-byte ECDSA signature (r ‖ s).
///
/// `ptrs`/`lens` are parallel arrays of `count` frame buffers. All partials
/// must come from the same presigning session and the same presignature; a
/// mismatch is refused. If `pk33` (compressed SEC1 public key) is non-null,
/// the result is verified before it is returned - without it, a wrong or
/// missing partial yields an *invalid* signature, not an error.
export fn zmpc_ecdsa_combine(
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
    digest: *const [32]u8,
    pk33: ?*const [33]u8,
    out_sig: *[64]u8,
) c_int {
    if (count == 0 or count > 128) return ZMPC_ERR_INVALID_ARG;
    const partials = allocator.alloc(Secp.Scalar, count) catch return ZMPC_ERR_CRYPTO;
    defer allocator.free(partials);

    var gamma: ?Secp.Point = null;
    var session: [32]u8 = undefined;
    for (0..count) |i| {
        const f = frame.parse(ptrs[i][0..lens[i]]) catch return ZMPC_ERR_INVALID_ARG;
        if (f.header.kind != .signature or !isCggmp(f.header.suite))
            return ZMPC_ERR_INVALID_ARG;
        if (i == 0) {
            session = f.header.session;
        } else if (!std.mem.eql(u8, &session, &f.header.session)) {
            return ZMPC_ERR_INVALID_ARG;
        }
        const partial = serde.decodeSlice(Ecdsa.PartialSig, f.payload, .{ .gpa = allocator }) catch
            return ZMPC_ERR_INVALID_ARG;
        if (gamma) |g| {
            if (!g.eql(partial.gamma)) return ZMPC_ERR_INVALID_ARG;
        } else {
            gamma = partial.gamma;
        }
        partials[i] = partial.sigma;
    }

    const m = scalarFromDigest(digest);
    const sig = Ecdsa.combine(gamma.?, partials, m) catch return ZMPC_ERR_CRYPTO;
    if (pk33) |pk_bytes| {
        const pk = Secp.Point.fromBytes(pk_bytes.*) catch return ZMPC_ERR_INVALID_ARG;
        if (!Ecdsa.verify(pk, m, sig)) return ZMPC_ERR_VERIFY;
    }
    out_sig[0..32].* = sig.r.toBytes();
    out_sig[32..64].* = sig.s.toBytes();
    return ZMPC_OK;
}

/// Verify a 64-byte ECDSA signature against a compressed SEC1 public key and
/// a 32-byte digest, the way any outside verifier would.
export fn zmpc_ecdsa_verify(
    pk33: *const [33]u8,
    digest: *const [32]u8,
    sig: *const [64]u8,
) c_int {
    const pk = Secp.Point.fromBytes(pk33.*) catch return ZMPC_ERR_INVALID_ARG;
    const r = Secp.Scalar.fromBytes(sig[0..32].*) catch return ZMPC_ERR_INVALID_ARG;
    const s = Secp.Scalar.fromBytes(sig[32..64].*) catch return ZMPC_ERR_INVALID_ARG;
    if (!Ecdsa.verify(pk, scalarFromDigest(digest), .{ .r = r, .s = s }))
        return ZMPC_ERR_VERIFY;
    return ZMPC_OK;
}
