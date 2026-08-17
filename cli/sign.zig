//! `zmpc sign` - FROST threshold signing across processes.
//!
//! Two rounds plus an aggregation, each a separate invocation:
//!
//!   commit     publish nonce commitments                         [broadcast]
//!   share      publish this signer's signature share             [broadcast]
//!   aggregate  combine the shares into one ordinary signature
//!
//! Signing runs among a chosen subset of the parties. The output is a plain
//! signature - Ed25519 under RFC 8032, or BIP-340 for Taproot - verifiable by
//! anyone with no knowledge that a threshold scheme was involved.
//!
//! Nonces are single-use. `share` deletes the nonce state as soon as it has
//! produced a signature share: signing two different messages with the same
//! FROST nonce reveals the signer's key share.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub const message_file = "message.bin";
pub const signature_file = "signature.bin";

/// What `commit` leaves behind for `share`: the secret nonces, the public
/// commitment, and the digest of the message this session was created to sign.
///
/// The digest is what makes nonce reuse detectable. FROST's round 1 does not
/// involve the message at all, so nothing in the protocol stops a signer from
/// committing once and then signing two different messages with those nonces -
/// which reveals the key share. Recording the message at commit time and
/// checking it at share time turns that into a refusal.
fn Committed(comptime F: type) type {
    return struct {
        nonces: F.SecretNonces,
        commitment: F.Commitment,
        msg_digest: [32]u8,
    };
}

/// What `share` leaves behind for `aggregate`: this signer's own contribution.
/// Public data - the secret nonces are destroyed at the same moment this is
/// written.
fn Partial(comptime F: type) type {
    return struct {
        commitment: F.Commitment,
        sig_share: F.E.Scalar,
    };
}

fn digestOf(msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &out, .{});
    return out;
}

/// `share_override` replaces the key-share path recorded at init, for when a
/// session directory has moved relative to the share it was created against.
pub fn run(ctx: cmd.Ctx, s: *session.Session, step: ?u16, share_override: ?[]const u8) !u8 {
    return switch (s.suite) {
        inline .ed25519, .secp256k1, .taproot => |tag| runFor(tag, ctx, s, step, share_override),
        else => {
            try ctx.warn(
                "suite '{t}' has no FROST ciphersuite; signing supports ed25519, " ++
                    "secp256k1 and taproot\n",
                .{s.suite},
            );
            return cmd.Exit.usage;
        },
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
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    step: ?u16,
    share_override: ?[]const u8,
) !u8 {
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => commit(tag, ctx, s, share_override),
        2 => shareRound(tag, ctx, s, share_override),
        3 => aggregate(tag, ctx, s, share_override),
        else => {
            try ctx.warn("sign has commit (1), share (2) and aggregate (3); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

fn header(s: *session.Session, round: u16) frame.Header {
    return .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .sign,
        .suite = s.suite,
        .round = round,
        .from = s.manifest.party,
        .n_parties = s.manifest.n_parties,
        .threshold = s.manifest.threshold,
        .session = s.id,
    };
}

/// Load the key share this session signs with. The recorded path is stored
/// exactly as it was given at init, so it is resolved against the current
/// directory; `--share` overrides it.
fn loadShare(
    comptime E: type,
    ctx: cmd.Ctx,
    s: *session.Session,
    override: ?[]const u8,
) !mpc.dkg.Dkg(E).KeyShare {
    const path = override orelse s.manifest.share_path orelse return error.NoKeyShare;
    const f = try cmd.readFrame(ctx, path);
    if (f.header.kind != .key_share) return error.WrongArtifactKind;
    if (f.header.suite != s.suite) return error.SuiteMismatch;
    const key = try mpc.serde.decodeSlice(mpc.dkg.Dkg(E).KeyShare, f.payload, .{ .gpa = ctx.gpa });
    try key.validate();
    return key;
}

fn loadMessage(ctx: cmd.Ctx, s: *session.Session) ![]const u8 {
    return cmd.readFileBytes(ctx, try s.artifactPath(message_file));
}

fn gather(ctx: cmd.Ctx, s: *session.Session, round: u16) !union(enum) {
    ready: session.Inbox,
    waiting: u8,
} {
    const inbox = s.scanInbox() catch |err| switch (err) {
        error.Equivocation => {
            try ctx.warn(
                "refusing to continue: a signer sent two different messages for the\n" ++
                    "same round. Inspect in/ before retrying.\n",
                .{},
            );
            return .{ .waiting = cmd.Exit.protocol };
        },
        else => return err,
    };
    const reqs = try session.requirements(ctx.gpa, .sign, round, try s.participants(), s.manifest.party);
    const missing = try inbox.missing(reqs);
    if (missing.len > 0)
        return .{ .waiting = try cmd.reportMissingWith(ctx, missing, inbox.rejected) };
    return .{ .ready = inbox };
}

// ---------------------------------------------------------------------------
// round 1: commit
// ---------------------------------------------------------------------------

fn commit(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    share_override: ?[]const u8,
) !u8 {
    const F = mpc.frost.Frost(suite_mod.FrostSuiteOf(tag).?);
    const E = F.E;

    const key = try loadShare(E, ctx, s, share_override);
    const msg = try loadMessage(ctx, s);
    const result = try F.commit(s.manifest.party, key.secret_share, ctx.rng);

    _ = try s.emit(F.Commitment, result.commitment, header(s, 1), ctx.armor);
    try s.saveState(Committed(F), .{
        .nonces = result.nonces,
        .commitment = result.commitment,
        .msg_digest = digestOf(msg),
    }, 1);
    try s.advance(1);

    try ctx.note("commit: nonce commitments published\n", .{});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// round 2: signature share
// ---------------------------------------------------------------------------

/// Assemble the commitment list every signer must agree on: ascending by
/// identifier, one entry per signer, ours included.
fn commitmentList(
    comptime F: type,
    ctx: cmd.Ctx,
    s: *session.Session,
    inbox: session.Inbox,
    own: F.Commitment,
) ![]F.Commitment {
    const parties = try s.participants();
    const list = try ctx.gpa.alloc(F.Commitment, parties.len);
    for (parties, 0..) |p, i| {
        list[i] = if (p == s.manifest.party)
            own
        else
            try inbox.decode(F.Commitment, .{ .round = 1, .channel = .broadcast, .from = p });
        if (list[i].identifier != p) return error.IdentifierMismatch;
    }
    // `participants` is already ascending, but the ciphersuite requires it, so
    // make that a checked property rather than an assumption.
    for (list[1..], 0..) |c, i| {
        if (c.identifier <= list[i].identifier) return error.UnsortedSigners;
    }
    return list;
}

fn shareRound(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    share_override: ?[]const u8,
) !u8 {
    const F = mpc.frost.Frost(suite_mod.FrostSuiteOf(tag).?);
    const E = F.E;

    const gathered = try gather(ctx, s, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = s.loadState(Committed(F), 1) catch |err| switch (err) {
        error.MissingState => {
            try ctx.warn(
                "no nonce state: either `zmpc sign commit` has not run, or this\n" ++
                    "signer already produced a share. FROST nonces are single-use -\n" ++
                    "start a new signing session rather than reusing them.\n",
                .{},
            );
            return cmd.Exit.bad_input;
        },
        else => return err,
    };

    const key = try loadShare(E, ctx, s, share_override);
    const msg = try loadMessage(ctx, s);

    // These nonces were committed to for one specific message. Signing a
    // different one with them would reveal this signer's key share, so a
    // changed message is a refusal, not a warning.
    if (!std.crypto.timing_safe.eql([32]u8, digestOf(msg), state.msg_digest)) {
        try ctx.warn(
            "the message changed since `sign commit` ran in this session.\n" ++
                "Signing it with the committed nonces would reveal this signer's\n" ++
                "key share. Start a new signing session for the new message.\n",
            .{},
        );
        return cmd.Exit.protocol;
    }

    const list = try commitmentList(F, ctx, s, inbox, state.commitment);

    const sig_share = try F.sign(
        s.manifest.party,
        key.secret_share,
        key.public_key,
        state.nonces,
        msg,
        list,
    );

    // Destroy the nonces *first*, before the share exists anywhere. If this
    // ran after emitting, a failure in between (a full disk, a kill) would
    // leave both the published share and the reusable nonces on disk with the
    // manifest still saying round 1 - so `sign share` would run again. Two
    // shares over the same nonces under different binding factors are two
    // equations in one unknown, and the key share falls out.
    try s.consumeState(1);

    _ = try s.emit(E.Scalar, sig_share, header(s, 2), ctx.armor);
    try s.saveState(Partial(F), .{ .commitment = state.commitment, .sig_share = sig_share }, 2);
    try s.advance(2);

    try ctx.note("share: signature share published, nonces destroyed\n", .{});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// round 3: aggregate
// ---------------------------------------------------------------------------

fn aggregate(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    share_override: ?[]const u8,
) !u8 {
    const F = mpc.frost.Frost(suite_mod.FrostSuiteOf(tag).?);
    const E = F.E;

    const gathered = try gather(ctx, s, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const own = try s.loadState(Partial(F), 2);
    const key = try loadShare(E, ctx, s, share_override);
    const msg = try loadMessage(ctx, s);
    const parties = try s.participants();
    const list = try commitmentList(F, ctx, s, inbox, own.commitment);

    const shares = try ctx.gpa.alloc(E.Scalar, parties.len);
    for (parties, 0..) |p, i| {
        shares[i] = if (p == s.manifest.party)
            own.sig_share
        else
            try inbox.decode(E.Scalar, .{ .round = 2, .channel = .broadcast, .from = p });
    }

    // Check each share before combining. A bad share would otherwise produce
    // an invalid signature with nothing to say about who caused it; this is
    // RFC 9591's identifiable abort.
    for (parties, shares) |p, sig_share| {
        const pk_i = try key.publicShareOf(p);
        const ok = F.verifySigShare(p, pk_i, sig_share, key.public_key, msg, list) catch false;
        if (!ok) return cmd.protocolAbortReason(ctx, "signing", .{
            .reason = .invalid_signature_share,
            .culprit = p,
        });
    }

    const sig = try F.aggregate(list, msg, key.public_key, shares);
    if (!F.verify(msg, key.public_key, sig)) {
        return cmd.protocolAbortReason(ctx, "signing", .{ .reason = .aggregate_signature_invalid });
    }

    // Taproot signatures go out in the 64-byte BIP-340 wire format; the other
    // suites use the ciphersuite's own encoding.
    const bytes: []const u8 = if (comptime tag == .taproot)
        try ctx.gpa.dupe(u8, &mpc.bip340.signatureToBytes(sig))
    else
        try ctx.gpa.dupe(u8, &sig.toBytes());

    const path = try s.artifactPath(signature_file);
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = bytes });
    try s.advance(3);
    try s.finish();
    try s.consumeState(2);

    try ctx.note("signature written to {s}\n", .{path});
    if (ctx.json) {
        const pk = if (comptime tag == .taproot)
            try cmd.hex(ctx.gpa, &key.public_key.xOnly())
        else
            try cmd.hex(ctx.gpa, &key.public_key.toBytes());
        try ctx.emit("{{\"signature\":\"{x}\",\"public_key\":\"{s}\",\"signers\":{d}}}\n", .{
            bytes, pk, parties.len,
        });
    } else {
        try ctx.emit("{x}\n", .{bytes});
    }
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// standalone verification
// ---------------------------------------------------------------------------

/// Verify a signature with nothing but the public key - the check any
/// outside party (a chain, a wallet) would perform.
pub fn verify(
    ctx: cmd.Ctx,
    st: suite_mod.Suite,
    pubkey_hex: []const u8,
    msg: []const u8,
    sig_bytes: []const u8,
) !u8 {
    return switch (st) {
        inline .ed25519, .secp256k1, .taproot => |tag| verifyFor(tag, ctx, pubkey_hex, msg, sig_bytes),
        // The ECDSA suites all produce plain r||s over secp256k1, whoever
        // generated it: DKLs23, CGGMP24, or a single signer.
        .dkls, .ecdsa_fast, .ecdsa_prod => verifyEcdsa(ctx, pubkey_hex, msg, sig_bytes),
        else => {
            try ctx.warn("suite '{t}' has no signature format to verify\n", .{st});
            return cmd.Exit.usage;
        },
    };
}

/// Verify a secp256k1 ECDSA signature, hashing the message with SHA-256.
fn verifyEcdsa(ctx: cmd.Ctx, pubkey_hex: []const u8, msg: []const u8, sig_bytes: []const u8) !u8 {
    const E = mpc.curve.Secp256k1;
    var pk_bytes: [E.Point.encoded_length]u8 = undefined;
    cmd.hexExact(&pk_bytes, pubkey_hex) catch {
        try ctx.warn("--pubkey must be {d} bytes of hex\n", .{E.Point.encoded_length});
        return cmd.Exit.usage;
    };
    const pk = E.Point.fromBytes(pk_bytes) catch {
        try ctx.warn("--pubkey is not a valid point\n", .{});
        return cmd.Exit.bad_input;
    };
    if (sig_bytes.len != 64) {
        try ctx.warn("an ECDSA signature here is 64 bytes (r||s); got {d}\n", .{sig_bytes.len});
        return cmd.Exit.bad_input;
    }

    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});
    const r = E.Scalar.fromBytes(sig_bytes[0..32].*) catch {
        try ctx.warn("signature is malformed\n", .{});
        return cmd.Exit.bad_input;
    };
    const sc = E.Scalar.fromBytes(sig_bytes[32..64].*) catch {
        try ctx.warn("signature is malformed\n", .{});
        return cmd.Exit.bad_input;
    };
    if (!mpc.dkls.sign.verify(E, pk, h, .{ .r = r, .s = sc, .recovery_id = 0 })) {
        try ctx.warn("signature is INVALID\n", .{});
        return cmd.Exit.protocol;
    }
    try ctx.note("signature is valid\n", .{});
    if (ctx.json) try ctx.emit("{{\"valid\":true}}\n", .{});
    return cmd.Exit.ok;
}

fn verifyFor(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    pubkey_hex: []const u8,
    msg: []const u8,
    sig_bytes: []const u8,
) !u8 {
    const F = mpc.frost.Frost(suite_mod.FrostSuiteOf(tag).?);
    const E = F.E;

    if (comptime tag == .taproot) {
        var pk: [32]u8 = undefined;
        cmd.hexExact(&pk, pubkey_hex) catch {
            try ctx.warn("--pubkey must be 32 bytes of hex (x-only)\n", .{});
            return cmd.Exit.usage;
        };
        if (sig_bytes.len != 64) {
            try ctx.warn("a BIP-340 signature is 64 bytes; got {d}\n", .{sig_bytes.len});
            return cmd.Exit.bad_input;
        }
        if (!mpc.bip340.verify(pk, msg, sig_bytes[0..64].*)) {
            try ctx.warn("signature is INVALID\n", .{});
            return cmd.Exit.protocol;
        }
    } else {
        var pk_bytes: [E.Point.encoded_length]u8 = undefined;
        cmd.hexExact(&pk_bytes, pubkey_hex) catch {
            try ctx.warn(
                "--pubkey must be {d} bytes of hex\n",
                .{E.Point.encoded_length},
            );
            return cmd.Exit.usage;
        };
        const pk = E.Point.fromBytes(pk_bytes) catch {
            try ctx.warn("--pubkey is not a valid point\n", .{});
            return cmd.Exit.bad_input;
        };
        if (sig_bytes.len != F.Signature.encoded_length) {
            try ctx.warn(
                "expected a {d}-byte signature; got {d}\n",
                .{ F.Signature.encoded_length, sig_bytes.len },
            );
            return cmd.Exit.bad_input;
        }
        const sig = F.Signature.fromBytes(sig_bytes[0..F.Signature.encoded_length].*) catch {
            try ctx.warn("signature is malformed\n", .{});
            return cmd.Exit.bad_input;
        };
        if (!F.verify(msg, pk, sig)) {
            try ctx.warn("signature is INVALID\n", .{});
            return cmd.Exit.protocol;
        }
    }

    try ctx.note("signature is valid\n", .{});
    if (ctx.json) try ctx.emit("{{\"valid\":true}}\n", .{});
    return cmd.Exit.ok;
}
