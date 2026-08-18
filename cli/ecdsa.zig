//! `zmpc presign` and `zmpc ecdsa` - CGGMP24 threshold ECDSA.
//!
//! Presigning is the expensive, message-independent part: three rounds of
//! Paillier ciphertexts and zero-knowledge proofs that produce a
//! presignature. Signing is then a single local operation per signer plus an
//! addition, so a wallet can prepare presignatures in advance and sign the
//! instant a transaction appears.
//!
//!   presign round1  encrypt k and γ, prove both in range          [bc + p2p]
//!   presign round2  the multiplicative-to-additive exchange            [p2p]
//!   presign round3  reveal δ and prove consistency               [broadcast]
//!   presign finalize check δG == Δ, emit the presignature
//!   ecdsa sign      σ_i = k̃·m + r·χ̃                            (local)
//!   ecdsa combine   s = Σσ_i
//!
//! A presignature must be used at most once. Signing two different messages
//! with the same presignature reveals the private key, so `ecdsa sign`
//! consumes it.
//!
//! Note the two index spaces: the library numbers signers 1..n within the
//! signing set, while frames carry real party numbers. The mapping happens
//! here, at the boundary.

const std = @import("std");
const mpc = @import("zig_mpc");

const auxgen_cmd = @import("auxgen.zig");
const cmd = @import("cmd.zig");
const dkg_cmd = @import("dkg.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

pub const presignature_file = "presignature.zmpc";

fn EcdsaOf(comptime tag: suite_mod.Suite) type {
    return mpc.ecdsa.Ecdsa(suite_mod.ParamsOf(tag).?, suite_mod.CurveOf(tag));
}

pub const Paths = struct {
    share: ?[]const u8 = null,
    aux: ?[]const u8 = null,
};

pub fn run(ctx: cmd.Ctx, s: *session.Session, step: ?u16, paths: Paths) !u8 {
    return switch (s.suite) {
        inline .ecdsa_fast, .ecdsa_prod => |tag| runFor(tag, ctx, s, step, paths),
        else => {
            try ctx.warn(
                "presigning is only for the CGGMP24 suites (ecdsa_fast, " ++
                    "ecdsa_prod); this session uses '{t}'\n",
                .{s.suite},
            );
            return cmd.Exit.usage;
        },
    };
}

pub fn runAll(ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    while (!s.manifest.complete) {
        const code = try run(ctx, s, null, paths);
        if (code != cmd.Exit.ok) return code;
    }
    return cmd.Exit.ok;
}

fn runFor(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    step: ?u16,
    paths: Paths,
) !u8 {
    const want = step orelse (s.manifest.round + 1);
    return switch (want) {
        1 => round1(tag, ctx, s, paths),
        2 => round2(tag, ctx, s),
        3 => round3(tag, ctx, s),
        4 => finalize(tag, ctx, s),
        else => {
            try ctx.warn("presign has rounds 1..3 plus finalize (4); got {d}\n", .{want});
            return cmd.Exit.usage;
        },
    };
}

/// Collect messages tagged with the sender's *position in the signing set*,
/// which is the numbering the library's rounds expect.
fn collectPositional(
    comptime T: type,
    ctx: cmd.Ctx,
    s: *session.Session,
    inbox: session.Inbox,
    round: u16,
    channel: frame.Channel,
) ![]mpc.message.From(T) {
    const signers = try s.participants();
    const me = s.manifest.party;
    const out = try ctx.gpa.alloc(mpc.message.From(T), signers.len - 1);
    var k: usize = 0;
    for (signers, 0..) |party, pos| {
        if (party == me) continue;
        out[k] = .{
            .from = @intCast(pos + 1),
            .msg = try inbox.decode(T, .{
                .round = round,
                .channel = channel,
                .from = party,
                .to = if (channel == .p2p) me else 0,
            }),
        };
        k += 1;
    }
    return out;
}

/// Real party number for a 1-based position in the signing set.
fn partyAt(s: *session.Session, position: u16) !u16 {
    const signers = try s.participants();
    if (position < 1 or position > signers.len) return error.BadSignerPosition;
    return signers[position - 1];
}

// ---------------------------------------------------------------------------
// assembling the signer's key material
// ---------------------------------------------------------------------------

/// Build the `Keys` the presigning rounds need out of two artifacts: the
/// threshold key share from the DKG, and the aux info.
///
/// This is where t-of-n Shamir shares become the additive shares CGGMP24
/// works with: each signer multiplies its share by the Lagrange coefficient
/// for the chosen signing set.
fn buildKeys(
    comptime tag: suite_mod.Suite,
    ctx: cmd.Ctx,
    s: *session.Session,
    paths: Paths,
) !EcdsaOf(tag).Keys {
    const P = suite_mod.ParamsOf(tag).?;
    const E = suite_mod.CurveOf(tag);
    const T = EcdsaOf(tag);
    const A = mpc.auxgen.AuxGen(P, suite_mod.repetitionsOf(tag));
    const Pl = mpc.zk.common.Pail(P);

    const key = (try cmd.loadKeyShare(E, ctx, s, paths.share)).share;

    const aux_path = paths.aux orelse s.manifest.aux_path orelse return error.NoAuxInfo;
    const aux_frame = try cmd.readFrame(ctx, aux_path);
    if (aux_frame.header.kind != .aux_info) return error.WrongArtifactKind;
    if (aux_frame.header.suite != s.suite) return error.SuiteMismatch;
    const aux = try mpc.serde.decodeSlice(A.AuxInfo, aux_frame.payload, .{ .gpa = ctx.gpa });

    const signers = try s.participants();
    const my_pos = try s.myPosition();
    if (key.party != s.manifest.party) return error.ShareIsForAnotherParty;
    if (aux.party != s.manifest.party) return error.AuxIsForAnotherParty;

    // Additive share for this signing set, and the matching public shares.
    const x_i = try T.toAdditive(key.secret_share, signers, my_pos);
    const big_x = try ctx.gpa.alloc(E.Point, signers.len);
    for (signers, 0..) |party, pos| {
        const lambda = try mpc.vss.lagrangeAtZero(E, signers, pos);
        big_x[pos] = try (try key.publicShareOf(party)).mulPublic(lambda);
    }

    // Aux info is generated among all parties and indexed by party number;
    // the signing set selects the entries it needs, in signer order.
    const parties = try ctx.gpa.alloc(T.PartyData, signers.len);
    for (signers, 0..) |party, pos| {
        if (party < 1 or party > aux.parties.len) return error.AuxMissingParty;
        const entry = aux.parties[party - 1];
        parties[pos] = .{
            .ek = try Pl.EncryptionKey.fromN(entry.n),
            .pedersen = entry.pedersen,
        };
    }

    return .{
        .i = @intCast(my_pos + 1),
        .n = @intCast(signers.len),
        .eid = mpc.ecdsa.ExecutionId.fromBytes(s.id),
        .x_i = x_i,
        .big_x = big_x,
        .pk = key.public_key,
        .dk = aux.dk,
        .parties = parties,
    };
}

// ---------------------------------------------------------------------------
// presigning rounds
// ---------------------------------------------------------------------------

fn round1(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session, paths: Paths) !u8 {
    const T = EcdsaOf(tag);

    const keys = try buildKeys(tag, ctx, s, paths);
    const result = try T.round1(ctx.gpa, keys, ctx.rng);

    _ = try s.emit(T.Round1aBroadcast, result.broadcast, s.msgHeader(1, .broadcast, 0), ctx.armor);
    for (result.p2p) |out| {
        const party = try partyAt(s, out.to);
        _ = try s.emit(T.Round1bP2p, out.msg, s.msgHeader(1, .p2p, party), ctx.armor);
    }
    try s.saveState(T.State1, result.state, 1);
    try s.advance(1);

    try ctx.note("presign round 1: published ciphertexts and range proofs\n", .{});
    return cmd.Exit.ok;
}

fn round2(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const T = EcdsaOf(tag);

    const gathered = try cmd.gather(ctx, s, 2);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(T.State1, 1);
    const bc = try collectPositional(T.Round1aBroadcast, ctx, s, inbox, 1, .broadcast);
    const p2p_in = try collectPositional(T.Round1bP2p, ctx, s, inbox, 1, .p2p);

    const result = T.round2(ctx.gpa, state, bc, p2p_in, ctx.rng) catch |err|
        return cmd.protocolAbort(ctx, "presigning", err, null);

    for (result.p2p) |out| {
        const party = try partyAt(s, out.to);
        _ = try s.emit(T.Round2P2p, out.msg, s.msgHeader(2, .p2p, party), ctx.armor);
    }
    try s.saveState(T.State2, result.state, 2);
    try s.advance(2);

    try ctx.note("presign round 2: multiplicative-to-additive exchange sent\n", .{});
    return cmd.Exit.ok;
}

fn round3(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const T = EcdsaOf(tag);

    const gathered = try cmd.gather(ctx, s, 3);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(T.State2, 2);
    const incoming = try collectPositional(T.Round2P2p, ctx, s, inbox, 2, .p2p);

    const result = T.round3(state, incoming, ctx.rng) catch |err| return cmd.protocolAbort(ctx, "presigning", err, null);

    _ = try s.emit(T.Round3Broadcast, result.broadcast, s.msgHeader(3, .broadcast, 0), ctx.armor);
    try s.saveState(T.State3, result.state, 3);
    try s.advance(3);

    try ctx.note("presign round 3: all proofs verified\n", .{});
    return cmd.Exit.ok;
}

fn finalize(comptime tag: suite_mod.Suite, ctx: cmd.Ctx, s: *session.Session) !u8 {
    const T = EcdsaOf(tag);

    const gathered = try cmd.gather(ctx, s, 4);
    const inbox = switch (gathered) {
        .waiting => |code| return code,
        .ready => |i| i,
    };

    const state = try s.loadState(T.State3, 3);
    const incoming = try collectPositional(T.Round3Broadcast, ctx, s, inbox, 3, .broadcast);

    var presig = T.finalize(state, incoming) catch |err| return cmd.protocolAbort(ctx, "presigning", err, null);

    const path = try s.saveArtifact(T.Presignature, presig, presignature_file, .presignature, true);
    try s.advance(4);
    try s.finish();
    for (1..4) |round| try s.consumeState(@intCast(round));

    try ctx.note("presignature ready at {s}\n", .{path});
    try ctx.note("use it for exactly one message: signing twice reveals the key\n", .{});
    if (ctx.json) {
        try ctx.emit("{{\"presignature\":\"{s}\",\"r\":\"{x}\"}}\n", .{ path, &presig.gamma.xOnly() });
    } else {
        try ctx.emit("{s}\n", .{path});
    }
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// signing with a presignature
// ---------------------------------------------------------------------------

/// The digest to sign: either SHA-256 of a message, or a digest supplied
/// directly (what a Bitcoin or Ethereum signer would pass in).
pub fn digestOf(ctx: cmd.Ctx, msg: ?[]const u8, digest_hex: ?[]const u8) ![32]u8 {
    _ = ctx;
    if (digest_hex) |text| {
        var out: [32]u8 = undefined;
        const decoded = std.fmt.hexToBytes(&out, text) catch return error.InvalidHex;
        if (decoded.len != 32) return error.BadDigestLength;
        return out;
    }
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg orelse return error.NoMessage, &out, .{});
    return out;
}

fn scalarFromDigest(comptime E: type, digest: [32]u8) E.Scalar {
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &digest);
    return E.Scalar.fromWideBytes(wide);
}

/// Produce this signer's partial signature and consume the presignature.
pub fn signPartial(
    ctx: cmd.Ctx,
    presig_path: []const u8,
    digest: [32]u8,
    out_path: []const u8,
    keep: bool,
) !u8 {
    const f = try cmd.readFrame(ctx, presig_path);
    if (f.header.kind != .presignature) {
        try ctx.warn("'{s}' is not a presignature\n", .{presig_path});
        return cmd.Exit.bad_input;
    }

    return switch (f.header.suite) {
        inline .ecdsa_fast, .ecdsa_prod => |tag| blk: {
            const T = EcdsaOf(tag);
            const E = suite_mod.CurveOf(tag);
            const presig = try mpc.serde.decodeSlice(T.Presignature, f.payload, .{ .gpa = ctx.gpa });
            const m = scalarFromDigest(E, digest);
            const sigma = T.partialSign(presig, m);

            const partial = T.PartialSig{ .gamma = presig.gamma, .sigma = sigma };
            const payload = try mpc.serde.encodeAlloc(T.PartialSig, partial, ctx.gpa);
            var out_header = f.header;
            out_header.kind = .signature;
            out_header.protocol = .sign;
            out_header.channel = .broadcast;
            out_header.round = 1;
            const bytes = try frame.encodeAlloc(ctx.gpa, out_header, payload);
            try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = out_path, .data = bytes });

            // A presignature is single-use: signing two messages with the same
            // one lets anyone solve for the private key. Delete it as soon as
            // it has been used.
            if (!keep) {
                std.Io.Dir.cwd().deleteFile(ctx.io, presig_path) catch |e| {
                    try ctx.warn(
                        "WARNING: could not delete the used presignature '{s}': {t}\n" ++
                            "Delete it by hand - reusing it would reveal the private key.\n",
                        .{ presig_path, e },
                    );
                };
            } else {
                try ctx.warn(
                    "WARNING: --keep left the presignature in place. Using it for a\n" ++
                        "second message would reveal the private key. Nothing needs it\n" ++
                        "kept - the partial signature already carries r.\n",
                    .{},
                );
            }

            try ctx.note("partial signature written to {s}\n", .{out_path});
            try ctx.emit("{x}\n", .{&sigma.toBytes()});
            break :blk cmd.Exit.ok;
        },
        else => {
            try ctx.warn("'{t}' presignatures are not CGGMP24 ECDSA\n", .{f.header.suite});
            return cmd.Exit.usage;
        },
    };
}

/// Combine the partial signatures into a complete ECDSA signature.
///
/// Takes nothing but the partials: each carries Γ, so no signer has to keep a
/// used presignature around.
pub fn combine(
    ctx: cmd.Ctx,
    partial_paths: []const []const u8,
    digest: [32]u8,
    pubkey_path: ?[]const u8,
    out_path: []const u8,
) !u8 {
    const first = try cmd.readFrame(ctx, partial_paths[0]);
    if (first.header.kind != .signature) {
        try ctx.warn("'{s}' is not a partial signature\n", .{partial_paths[0]});
        return cmd.Exit.bad_input;
    }

    return switch (first.header.suite) {
        inline .ecdsa_fast, .ecdsa_prod => |tag| blk: {
            const T = EcdsaOf(tag);
            const E = suite_mod.CurveOf(tag);

            const partials = try ctx.gpa.alloc(E.Scalar, partial_paths.len);
            var gamma: ?E.Point = null;

            for (partial_paths, 0..) |path, i| {
                const pf = try cmd.readFrame(ctx, path);
                if (pf.header.kind != .signature) {
                    try ctx.warn("'{s}' is not a partial signature\n", .{path});
                    return cmd.Exit.bad_input;
                }
                if (!std.mem.eql(u8, &pf.header.session, &first.header.session)) {
                    try ctx.warn(
                        "'{s}' comes from a different presigning session than '{s}';\n" ++
                            "partials from separate runs cannot be combined\n",
                        .{ path, partial_paths[0] },
                    );
                    return cmd.Exit.bad_input;
                }
                const partial = try mpc.serde.decodeSlice(
                    T.PartialSig,
                    pf.payload,
                    .{ .gpa = ctx.gpa },
                );
                // Every signer must have used the same presignature; a
                // mismatch means these partials belong to different signatures.
                if (gamma) |g| {
                    if (!g.eql(partial.gamma)) {
                        try ctx.warn("'{s}' was made from a different presignature\n", .{path});
                        return cmd.Exit.bad_input;
                    }
                } else gamma = partial.gamma;
                partials[i] = partial.sigma;
            }

            const m = scalarFromDigest(E, digest);
            const sig = T.combine(gamma.?, partials, m) catch |e| {
                try ctx.warn("could not combine: {t}\n", .{e});
                return cmd.Exit.protocol;
            };

            var bytes: [64]u8 = undefined;
            bytes[0..32].* = sig.r.toBytes();
            bytes[32..].* = sig.s.toBytes();

            // Verify if we were given the public key. A missing or wrong
            // partial yields an invalid signature rather than an error, so
            // this check is the only thing that catches it.
            if (pubkey_path) |pk_path| {
                const kf = try cmd.readFrame(ctx, pk_path);
                const key = try mpc.serde.decodeSlice(
                    mpc.dkg.Dkg(E).KeyShare,
                    kf.payload,
                    .{ .gpa = ctx.gpa },
                );
                try key.validate();
                if (!T.verify(key.public_key, m, sig)) {
                    try ctx.warn(
                        "the combined signature is INVALID - a partial is missing,\n" ++
                            "wrong, or was made for a different message\n",
                        .{},
                    );
                    return cmd.Exit.protocol;
                }
                try ctx.note("signature verifies under the group public key\n", .{});
            }

            try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = out_path, .data = &bytes });
            try ctx.note("signature written to {s}\n", .{out_path});
            if (ctx.json) {
                try ctx.emit("{{\"signature\":\"{x}\",\"r\":\"{x}\",\"s\":\"{x}\"}}\n", .{
                    &bytes, &sig.r.toBytes(), &sig.s.toBytes(),
                });
            } else {
                try ctx.emit("{x}\n", .{&bytes});
            }
            break :blk cmd.Exit.ok;
        },
        else => {
            try ctx.warn("'{t}' is not a CGGMP24 ECDSA suite\n", .{first.header.suite});
            return cmd.Exit.usage;
        },
    };
}

/// Verify a 64-byte ECDSA signature against a public key, the way any
/// outside verifier would.
pub fn verify(
    ctx: cmd.Ctx,
    pubkey_hex: []const u8,
    digest: [32]u8,
    sig_bytes: []const u8,
) !u8 {
    const E = mpc.curve.Secp256k1;

    if (sig_bytes.len != 64) {
        try ctx.warn("an ECDSA signature is 64 bytes (r || s); got {d}\n", .{sig_bytes.len});
        return cmd.Exit.bad_input;
    }
    var pk_bytes: [33]u8 = undefined;
    cmd.hexExact(&pk_bytes, pubkey_hex) catch {
        try ctx.warn("--pubkey must be 33 bytes of hex (compressed secp256k1)\n", .{});
        return cmd.Exit.usage;
    };
    const pk = E.Point.fromBytes(pk_bytes) catch {
        try ctx.warn("--pubkey is not a valid point\n", .{});
        return cmd.Exit.bad_input;
    };

    const r = E.Scalar.fromBytes(sig_bytes[0..32].*) catch {
        try ctx.warn("signature r is not a canonical scalar\n", .{});
        return cmd.Exit.bad_input;
    };
    const sc = E.Scalar.fromBytes(sig_bytes[32..64].*) catch {
        try ctx.warn("signature s is not a canonical scalar\n", .{});
        return cmd.Exit.bad_input;
    };

    if (!mpc.ecdsa.verifySignature(E, pk, scalarFromDigest(E, digest), r, sc)) {
        try ctx.warn("signature is INVALID\n", .{});
        return cmd.Exit.protocol;
    }
    try ctx.note("signature is valid\n", .{});
    if (ctx.json) try ctx.emit("{{\"valid\":true}}\n", .{});
    return cmd.Exit.ok;
}
