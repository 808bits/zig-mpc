//! `zmpc hd` - BIP-32 / SLIP-10 non-hardened derivation for threshold keys.
//!
//! A non-hardened child differs from its parent by a *public* additive tweak
//! computed from the parent public key and chain code. So every signer can
//! derive a child share on its own, with no interaction and no new protocol
//! run: add the tweak to the Shamir share and the polynomial's constant term
//! moves with it.
//!
//! Hardened derivation needs the parent private key and is therefore
//! impossible for a threshold key - by design, not by omission.

const std = @import("std");
const mpc = @import("zig_mpc");

const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const session = @import("session.zig");
const suite_mod = @import("suite.zig");

/// Parse `m/44/0/7`, `44/0/7`, or `44'/0` (rejected - hardened).
pub fn parsePath(gpa: std.mem.Allocator, text: []const u8) ![]u32 {
    var out: std.ArrayList(u32) = .empty;
    var it = std.mem.splitScalar(u8, text, '/');
    var first = true;
    while (it.next()) |piece| {
        const part = std.mem.trim(u8, piece, " ");
        if (first) {
            first = false;
            if (part.len == 0 or std.mem.eql(u8, part, "m") or std.mem.eql(u8, part, "M")) continue;
        }
        if (part.len == 0) continue;
        if (part[part.len - 1] == '\'' or part[part.len - 1] == 'h' or part[part.len - 1] == 'H')
            return error.HardenedIndex;
        const index = std.fmt.parseInt(u32, part, 10) catch return error.BadPathComponent;
        if (index >= 1 << 31) return error.HardenedIndex;
        try out.append(gpa, index);
    }
    if (out.items.len == 0) return error.EmptyPath;
    return out.toOwnedSlice(gpa);
}

pub fn derive(
    ctx: cmd.Ctx,
    share_path: []const u8,
    path_text: []const u8,
    out_path: ?[]const u8,
) !u8 {
    const f = cmd.readFrame(ctx, share_path) catch |e| {
        try ctx.warn("cannot read key share '{s}': {t}\n", .{ share_path, e });
        return cmd.Exit.bad_input;
    };
    if (f.header.kind != .key_share) {
        try ctx.warn("'{s}' is not a key share\n", .{share_path});
        return cmd.Exit.bad_input;
    }

    // SLIP-10 derivation here is defined over secp256k1.
    switch (f.header.suite) {
        .secp256k1, .taproot, .ecdsa_fast, .ecdsa_prod => {},
        else => {
            try ctx.warn(
                "HD derivation is defined for secp256k1 keys; this share is {t}\n",
                .{f.header.suite},
            );
            return cmd.Exit.usage;
        },
    }

    const indices = parsePath(ctx.gpa, path_text) catch |e| {
        switch (e) {
            error.HardenedIndex => try ctx.warn(
                "hardened derivation needs the private key and cannot be done with a\n" ++
                    "threshold key - use only non-hardened components\n",
                .{},
            ),
            error.EmptyPath => try ctx.warn("--path is empty\n", .{}),
            else => try ctx.warn("cannot parse --path '{s}'\n", .{path_text}),
        }
        return cmd.Exit.usage;
    };

    const E = mpc.hd.E;
    const D = mpc.dkg.Dkg(E);
    var share = try mpc.serde.decodeSlice(D.KeyShare, f.payload, .{ .gpa = ctx.gpa });
    share.validate() catch |e| {
        try ctx.warn("'{s}' is not a well-formed key share: {t}\n", .{ share_path, e });
        return cmd.Exit.bad_input;
    };

    const parent = mpc.hd.ExtendedPublicKey{ .pk = share.public_key, .chain_code = share.chain_code };
    const step = mpc.hd.derivePath(parent, indices) catch |e| {
        switch (e) {
            error.InvalidChild => try ctx.warn(
                "this path hits an invalid child key (probability about 2^-127);\n" ++
                    "per BIP-32, skip to the next index\n",
                .{},
            ),
            error.HardenedIndex => try ctx.warn("hardened components are not derivable\n", .{}),
        }
        return cmd.Exit.protocol;
    };

    if (out_path == null) {
        // Public information only: anyone holding the xpub can compute this.
        if (ctx.json) {
            try ctx.emit(
                "{{\"path\":\"{s}\",\"parent\":\"{x}\",\"child\":\"{x}\"," ++
                    "\"chain_code\":\"{x}\",\"xonly\":\"{x}\"}}\n",
                .{
                    path_text,              &parent.pk.toBytes(),   &step.child.pk.toBytes(),
                    &step.child.chain_code, &step.child.pk.xOnly(),
                },
            );
        } else {
            try ctx.emit("{x}\n", .{&step.child.pk.toBytes()});
        }
        return cmd.Exit.ok;
    }

    // Apply the tweak locally. The share stays a valid share of the same
    // polynomial with a shifted constant term, so the whole signing set
    // derives consistently without talking to each other.
    share.secret_share = share.secret_share.add(step.shift);
    share.public_key = step.child.pk;
    share.chain_code = step.child.chain_code;
    if (share.vss_commitment.len > 0) {
        const shift_point = if (step.shift.isZero())
            E.Point.identity
        else
            try E.Point.mulBase(step.shift);
        share.vss_commitment[0] = share.vss_commitment[0].add(shift_point);
    }

    // Taproot keys must stay even-Y after the tweak.
    if (f.header.suite == .taproot) {
        var pk = share.public_key;
        if (mpc.bip340.normalizeKeyMaterial(&share.secret_share, &pk, share.vss_commitment)) {
            try ctx.note("child key had odd Y; negated key material for BIP-340\n", .{});
        }
        share.public_key = pk;
    }

    // Sanity: the derived share must still verify against the derived
    // commitment. If this fails the tweak was applied inconsistently.
    const com = mpc.vss.Commitment(E){ .points = share.vss_commitment, .allocator = ctx.gpa };
    if (!com.verifyShare(share.party, share.secret_share)) {
        try ctx.warn("BUG: derived share is inconsistent with its commitment\n", .{});
        return cmd.Exit.internal;
    }

    const payload = try mpc.serde.encodeAlloc(D.KeyShare, share, ctx.gpa);
    var out_header = f.header;
    out_header.from = share.party;
    const bytes = try frame.encodeAlloc(ctx.gpa, out_header, payload);
    try std.Io.Dir.cwd().writeFile(ctx.io, .{
        .sub_path = out_path.?,
        .data = bytes,
        .flags = .{ .permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
            .fromMode(0o600)
        else
            .default_file },
    });

    try ctx.note("child share for {s} written to {s}\n", .{ path_text, out_path.? });
    try ctx.note("every signer must derive the same path, or signing will fail\n", .{});
    if (ctx.json) {
        try ctx.emit("{{\"path\":\"{s}\",\"child\":\"{x}\",\"share\":\"{s}\"}}\n", .{
            path_text, &share.public_key.toBytes(), out_path.?,
        });
    } else {
        try ctx.emit("{x}\n", .{&share.public_key.toBytes()});
    }
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "path parsing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualSlices(u32, &.{ 44, 0, 7 }, try parsePath(arena, "m/44/0/7"));
    try testing.expectEqualSlices(u32, &.{ 44, 0, 7 }, try parsePath(arena, "44/0/7"));
    try testing.expectEqualSlices(u32, &.{0}, try parsePath(arena, "m/0"));

    // Hardened components cannot work for a threshold key, in any notation.
    try testing.expectError(error.HardenedIndex, parsePath(arena, "m/44'/0"));
    try testing.expectError(error.HardenedIndex, parsePath(arena, "m/44h/0"));
    try testing.expectError(error.HardenedIndex, parsePath(arena, "m/2147483648"));

    try testing.expectError(error.EmptyPath, parsePath(arena, "m"));
    try testing.expectError(error.BadPathComponent, parsePath(arena, "m/abc"));
}
