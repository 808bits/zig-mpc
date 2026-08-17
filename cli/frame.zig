//! The zmpc wire frame: a fixed 60-byte header, a canonical serde payload,
//! and a 32-byte integrity tag.
//!
//! A frame is inert, self-describing data. It says which session it belongs
//! to, which protocol and round produced it, who sent it and who it is for -
//! everything a receiving process needs to decide whether the payload is even
//! worth parsing. Nothing about how it travels is encoded here: the same bytes
//! go into a file, an `scp`, a relay socket, or a base64 block in an email.
//!
//! The tag is SHA-256 over header+payload and buys integrity against accident
//! only - a bit flipped by a bad USB stick would otherwise surface as an
//! inscrutable ZK-proof failure deep inside a round. It is NOT authenticity:
//! anyone who can modify a frame can recompute it. `flags` bit 0 is reserved
//! for upgrading the tag to HMAC-SHA256 under a pre-shared key, which needs no
//! format change.
//!
//! Confidentiality and authenticity of the transport remain the operator's
//! responsibility - DKG and refresh p2p frames carry secret VSS shares.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

pub const magic = "ZMPC";
pub const version: u8 = 1;
pub const header_len: u16 = 60;
pub const tag_len = 32;
pub const overhead = header_len + tag_len;

/// What the payload is. The reader needs this to pick a decode type.
pub const Kind = enum(u8) {
    /// A protocol round message.
    message = 1,
    /// Saved round state, so the next round can run in a new process.
    state = 2,
    key_share = 3,
    aux_info = 4,
    presignature = 5,
    /// Pre-generated safe primes for aux-info generation.
    primes = 6,
    /// Relay handshake: announces (session, party) on a new connection.
    hello = 7,
    signature = 8,
    /// DKLs23 pairwise setup: base-OT correlations and zero-share seeds.
    dkls_setup = 9,
};

pub const Channel = enum(u8) {
    /// To every other party. `to` is 0.
    broadcast = 0,
    /// To exactly one party.
    p2p = 1,
    /// Not a protocol message; a stored artifact.
    artifact = 2,
};

pub const Protocol = enum(u16) {
    dkg = 1,
    refresh = 2,
    auxgen = 3,
    presign = 4,
    sign = 5,
    dkls_setup = 7,
    dkls_sign = 8,
    /// Artifacts and relay control frames belong to no round protocol.
    none = 6,
};

/// A suite pins down every comptime parameter the payload's type depends on:
/// the curve, and for CGGMP24 the Paillier/ZK parameter set. Two parties on
/// different suites cannot exchange frames, and the mismatch is caught in the
/// header rather than as a length error halfway through a proof.
pub const Suite = enum(u16) {
    ed25519 = 0x0001,
    secp256k1 = 0x0002,
    p256 = 0x0003,
    p384 = 0x0004,
    taproot = 0x0005,
    /// secp256k1 + Params(576, 256, 512, 384), M = 16 - fast, demo-sized.
    ecdsa_fast = 0x0101,
    /// secp256k1 + Params(1024, 256, 512, 512), M = 80 - 2048-bit Paillier.
    ecdsa_prod = 0x0102,
    /// secp256k1 + DKLs23. ECDSA without Paillier: no aux-info step, and
    /// signing needs only the pairwise setup in `zmpc dkls setup`.
    dkls = 0x0201,
};

pub const Header = struct {
    kind: Kind,
    channel: Channel,
    /// bit 0: tag is HMAC-SHA256 rather than SHA-256. Other bits must be 0.
    flags: u8 = 0,
    protocol: Protocol,
    suite: Suite,
    /// 1..4 for round messages, 0 for artifacts.
    round: u16 = 0,
    /// 1-based sender index; 0 when not applicable.
    from: u16 = 0,
    /// 1-based recipient index; 0 for broadcast.
    to: u16 = 0,
    n_parties: u16 = 0,
    threshold: u16 = 0,
    /// The protocol execution id - binds every frame to one run.
    session: [32]u8,
};

pub const ParseError = error{
    /// Not a zmpc frame at all.
    BadMagic,
    /// A frame from a future format version, or one claiming a different
    /// header size. v1 refuses rather than skipping unknown header bytes:
    /// skipping would let an attacker smuggle semantics past an old reader.
    UnsupportedVersion,
    /// Truncated, or a payload length that disagrees with the input size.
    MalformedFrame,
    /// Reserved flag bits set.
    UnknownFlags,
    /// The tag does not match the contents.
    CorruptFrame,
    InvalidEnumTag,
};

pub const Frame = struct {
    header: Header,
    payload: []const u8,
};

// ---------------------------------------------------------------------------
// binary
// ---------------------------------------------------------------------------

fn writeHeader(buf: *[header_len]u8, h: Header, payload_len: usize) void {
    @memcpy(buf[0..4], magic);
    buf[4] = version;
    buf[5] = @intFromEnum(h.kind);
    buf[6] = @intFromEnum(h.channel);
    buf[7] = h.flags;
    std.mem.writeInt(u16, buf[8..10], @intFromEnum(h.protocol), .little);
    std.mem.writeInt(u16, buf[10..12], @intFromEnum(h.suite), .little);
    std.mem.writeInt(u16, buf[12..14], h.round, .little);
    std.mem.writeInt(u16, buf[14..16], h.from, .little);
    std.mem.writeInt(u16, buf[16..18], h.to, .little);
    std.mem.writeInt(u16, buf[18..20], h.n_parties, .little);
    std.mem.writeInt(u16, buf[20..22], h.threshold, .little);
    std.mem.writeInt(u16, buf[22..24], header_len, .little);
    @memcpy(buf[24..56], &h.session);
    std.mem.writeInt(u32, buf[56..60], @intCast(payload_len), .little);
}

/// Serialize a complete frame into a caller-owned buffer.
pub fn encodeAlloc(gpa: Allocator, h: Header, payload: []const u8) ![]u8 {
    if (payload.len > std.math.maxInt(u32)) return error.PayloadTooLarge;
    const out = try gpa.alloc(u8, overhead + payload.len);
    errdefer gpa.free(out);

    writeHeader(out[0..header_len], h, payload.len);
    @memcpy(out[header_len..][0..payload.len], payload);

    var digest: [tag_len]u8 = undefined;
    Sha256.hash(out[0 .. header_len + payload.len], &digest, .{});
    @memcpy(out[header_len + payload.len ..][0..tag_len], &digest);
    return out;
}

/// Parse and verify a frame. The returned payload aliases `bytes`.
pub fn parse(bytes: []const u8) ParseError!Frame {
    if (bytes.len < overhead) return error.MalformedFrame;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.BadMagic;
    if (bytes[4] != version) return error.UnsupportedVersion;
    if (std.mem.readInt(u16, bytes[22..24], .little) != header_len) return error.UnsupportedVersion;

    const flags = bytes[7];
    if (flags & 0xfe != 0) return error.UnknownFlags;

    const payload_len = std.mem.readInt(u32, bytes[56..60], .little);
    if (bytes.len != overhead + @as(usize, payload_len)) return error.MalformedFrame;

    var digest: [tag_len]u8 = undefined;
    Sha256.hash(bytes[0 .. header_len + payload_len], &digest, .{});
    if (!std.crypto.timing_safe.eql([tag_len]u8, digest, bytes[header_len + payload_len ..][0..tag_len].*))
        return error.CorruptFrame;

    return .{
        .header = .{
            .kind = try intToEnum(Kind, bytes[5]),
            .channel = try intToEnum(Channel, bytes[6]),
            .flags = flags,
            .protocol = try intToEnum(Protocol, std.mem.readInt(u16, bytes[8..10], .little)),
            .suite = try intToEnum(Suite, std.mem.readInt(u16, bytes[10..12], .little)),
            .round = std.mem.readInt(u16, bytes[12..14], .little),
            .from = std.mem.readInt(u16, bytes[14..16], .little),
            .to = std.mem.readInt(u16, bytes[16..18], .little),
            .n_parties = std.mem.readInt(u16, bytes[18..20], .little),
            .threshold = std.mem.readInt(u16, bytes[20..22], .little),
            .session = bytes[24..56].*,
        },
        .payload = bytes[header_len..][0..payload_len],
    };
}

fn intToEnum(comptime T: type, value: anytype) ParseError!T {
    return std.enums.fromInt(T, value) orelse error.InvalidEnumTag;
}

/// Read just the header without verifying the tag or requiring the whole
/// frame - what the relay needs to route a frame it will never interpret.
pub fn peekHeader(bytes: []const u8) ParseError!struct { header: Header, payload_len: u32 } {
    if (bytes.len < header_len) return error.MalformedFrame;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.BadMagic;
    if (bytes[4] != version) return error.UnsupportedVersion;
    if (std.mem.readInt(u16, bytes[22..24], .little) != header_len) return error.UnsupportedVersion;
    return .{
        .header = .{
            .kind = try intToEnum(Kind, bytes[5]),
            .channel = try intToEnum(Channel, bytes[6]),
            .flags = bytes[7],
            .protocol = try intToEnum(Protocol, std.mem.readInt(u16, bytes[8..10], .little)),
            .suite = try intToEnum(Suite, std.mem.readInt(u16, bytes[10..12], .little)),
            .round = std.mem.readInt(u16, bytes[12..14], .little),
            .from = std.mem.readInt(u16, bytes[14..16], .little),
            .to = std.mem.readInt(u16, bytes[16..18], .little),
            .n_parties = std.mem.readInt(u16, bytes[18..20], .little),
            .threshold = std.mem.readInt(u16, bytes[20..22], .little),
            .session = bytes[24..56].*,
        },
        .payload_len = std.mem.readInt(u32, bytes[56..60], .little),
    };
}

// ---------------------------------------------------------------------------
// armor - base64 text for transports that mangle binary
// ---------------------------------------------------------------------------

pub const armor_begin = "-----BEGIN ZMPC ";
pub const armor_end = "-----END ZMPC ";

fn armorLabel(kind: Kind) []const u8 {
    return switch (kind) {
        .message => "MESSAGE",
        .state => "STATE",
        .key_share => "KEY SHARE",
        .aux_info => "AUX INFO",
        .presignature => "PRESIGNATURE",
        .primes => "PRIMES",
        .hello => "HELLO",
        .signature => "SIGNATURE",
        .dkls_setup => "DKLS SETUP",
    };
}

pub fn isArmored(bytes: []const u8) bool {
    return std.mem.startsWith(u8, std.mem.trimStart(u8, bytes, " \t\r\n"), armor_begin);
}

/// Wrap a binary frame as armored text. The headers above the base64 block
/// are decorative - `dearmor` re-derives everything from the frame itself and
/// rejects any decorative line that disagrees, so a hand-edited label can
/// never change how a frame is interpreted.
pub fn armor(gpa: Allocator, frame_bytes: []const u8) ![]u8 {
    const frame = try parse(frame_bytes);
    const label = armorLabel(frame.header.kind);

    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print("{s}{s}-----\n", .{ armor_begin, label });
    try w.print("session: {x}\n", .{&frame.header.session});
    try w.print("protocol: {t}\n", .{frame.header.protocol});
    try w.print("suite: {t}\n", .{frame.header.suite});
    if (frame.header.round != 0) try w.print("round: {d}\n", .{frame.header.round});
    if (frame.header.from != 0) try w.print("from: {d}\n", .{frame.header.from});
    try w.print("channel: {t}\n", .{frame.header.channel});
    if (frame.header.channel == .p2p) try w.print("to: {d}\n", .{frame.header.to});
    try w.writeAll("\n");

    const enc = std.base64.standard.Encoder;
    const b64 = try gpa.alloc(u8, enc.calcSize(frame_bytes.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, frame_bytes);

    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try w.print("{s}\n", .{b64[i..@min(i + 64, b64.len)]});
    }
    try w.print("{s}{s}-----\n", .{ armor_end, label });
    return out.toOwnedSlice();
}

pub const DearmorError = ParseError || error{ OutOfMemory, MalformedArmor, ArmorHeaderMismatch };

/// Recover the binary frame from armored text, then check every decorative
/// header against it.
pub fn dearmor(gpa: Allocator, text: []const u8) DearmorError![]u8 {
    const body_start = std.mem.indexOf(u8, text, "-----\n") orelse return error.MalformedArmor;
    const after_begin = text[body_start + 6 ..];
    const blank = std.mem.indexOf(u8, after_begin, "\n\n") orelse return error.MalformedArmor;
    const headers = after_begin[0..blank];
    const rest = after_begin[blank + 2 ..];
    const end_idx = std.mem.indexOf(u8, rest, armor_end) orelse return error.MalformedArmor;

    // Strip whitespace out of the base64 block.
    var packed_b64 = try std.ArrayList(u8).initCapacity(gpa, end_idx);
    defer packed_b64.deinit(gpa);
    for (rest[0..end_idx]) |c| {
        if (c == '\n' or c == '\r' or c == ' ' or c == '\t') continue;
        try packed_b64.append(gpa, c);
    }

    const dec = std.base64.standard.Decoder;
    const size = dec.calcSizeForSlice(packed_b64.items) catch return error.MalformedArmor;
    const out = try gpa.alloc(u8, size);
    errdefer gpa.free(out);
    dec.decode(out, packed_b64.items) catch return error.MalformedArmor;

    const frame = try parse(out);
    try checkArmorHeaders(headers, frame.header);
    return out;
}

fn checkArmorHeaders(headers: []const u8, h: Header) DearmorError!void {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t\r");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");
        if (value.len == 0) continue;

        const ok = if (std.mem.eql(u8, key, "session"))
            eqlHex(value, &h.session)
        else if (std.mem.eql(u8, key, "protocol"))
            std.mem.eql(u8, value, @tagName(h.protocol))
        else if (std.mem.eql(u8, key, "suite"))
            std.mem.eql(u8, value, @tagName(h.suite))
        else if (std.mem.eql(u8, key, "channel"))
            std.mem.eql(u8, value, @tagName(h.channel))
        else if (std.mem.eql(u8, key, "round"))
            eqlDecimal(value, h.round)
        else if (std.mem.eql(u8, key, "from"))
            eqlDecimal(value, h.from)
        else if (std.mem.eql(u8, key, "to"))
            eqlDecimal(value, h.to)
        else
            true; // unknown decorative keys are ignored

        if (!ok) return error.ArmorHeaderMismatch;
    }
}

fn eqlHex(text: []const u8, bytes: []const u8) bool {
    if (text.len != bytes.len * 2) return false;
    var buf: [64]u8 = undefined;
    if (bytes.len > buf.len / 2) return false;
    const decoded = std.fmt.hexToBytes(buf[0..bytes.len], text) catch return false;
    return std.mem.eql(u8, decoded, bytes);
}

fn eqlDecimal(text: []const u8, value: u16) bool {
    const parsed = std.fmt.parseInt(u16, text, 10) catch return false;
    return parsed == value;
}

// ---------------------------------------------------------------------------
// file naming
// ---------------------------------------------------------------------------

/// Frames are named so that delivering one is a plain `cp` and a human can
/// see at a glance what is waiting: `<sid8>-<proto>-r<n>-<b|p>-f<from>-t<to>`.
///
/// The name is a convenience only. The header is authoritative - a file named
/// `-f2-` whose header says `from=5` is treated as from 5.
pub fn fileName(buf: []u8, h: Header, armored: bool) ![]const u8 {
    var sid8: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&sid8, "{x}", .{h.session[0..4]}) catch unreachable;
    const channel_char: u8 = switch (h.channel) {
        .broadcast => 'b',
        .p2p => 'p',
        .artifact => 'a',
    };
    return std.fmt.bufPrint(buf, "{s}-{t}-r{d}-{c}-f{d}-t{d}.zmpc{s}", .{
        &sid8,                       h.protocol, h.round, channel_char, h.from, h.to,
        if (armored) ".asc" else "",
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleHeader() Header {
    return .{
        .kind = .message,
        .channel = .p2p,
        .protocol = .dkg,
        .suite = .secp256k1,
        .round = 2,
        .from = 1,
        .to = 3,
        .n_parties = 3,
        .threshold = 2,
        .session = @splat(0xab),
    };
}

test "frame round-trips and reports its header" {
    const gpa = testing.allocator;
    const payload = "not really a protocol message";
    const bytes = try encodeAlloc(gpa, sampleHeader(), payload);
    defer gpa.free(bytes);

    try testing.expectEqual(@as(usize, overhead + payload.len), bytes.len);

    const frame = try parse(bytes);
    try testing.expectEqualSlices(u8, payload, frame.payload);
    try testing.expectEqual(Protocol.dkg, frame.header.protocol);
    try testing.expectEqual(Suite.secp256k1, frame.header.suite);
    try testing.expectEqual(@as(u16, 2), frame.header.round);
    try testing.expectEqual(@as(u16, 3), frame.header.to);

    // Header-only parse agrees and needs no payload.
    const peek = try peekHeader(bytes[0..header_len]);
    try testing.expectEqual(@as(u32, payload.len), peek.payload_len);
    try testing.expectEqual(@as(u16, 1), peek.header.from);
}

test "corrupt, truncated and foreign frames are rejected" {
    const gpa = testing.allocator;
    const bytes = try encodeAlloc(gpa, sampleHeader(), "payload");
    defer gpa.free(bytes);

    // every single-bit flip must be caught by the tag or a field check
    for (0..bytes.len) |i| {
        const copy = try gpa.dupe(u8, bytes);
        defer gpa.free(copy);
        copy[i] ^= 0x01;
        try testing.expect(std.meta.isError(parse(copy)));
    }

    for (0..bytes.len) |cut| {
        try testing.expect(std.meta.isError(parse(bytes[0..cut])));
    }

    var not_ours = try gpa.dupe(u8, bytes);
    defer gpa.free(not_ours);
    @memcpy(not_ours[0..4], "XXXX");
    try testing.expectError(error.BadMagic, parse(not_ours));

    var future = try gpa.dupe(u8, bytes);
    defer gpa.free(future);
    future[4] = 99;
    try testing.expectError(error.UnsupportedVersion, parse(future));

    // A payload_len that disagrees with the actual size is refused before the
    // tag is even computed.
    var lying = try gpa.dupe(u8, bytes);
    defer gpa.free(lying);
    std.mem.writeInt(u32, lying[56..60], 9999, .little);
    try testing.expectError(error.MalformedFrame, parse(lying));
}

test "armor round-trips and rejects doctored headers" {
    const gpa = testing.allocator;
    const payload = "armored payload";
    const bytes = try encodeAlloc(gpa, sampleHeader(), payload);
    defer gpa.free(bytes);

    const text = try armor(gpa, bytes);
    defer gpa.free(text);
    try testing.expect(isArmored(text));
    try testing.expect(std.mem.indexOf(u8, text, "round: 2") != null);

    const back = try dearmor(gpa, text);
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, bytes, back);

    // The decorative headers must not be able to lie about the payload.
    const doctored = try std.mem.replaceOwned(u8, gpa, text, "round: 2", "round: 3");
    defer gpa.free(doctored);
    try testing.expectError(error.ArmorHeaderMismatch, dearmor(gpa, doctored));

    const wrong_party = try std.mem.replaceOwned(u8, gpa, text, "from: 1", "from: 2");
    defer gpa.free(wrong_party);
    try testing.expectError(error.ArmorHeaderMismatch, dearmor(gpa, wrong_party));
}

test "file names encode routing" {
    var buf: [128]u8 = undefined;

    const p2p = try fileName(&buf, sampleHeader(), false);
    try testing.expectEqualStrings("abababab-dkg-r2-p-f1-t3.zmpc", p2p);

    var h = sampleHeader();
    h.channel = .broadcast;
    h.to = 0;
    var buf2: [128]u8 = undefined;
    const bc = try fileName(&buf2, h, true);
    try testing.expectEqualStrings("abababab-dkg-r2-b-f1-t0.zmpc.asc", bc);
}
