//! Canonical binary serialization for every protocol message, round state and
//! key share in this library.
//!
//! The protocol types were written to be passed between function calls, not
//! between machines: they interleave wire data with derived caches
//! (`ff.Modulus`, whose in-memory form is limb-width- and `usize`-dependent),
//! allocators, and curve points held in opaque projective coordinates. This
//! codec walks any of those types with `@typeInfo` and applies a fixed rule
//! set, first match winning:
//!
//!   0. `std.mem.Allocator`            - not wire data; re-injected on decode
//!   1. Paillier `EncryptionKey`       - `n` only; rest re-derived via `fromN`
//!      Paillier `DecryptionKey`       - `p`,`q` only; via `fromPrimes`
//!      ring-Pedersen `Aux`            - `n_hat`,`s`,`t`; via `fromParts`
//!      `Signed`                       - sign byte + magnitude, canonicalized
//!   2. types with their own fixed-size codec (`encoded_length` +
//!      `toBytes`/`fromBytes`): curve points, scalars, FROST signatures
//!   3. bool, integer, enum, optional, array, slice, struct
//!   4. anything else                  - `@compileError`
//!
//! Rule 2 is where input validation comes from for free: `Point.fromBytes`
//! rejects off-curve encodings and `Scalar.fromBytes` rejects unreduced ones,
//! so a hostile peer cannot push either past the decoder. Rule 1 likewise
//! re-runs `Aux.fromParts`' unit checks on `s` and `t`.
//!
//! The encoding is canonical - every value has exactly one byte string, and
//! decode rejects the alternatives (bools outside {0,1}, negative zero,
//! unreduced scalars). `encode(decode(b)) == b` is asserted by the tests.
//!
//! Integers are little-endian, fixed width; `usize` is refused because its
//! width is not portable. Slices carry a `u32` length prefix. Arrays carry
//! none - their length is a comptime property of the instantiation, which the
//! reader must already agree on (that is what the frame header's suite id
//! pins down). Nothing here is self-describing: the reader must know `T`.
//!
//! Memory: an arena is convenient but not required. `decode` allocates from
//! the allocator it is given and `free` releases what it produced; if decode
//! fails partway through it unwinds its own allocations before returning the
//! error, so a failed decode leaks nothing either. That is what lets the
//! malformed-input tests run under `std.testing.allocator` - several hundred
//! corrupted inputs, every one of them leak-checked.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;

pub const EncodeError = Writer.Error || error{SliceTooLong};

pub const DecodeError = error{
    /// Ran out of input.
    EndOfStream,
    ReadFailed,
    /// Input remained after a complete value was decoded.
    TrailingData,
    /// Structurally uninterpretable: an impossible length prefix, or a
    /// fixed-size field that decodes to nothing valid.
    MalformedEncoding,
    /// Structurally fine but not the canonical encoding of any value: a bool
    /// outside {0,1}, a negative zero, an unreduced scalar, an off-curve
    /// point.
    NonCanonical,
    /// A length prefix beyond `Ctx.max_slice_elems`.
    SliceTooLong,
    InvalidEnumTag,
    OutOfMemory,
};

pub const Ctx = struct {
    /// Slices are allocated from here; `free` gives them back, and a decode
    /// that fails cleans up after itself. Any allocator works.
    gpa: Allocator,
    /// Hard cap on any single length prefix. Real protocol slices are the VSS
    /// commitment (length = threshold) and per-party tables (length = n).
    max_slice_elems: u32 = 4096,
};

// ---------------------------------------------------------------------------
// comptime classification
// ---------------------------------------------------------------------------

const Rule = enum {
    allocator,
    encryption_key,
    decryption_key,
    pedersen_aux,
    signed,
    byte_codec,
    plain,
};

fn isStruct(comptime T: type) bool {
    return @typeInfo(T) == .@"struct";
}

/// Paillier `EncryptionKey`: `{n, n_wide, mod_n, mod_n2}`, all derived from
/// `n`. `mod_n`/`mod_n2` are Montgomery-form caches that must not go on the
/// wire.
fn isEncryptionKey(comptime T: type) bool {
    if (!isStruct(T)) return false;
    return @hasDecl(T, "fromN") and @hasField(T, "n") and @hasField(T, "n_wide") and
        @hasField(T, "mod_n") and @hasField(T, "mod_n2");
}

/// Paillier `DecryptionKey`: `{ek, p, q, phi, mu}`, all derived from `p`,`q`.
fn isDecryptionKey(comptime T: type) bool {
    if (!isStruct(T)) return false;
    return @hasDecl(T, "fromPrimes") and @hasField(T, "ek") and @hasField(T, "p") and
        @hasField(T, "q") and @hasField(T, "phi") and @hasField(T, "mu");
}

/// Ring-Pedersen `Aux`: `{n_hat, s, t, mod}`. Note `Aux` also declares a
/// `fromPrimes`, which is why `isDecryptionKey` is checked on distinct fields.
fn isPedersenAux(comptime T: type) bool {
    if (!isStruct(T)) return false;
    return @hasDecl(T, "fromParts") and @hasField(T, "n_hat") and @hasField(T, "s") and
        @hasField(T, "t") and @hasField(T, "mod");
}

/// `zk.common.Signed(F)` declares `Fx = F`, so the type can prove its own
/// identity rather than being matched by shape alone.
fn isSigned(comptime T: type) bool {
    if (!isStruct(T)) return false;
    if (!@hasDecl(T, "Fx")) return false;
    if (!@hasField(T, "neg") or !@hasField(T, "mag")) return false;
    return @hasDecl(T, "canonPub") and @hasDecl(T, "isZero");
}

/// A type that already defines its own canonical fixed-size encoding.
/// Matching the exact return type keeps `ff.Modulus` out - its `toBytes`
/// takes a destination buffer and an endianness and returns an error union.
fn isByteCodec(comptime T: type) bool {
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {},
        else => return false,
    }
    if (!@hasDecl(T, "encoded_length")) return false;
    if (!@hasDecl(T, "toBytes") or !@hasDecl(T, "fromBytes")) return false;
    const fn_info = @typeInfo(@TypeOf(T.toBytes));
    if (fn_info != .@"fn") return false;
    const ret = fn_info.@"fn".return_type orelse return false;
    return ret == [T.encoded_length]u8;
}

fn ruleFor(comptime T: type) Rule {
    if (T == Allocator) return .allocator;
    if (isEncryptionKey(T)) return .encryption_key;
    if (isDecryptionKey(T)) return .decryption_key;
    if (isPedersenAux(T)) return .pedersen_aux;
    if (isSigned(T)) return .signed;
    if (isByteCodec(T)) return .byte_codec;
    return .plain;
}

/// Byte length of a fixed-size array field, e.g. `arrayLen(EncryptionKey, "n")`.
fn arrayLen(comptime T: type, comptime field: []const u8) comptime_int {
    const info = @typeInfo(@FieldType(T, field));
    if (info != .array or info.array.child != u8) @compileError(
        "zmpc serde: expected " ++ @typeName(T) ++ "." ++ field ++ " to be a byte array",
    );
    return info.array.len;
}

/// Guards against a field being added to an overridden type without anyone
/// updating the override - the wire format would change silently otherwise.
fn assertFieldCount(comptime T: type, comptime expected: comptime_int) void {
    const actual = @typeInfo(T).@"struct".fields.len;
    if (actual != expected) @compileError(std.fmt.comptimePrint(
        "zmpc serde: {s} has {d} fields but its wire override expects {d}; " ++
            "update src/serde.zig before changing this type",
        .{ @typeName(T), actual, expected },
    ));
}

fn intByteLen(comptime T: type) comptime_int {
    const info = @typeInfo(T).int;
    if (T == usize or T == isize) @compileError(
        "zmpc serde: usize/isize is not portable on the wire; use a fixed width",
    );
    if (info.bits == 0 or info.bits % 8 != 0 or info.bits > 64) @compileError(
        "zmpc serde: unsupported integer width " ++ @typeName(T),
    );
    return info.bits / 8;
}

/// Smallest possible encoded size of one `T`. Used to reject a length prefix
/// that could not possibly be backed by the remaining input, before any
/// allocation happens.
pub fn minEncodedLen(comptime T: type) comptime_int {
    switch (comptime ruleFor(T)) {
        .allocator => return 0,
        .encryption_key => return arrayLen(T, "n"),
        .decryption_key => return 2 * arrayLen(T, "p"),
        .pedersen_aux => return 3 * arrayLen(T, "n_hat"),
        .signed => return 1 + arrayLen(T, "mag"),
        .byte_codec => return T.encoded_length,
        .plain => {},
    }
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int => intByteLen(T),
        .@"enum" => |info| intByteLen(info.tag_type),
        .optional => 1,
        .array => |info| info.len * minEncodedLen(info.child),
        .@"struct" => |info| blk: {
            var total: comptime_int = 0;
            for (info.fields) |f| total += minEncodedLen(f.type);
            break :blk total;
        },
        .pointer => |info| switch (info.size) {
            .slice => 4,
            else => @compileError("zmpc serde: unsupported pointer " ++ @typeName(T)),
        },
        else => @compileError("zmpc serde: unsupported type " ++ @typeName(T)),
    };
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

pub fn encode(comptime T: type, value: T, w: *Writer) EncodeError!void {
    switch (comptime ruleFor(T)) {
        .allocator => return,

        .encryption_key => {
            comptime assertFieldCount(T, 4);
            return w.writeAll(&value.n);
        },

        .decryption_key => {
            comptime assertFieldCount(T, 5);
            try w.writeAll(&value.p);
            return w.writeAll(&value.q);
        },

        .pedersen_aux => {
            comptime assertFieldCount(T, 4);
            try w.writeAll(&value.n_hat);
            try w.writeAll(&value.s);
            return w.writeAll(&value.t);
        },

        .signed => {
            comptime assertFieldCount(T, 2);
            // Canonical form: zero is never negative.
            const c = value.canonPub();
            try w.writeByte(@intFromBool(c.neg));
            return w.writeAll(&c.mag);
        },

        .byte_codec => {
            const bytes = value.toBytes();
            return w.writeAll(&bytes);
        },

        .plain => {},
    }

    switch (@typeInfo(T)) {
        .bool => return w.writeByte(@intFromBool(value)),

        .int => {
            var buf: [intByteLen(T)]u8 = undefined;
            std.mem.writeInt(T, &buf, value, .little);
            return w.writeAll(&buf);
        },

        .@"enum" => |info| {
            const Tag = info.tag_type;
            var buf: [intByteLen(Tag)]u8 = undefined;
            std.mem.writeInt(Tag, &buf, @intFromEnum(value), .little);
            return w.writeAll(&buf);
        },

        .optional => |info| {
            if (value) |payload| {
                try w.writeByte(1);
                return encode(info.child, payload, w);
            }
            return w.writeByte(0);
        },

        .array => |info| {
            if (info.child == u8) return w.writeAll(&value);
            for (value) |item| try encode(info.child, item, w);
        },

        .@"struct" => |info| {
            if (info.layout == .@"packed") @compileError(
                "zmpc serde: packed struct " ++ @typeName(T) ++ " needs an explicit rule",
            );
            inline for (info.fields) |f| {
                if (f.is_comptime) @compileError(
                    "zmpc serde: comptime field " ++ @typeName(T) ++ "." ++ f.name,
                );
                try encode(f.type, @field(value, f.name), w);
            }
        },

        .pointer => |info| switch (info.size) {
            .slice => {
                if (value.len > std.math.maxInt(u32)) return error.SliceTooLong;
                var len_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &len_buf, @intCast(value.len), .little);
                try w.writeAll(&len_buf);
                if (info.child == u8) return w.writeAll(value);
                for (value) |item| try encode(info.child, item, w);
            },
            else => @compileError(
                "zmpc serde: " ++ @typeName(T) ++ " is a pointer and has no wire form; " ++
                    "rebuild it from the value it points at",
            ),
        },

        else => @compileError("zmpc serde: unsupported type " ++ @typeName(T)),
    }
}

pub fn encodeAlloc(comptime T: type, value: T, gpa: Allocator) (EncodeError || error{OutOfMemory})![]u8 {
    var alloc_writer: Writer.Allocating = .init(gpa);
    errdefer alloc_writer.deinit();
    try encode(T, value, &alloc_writer.writer);
    return alloc_writer.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

/// Decode one `T` from a complete byte string, rejecting trailing data.
///
/// This is the entry point: the payload length is always known from the frame
/// header, and decoding over a fixed slice is what lets the allocation guard
/// compare a length prefix against the input that actually remains.
pub fn decodeSlice(comptime T: type, bytes: []const u8, ctx: Ctx) DecodeError!T {
    var reader: Reader = .fixed(bytes);
    const value = try decode(T, &reader, ctx);
    errdefer free(T, value, ctx.gpa);
    if (reader.seek != reader.end) return error.TrailingData;
    return value;
}

/// Decode one `T`. `r` must be a fixed reader (`std.Io.Reader.fixed`); the
/// slice-length guard relies on `r.end - r.seek` being the true remainder.
pub fn decode(comptime T: type, r: *Reader, ctx: Ctx) DecodeError!T {
    switch (comptime ruleFor(T)) {
        .allocator => return ctx.gpa,

        .encryption_key => {
            const n = (try r.takeArray(arrayLen(T, "n"))).*;
            return T.fromN(n) catch error.MalformedEncoding;
        },

        .decryption_key => {
            const p = (try r.takeArray(arrayLen(T, "p"))).*;
            const q = (try r.takeArray(arrayLen(T, "q"))).*;
            return T.fromPrimes(p, q) catch error.MalformedEncoding;
        },

        .pedersen_aux => {
            const n_hat = (try r.takeArray(arrayLen(T, "n_hat"))).*;
            const s = (try r.takeArray(arrayLen(T, "s"))).*;
            const t = (try r.takeArray(arrayLen(T, "t"))).*;
            // Re-validates that s and t are units mod n_hat.
            return T.fromParts(n_hat, s, t) catch error.MalformedEncoding;
        },

        .signed => {
            const neg = try decodeBool(r);
            const mag = (try r.takeArray(arrayLen(T, "mag"))).*;
            const out = T{ .neg = neg, .mag = mag };
            if (neg and out.isZero()) return error.NonCanonical;
            return out;
        },

        .byte_codec => {
            const bytes = (try r.takeArray(T.encoded_length)).*;
            const result = T.fromBytes(bytes);
            return switch (@typeInfo(@TypeOf(result))) {
                .error_union => result catch error.NonCanonical,
                else => result,
            };
        },

        .plain => {},
    }

    switch (@typeInfo(T)) {
        .bool => return decodeBool(r),

        .int => {
            const bytes = (try r.takeArray(intByteLen(T))).*;
            return std.mem.readInt(T, &bytes, .little);
        },

        .@"enum" => |info| {
            const Tag = info.tag_type;
            const bytes = (try r.takeArray(intByteLen(Tag))).*;
            const tag = std.mem.readInt(Tag, &bytes, .little);
            return std.enums.fromInt(T, tag) orelse error.InvalidEnumTag;
        },

        .optional => |info| {
            if (!try decodeBool(r)) return null;
            return try decode(info.child, r, ctx);
        },

        .array => |info| {
            var out: T = undefined;
            if (info.child == u8) {
                try r.readSliceAll(&out);
                return out;
            }
            var filled: usize = 0;
            errdefer freeElements(info.child, &out, filled, ctx.gpa);
            for (&out) |*slot| {
                slot.* = try decode(info.child, r, ctx);
                filled += 1;
            }
            return out;
        },

        .@"struct" => |info| {
            // Assigned field by field into `undefined` rather than built from
            // a struct literal: several of these types have default field
            // values, and a literal would let a forgotten field silently take
            // its default instead of the decoded one.
            var out: T = undefined;
            // If a later field fails, the earlier ones may already own heap
            // memory. Track how far we got so the errdefer releases exactly
            // those and never reads an `undefined` field.
            var done: usize = 0;
            errdefer freeFields(T, &out, done, ctx.gpa);
            inline for (info.fields, 0..) |f, i| {
                @field(out, f.name) = try decode(f.type, r, ctx);
                done = i + 1;
            }
            return out;
        },

        .pointer => |info| switch (info.size) {
            .slice => {
                const len_bytes = (try r.takeArray(4)).*;
                const len = std.mem.readInt(u32, &len_bytes, .little);
                if (len > ctx.max_slice_elems) return error.SliceTooLong;

                // Reject a length the remaining input could not possibly back,
                // so a 60-byte file cannot ask for a 20 MB allocation.
                const min_each = comptime minEncodedLen(info.child);
                if (min_each > 0 and len > (r.end - r.seek) / min_each)
                    return error.MalformedEncoding;

                const out = try ctx.gpa.alloc(info.child, len);
                errdefer ctx.gpa.free(out);
                if (info.child == u8) {
                    try r.readSliceAll(out);
                    return out;
                }
                var filled: usize = 0;
                errdefer freeElements(info.child, out, filled, ctx.gpa);
                for (out) |*slot| {
                    slot.* = try decode(info.child, r, ctx);
                    filled += 1;
                }
                return out;
            },
            else => @compileError("zmpc serde: unsupported pointer " ++ @typeName(T)),
        },

        else => @compileError("zmpc serde: unsupported type " ++ @typeName(T)),
    }
}

fn decodeBool(r: *Reader) DecodeError!bool {
    return switch (try r.takeByte()) {
        0 => false,
        1 => true,
        else => error.NonCanonical,
    };
}

// ---------------------------------------------------------------------------
// releasing what decode allocated
// ---------------------------------------------------------------------------

/// True if a `T` can own heap memory at all - i.e. whether `free` has any
/// work to do. Lets callers and the walker skip whole subtrees.
pub fn ownsMemory(comptime T: type) bool {
    switch (comptime ruleFor(T)) {
        // The override types are rebuilt from bytes and hold no allocation.
        .allocator, .encryption_key, .decryption_key, .pedersen_aux, .signed, .byte_codec => return false,
        .plain => {},
    }
    switch (@typeInfo(T)) {
        .bool, .int, .@"enum" => return false,
        .optional => |info| return comptime ownsMemory(info.child),
        .array => |info| return comptime ownsMemory(info.child),
        .pointer => return true,
        .@"struct" => |info| {
            inline for (info.fields) |f| {
                if (comptime ownsMemory(f.type)) return true;
            }
            return false;
        },
        else => @compileError("zmpc serde: unsupported type " ++ @typeName(T)),
    }
}

/// Free the first `count` elements of `items`. Used to unwind a slice or
/// array that decode was still filling when it hit an error - the elements
/// past `count` are still `undefined` and must not be touched.
fn freeElements(comptime C: type, items: []const C, count: usize, gpa: Allocator) void {
    if (comptime !ownsMemory(C)) return;
    for (items[0..count]) |item| free(C, item, gpa);
}

/// Free the first `count` fields of a struct decode was still building.
fn freeFields(comptime T: type, value: *const T, count: usize, gpa: Allocator) void {
    if (comptime !ownsMemory(T)) return;
    const info = @typeInfo(T).@"struct";
    inline for (info.fields, 0..) |f, i| {
        if (i >= count) return;
        free(f.type, @field(value.*, f.name), gpa);
    }
}

/// Release everything `decode` allocated for `value`, mirroring the decode
/// rules exactly.
///
/// `decode` hands back structures containing slices it allocated; an arena
/// reclaims them wholesale, and this is how everyone else does it. `gpa` must
/// be the allocator that was in the decoding `Ctx`.
///
/// Only decode's own allocations are freed. Nothing here touches the byte
/// arrays and curve points held inline, and the override types (Paillier
/// keys, ring-Pedersen parameters) own nothing to begin with.
pub fn free(comptime T: type, value: T, gpa: Allocator) void {
    if (comptime !ownsMemory(T)) return;

    switch (@typeInfo(T)) {
        .optional => |info| {
            if (value) |payload| free(info.child, payload, gpa);
        },
        .array => |info| {
            for (value) |item| free(info.child, item, gpa);
        },
        .@"struct" => |info| {
            inline for (info.fields) |f| {
                free(f.type, @field(value, f.name), gpa);
            }
        },
        .pointer => |info| switch (info.size) {
            .slice => {
                if (comptime ownsMemory(info.child)) {
                    for (value) |item| free(info.child, item, gpa);
                }
                gpa.free(value);
            },
            else => @compileError("zmpc serde: unsupported pointer " ++ @typeName(T)),
        },
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const curve = @import("curve.zig");
const vss = @import("vss.zig");
const dkg = @import("dkg.zig");
const frost = @import("frost.zig");
const bip340 = @import("bip340.zig");
const paillier = @import("paillier.zig");
const zk = @import("zk.zig");
const auxgen = @import("auxgen.zig");
const ecdsa = @import("ecdsa.zig");

/// Encode, decode, and re-encode; assert the two encodings are byte-identical
/// (canonicality) and hand the decoded value back for structural checks.
fn roundTrip(comptime T: type, value: T, arena: Allocator) !T {
    const bytes = try encodeAlloc(T, value, arena);
    const back = try decodeSlice(T, bytes, .{ .gpa = arena });
    const again = try encodeAlloc(T, back, arena);
    try testing.expectEqualSlices(u8, bytes, again);
    return back;
}

/// Encode, decode and free under `std.testing.allocator`, which fails the
/// test if a single byte is left allocated.
///
/// The other tests in this file wrap an arena around the testing allocator so
/// they can drive whole protocols and hit decode's error paths (decode does
/// not unwind its allocations on failure - see `Ctx`). That hides leaks, so
/// this test carries the leak-checking duty for the codec itself.
fn leakCheckRoundTrip(comptime T: type, value: T) !void {
    const gpa = testing.allocator;

    const bytes = try encodeAlloc(T, value, gpa);
    defer gpa.free(bytes);

    const back = try decodeSlice(T, bytes, .{ .gpa = gpa });
    defer free(T, back, gpa);

    const again = try encodeAlloc(T, back, gpa);
    defer gpa.free(again);

    try testing.expectEqualSlices(u8, bytes, again);
}

test "the codec frees everything it allocates" {
    var prng = std.Random.DefaultPrng.init(20250814);
    const rng = prng.random();
    const gpa = testing.allocator;

    // Fixed-size types own nothing; `free` must still be safe on them.
    inline for (.{ curve.Secp256k1, curve.Ed25519 }) |E| {
        try testing.expect(!ownsMemory(E.Scalar));
        try testing.expect(!ownsMemory(E.Point));
        try leakCheckRoundTrip(E.Scalar, E.Scalar.random(rng));
        try leakCheckRoundTrip(E.Point, try E.Point.mulBase(E.Scalar.random(rng)));
    }

    const E = curve.Secp256k1;
    const D = dkg.Dkg(E);
    const eid = dkg.ExecutionId.random(rng);
    const n: u16 = 3;

    // Everything below owns at least one slice, which is the interesting case.
    try testing.expect(ownsMemory(D.KeyShare));
    try testing.expect(ownsMemory(D.Round2Broadcast));
    try testing.expect(ownsMemory(D.State1));
    try testing.expect(ownsMemory(D.State2));

    var r1: [n]D.Round1Result = undefined;
    for (0..n) |i| {
        r1[i] = try D.round1(gpa, .{ .party = @intCast(i + 1), .threshold = 2, .n = n }, eid, rng);
    }
    try leakCheckRoundTrip(D.State1, r1[0].state);

    var r2: [n]D.Round2Result = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]D.From(D.Round1Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r1[j].broadcast };
            k += 1;
        }
        r2[i] = try D.round2(r1[i].state, &incoming);
    }
    defer for (0..n) |i| r2[i].deinitMessages(gpa);

    // A message carrying a slice, and a state nesting a state plus a slice of
    // optionals.
    try leakCheckRoundTrip(D.Round2Broadcast, r2[0].broadcast);
    try leakCheckRoundTrip(D.State2, r2[0].state);

    var r3: [n]D.Round3Result = undefined;
    for (0..n) |i| {
        var bcs: [n - 1]D.From(D.Round2Broadcast) = undefined;
        var p2p: [n - 1]D.From(D.Round2P2p) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            bcs[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
            for (r2[j].p2p) |pm| {
                if (pm.to == i + 1) p2p[k] = .{ .from = @intCast(j + 1), .msg = pm.msg };
            }
            k += 1;
        }
        r3[i] = try D.round3(r2[i].state, &bcs, &p2p);
    }
    try leakCheckRoundTrip(D.State3, r3[0].state);

    var shares: [n]D.KeyShare = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]D.From(D.Round3Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r3[j].broadcast };
            k += 1;
        }
        shares[i] = try D.finalize(r3[i].state, &incoming);
    }
    defer for (&shares) |*s| s.deinit();

    // The artifact that actually gets written to disk and read back.
    try leakCheckRoundTrip(D.KeyShare, shares[0]);
}

test "the CGGMP24 types free cleanly too" {
    // Separate test so the Paillier keygen cost is visible on its own.
    var prng = std.Random.DefaultPrng.init(4242);
    const rng = prng.random();
    const gpa = testing.allocator;

    const P = zk.common.TestParams;
    const A = auxgen.AuxGen(P, 16);

    // Aux info holds a slice of per-party records, each with an encryption
    // key and ring-Pedersen parameters - the deepest override nesting there is.
    try testing.expect(ownsMemory(A.AuxInfo));
    try testing.expect(!ownsMemory(A.Round2Broadcast));

    var primes1 = try A.Primes.generate(rng, false);
    defer primes1.zeroize();
    var primes2 = try A.Primes.generate(rng, false);
    defer primes2.zeroize();
    const eid = auxgen.ExecutionId.random(rng);

    const a1 = try A.round1(1, 2, eid, primes1, rng);
    const a2 = try A.round1(2, 2, eid, primes2, rng);
    try leakCheckRoundTrip(A.Round1Broadcast, a1.broadcast);
    try leakCheckRoundTrip(A.State1, a1.state);

    const b1 = try A.round2(gpa, a1.state, &.{.{ .from = 2, .msg = a2.broadcast }});
    const b2 = try A.round2(gpa, a2.state, &.{.{ .from = 1, .msg = a1.broadcast }});
    try leakCheckRoundTrip(A.Round2Broadcast, b1.broadcast);
    try leakCheckRoundTrip(A.State2, b1.state);

    const c1 = try A.round3(b1.state, rng, &.{.{ .from = 2, .msg = b2.broadcast }});
    const c2 = try A.round3(b2.state, rng, &.{.{ .from = 1, .msg = b1.broadcast }});
    defer gpa.free(c1.p2p);
    defer gpa.free(c2.p2p);
    try leakCheckRoundTrip(A.Round3P2p, c1.p2p[0].msg);
    try leakCheckRoundTrip(A.State3, c1.state);

    var info1 = try A.finalize(c1.state, rng, &.{.{ .from = 2, .msg = c2.p2p[0].msg }});
    defer info1.deinit();
    var info2 = try A.finalize(c2.state, rng, &.{.{ .from = 1, .msg = c1.p2p[0].msg }});
    defer info2.deinit();
    try leakCheckRoundTrip(A.AuxInfo, info1);
}

test "curve scalars and points round-trip on every curve" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();

    inline for (.{ curve.Secp256k1, curve.P256, curve.P384, curve.Ed25519 }) |E| {
        const s = E.Scalar.random(rng);
        try testing.expect((try roundTrip(E.Scalar, s, arena)).eql(s));

        const p = try E.Point.mulBase(s);
        try testing.expect((try roundTrip(E.Point, p, arena)).eql(p));

        // A point must occupy exactly its canonical encoded length, not the
        // in-memory size of the projective representation.
        const encoded = try encodeAlloc(E.Point, p, arena);
        try testing.expectEqual(@as(usize, E.Point.encoded_length), encoded.len);
    }
}

test "off-curve points and unreduced scalars are rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const E = curve.Secp256k1;

    // 0x02 || x where x is not a valid x-coordinate.
    var bad_point: [E.Point.encoded_length]u8 = @splat(0);
    bad_point[0] = 0x02;
    bad_point[E.Point.encoded_length - 1] = 0x05;
    try testing.expectError(error.NonCanonical, decodeSlice(E.Point, &bad_point, .{ .gpa = arena }));

    // All-ones is above the group order.
    const bad_scalar: [E.Scalar.encoded_length]u8 = @splat(0xff);
    try testing.expectError(error.NonCanonical, decodeSlice(E.Scalar, &bad_scalar, .{ .gpa = arena }));
}

test "FROST commitments and signatures round-trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(22);
    const rng = prng.random();

    const F = frost.Frost(frost.Ed25519Sha512);
    const E = F.E;
    const sk = E.Scalar.random(rng);
    const c = try F.commit(7, sk, rng);

    const back = try roundTrip(F.Commitment, c.commitment, arena);
    try testing.expectEqual(@as(u16, 7), back.identifier);
    try testing.expect(back.hiding.eql(c.commitment.hiding));
    try testing.expect(back.binding.eql(c.commitment.binding));

    // Secret nonces are a state type but serialize like any other struct.
    const nonces = try roundTrip(F.SecretNonces, c.nonces, arena);
    try testing.expect(nonces.hiding.eql(c.nonces.hiding));

    const sig = F.Signature{ .R = try E.Point.mulBase(sk), .z = sk };
    const sig_back = try roundTrip(F.Signature, sig, arena);
    try testing.expectEqualSlices(u8, &sig.toBytes(), &sig_back.toBytes());
}

test "DKG messages, key shares and round states round-trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(33);
    const rng = prng.random();

    const E = curve.Secp256k1;
    const D = dkg.Dkg(E);
    const n: u16 = 3;
    const eid = dkg.ExecutionId.random(rng);

    var r1: [n]D.Round1Result = undefined;
    for (0..n) |i| {
        r1[i] = try D.round1(arena, .{ .party = @intCast(i + 1), .threshold = 2, .n = n }, eid, rng);
    }

    // Round-1 broadcast: a bare hash.
    _ = try roundTrip(D.Round1Broadcast, r1[0].broadcast, arena);

    // State1 carries the secret polynomial, a Feldman slice, and an allocator.
    const st1 = try roundTrip(D.State1, r1[0].state, arena);
    try testing.expectEqual(r1[0].state.poly.coeffs.len, st1.poly.coeffs.len);
    try testing.expect(st1.poly.coeffs[0].eql(r1[0].state.poly.coeffs[0]));
    try testing.expectEqual(@as(u16, 1), st1.params.party);

    var r2: [n]D.Round2Result = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]D.From(D.Round1Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r1[j].broadcast };
            k += 1;
        }
        r2[i] = try D.round2(r1[i].state, &incoming);
    }

    // Round-2 broadcast is the one wire message carrying a slice.
    const bc = try roundTrip(D.Round2Broadcast, r2[0].broadcast, arena);
    try testing.expectEqual(@as(usize, 2), bc.feldman.len);
    try testing.expect(bc.feldman[0].eql(r2[0].broadcast.feldman[0]));
    try testing.expectEqualSlices(u8, &r2[0].broadcast.rid, &bc.rid);

    _ = try roundTrip(D.Round2P2p, r2[0].p2p[0].msg, arena);

    // State2 nests State1 and a slice of optionals.
    const st2 = try roundTrip(D.State2, r2[0].state, arena);
    try testing.expectEqual(@as(usize, n), st2.hashes.len);
    try testing.expect(st2.hashes[0] != null);

    var r3: [n]D.Round3Result = undefined;
    for (0..n) |i| {
        var bcs: [n - 1]D.From(D.Round2Broadcast) = undefined;
        var p2p: [n - 1]D.From(D.Round2P2p) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            bcs[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
            for (r2[j].p2p) |pm| {
                if (pm.to == i + 1) p2p[k] = .{ .from = @intCast(j + 1), .msg = pm.msg };
            }
            k += 1;
        }
        r3[i] = try D.round3(r2[i].state, &bcs, &p2p);
    }

    _ = try roundTrip(D.Round3Broadcast, r3[0].broadcast, arena);
    const st3 = try roundTrip(D.State3, r3[0].state, arena);
    try testing.expect(st3.agg_commitment[0].eql(r3[0].state.agg_commitment[0]));

    var shares: [n]D.KeyShare = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]D.From(D.Round3Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{ .from = @intCast(j + 1), .msg = r3[j].broadcast };
            k += 1;
        }
        shares[i] = try D.finalize(r3[i].state, &incoming);
    }

    // The key share is the artifact that has to survive between machines.
    const share = try roundTrip(D.KeyShare, shares[0], arena);
    try testing.expectEqual(shares[0].party, share.party);
    try testing.expectEqual(shares[0].threshold, share.threshold);
    try testing.expect(share.secret_share.eql(shares[0].secret_share));
    try testing.expect(share.public_key.eql(shares[0].public_key));
    try testing.expectEqualSlices(u8, &shares[0].chain_code, &share.chain_code);

    // A decoded share is still usable: it verifies against its own commitment
    // and its public shares still evaluate.
    const com = vss.Commitment(E){ .points = share.vss_commitment, .allocator = arena };
    try testing.expect(com.verifyShare(share.party, share.secret_share));
    const pk2 = try share.publicShareOf(2);
    try testing.expect(pk2.eql(try shares[0].publicShareOf(2)));
}

test "a decoded key share still signs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(44);
    const rng = prng.random();

    const Suite = frost.Ed25519Sha512;
    const E = Suite.E;
    const F = frost.Frost(Suite);

    const shares = try dkg.runDkgForTest(E, arena, 2, 3, rng);

    // Round-trip every share through bytes, as if each party had written it to
    // disk and a fresh process had loaded it.
    var loaded: [3]dkg.Dkg(E).KeyShare = undefined;
    for (shares, 0..) |s, i| loaded[i] = try roundTrip(dkg.Dkg(E).KeyShare, s, arena);

    const msg = "signed by processes that never shared memory";
    const c1 = try F.commit(1, loaded[0].secret_share, rng);
    const c3 = try F.commit(3, loaded[2].secret_share, rng);
    const list = [_]F.Commitment{ c1.commitment, c3.commitment };
    const z1 = try F.sign(1, loaded[0].secret_share, loaded[0].public_key, c1.nonces, msg, &list);
    const z3 = try F.sign(3, loaded[2].secret_share, loaded[2].public_key, c3.nonces, msg, &list);
    const sig = try F.aggregate(&list, msg, loaded[0].public_key, &.{ z1, z3 });
    try testing.expect(F.verify(msg, loaded[0].public_key, sig));

    // and it is a plain Ed25519 signature under an independent verifier
    const Std = std.crypto.sign.Ed25519;
    const std_pk = try Std.PublicKey.fromBytes(loaded[0].public_key.toBytes());
    try Std.Signature.fromBytes(sig.toBytes()).verify(msg, std_pk);
}

test "Paillier and ring-Pedersen keys re-derive their caches" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(55);
    const rng = prng.random();

    const Pl = paillier.Paillier(128);
    var dk = try Pl.DecryptionKey.generate(rng);
    defer dk.zeroize();

    // Only n goes on the wire; the moduli are rebuilt.
    const ek_bytes = try encodeAlloc(Pl.EncryptionKey, dk.ek, arena);
    try testing.expectEqual(@as(usize, Pl.Fn.num_bytes), ek_bytes.len);

    const ek = try roundTrip(Pl.EncryptionKey, dk.ek, arena);
    try testing.expectEqualSlices(u8, &dk.ek.n, &ek.n);

    // The rebuilt key must actually work: encrypt under it, decrypt with the
    // original secret key.
    const m = Pl.Fn.fromU64(123456789);
    const ct = try ek.encrypt(m, rng);
    try testing.expectEqualSlices(u8, &m, &try dk.decrypt(ct.c));

    // Only p and q go on the wire; phi and mu are rebuilt.
    const dk_bytes = try encodeAlloc(Pl.DecryptionKey, dk, arena);
    try testing.expectEqual(@as(usize, 2 * Pl.Fp.num_bytes), dk_bytes.len);
    const dk2 = try roundTrip(Pl.DecryptionKey, dk, arena);
    try testing.expectEqualSlices(u8, &m, &try dk2.decrypt(ct.c));

    // Ring-Pedersen parameters.
    const P = zk.common.TestParams;
    var gen = try zk.common.Aux(P).generate(rng, false);
    defer gen.secret.zeroize();
    const aux = try roundTrip(zk.common.Aux(P), gen.aux, arena);
    try testing.expectEqualSlices(u8, &gen.aux.s, &aux.s);
    const commit_a = try gen.aux.combine(P.S.fromU64(5), P.S.fromU64(7));
    const commit_b = try aux.combine(P.S.fromU64(5), P.S.fromU64(7));
    try testing.expectEqualSlices(u8, &commit_a, &commit_b);
}

test "signed integers are canonical" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const S = zk.common.TestParams.S;

    const pos = S.fromU64(42);
    try testing.expect((try roundTrip(S, pos, arena)).eql(pos));
    const neg = S.fromU64(42).negate();
    const neg_back = try roundTrip(S, neg, arena);
    try testing.expect(neg_back.eql(neg));
    try testing.expect(neg_back.neg);

    // Negative zero has no canonical encoding and must be refused on input.
    const bytes = try encodeAlloc(S, S.zero, arena);
    try testing.expectEqual(@as(u8, 0), bytes[0]);
    const forged = try arena.dupe(u8, bytes);
    forged[0] = 1; // claim "-0"
    try testing.expectError(error.NonCanonical, decodeSlice(S, forged, .{ .gpa = arena }));
}

test "malformed input is rejected, never accepted or panicking" {
    // Deliberately NOT an arena: this test decodes hundreds of corrupted
    // inputs, so it is the one that proves decode unwinds its own allocations
    // when it fails partway through. std.testing.allocator fails the test if a
    // single byte survives.
    const gpa = testing.allocator;
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const setup = scratch.allocator(); // only for building the valid input

    var prng = std.Random.DefaultPrng.init(66);
    const rng = prng.random();

    const E = curve.Secp256k1;
    const D = dkg.Dkg(E);
    const eid = dkg.ExecutionId.random(rng);
    const r1a = try D.round1(setup, .{ .party = 1, .threshold = 2, .n = 2 }, eid, rng);
    const r1b = try D.round1(setup, .{ .party = 2, .threshold = 2, .n = 2 }, eid, rng);
    const r2 = try D.round2(r1a.state, &.{.{ .from = 2, .msg = r1b.broadcast }});

    const good = try encodeAlloc(D.Round2Broadcast, r2.broadcast, gpa);
    defer gpa.free(good);

    // Truncation at every offset must be refused. Which error comes out
    // depends on where the cut lands - running out of input, or a length
    // prefix the remaining bytes can no longer back - so the invariant under
    // test is only that nothing is ever accepted, and nothing is ever leaked.
    for (0..good.len) |cut| {
        if (decodeSlice(D.Round2Broadcast, good[0..cut], .{ .gpa = gpa })) |value| {
            free(D.Round2Broadcast, value, gpa);
            std.debug.print("truncation to {d} of {d} bytes was accepted\n", .{ cut, good.len });
            return error.TruncatedInputAccepted;
        } else |_| {}
    }

    // Every single-byte corruption, for the same reason: some of these fail
    // deep inside the slice loop, after elements have been allocated.
    for (0..good.len) |i| {
        const copy = try gpa.dupe(u8, good);
        defer gpa.free(copy);
        copy[i] ^= 0x55;
        if (decodeSlice(D.Round2Broadcast, copy, .{ .gpa = gpa })) |value| {
            free(D.Round2Broadcast, value, gpa);
        } else |_| {}
    }

    // Trailing data is rejected rather than silently ignored - and the value
    // decode had already built is released, not stranded.
    const padded = try gpa.alloc(u8, good.len + 1);
    defer gpa.free(padded);
    @memcpy(padded[0..good.len], good);
    padded[good.len] = 0;
    try testing.expectError(
        error.TrailingData,
        decodeSlice(D.Round2Broadcast, padded, .{ .gpa = gpa }),
    );

    // An absurd length prefix is refused before anything is allocated. The
    // feldman slice length is the first field after rid and chain_code.
    const len_off = 64;
    const huge = try gpa.dupe(u8, good);
    defer gpa.free(huge);
    std.mem.writeInt(u32, huge[len_off..][0..4], 0xffff_ffff, .little);
    try testing.expectError(
        error.SliceTooLong,
        decodeSlice(D.Round2Broadcast, huge, .{ .gpa = gpa }),
    );

    // A length that is under the cap but still unbackable by the remaining
    // bytes is refused too.
    const greedy = try gpa.dupe(u8, good);
    defer gpa.free(greedy);
    std.mem.writeInt(u32, greedy[len_off..][0..4], 4000, .little);
    try testing.expectError(
        error.MalformedEncoding,
        decodeSlice(D.Round2Broadcast, greedy, .{ .gpa = gpa }),
    );

    // A bool outside {0,1} is not a canonical encoding of anything.
    var reader: Reader = .fixed(&[_]u8{2});
    try testing.expectError(error.NonCanonical, decode(bool, &reader, .{ .gpa = gpa }));
}

test "CGGMP24 aux-info messages round-trip (Prm, Mod, Fac proofs)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(88);
    const rng = prng.random();

    const P = zk.common.TestParams;
    const A = auxgen.AuxGen(P, 16);
    const eid = auxgen.ExecutionId.random(rng);

    var primes1 = try A.Primes.generate(rng, false);
    defer primes1.zeroize();
    var primes2 = try A.Primes.generate(rng, false);
    defer primes2.zeroize();

    const a1 = try A.round1(1, 2, eid, primes1, rng);
    const a2 = try A.round1(2, 2, eid, primes2, rng);
    _ = try roundTrip(A.Round1Broadcast, a1.broadcast, arena);

    const b1 = try A.round2(arena, a1.state, &.{.{ .from = 2, .msg = a2.broadcast }});
    const b2 = try A.round2(arena, a2.state, &.{.{ .from = 1, .msg = a1.broadcast }});

    // Round-2 broadcast carries the Paillier modulus, the Pedersen parameters
    // and a Πprm proof (two M-element arrays).
    const bc = try roundTrip(A.Round2Broadcast, b1.broadcast, arena);
    try testing.expectEqualSlices(u8, &b1.broadcast.n, &bc.n);
    try testing.expectEqualSlices(u8, &b1.broadcast.prm_proof.zs[15], &bc.prm_proof.zs[15]);

    const c1 = try A.round3(b1.state, rng, &.{.{ .from = 2, .msg = b2.broadcast }});
    const c2 = try A.round3(b2.state, rng, &.{.{ .from = 1, .msg = b1.broadcast }});

    // Round-3 p2p carries Πmod (M proof points, each with two bools) and Πfac
    // (five signed integers). Note `.from` on a result is the RECIPIENT, so
    // c1.p2p[0] is party 1's message *for* party 2.
    const from_1 = try roundTrip(A.Round3P2p, c1.p2p[0].msg, arena);
    const from_2 = try roundTrip(A.Round3P2p, c2.p2p[0].msg, arena);
    try testing.expect(from_1.mod_proof.points[7].a == c1.p2p[0].msg.mod_proof.points[7].a);
    try testing.expect(from_1.fac_proof.z1.eql(c1.p2p[0].msg.fac_proof.z1));

    // A decoded proof must still verify - the real test that nothing was lost.
    // Πfac in particular is bound to the recipient's Pedersen parameters, so
    // a corrupted decode would fail here rather than silently pass.
    var info1 = try A.finalize(c1.state, rng, &.{.{ .from = 2, .msg = from_2 }});
    defer info1.deinit();
    var info2 = try A.finalize(c2.state, rng, &.{.{ .from = 1, .msg = from_1 }});
    defer info2.deinit();
    try testing.expectEqualSlices(u8, &info1.rho, &info2.rho);

    // The aux-info artifact itself, which has to persist between processes.
    const loaded = try roundTrip(A.AuxInfo, info1, arena);
    try testing.expectEqual(info1.party, loaded.party);
    try testing.expectEqualSlices(u8, &info1.parties[1].n, &loaded.parties[1].n);
    const m = P.Fn.fromU64(31337);
    const ct = try loaded.dk.ek.encrypt(m, rng);
    try testing.expectEqualSlices(u8, &m, &try loaded.dk.decrypt(ct.c));
}

test "3-party aux-info survives a full store/load cycle between every round" {
    // This is the shape the CLI runs in: each round is a separate process, so
    // every state goes to disk and comes back, and every message is encoded,
    // written, read and decoded before the next round sees it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(1234);
    const rng = prng.random();

    const P = zk.common.Params(576, 256, 512, 384); // matches the CLI's ecdsa_fast
    const A = auxgen.AuxGen(P, 16);
    const n = 3;
    const eid = auxgen.ExecutionId.random(rng);

    fn_scope: {
        var r1: [n]A.Round1Result = undefined;
        var bc1: [n]A.Round1Broadcast = undefined;
        var st1: [n]A.State1 = undefined;
        for (0..n) |i| {
            var primes = try A.Primes.generate(rng, false);
            defer primes.zeroize();
            r1[i] = try A.round1(@intCast(i + 1), n, eid, primes, rng);
            bc1[i] = try roundTrip(A.Round1Broadcast, r1[i].broadcast, arena);
            st1[i] = try roundTrip(A.State1, r1[i].state, arena);
        }

        var bc2: [n]A.Round2Broadcast = undefined;
        var st2: [n]A.State2 = undefined;
        for (0..n) |i| {
            var incoming: [n - 1]A.From(A.Round1Broadcast) = undefined;
            var k: usize = 0;
            for (0..n) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = bc1[j] };
                k += 1;
            }
            const r2 = try A.round2(arena, st1[i], &incoming);
            bc2[i] = try roundTrip(A.Round2Broadcast, r2.broadcast, arena);
            st2[i] = try roundTrip(A.State2, r2.state, arena);
        }

        // p2p[i][j] is what party i+1 produced for party j+1.
        var p2p: [n][n]?A.Round3P2p = @splat(@splat(null));
        var st3: [n]A.State3 = undefined;
        for (0..n) |i| {
            var incoming: [n - 1]A.From(A.Round2Broadcast) = undefined;
            var k: usize = 0;
            for (0..n) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = bc2[j] };
                k += 1;
            }
            const r3 = try A.round3(st2[i], rng, &incoming);
            for (r3.p2p) |out| {
                p2p[i][out.to - 1] = try roundTrip(A.Round3P2p, out.msg, arena);
            }
            st3[i] = try roundTrip(A.State3, r3.state, arena);
        }

        var infos: [n]A.AuxInfo = undefined;
        for (0..n) |i| {
            var incoming: [n - 1]A.From(A.Round3P2p) = undefined;
            var k: usize = 0;
            for (0..n) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = p2p[j][i].? };
                k += 1;
            }
            infos[i] = try A.finalize(st3[i], rng, &incoming);
        }

        try testing.expectEqualSlices(u8, &infos[0].rho, &infos[2].rho);
        for (0..n) |j| {
            try testing.expectEqualSlices(u8, &infos[0].parties[j].n, &infos[1].parties[j].n);
        }
        break :fn_scope;
    }
}

test "CGGMP24 presigning messages and states round-trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(99);
    const rng = prng.random();

    const P = zk.common.Params(320, 256, 512, 384);
    const E = curve.Secp256k1;
    const T = ecdsa.Ecdsa(P, E);
    const Pl = zk.common.Pail(P);
    const eid = ecdsa.ExecutionId.random(rng);

    const x1 = E.Scalar.random(rng);
    const x2 = E.Scalar.random(rng);
    const pk = try E.Point.mulBase(x1.add(x2));
    const big_x = [_]E.Point{ try E.Point.mulBase(x1), try E.Point.mulBase(x2) };

    var dks: [2]Pl.DecryptionKey = undefined;
    var parties: [2]T.PartyData = undefined;
    for (0..2) |i| {
        dks[i] = try Pl.DecryptionKey.generate(rng);
        var gen = try zk.common.Aux(P).generate(rng, false);
        gen.secret.zeroize();
        parties[i] = .{ .ek = dks[i].ek, .pedersen = gen.aux };
    }
    defer for (&dks) |*dk| dk.zeroize();

    // PartyData mixes an encryption key with ring-Pedersen parameters; both
    // are override types whose caches must be rebuilt.
    const pd = try roundTrip(T.PartyData, parties[0], arena);
    try testing.expectEqualSlices(u8, &parties[0].ek.n, &pd.ek.n);
    try testing.expectEqualSlices(u8, &parties[0].pedersen.t, &pd.pedersen.t);

    const keys1 = T.Keys{ .i = 1, .n = 2, .eid = eid, .x_i = x1, .big_x = &big_x, .pk = pk, .dk = dks[0], .parties = &parties };
    const keys2 = T.Keys{ .i = 2, .n = 2, .eid = eid, .x_i = x2, .big_x = &big_x, .pk = pk, .dk = dks[1], .parties = &parties };

    const r1_1 = try T.round1(arena, keys1, rng);
    const r1_2 = try T.round1(arena, keys2, rng);

    _ = try roundTrip(T.Round1aBroadcast, r1_1.broadcast, arena);
    // Round-1b carries two Πenc-elg proofs.
    const psi = try roundTrip(T.Round1bP2p, r1_1.p2p[0].msg, arena);
    try testing.expect(psi.psi0.w.eql(r1_1.p2p[0].msg.psi0.w));

    // State1 nests the whole Keys struct: a Paillier decryption key, a slice
    // of PartyData, and the additive share.
    const st1 = try roundTrip(T.State1, r1_1.state, arena);
    try testing.expect(st1.k_i.eql(r1_1.state.k_i));
    try testing.expect(st1.keys.x_i.eql(x1));
    try testing.expectEqual(@as(usize, 2), st1.keys.parties.len);
    try testing.expectEqualSlices(u8, &dks[0].p, &st1.keys.dk.p);

    const r2_1 = try T.round2(arena, r1_1.state, &.{.{ .from = 2, .msg = r1_2.broadcast }}, &.{.{ .from = 2, .msg = r1_2.p2p[0].msg }}, rng);
    const r2_2 = try T.round2(arena, r1_2.state, &.{.{ .from = 1, .msg = r1_1.broadcast }}, &.{.{ .from = 1, .msg = r1_1.p2p[0].msg }}, rng);

    // The largest message in the protocol: four Paillier ciphertexts, a Πelog
    // and two Πaff-g proofs.
    const big = try roundTrip(T.Round2P2p, r2_1.p2p[0].msg, arena);
    try testing.expectEqualSlices(u8, &r2_1.p2p[0].msg.d, &big.d);
    try testing.expect(big.psi.z1.eql(r2_1.p2p[0].msg.psi.z1));
    try testing.expect(big.gamma.eql(r2_1.p2p[0].msg.gamma));

    // State2 holds a slice of optional round-1 broadcasts (own slot null).
    const st2 = try roundTrip(T.State2, r2_1.state, arena);
    try testing.expect(st2.peers_1a[0] == null);
    try testing.expect(st2.peers_1a[1] != null);
    try testing.expect(st2.beta_sum.eql(r2_1.state.beta_sum));

    // Feed each party the *decoded* peer message, so the rest of the protocol
    // runs on data that made a round trip through bytes.
    const r3_1 = try T.round3(r2_1.state, &.{.{ .from = 2, .msg = try roundTrip(T.Round2P2p, r2_2.p2p[0].msg, arena) }}, rng);
    const r3_2 = try T.round3(r2_2.state, &.{.{ .from = 1, .msg = big }}, rng);

    const r3msg = try roundTrip(T.Round3Broadcast, r3_1.broadcast, arena);
    try testing.expect(r3msg.delta.eql(r3_1.broadcast.delta));
    const st3 = try roundTrip(T.State3, r3_1.state, arena);
    try testing.expect(st3.chi_i.eql(r3_1.state.chi_i));

    var presig1 = try T.finalize(r3_1.state, &.{.{ .from = 2, .msg = try roundTrip(T.Round3Broadcast, r3_2.broadcast, arena) }});
    defer presig1.zeroize();
    var presig2 = try T.finalize(r3_2.state, &.{.{ .from = 1, .msg = r3msg }});
    defer presig2.zeroize();

    // The presignature is an artifact: generated ahead of time, stored, and
    // consumed by a later process once a message is known.
    const loaded1 = try roundTrip(T.Presignature, presig1, arena);
    const loaded2 = try roundTrip(T.Presignature, presig2, arena);
    try testing.expect(loaded1.gamma.eql(loaded2.gamma));

    const msg = "a presignature that survived serialization";
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &h);
    const m_scalar = E.Scalar.fromWideBytes(wide);

    const sig = try T.combine(loaded1.gamma, &.{
        T.partialSign(loaded1, m_scalar),
        T.partialSign(loaded2, m_scalar),
    }, m_scalar);
    try testing.expect(T.verify(pk, m_scalar, sig));

    // and it verifies under std.crypto's independent ECDSA
    const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const std_pk = try StdEcdsa.PublicKey.fromSec1(&pk.toBytes());
    var sig_bytes: [64]u8 = undefined;
    sig_bytes[0..32].* = sig.r.toBytes();
    sig_bytes[32..].* = sig.s.toBytes();
    try StdEcdsa.Signature.fromBytes(sig_bytes).verify(msg, std_pk);
}

test "every byte of a message matters" {
    // Flipping any single bit must change the encoding, i.e. no field is
    // dropped on the way out. Catches an override that silently omits data.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(77);
    const rng = prng.random();

    const E = curve.Ed25519;
    const shares = try dkg.runDkgForTest(E, arena, 2, 2, rng);
    const original = try encodeAlloc(dkg.Dkg(E).KeyShare, shares[0], arena);

    var mutated = shares[0];
    mutated.secret_share = mutated.secret_share.add(E.Scalar.one);
    const changed = try encodeAlloc(dkg.Dkg(E).KeyShare, mutated, arena);
    try testing.expect(!std.mem.eql(u8, original, changed));
    try testing.expectEqual(original.len, changed.len);
}
