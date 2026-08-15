//! Minimal flag parsing for zmpc.
//!
//! Deliberately strict: an unrecognized `--flag` is an error rather than
//! being ignored. A typo like `--treshold 2` silently falling back to a
//! default would change the security parameters of a key without telling
//! anyone, which is exactly the class of mistake this tool must not make.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    UnknownFlag,
    MissingValue,
    MissingRequiredFlag,
    InvalidValue,
    DuplicateFlag,
    OutOfMemory,
};

pub const Flag = struct {
    name: []const u8,
    value: ?[]const u8,
};

pub const Args = struct {
    /// Words before the first `-` - the command path, e.g. `dkg round1`.
    words: [][]const u8,
    flags: []Flag,
    /// Set by `reportUnknown` so the error message can name the offender.
    bad_flag: []const u8 = "",
    /// Set when a value fails to parse.
    bad_value_for: []const u8 = "",

    pub fn parse(gpa: Allocator, argv: []const [:0]const u8) Error!Args {
        var words: std.ArrayList([]const u8) = .empty;
        var flags: std.ArrayList(Flag) = .empty;

        var i: usize = 0;
        while (i < argv.len) : (i += 1) {
            const arg: []const u8 = argv[i];
            if (!std.mem.startsWith(u8, arg, "-")) {
                try words.append(gpa, arg);
                continue;
            }
            const body = std.mem.trimStart(u8, arg, "-");
            if (body.len == 0) return error.UnknownFlag;

            // --name=value
            if (std.mem.indexOfScalar(u8, body, '=')) |eq| {
                try flags.append(gpa, .{ .name = body[0..eq], .value = body[eq + 1 ..] });
                continue;
            }
            // --name value, unless the next token is itself a flag
            const next: ?[]const u8 = if (i + 1 < argv.len) argv[i + 1] else null;
            if (next) |n| {
                if (!std.mem.startsWith(u8, n, "-") or looksNegativeNumber(n)) {
                    try flags.append(gpa, .{ .name = body, .value = n });
                    i += 1;
                    continue;
                }
            }
            try flags.append(gpa, .{ .name = body, .value = null });
        }

        return .{ .words = try words.toOwnedSlice(gpa), .flags = try flags.toOwnedSlice(gpa) };
    }

    fn looksNegativeNumber(text: []const u8) bool {
        return text.len > 1 and text[0] == '-' and std.ascii.isDigit(text[1]);
    }

    pub fn word(self: Args, index: usize) ?[]const u8 {
        return if (index < self.words.len) self.words[index] else null;
    }

    pub fn has(self: Args, name: []const u8) bool {
        for (self.flags) |f| {
            if (std.mem.eql(u8, f.name, name)) return true;
        }
        return false;
    }

    /// The value attached to `name`, or null if the flag is absent *or* was
    /// given without one. Use `has` to distinguish; `require` reports the
    /// difference as separate errors.
    pub fn value(self: Args, name: []const u8) ?[]const u8 {
        for (self.flags) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    pub fn valueOr(self: Args, name: []const u8, fallback: []const u8) []const u8 {
        return self.value(name) orelse fallback;
    }

    pub fn require(self: *Args, name: []const u8) Error![]const u8 {
        for (self.flags) |f| {
            if (!std.mem.eql(u8, f.name, name)) continue;
            return f.value orelse {
                self.bad_flag = name;
                return error.MissingValue;
            };
        }
        self.bad_flag = name;
        return error.MissingRequiredFlag;
    }

    pub fn int(self: *Args, comptime T: type, name: []const u8) Error!?T {
        if (!self.has(name)) return null;
        return try self.intRequired(T, name);
    }

    pub fn intRequired(self: *Args, comptime T: type, name: []const u8) Error!T {
        const text = try self.require(name);
        return std.fmt.parseInt(T, text, 10) catch {
            self.bad_value_for = name;
            return error.InvalidValue;
        };
    }

    pub fn enumRequired(self: *Args, comptime T: type, name: []const u8) Error!T {
        const text = try self.require(name);
        return std.meta.stringToEnum(T, text) orelse {
            self.bad_value_for = name;
            return error.InvalidValue;
        };
    }

    /// Reject any flag not in `allowed`. Call this once per command, after
    /// reading everything, so typos surface instead of being ignored.
    pub fn rejectUnknown(self: *Args, allowed: []const []const u8) Error!void {
        outer: for (self.flags) |f| {
            for (allowed) |name| {
                if (std.mem.eql(u8, f.name, name)) continue :outer;
            }
            self.bad_flag = f.name;
            return error.UnknownFlag;
        }
    }

    /// Comma-separated integer list, e.g. `--signers 1,3`.
    pub fn intList(self: *Args, comptime T: type, gpa: Allocator, name: []const u8) Error![]T {
        const text = try self.require(name);
        var out: std.ArrayList(T) = .empty;
        var it = std.mem.splitScalar(u8, text, ',');
        while (it.next()) |piece| {
            const trimmed = std.mem.trim(u8, piece, " ");
            if (trimmed.len == 0) continue;
            const parsed = std.fmt.parseInt(T, trimmed, 10) catch {
                self.bad_value_for = name;
                return error.InvalidValue;
            };
            try out.append(gpa, parsed);
        }
        if (out.items.len == 0) {
            self.bad_value_for = name;
            return error.InvalidValue;
        }
        return out.toOwnedSlice(gpa);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn parseForTest(gpa: Allocator, comptime argv: []const [:0]const u8) !Args {
    return Args.parse(gpa, argv);
}

test "words, flags and values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a = try parseForTest(arena, &.{ "dkg", "round1", "--dir", "p1", "--party=2", "--armor" });
    try testing.expectEqualStrings("dkg", a.word(0).?);
    try testing.expectEqualStrings("round1", a.word(1).?);
    try testing.expect(a.word(2) == null);
    try testing.expectEqualStrings("p1", a.value("dir").?);
    try testing.expectEqual(@as(u16, 2), (try a.int(u16, "party")).?);
    try testing.expect(a.has("armor"));
    try testing.expect(a.value("armor") == null);
    try testing.expect(!a.has("nope"));
    try testing.expect((try a.int(u16, "nope")) == null);
}

test "a flag directly followed by another flag has no value" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a = try parseForTest(arena, &.{ "--armor", "--dir", "p1" });
    try testing.expect(a.has("armor"));
    try testing.expect(a.value("armor") == null);
    try testing.expectEqualStrings("p1", try a.require("dir"));
    try testing.expectError(error.MissingValue, a.require("armor"));
}

test "unknown flags are refused rather than ignored" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a = try parseForTest(arena, &.{ "--treshold", "2" });
    try testing.expectError(error.UnknownFlag, a.rejectUnknown(&.{ "threshold", "dir" }));
    try testing.expectEqualStrings("treshold", a.bad_flag);

    var b = try parseForTest(arena, &.{ "--threshold", "2" });
    try b.rejectUnknown(&.{ "threshold", "dir" });
}

test "missing and malformed values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a = try parseForTest(arena, &.{"--n"});
    try testing.expectError(error.MissingValue, a.intRequired(u16, "n"));

    var b = try parseForTest(arena, &.{ "--n", "many" });
    try testing.expectError(error.InvalidValue, b.intRequired(u16, "n"));
    try testing.expectEqualStrings("n", b.bad_value_for);

    var c = try parseForTest(arena, &.{"--other"});
    try testing.expectError(error.MissingRequiredFlag, c.require("n"));
}

test "signer lists" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a = try parseForTest(arena, &.{ "--signers", "1,3" });
    try testing.expectEqualSlices(u16, &.{ 1, 3 }, try a.intList(u16, arena, "signers"));

    var b = try parseForTest(arena, &.{ "--signers", "2, 4 ,5" });
    try testing.expectEqualSlices(u16, &.{ 2, 4, 5 }, try b.intList(u16, arena, "signers"));

    var c = try parseForTest(arena, &.{ "--signers", "" });
    try testing.expectError(error.InvalidValue, c.intList(u16, arena, "signers"));
}
