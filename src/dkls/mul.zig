//! Two-party multiplication: random vector OLE.
//!
//! Realizes Functionality 3.5 of DKLs23 using Protocol 1 of DKLs19
//! (<https://eprint.iacr.org/2019/523.pdf>), in the two-round form the former
//! describes on page 8 and in Section 5.1.
//!
//! The contract: the sender holds `L` scalars `a`, the receiver holds one
//! scalar `b` that the protocol itself samples, and afterwards
//!
//!     output_sender[i] + output_receiver[i] == a[i] * b
//!
//! with neither side learning the other's input. This is the piece ECDSA
//! actually needs, because `k^-1 (m + r x)` requires multiplying two
//! secret-shared values, and it is the piece CGGMP24 solves with Paillier and
//! range proofs instead.
//!
//! `b` is not chosen by the receiver: it is the sum of the gadget-vector
//! entries its OT choice bits select. That is what lets the sender's OT
//! correlations do the multiplying.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash = @import("hash.zig");
pub const ote = @import("ote.zig");

/// Number of products per invocation. Signing multiplies both the instance key
/// and the key share against the same counterparty value, so two.
pub const l = 2;

comptime {
    // Each input needs a pad and a check value, and the extension carries them
    // in one batch.
    std.debug.assert(ote.ot_width == 2 * l);
}

pub const Error = error{
    /// The sender's opened check value did not match. As with the OT extension
    /// this indicates an active cheat, and the shared base-OT state is burned.
    ConsistencyCheckFailed,
};

/// Derive the gadget vector. Both parties must call this with the same setup
/// session id and nonce, or nothing agrees.
pub fn deriveGadget(comptime E: type, session_id: []const u8, nonce: E.Scalar, out: []E.Scalar) void {
    std.debug.assert(out.len == ote.batch_size);
    var counter = nonce;
    for (out) |*g| {
        counter = counter.add(E.Scalar.one);
        const b = counter.toBytes();
        g.* = hash.taggedHashScalar(E, hash.tag.mul_gadget, &.{ session_id, &b });
    }
}

/// Build the transcript both sides hash to derive the check challenges: the
/// receiver's opened matrix and its two check values, in that order.
fn transcriptOf(comptime E: type, gpa: Allocator, data: ote.DataToSender(E)) Allocator.Error![]u8 {
    const u_len = data.u.len * ote.prg_len;
    const t_len = data.verify_t.len * ote.field_len;
    const buf = try gpa.alloc(u8, u_len + ote.field_len + t_len);
    for (data.u, 0..) |row, i| @memcpy(buf[i * ote.prg_len ..][0..ote.prg_len], &row);
    @memcpy(buf[u_len..][0..ote.field_len], &data.verify_x);
    for (data.verify_t, 0..) |t, i| @memcpy(buf[u_len + ote.field_len + i * ote.field_len ..][0..ote.field_len], &t);
    return buf;
}

fn challenges(comptime E: type, session_id: []const u8, transcript: []const u8, tilde: *[l]E.Scalar, hat: *[l]E.Scalar) void {
    for (0..l) |i| {
        const i_be = [_]u8{@intCast(i)};
        tilde[i] = hash.taggedHashScalar(E, hash.tag.mul_chi_tilde, &.{ session_id, &i_be, transcript });
        hat[i] = hash.taggedHashScalar(E, hash.tag.mul_chi_hat, &.{ session_id, &i_be, transcript });
    }
}

/// The session id the underlying extension runs under.
fn oteSessionId(gpa: Allocator, session_id: []const u8) Allocator.Error![]u8 {
    const prefix = "OT Extension protocol";
    const buf = try gpa.alloc(u8, prefix.len + session_id.len);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..], session_id);
    return buf;
}

/// What the sender sends back to close the protocol.
pub fn DataToReceiver(comptime E: type) type {
    return struct {
        const Self = @This();
        /// `ot_width * batch_size` adjustments from the extension.
        tau: []E.Scalar,
        /// Hash of the check matrix.
        verify_r: hash.Digest,
        verify_u: [l]E.Scalar,
        /// `input - pad`, the only place the sender's input surfaces.
        gamma: [l]E.Scalar,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.tau);
            self.* = undefined;
        }
    };
}

pub fn Sender(comptime E: type) type {
    return struct {
        const Self = @This();

        ote_sender: ote.Sender(E),
        /// `batch_size` public scalars, shared with the receiver.
        gadget: []E.Scalar,

        pub fn zeroize(self: *Self) void {
            self.ote_sender.zeroize();
        }

        /// Multiply `input` against the receiver's hidden value.
        pub fn run(
            self: Self,
            gpa: Allocator,
            session_id: []const u8,
            input: [l]E.Scalar,
            data: ote.DataToSender(E),
            rng: std.Random,
        ) (Error || ote.Error || Allocator.Error)!struct { output: [l]E.Scalar, to_receiver: DataToReceiver(E) } {
            const n = ote.ot_width * ote.batch_size;

            // Pads and check values, one pair per input.
            var pad: [l]E.Scalar = undefined;
            var check: [l]E.Scalar = undefined;
            for (0..l) |i| {
                pad[i] = E.Scalar.random(rng);
                check[i] = E.Scalar.random(rng);
            }

            // The extension carries 2L correlations: each pad, then each check
            // value, every entry repeated across the batch.
            const correlations = try gpa.alloc(E.Scalar, n);
            defer gpa.free(correlations);
            for (0..l) |i| {
                @memset(correlations[i * ote.batch_size ..][0..ote.batch_size], pad[i]);
                @memset(correlations[(l + i) * ote.batch_size ..][0..ote.batch_size], check[i]);
            }

            const ote_sid = try oteSessionId(gpa, session_id);
            defer gpa.free(ote_sid);

            const z = try gpa.alloc(E.Scalar, n);
            errdefer gpa.free(z);
            const tau = try gpa.alloc(E.Scalar, n);
            errdefer gpa.free(tau);
            try self.ote_sender.run(gpa, ote_sid, correlations, data, z, tau);

            const transcript = try transcriptOf(E, gpa, data);
            defer gpa.free(transcript);
            var chi_tilde: [l]E.Scalar = undefined;
            var chi_hat: [l]E.Scalar = undefined;
            challenges(E, session_id, transcript, &chi_tilde, &chi_hat);

            // The check matrix, hashed rather than sent: the receiver can
            // rebuild it from its own shares and must reach the same hash.
            const r_bytes = try gpa.alloc(u8, l * ote.batch_size * E.Scalar.encoded_length);
            defer gpa.free(r_bytes);
            var verify_u: [l]E.Scalar = undefined;
            for (0..l) |i| {
                for (0..ote.batch_size) |j| {
                    const entry = chi_tilde[i].mul(z[i * ote.batch_size + j])
                        .add(chi_hat[i].mul(z[(l + i) * ote.batch_size + j]));
                    const at = (i * ote.batch_size + j) * E.Scalar.encoded_length;
                    @memcpy(r_bytes[at..][0..E.Scalar.encoded_length], &entry.toBytes());
                }
                verify_u[i] = chi_tilde[i].mul(pad[i]).add(chi_hat[i].mul(check[i]));
            }
            const verify_r = hash.taggedHash(hash.tag.mul_verify, &.{ session_id, r_bytes });

            var gamma: [l]E.Scalar = undefined;
            var output: [l]E.Scalar = undefined;
            for (0..l) |i| {
                gamma[i] = input[i].sub(pad[i]);
                var sum = E.Scalar.zero;
                for (0..ote.batch_size) |j| sum = sum.add(self.gadget[j].mul(z[i * ote.batch_size + j]));
                output[i] = sum;
            }

            for (pad[0..]) |*p| p.zeroize();
            for (check[0..]) |*c| c.zeroize();
            gpa.free(z);

            return .{
                .output = output,
                .to_receiver = .{ .tau = tau, .verify_r = verify_r, .verify_u = verify_u, .gamma = gamma },
            };
        }
    };
}

pub fn Receiver(comptime E: type) type {
    return struct {
        const Self = @This();

        ote_receiver: ote.Receiver(E),
        gadget: []E.Scalar,

        pub fn zeroize(self: *Self) void {
            self.ote_receiver.zeroize();
        }

        /// State carried between the receiver's two phases. Secret.
        pub const Kept = struct {
            /// The value being multiplied by. Determined by the choice bits.
            b: E.Scalar,
            choice_bits: [ote.batch_bytes]u8,
            kept: []ote.PrgRow,
            chi_tilde: [l]E.Scalar,
            chi_hat: [l]E.Scalar,

            pub fn deinit(self: *Kept, gpa: Allocator) void {
                self.b.zeroize();
                std.crypto.secureZero(u8, &self.choice_bits);
                for (self.kept) |*row| std.crypto.secureZero(u8, row);
                gpa.free(self.kept);
                self.* = undefined;
            }
        };

        /// Open the protocol. `b` is returned because the caller needs it, but
        /// it is chosen here, not supplied.
        pub fn start(
            self: Self,
            gpa: Allocator,
            session_id: []const u8,
            rng: std.Random,
        ) Allocator.Error!struct { b: E.Scalar, kept: Kept, to_sender: ote.DataToSender(E) } {
            var choice_bits: [ote.batch_bytes]u8 = undefined;
            rng.bytes(&choice_bits);

            // b is the sum of the gadget entries the choice bits select.
            var b = E.Scalar.zero;
            for (0..ote.batch_size) |j| {
                if (ote.getBit(&choice_bits, j) == 1) b = b.add(self.gadget[j]);
            }

            const ote_sid = try oteSessionId(gpa, session_id);
            defer gpa.free(ote_sid);

            var to_sender = try ote.DataToSender(E).init(gpa);
            errdefer to_sender.deinit(gpa);
            const kept_rows = try gpa.alloc(ote.PrgRow, ote.kappa);
            errdefer gpa.free(kept_rows);
            self.ote_receiver.start(ote_sid, &choice_bits, kept_rows, &to_sender, rng);

            const transcript = try transcriptOf(E, gpa, to_sender);
            defer gpa.free(transcript);
            var chi_tilde: [l]E.Scalar = undefined;
            var chi_hat: [l]E.Scalar = undefined;
            challenges(E, session_id, transcript, &chi_tilde, &chi_hat);

            return .{
                .b = b,
                .kept = .{ .b = b, .choice_bits = choice_bits, .kept = kept_rows, .chi_tilde = chi_tilde, .chi_hat = chi_hat },
                .to_sender = to_sender,
            };
        }

        /// Close the protocol against the sender's reply.
        pub fn finish(
            self: Self,
            gpa: Allocator,
            session_id: []const u8,
            kept: Kept,
            received: DataToReceiver(E),
        ) (Error || Allocator.Error)![l]E.Scalar {
            const n = ote.ot_width * ote.batch_size;
            const ote_sid = try oteSessionId(gpa, session_id);
            defer gpa.free(ote_sid);

            const z = try gpa.alloc(E.Scalar, n);
            defer gpa.free(z);
            try ote.Receiver(E).finish(gpa, ote_sid, &kept.choice_bits, kept.kept, received.tau, z);

            // Rebuild the check matrix from this side and compare hashes. Where
            // the choice bit is set the shares differ by the sender's opened
            // value, so adding it back must reproduce the sender's row.
            const r_bytes = try gpa.alloc(u8, l * ote.batch_size * E.Scalar.encoded_length);
            defer gpa.free(r_bytes);
            for (0..l) |i| {
                for (0..ote.batch_size) |j| {
                    var entry = kept.chi_tilde[i].mul(z[i * ote.batch_size + j])
                        .add(kept.chi_hat[i].mul(z[(l + i) * ote.batch_size + j])).neg();
                    if (ote.getBit(&kept.choice_bits, j) == 1) entry = entry.add(received.verify_u[i]);
                    const at = (i * ote.batch_size + j) * E.Scalar.encoded_length;
                    @memcpy(r_bytes[at..][0..E.Scalar.encoded_length], &entry.toBytes());
                }
            }
            const expected = hash.taggedHash(hash.tag.mul_verify, &.{ session_id, r_bytes });
            if (!std.crypto.timing_safe.eql(hash.Digest, expected, received.verify_r)) {
                return error.ConsistencyCheckFailed;
            }

            var output: [l]E.Scalar = undefined;
            for (0..l) |i| {
                var sum = E.Scalar.zero;
                for (0..ote.batch_size) |j| sum = sum.add(self.gadget[j].mul(z[i * ote.batch_size + j]));
                output[i] = kept.b.mul(received.gamma[i]).add(sum);
            }
            return output;
        }
    };
}

/// Establish a sender/receiver pair, including the shared gadget vector.
/// In the real protocol the nonce travels with the setup messages.
pub fn setupPair(
    comptime E: type,
    gpa: Allocator,
    session_id: []const u8,
    rng: std.Random,
) !struct { sender: Sender(E), receiver: Receiver(E), gadget: []E.Scalar } {
    var pair = try ote.setupPair(E, gpa, session_id, rng);
    errdefer pair.sender.zeroize();
    errdefer pair.receiver.zeroize();

    const nonce = E.Scalar.random(rng);
    const gadget = try gpa.alloc(E.Scalar, ote.batch_size);
    deriveGadget(E, session_id, nonce, gadget);

    return .{
        .sender = .{ .ote_sender = pair.sender, .gadget = gadget },
        .receiver = .{ .ote_receiver = pair.receiver, .gadget = gadget },
        .gadget = gadget,
    };
}

/// Test-support twin of `setupPair` that skips the base OT.
/// See `ote.pairFromRandomSeeds` for why the tests want this.
pub fn pairFromRandomSeeds(comptime E: type, gpa: Allocator, rng: std.Random) Allocator.Error!struct { sender: Sender(E), receiver: Receiver(E), gadget: []E.Scalar } {
    const pair = ote.pairFromRandomSeeds(E, rng);
    const gadget = try gpa.alloc(E.Scalar, ote.batch_size);
    deriveGadget(E, "test-gadget", E.Scalar.random(rng), gadget);
    return .{
        .sender = .{ .ote_sender = pair.sender, .gadget = gadget },
        .receiver = .{ .ote_receiver = pair.receiver, .gadget = gadget },
        .gadget = gadget,
    };
}

const testing = std.testing;
const K1 = @import("../curve.zig").Secp256k1;
const vectors = @import("../testdata/dkls_vectors.zig");

test "gadget vector matches dkls23-core" {
    const gpa = testing.allocator;
    var sid_buf: [16]u8 = undefined;
    const sid = std.fmt.hexToBytes(&sid_buf, vectors.gadget_sid) catch unreachable;
    var nonce_buf: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&nonce_buf, vectors.gadget_nonce) catch unreachable;
    const nonce = try K1.Scalar.fromBytes(nonce_buf);

    const g = try gpa.alloc(K1.Scalar, ote.batch_size);
    defer gpa.free(g);
    deriveGadget(K1, sid, nonce, g);

    try testing.expectEqual(@as(usize, vectors.gadget_len), g.len);

    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, std.fmt.hexToBytes(&buf, vectors.gadget_first) catch unreachable, &g[0].toBytes());
    var buf2: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, std.fmt.hexToBytes(&buf2, vectors.gadget_last) catch unreachable, &g[g.len - 1].toBytes());

    const flat = try gpa.alloc(u8, g.len * 32);
    defer gpa.free(flat);
    for (g, 0..) |s, i| @memcpy(flat[i * 32 ..][0..32], &s.toBytes());
    var dbuf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, std.fmt.hexToBytes(&dbuf, vectors.gadget_digest) catch unreachable, &hash.taggedHash("dump", &.{flat}));
}

test "the two shares multiply to a times b" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(31));
    const rng = prng.random();

    var pair = try pairFromRandomSeeds(K1, gpa, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();
    defer gpa.free(pair.gadget);

    const sid = "mul-session";
    var started = try pair.receiver.start(gpa, sid, rng);
    defer started.kept.deinit(gpa);
    defer started.to_sender.deinit(gpa);

    const input = [_]K1.Scalar{ K1.Scalar.fromU64(0xDEAD), K1.Scalar.fromU64(0xBEEF) };
    var sent = try pair.sender.run(gpa, sid, input, started.to_sender, rng);
    defer sent.to_receiver.deinit(gpa);

    const got = try pair.receiver.finish(gpa, sid, started.kept, sent.to_receiver);

    // The whole point: the shares of each product sum to a_i * b.
    for (0..l) |i| {
        const sum = sent.output[i].add(got[i]);
        try testing.expect(sum.eql(input[i].mul(started.b)));
    }
    // And b is not zero or one, which would make the test vacuous.
    try testing.expect(!started.b.isZero());
    try testing.expect(!started.b.eql(K1.Scalar.one));
}

test "a cheating sender is caught by the check hash" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(32));
    const rng = prng.random();

    var pair = try pairFromRandomSeeds(K1, gpa, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();
    defer gpa.free(pair.gadget);

    const sid = "mul-session";
    var started = try pair.receiver.start(gpa, sid, rng);
    defer started.kept.deinit(gpa);
    defer started.to_sender.deinit(gpa);

    const input = [_]K1.Scalar{ K1.Scalar.one, K1.Scalar.one };
    var sent = try pair.sender.run(gpa, sid, input, started.to_sender, rng);
    defer sent.to_receiver.deinit(gpa);

    // tau only enters the receiver's share where its choice bit is set, so a
    // tamper anywhere else is provably inert: it changes neither the output
    // nor the check. Aim at a position that is actually live.
    var live: ?usize = null;
    for (0..ote.batch_size) |j| {
        if (ote.getBit(&started.kept.choice_bits, j) == 1) {
            live = j;
            break;
        }
    }
    const at = live orelse return error.SkipZigTest;
    sent.to_receiver.tau[at] = sent.to_receiver.tau[at].add(K1.Scalar.one);
    try testing.expectError(error.ConsistencyCheckFailed, pair.receiver.finish(gpa, sid, started.kept, sent.to_receiver));
}

test "the check is bound to the session" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(33));
    const rng = prng.random();

    var pair = try pairFromRandomSeeds(K1, gpa, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();
    defer gpa.free(pair.gadget);

    var started = try pair.receiver.start(gpa, "sid-a", rng);
    defer started.kept.deinit(gpa);
    defer started.to_sender.deinit(gpa);

    const input = [_]K1.Scalar{ K1.Scalar.one, K1.Scalar.one };
    var sent = try pair.sender.run(gpa, "sid-a", input, started.to_sender, rng);
    defer sent.to_receiver.deinit(gpa);

    // Replaying the sender's reply under a different session must not close.
    try testing.expectError(error.ConsistencyCheckFailed, pair.receiver.finish(gpa, "sid-b", started.kept, sent.to_receiver));
}

test "tampering where the choice bit is clear is inert, not undetected" {
    // Worth pinning: a reviewer seeing the check pass on a modified tau should
    // find the reason here rather than assume the check is weak. Where the bit
    // is 0 the receiver never reads tau, so the value cannot influence its
    // output either; there is nothing to detect.
    const gpa = testing.allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(34));
    const rng = prng.random();

    var pair = try pairFromRandomSeeds(K1, gpa, rng);
    defer pair.sender.zeroize();
    defer pair.receiver.zeroize();
    defer gpa.free(pair.gadget);

    const sid = "mul-session";
    var started = try pair.receiver.start(gpa, sid, rng);
    defer started.kept.deinit(gpa);
    defer started.to_sender.deinit(gpa);

    const input = [_]K1.Scalar{ K1.Scalar.fromU64(3), K1.Scalar.fromU64(5) };
    var sent = try pair.sender.run(gpa, sid, input, started.to_sender, rng);
    defer sent.to_receiver.deinit(gpa);

    var dead: ?usize = null;
    for (0..ote.batch_size) |j| {
        if (ote.getBit(&started.kept.choice_bits, j) == 0) {
            dead = j;
            break;
        }
    }
    const at = dead orelse return error.SkipZigTest;

    const before = try pair.receiver.finish(gpa, sid, started.kept, sent.to_receiver);
    sent.to_receiver.tau[at] = sent.to_receiver.tau[at].add(K1.Scalar.one);
    const after = try pair.receiver.finish(gpa, sid, started.kept, sent.to_receiver);

    for (0..l) |i| try testing.expect(before[i].eql(after[i]));
    // The product still holds, which is the property that actually matters.
    for (0..l) |i| try testing.expect(sent.output[i].add(after[i]).eql(input[i].mul(started.b)));
}
