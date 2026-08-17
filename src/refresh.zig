//! Proactive key refresh: re-randomizes threshold key shares without
//! changing the public key. Every party deals a zero-sharing (a degree-(t-1)
//! polynomial with f(0) = 0); shares are added to the existing shares and
//! the aggregated Feldman commitment is updated. Old shares become
//! inconsistent with the new commitment and are useless to an attacker who
//! later compromises fewer than t parties.
//!
//! 3 rounds, mirroring the DKG: hash-commit, then decommit + p2p shares,
//! then verification. Transport must provide consistent broadcast; p2p shares
//! must be confidential.

const std = @import("std");
const Allocator = std.mem.Allocator;
const vss = @import("vss.zig");
const dkg = @import("dkg.zig");
const message = @import("message.zig");
const transcript = @import("transcript.zig");

const Transcript = transcript.Transcript;
pub const ExecutionId = transcript.ExecutionId;

pub fn Refresh(comptime E: type) type {
    return struct {
        pub const KeyShare = dkg.Dkg(E).KeyShare;

        pub const From = message.From;
        pub const To = message.To;

        pub const Round1Broadcast = struct {
            commitment_hash: [32]u8,
        };

        pub const Round2Broadcast = struct {
            /// Commitments to coefficients 1..t-1 (the constant term is 0,
            /// committed implicitly as the identity).
            feldman_tail: []E.Point,
            decommit_nonce: [32]u8,
        };

        pub const Round2P2p = struct {
            /// f_i(recipient) - CONFIDENTIAL.
            share: E.Scalar,
        };

        /// Evaluate the tail commitment: sum_{k=1..} x^k * A_k.
        fn evalTail(tail: []const E.Point, x: E.Scalar) ?E.Point {
            if (tail.len == 0) return null;
            var i = tail.len - 1;
            var acc = tail[i];
            while (i > 0) {
                i -= 1;
                acc = (acc.mulPublic(x) catch return null).add(tail[i]);
            }
            return acc.mulPublic(x) catch null;
        }

        fn verifyZeroShare(tail: []const E.Point, index: u16, share: E.Scalar) bool {
            const x = vss.shareIndex(E, index) catch return false;
            const expected = evalTail(tail, x) orelse return false;
            const actual = E.Point.mulBase(share) catch return false;
            return expected.eql(actual);
        }

        fn commitmentHash(eid: ExecutionId, party: u16, tail: []const E.Point, nonce: [32]u8) [32]u8 {
            var t = Transcript.init("zig-mpc/refresh/commit/v1");
            t.appendExecutionId(eid);
            t.appendU64("party", party);
            t.appendU64("tail-len", tail.len);
            for (tail) |p| t.appendPoint(E, "feldman", p);
            t.appendBytes("decommit-nonce", &nonce);
            var rng = t.challengeRng();
            var out: [32]u8 = undefined;
            rng.fill(&out);
            return out;
        }

        /// Round state deliberately holds no reference to the key share: the
        /// share is only touched at the very end, by `finalize`, and keeping
        /// the state free of pointers is what lets a caller write it to disk
        /// between rounds and continue in another process.
        pub const State1 = struct {
            party: u16,
            threshold: u16,
            n: u16,
            eid: ExecutionId,
            poly_coeffs: []E.Scalar, // coeffs[0] == 0
            tail: []E.Point,
            decommit_nonce: [32]u8,
            allocator: Allocator,

            /// round1 copies these from a validated KeyShare, but the CLI
            /// reloads State1 from a decoded frame between rounds; a tampered
            /// frame with party = 0 underflows `party - 1` in round2, so the
            /// later rounds revalidate. finalize additionally cross-checks the
            /// state against the freshly validated share it updates.
            fn validate(self: State1) !void {
                if (self.party < 1 or self.party > self.n or self.n < 2) return error.InvalidParams;
                if (self.threshold < 1) return error.InvalidParams;
            }

            fn evalPoly(self: State1, x: E.Scalar) E.Scalar {
                var acc = E.Scalar.zero;
                var i = self.poly_coeffs.len;
                while (i > 0) {
                    i -= 1;
                    acc = acc.mul(x).add(self.poly_coeffs[i]);
                }
                return acc;
            }

            pub fn deinit(self: *State1) void {
                for (self.poly_coeffs) |*c| c.zeroize();
                self.allocator.free(self.poly_coeffs);
                self.allocator.free(self.tail);
                self.* = undefined;
            }
        };

        pub const Round1Result = struct { state: State1, broadcast: Round1Broadcast };

        /// Reads only the share's parameters; the share itself is updated
        /// later, by `finalize`.
        pub fn round1(allocator: Allocator, share: KeyShare, eid: ExecutionId, rng: std.Random) !Round1Result {
            const t_deg = share.threshold;
            if (t_deg < 1) return error.InvalidThreshold;

            const coeffs = try allocator.alloc(E.Scalar, t_deg);
            errdefer allocator.free(coeffs);
            coeffs[0] = E.Scalar.zero;
            for (coeffs[1..]) |*c| {
                c.* = E.Scalar.random(rng);
                while (c.isZero()) c.* = E.Scalar.random(rng);
            }

            const tail = try allocator.alloc(E.Point, t_deg - 1);
            errdefer allocator.free(tail);
            for (coeffs[1..], tail) |c, *p| {
                p.* = E.Point.mulBase(c) catch unreachable; // nonzero by construction
            }

            var nonce: [32]u8 = undefined;
            rng.bytes(&nonce);

            return .{
                .state = .{
                    .party = share.party,
                    .threshold = share.threshold,
                    .n = share.n,
                    .eid = eid,
                    .poly_coeffs = coeffs,
                    .tail = tail,
                    .decommit_nonce = nonce,
                    .allocator = allocator,
                },
                .broadcast = .{ .commitment_hash = commitmentHash(eid, share.party, tail, nonce) },
            };
        }

        pub const State2 = struct {
            s1: State1,
            hashes: []?[32]u8,

            pub fn deinit(self: *State2) void {
                self.s1.allocator.free(self.hashes);
                self.s1.deinit();
                self.* = undefined;
            }
        };

        pub const Round2Result = struct {
            state: State2,
            /// `broadcast.feldman_tail` is an owned copy; free it after
            /// delivery via `deinitMessages`.
            broadcast: Round2Broadcast,
            /// One entry per other party, addressed to that party.
            p2p: []To(Round2P2p),

            pub fn deinitMessages(self: *Round2Result, allocator: Allocator) void {
                allocator.free(self.broadcast.feldman_tail);
                allocator.free(self.p2p);
            }
        };

        pub fn round2(state: State1, incoming: []const From(Round1Broadcast)) !Round2Result {
            try state.validate();
            const allocator = state.allocator;
            const n = state.n;

            const hashes = try allocator.alloc(?[32]u8, n);
            errdefer allocator.free(hashes);
            @memset(hashes, null);
            hashes[state.party - 1] = commitmentHash(state.eid, state.party, state.tail, state.decommit_nonce);
            for (incoming) |m| {
                if (m.from < 1 or m.from > n or m.from == state.party) return error.InvalidSender;
                if (hashes[m.from - 1] != null) return error.DuplicateMessage;
                hashes[m.from - 1] = m.msg.commitment_hash;
            }
            for (hashes) |h| if (h == null) return error.MissingMessage;

            const p2p = try allocator.alloc(To(Round2P2p), n - 1);
            errdefer allocator.free(p2p);
            var k: usize = 0;
            var j: u16 = 1;
            while (j <= n) : (j += 1) {
                if (j == state.party) continue;
                p2p[k] = .{ .to = j, .msg = .{ .share = state.evalPoly(try vss.shareIndex(E, j)) } };
                k += 1;
            }

            const tail_copy = try allocator.dupe(E.Point, state.tail);
            errdefer allocator.free(tail_copy);

            return .{
                .state = .{ .s1 = state, .hashes = hashes },
                .broadcast = .{ .feldman_tail = tail_copy, .decommit_nonce = state.decommit_nonce },
                .p2p = p2p,
            };
        }

        /// Verify everything and apply the refresh to the key share in place.
        /// On error the share is left UNCHANGED.
        pub fn finalize(
            state: State2,
            share: *KeyShare,
            incoming_bc: []const From(Round2Broadcast),
            incoming_p2p: []const From(Round2P2p),
        ) !void {
            var st = state;
            try st.s1.validate();
            const allocator = st.s1.allocator;
            const n = st.s1.n;
            const t_deg = st.s1.threshold;
            if (share.party != st.s1.party or share.n != n or share.threshold != t_deg)
                return error.ShareDoesNotMatchState;

            if (incoming_bc.len != n - 1 or incoming_p2p.len != n - 1) return error.MissingMessage;

            const seen = try allocator.alloc(bool, n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[share.party - 1] = true;

            var delta = st.s1.evalPoly(try vss.shareIndex(E, share.party));
            const new_tail = try allocator.alloc(E.Point, t_deg - 1);
            defer allocator.free(new_tail);
            @memcpy(new_tail, st.s1.tail);

            for (incoming_bc) |m| {
                const j = m.from;
                if (j < 1 or j > n or j == share.party) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;

                if (m.msg.feldman_tail.len != t_deg - 1) return error.InvalidCommitmentLength;
                const expect = st.hashes[j - 1].?;
                const actual = commitmentHash(st.s1.eid, j, m.msg.feldman_tail, m.msg.decommit_nonce);
                if (!std.crypto.timing_safe.eql([32]u8, expect, actual)) return error.DecommitmentMismatch;

                var sigma: ?E.Scalar = null;
                for (incoming_p2p) |pm| {
                    if (pm.from == j) sigma = pm.msg.share;
                }
                const s = sigma orelse return error.MissingMessage;
                if (t_deg > 1) {
                    if (!verifyZeroShare(m.msg.feldman_tail, share.party, s)) return error.InvalidShare;
                } else {
                    // t == 1: zero polynomial, shares must be zero
                    if (!s.isZero()) return error.InvalidShare;
                }

                delta = delta.add(s);
                for (new_tail, m.msg.feldman_tail) |*a, b| a.* = a.add(b);
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            // apply: share += delta; commitment tail += sum of zero-sharing
            // tails (constant term untouched - public key preserved)
            const new_secret = share.secret_share.add(delta);
            for (share.vss_commitment[1..], new_tail) |*a, b| a.* = a.add(b);
            share.secret_share.zeroize();
            share.secret_share = new_secret;

            // sanity: new share consistent with new commitment
            const com = vss.Commitment(E){ .points = share.vss_commitment, .allocator = allocator };
            if (!com.verifyShare(share.party, share.secret_share)) return error.InconsistentShare;

            st.deinit();
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const curve = @import("curve.zig");
const frost = @import("frost.zig");

test "refresh preserves public key, invalidates old shares, signing still works" {
    var prng = std.Random.DefaultPrng.init(505050);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    inline for (.{ frost.Ed25519Sha512, frost.Secp256k1Sha256 }) |Suite| {
        const E = Suite.E;
        const R = Refresh(E);
        const n: u16 = 3;

        const shares = try dkg.runDkgForTest(E, allocator, 2, n, rng);
        defer {
            for (shares) |*s| s.deinit();
            allocator.free(shares);
        }
        const pk_before = shares[0].public_key;
        const old_secret_1 = shares[0].secret_share;

        // run refresh
        const eid = ExecutionId.random(rng);
        var r1: [n]R.Round1Result = undefined;
        for (0..n) |i| r1[i] = try R.round1(allocator, shares[i], eid, rng);

        var r2: [n]R.Round2Result = undefined;
        for (0..n) |i| {
            var incoming: [n - 1]R.From(R.Round1Broadcast) = undefined;
            var k: usize = 0;
            for (0..n) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = r1[j].broadcast };
                k += 1;
            }
            r2[i] = try R.round2(r1[i].state, &incoming);
        }

        for (0..n) |i| {
            var bc: [n - 1]R.From(R.Round2Broadcast) = undefined;
            var p2p: [n - 1]R.From(R.Round2P2p) = undefined;
            var k: usize = 0;
            for (0..n) |j| {
                if (j == i) continue;
                bc[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
                for (r2[j].p2p) |pm| {
                    if (pm.to == i + 1) p2p[k] = .{ .from = @intCast(j + 1), .msg = pm.msg };
                }
                k += 1;
            }
            try R.finalize(r2[i].state, &shares[i], &bc, &p2p);
        }
        for (0..n) |i| r2[i].deinitMessages(allocator);

        // public key unchanged, share changed, old share invalid vs new commitment
        try std.testing.expect(shares[0].public_key.eql(pk_before));
        try std.testing.expect(!shares[0].secret_share.eql(old_secret_1));
        const com = vss.Commitment(E){ .points = shares[0].vss_commitment, .allocator = allocator };
        try std.testing.expect(com.verifyShare(1, shares[0].secret_share));
        try std.testing.expect(!com.verifyShare(1, old_secret_1));

        // refreshed shares still reconstruct the same key and sign correctly
        const rec = try vss.reconstructAtZero(E, &.{ 2, 3 }, &.{ shares[1].secret_share, shares[2].secret_share });
        try std.testing.expect((try E.Point.mulBase(rec)).eql(pk_before));

        const F = frost.Frost(Suite);
        const msg = "post-refresh signing";
        const c2 = try F.commit(2, shares[1].secret_share, rng);
        const c3 = try F.commit(3, shares[2].secret_share, rng);
        const commitment_list = [_]F.Commitment{ c2.commitment, c3.commitment };
        const z2 = try F.sign(2, shares[1].secret_share, pk_before, c2.nonces, msg, &commitment_list);
        const z3 = try F.sign(3, shares[2].secret_share, pk_before, c3.nonces, msg, &commitment_list);
        const sig = try F.aggregate(&commitment_list, msg, pk_before, &.{ z2, z3 });
        try std.testing.expect(F.verify(msg, pk_before, sig));
    }
}

test "refresh rejects tampered zero-share" {
    const E = curve.Secp256k1;
    const R = Refresh(E);
    var prng = std.Random.DefaultPrng.init(606060);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const n: u16 = 2;

    const shares = try dkg.runDkgForTest(E, allocator, 2, n, rng);
    defer {
        for (shares) |*s| s.deinit();
        allocator.free(shares);
    }

    const eid = ExecutionId.random(rng);
    const r1_1 = try R.round1(allocator, shares[0], eid, rng);
    const r1_2 = try R.round1(allocator, shares[1], eid, rng);

    var r2_1 = try R.round2(r1_1.state, &.{.{ .from = 2, .msg = r1_2.broadcast }});
    var r2_2 = try R.round2(r1_2.state, &.{.{ .from = 1, .msg = r1_1.broadcast }});
    defer r2_2.state.deinit();

    var bad_share = r2_2.p2p[0].msg;
    bad_share.share = bad_share.share.add(E.Scalar.one);
    try std.testing.expectError(error.InvalidShare, R.finalize(
        r2_1.state,
        &shares[0],
        &.{.{ .from = 2, .msg = r2_2.broadcast }},
        &.{.{ .from = 2, .msg = bad_share }},
    ));
    r2_1.state.deinit();
    r2_1.deinitMessages(allocator);
    r2_2.deinitMessages(allocator);
}
