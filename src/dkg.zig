//! Curve-generic 3-round distributed key generation (Feldman VSS based,
//! following the CGGMP24 keygen structure). Produces threshold key shares
//! usable by both FROST (Schnorr/EdDSA) and CGGMP (ECDSA) signing.
//!
//! Round 1: hash-commit to (rid_i, chain_code_i, Feldman commitment F_i,
//!          Schnorr PoK nonce commitment R_i).            [broadcast]
//! Round 2: decommit; send VSS share f_i(j) to each j.    [broadcast + p2p]
//! Round 3: verify commitments and shares; broadcast Schnorr PoK of x_i,
//!          with the challenge bound to the joint rid.    [broadcast]
//! Finalize: verify all PoKs; output share sum_j f_j(i), aggregated
//!          commitment, public key, rid, chain code.
//!
//! The transport MUST provide consistent ("echo") broadcast; this
//! implementation does not yet include the optional reliability round.
//! P2p shares MUST be sent over confidential authenticated channels.

const std = @import("std");
const Allocator = std.mem.Allocator;
const vss = @import("vss.zig");
const transcript = @import("transcript.zig");
const message = @import("message.zig");

const Transcript = transcript.Transcript;
pub const ExecutionId = transcript.ExecutionId;

pub fn Dkg(comptime E: type) type {
    return struct {
        pub const Params = struct {
            /// This party's 1-based index.
            party: u16,
            /// Number of parties required to sign.
            threshold: u16,
            /// Total number of parties.
            n: u16,

            fn validate(self: Params) !void {
                if (self.threshold < 1 or self.n < 2) return error.InvalidParams;
                if (self.threshold > self.n) return error.InvalidParams;
                if (self.party < 1 or self.party > self.n) return error.InvalidParams;
            }
        };

        /// An incoming message, tagged with its sender's party index.
        pub const From = message.From;
        /// An outgoing p2p message, tagged with its recipient's party index.
        pub const To = message.To;

        pub const Round1Broadcast = struct {
            commitment_hash: [32]u8,
        };

        pub const Round2Broadcast = struct {
            rid: [32]u8,
            chain_code: [32]u8,
            /// Feldman commitment, length = threshold; feldman[0] = x_i * G.
            feldman: []E.Point,
            /// Schnorr PoK nonce commitment R_i.
            sch_commit: E.Point,
            decommit_nonce: [32]u8,
        };

        pub const Round2P2p = struct {
            /// f_i(recipient) - CONFIDENTIAL.
            share: E.Scalar,
        };

        pub const Round3Broadcast = struct {
            sch_response: E.Scalar,
        };

        pub const KeyShare = struct {
            party: u16,
            threshold: u16,
            n: u16,
            /// This party's secret signing share: sum_j f_j(party).
            secret_share: E.Scalar,
            public_key: E.Point,
            /// Aggregated Feldman commitment (length = threshold).
            vss_commitment: []E.Point,
            rid: [32]u8,
            chain_code: [32]u8,
            allocator: Allocator,

            /// Check the invariants a share produced by `finalize` always
            /// holds. A share that arrived from somewhere else - read back
            /// from disk, received over a network - is just bytes, and the
            /// rest of this type's methods assume these relations. Call this
            /// once after deserializing, before using it for anything.
            pub fn validate(self: KeyShare) !void {
                if (self.n < 2) return error.InvalidParams;
                if (self.threshold < 1 or self.threshold > self.n) return error.InvalidParams;
                if (self.party < 1 or self.party > self.n) return error.InvalidParams;
                // The commitment has one point per polynomial coefficient;
                // `publicShareOf` and the refresh update both index it against
                // `threshold`.
                if (self.vss_commitment.len != self.threshold) return error.InvalidCommitmentLength;
                // The constant term of the commitment *is* the group key.
                if (!self.vss_commitment[0].eql(self.public_key)) return error.InconsistentShare;
                // The secret share must lie on the committed polynomial:
                // secret_share * G == F(party). finalize() enforces exactly
                // this before ever writing a share out (see agg_com.verifyShare
                // below). Without repeating it here, a share reloaded from disk
                // with a corrupted or substituted secret_share but intact
                // public fields passes validation and then makes every signing
                // session emit an invalid aggregate signature.
                const expected = try self.publicShareOf(self.party);
                if (!(try E.Point.mulBase(self.secret_share)).eql(expected))
                    return error.InconsistentShare;
            }

            /// Public key share of any party: F(j) in the exponent.
            pub fn publicShareOf(self: KeyShare, party_j: u16) !E.Point {
                const com = vss.Commitment(E){
                    .points = self.vss_commitment,
                    .allocator = self.allocator,
                };
                return com.evaluate(try vss.shareIndex(E, party_j));
            }

            pub fn deinit(self: *KeyShare) void {
                self.secret_share.zeroize();
                self.allocator.free(self.vss_commitment);
                self.* = undefined;
            }
        };

        fn commitmentHash(
            eid: ExecutionId,
            party: u16,
            rid: [32]u8,
            chain_code: [32]u8,
            feldman: []const E.Point,
            sch_commit: E.Point,
            decommit_nonce: [32]u8,
        ) [32]u8 {
            var t = Transcript.init("zig-mpc/dkg/commit/v1");
            t.appendExecutionId(eid);
            t.appendU64("party", party);
            t.appendBytes("rid", &rid);
            t.appendBytes("chain-code", &chain_code);
            t.appendU64("feldman-len", feldman.len);
            for (feldman) |p| t.appendPoint(E, "feldman", p);
            t.appendPoint(E, "sch-commit", sch_commit);
            t.appendBytes("decommit-nonce", &decommit_nonce);
            var rng = t.challengeRng();
            var out: [32]u8 = undefined;
            rng.fill(&out);
            return out;
        }

        fn schnorrChallenge(eid: ExecutionId, rid: [32]u8, party: u16, public: E.Point, sch_commit: E.Point) E.Scalar {
            var t = Transcript.init("zig-mpc/dkg/schnorr-pok/v1");
            t.appendExecutionId(eid);
            t.appendBytes("rid", &rid);
            t.appendU64("party", party);
            t.appendPoint(E, "public", public);
            t.appendPoint(E, "commit", sch_commit);
            return t.challengeScalar(E);
        }

        pub const State1 = struct {
            params: Params,
            eid: ExecutionId,
            poly: vss.Polynomial(E),
            feldman: []E.Point,
            rid: [32]u8,
            chain_code: [32]u8,
            sch_nonce: E.Scalar,
            sch_commit: E.Point,
            decommit_nonce: [32]u8,
            allocator: Allocator,

            pub fn deinit(self: *State1) void {
                self.poly.deinit();
                self.sch_nonce.zeroize();
                self.allocator.free(self.feldman);
                self.* = undefined;
            }
        };

        pub const Round1Result = struct { state: State1, broadcast: Round1Broadcast };

        pub fn round1(allocator: Allocator, params: Params, eid: ExecutionId, rng: std.Random) !Round1Result {
            try params.validate();

            var secret = E.Scalar.random(rng);
            while (secret.isZero()) secret = E.Scalar.random(rng);

            var poly = try vss.Polynomial(E).initRandom(allocator, secret, params.threshold, rng);
            errdefer poly.deinit();
            const com = try poly.commit(allocator);
            // ownership of com.points moves into the state
            const feldman = com.points;
            errdefer allocator.free(feldman);

            var rid: [32]u8 = undefined;
            rng.bytes(&rid);
            var chain_code: [32]u8 = undefined;
            rng.bytes(&chain_code);
            var decommit_nonce: [32]u8 = undefined;
            rng.bytes(&decommit_nonce);

            var sch_nonce = E.Scalar.random(rng);
            while (sch_nonce.isZero()) sch_nonce = E.Scalar.random(rng);
            const sch_commit = try E.Point.mulBase(sch_nonce);

            const hash = commitmentHash(eid, params.party, rid, chain_code, feldman, sch_commit, decommit_nonce);

            return .{
                .state = .{
                    .params = params,
                    .eid = eid,
                    .poly = poly,
                    .feldman = feldman,
                    .rid = rid,
                    .chain_code = chain_code,
                    .sch_nonce = sch_nonce,
                    .sch_commit = sch_commit,
                    .decommit_nonce = decommit_nonce,
                    .allocator = allocator,
                },
                .broadcast = .{ .commitment_hash = hash },
            };
        }

        pub const State2 = struct {
            s1: State1,
            hashes: []?[32]u8, // indexed by party-1

            pub fn deinit(self: *State2) void {
                self.s1.allocator.free(self.hashes);
                self.s1.deinit();
                self.* = undefined;
            }
        };

        pub const Round2Result = struct {
            state: State2,
            /// `broadcast.feldman` is an independently allocated copy owned by
            /// this result; free it (e.g. via `deinitMessages`) once the
            /// broadcast has been delivered.
            broadcast: Round2Broadcast,
            /// One entry per other party, addressed to that party.
            p2p: []To(Round2P2p),

            pub fn deinitMessages(self: *Round2Result, allocator: Allocator) void {
                allocator.free(self.broadcast.feldman);
                allocator.free(self.p2p);
            }
        };

        /// `incoming` must contain exactly one Round1Broadcast from every other party.
        pub fn round2(state: State1, incoming: []const From(Round1Broadcast)) !Round2Result {
            const params = state.params;
            // round1 validated these, but the CLI reloads the state from a
            // decoded frame between rounds; a tampered frame with party = 0
            // would underflow `party - 1` below. Same in round3 and finalize.
            try params.validate();
            const allocator = state.allocator;

            const hashes = try allocator.alloc(?[32]u8, params.n);
            errdefer allocator.free(hashes);
            @memset(hashes, null);
            hashes[params.party - 1] = commitmentHash(
                state.eid,
                params.party,
                state.rid,
                state.chain_code,
                state.feldman,
                state.sch_commit,
                state.decommit_nonce,
            );
            for (incoming) |m| {
                if (m.from < 1 or m.from > params.n or m.from == params.party) return error.InvalidSender;
                if (hashes[m.from - 1] != null) return error.DuplicateMessage;
                hashes[m.from - 1] = m.msg.commitment_hash;
            }
            for (hashes) |h| if (h == null) return error.MissingMessage;

            const p2p = try allocator.alloc(To(Round2P2p), params.n - 1);
            errdefer allocator.free(p2p);
            var k: usize = 0;
            var j: u16 = 1;
            while (j <= params.n) : (j += 1) {
                if (j == params.party) continue;
                p2p[k] = .{ .to = j, .msg = .{ .share = try state.poly.share(j) } };
                k += 1;
            }

            const feldman_copy = try allocator.dupe(E.Point, state.feldman);
            errdefer allocator.free(feldman_copy);

            return .{
                .state = .{ .s1 = state, .hashes = hashes },
                .broadcast = .{
                    .rid = state.rid,
                    .chain_code = state.chain_code,
                    .feldman = feldman_copy,
                    .sch_commit = state.sch_commit,
                    .decommit_nonce = state.decommit_nonce,
                },
                .p2p = p2p,
            };
        }

        pub const State3 = struct {
            params: Params,
            eid: ExecutionId,
            secret_share: E.Scalar,
            agg_commitment: []E.Point,
            rid: [32]u8,
            chain_code: [32]u8,
            sch_commits: []E.Point, // R_j per party, indexed by party-1
            own_publics: []E.Point, // X_j = F_j[0] per party, indexed by party-1
            allocator: Allocator,

            pub fn deinit(self: *State3) void {
                self.secret_share.zeroize();
                self.allocator.free(self.agg_commitment);
                self.allocator.free(self.sch_commits);
                self.allocator.free(self.own_publics);
                self.* = undefined;
            }
        };

        pub const Round3Result = struct { state: State3, broadcast: Round3Broadcast };

        /// `incoming_bc` / `incoming_p2p` must each contain exactly one message
        /// from every other party. Consumes `state` (its resources move or are
        /// freed here).
        pub fn round3(
            state: State2,
            incoming_bc: []const From(Round2Broadcast),
            incoming_p2p: []const From(Round2P2p),
        ) !Round3Result {
            var st = state;
            const params = st.s1.params;
            try params.validate();
            const allocator = st.s1.allocator;

            if (incoming_bc.len != params.n - 1 or incoming_p2p.len != params.n - 1)
                return error.MissingMessage;

            const seen = try allocator.alloc(bool, params.n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[params.party - 1] = true;

            var rid = st.s1.rid;
            var chain_code = st.s1.chain_code;

            const sch_commits = try allocator.alloc(E.Point, params.n);
            errdefer allocator.free(sch_commits);
            const own_publics = try allocator.alloc(E.Point, params.n);
            errdefer allocator.free(own_publics);
            sch_commits[params.party - 1] = st.s1.sch_commit;
            own_publics[params.party - 1] = st.s1.feldman[0];

            // aggregate commitment starts as a copy of our own
            const agg = try allocator.dupe(E.Point, st.s1.feldman);
            errdefer allocator.free(agg);

            var secret_share = try st.s1.poly.share(params.party);

            for (incoming_bc) |m| {
                const j = m.from;
                if (j < 1 or j > params.n or j == params.party) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;

                if (m.msg.feldman.len != params.threshold) return error.InvalidCommitmentLength;

                // check decommitment against round-1 hash
                const expect_hash = st.hashes[j - 1].?;
                const actual = commitmentHash(st.s1.eid, j, m.msg.rid, m.msg.chain_code, m.msg.feldman, m.msg.sch_commit, m.msg.decommit_nonce);
                if (!std.crypto.timing_safe.eql([32]u8, expect_hash, actual))
                    return error.DecommitmentMismatch;

                // find the p2p share from j and verify against j's Feldman commitment
                var share_j: ?E.Scalar = null;
                for (incoming_p2p) |pm| {
                    if (pm.from == j) share_j = pm.msg.share;
                }
                const sigma = share_j orelse return error.MissingMessage;
                const com_j = vss.Commitment(E){ .points = m.msg.feldman, .allocator = allocator };
                if (!com_j.verifyShare(params.party, sigma)) return error.InvalidShare;

                for (&rid, m.msg.rid) |*a, b| a.* ^= b;
                for (&chain_code, m.msg.chain_code) |*a, b| a.* ^= b;
                for (agg, m.msg.feldman) |*a, b| a.* = a.add(b);
                secret_share = secret_share.add(sigma);
                sch_commits[j - 1] = m.msg.sch_commit;
                own_publics[j - 1] = m.msg.feldman[0];
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            // Schnorr PoK response, challenge bound to the joint rid
            const e = schnorrChallenge(st.s1.eid, rid, params.party, st.s1.feldman[0], st.s1.sch_commit);
            const z = st.s1.sch_nonce.add(e.mul(st.s1.poly.coeffs[0]));

            const eid = st.s1.eid;
            st.deinit();

            return .{
                .state = .{
                    .params = params,
                    .eid = eid,
                    .secret_share = secret_share,
                    .agg_commitment = agg,
                    .rid = rid,
                    .chain_code = chain_code,
                    .sch_commits = sch_commits,
                    .own_publics = own_publics,
                    .allocator = allocator,
                },
                .broadcast = .{ .sch_response = z },
            };
        }

        /// Verify every party's PoK and produce the final key share.
        /// Consumes `state`.
        pub fn finalize(state: State3, incoming: []const From(Round3Broadcast)) !KeyShare {
            var st = state;
            const params = st.params;
            try params.validate();
            const allocator = st.allocator;

            if (incoming.len != params.n - 1) return error.MissingMessage;

            const seen = try allocator.alloc(bool, params.n);
            defer allocator.free(seen);
            @memset(seen, false);
            seen[params.party - 1] = true;

            for (incoming) |m| {
                const j = m.from;
                if (j < 1 or j > params.n or j == params.party) return error.InvalidSender;
                if (seen[j - 1]) return error.DuplicateMessage;
                seen[j - 1] = true;

                const e = schnorrChallenge(st.eid, st.rid, j, st.own_publics[j - 1], st.sch_commits[j - 1]);
                // z*G == R_j + e*X_j
                const lhs = E.Point.mulBase(m.msg.sch_response) catch return error.InvalidSchnorrProof;
                const ex = st.own_publics[j - 1].mulPublic(e) catch return error.InvalidSchnorrProof;
                const rhs = st.sch_commits[j - 1].add(ex);
                if (!lhs.eql(rhs)) return error.InvalidSchnorrProof;
            }
            for (seen) |s| if (!s) return error.MissingMessage;

            // sanity: our aggregated share must be consistent with the
            // aggregated commitment
            const agg_com = vss.Commitment(E){ .points = st.agg_commitment, .allocator = allocator };
            if (!agg_com.verifyShare(params.party, st.secret_share)) return error.InconsistentShare;

            const share = KeyShare{
                .party = params.party,
                .threshold = params.threshold,
                .n = params.n,
                .secret_share = st.secret_share,
                .public_key = st.agg_commitment[0],
                .vss_commitment = st.agg_commitment,
                .rid = st.rid,
                .chain_code = st.chain_code,
                .allocator = allocator,
            };
            allocator.free(st.sch_commits);
            allocator.free(st.own_publics);
            return share;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests: full in-memory DKG execution + signing with the resulting shares
// ---------------------------------------------------------------------------

const curve = @import("curve.zig");
const frost = @import("frost.zig");

/// Run a complete n-party DKG in one process and return every party's key
/// share. Intended for tests and local simulation only - real deployments
/// must run each party on its own machine.
pub fn runDkgForTest(comptime E: type, allocator: Allocator, threshold: u16, n: u16, rng: std.Random) ![]Dkg(E).KeyShare {
    const D = Dkg(E);
    const eid = ExecutionId.random(rng);

    var r1 = try allocator.alloc(D.Round1Result, n);
    defer allocator.free(r1);
    for (0..n) |i| {
        r1[i] = try D.round1(allocator, .{ .party = @intCast(i + 1), .threshold = threshold, .n = n }, eid, rng);
    }

    var r2 = try allocator.alloc(D.Round2Result, n);
    defer allocator.free(r2);
    for (0..n) |i| {
        var incoming = std.array_list.Managed(D.From(D.Round1Broadcast)).init(allocator);
        defer incoming.deinit();
        for (0..n) |j| {
            if (j == i) continue;
            try incoming.append(.{ .from = @intCast(j + 1), .msg = r1[j].broadcast });
        }
        r2[i] = try D.round2(r1[i].state, incoming.items);
    }

    var r3 = try allocator.alloc(D.Round3Result, n);
    defer allocator.free(r3);
    for (0..n) |i| {
        var bc = std.array_list.Managed(D.From(D.Round2Broadcast)).init(allocator);
        defer bc.deinit();
        var p2p = std.array_list.Managed(D.From(D.Round2P2p)).init(allocator);
        defer p2p.deinit();
        for (0..n) |j| {
            if (j == i) continue;
            try bc.append(.{ .from = @intCast(j + 1), .msg = r2[j].broadcast });
            // find the share j sent to i
            for (r2[j].p2p) |pm| {
                if (pm.to == i + 1) try p2p.append(.{ .from = @intCast(j + 1), .msg = pm.msg });
            }
        }
        r3[i] = try D.round3(r2[i].state, bc.items, p2p.items);
    }
    for (0..n) |i| r2[i].deinitMessages(allocator);

    const shares = try allocator.alloc(D.KeyShare, n);
    errdefer allocator.free(shares);
    for (0..n) |i| {
        var incoming = std.array_list.Managed(D.From(D.Round3Broadcast)).init(allocator);
        defer incoming.deinit();
        for (0..n) |j| {
            if (j == i) continue;
            try incoming.append(.{ .from = @intCast(j + 1), .msg = r3[j].broadcast });
        }
        shares[i] = try D.finalize(r3[i].state, incoming.items);
    }
    return shares;
}

test "3-party 2-of-3 DKG then FROST signing (Ed25519 and secp256k1)" {
    var prng = std.Random.DefaultPrng.init(4242);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    inline for (.{ frost.Ed25519Sha512, frost.Secp256k1Sha256 }) |Suite| {
        const E = Suite.E;
        const shares = try runDkgForTest(E, allocator, 2, 3, rng);
        defer {
            for (shares) |*s| s.deinit();
            allocator.free(shares);
        }

        // all parties agree on the public key and rid
        try std.testing.expect(shares[0].public_key.eql(shares[1].public_key));
        try std.testing.expect(shares[1].public_key.eql(shares[2].public_key));
        try std.testing.expectEqualSlices(u8, &shares[0].rid, &shares[2].rid);

        // shares reconstruct a secret matching the public key
        const rec = try vss.reconstructAtZero(E, &.{ 1, 3 }, &.{ shares[0].secret_share, shares[2].secret_share });
        const rec_pk = try E.Point.mulBase(rec);
        try std.testing.expect(rec_pk.eql(shares[0].public_key));

        // sign with parties {1, 3} via FROST
        const F = frost.Frost(Suite);
        const msg = "dkg-then-frost";
        const c1 = try F.commit(1, shares[0].secret_share, rng);
        const c3 = try F.commit(3, shares[2].secret_share, rng);
        const commitment_list = [_]F.Commitment{ c1.commitment, c3.commitment };
        const z1 = try F.sign(1, shares[0].secret_share, shares[0].public_key, c1.nonces, msg, &commitment_list);
        const z3 = try F.sign(3, shares[2].secret_share, shares[2].public_key, c3.nonces, msg, &commitment_list);
        const sig = try F.aggregate(&commitment_list, msg, shares[0].public_key, &.{ z1, z3 });
        try std.testing.expect(F.verify(msg, shares[0].public_key, sig));

        // identifiable abort works with DKG-derived public shares
        const pk1 = try shares[1].publicShareOf(1);
        try std.testing.expect(try F.verifySigShare(1, pk1, z1, shares[0].public_key, msg, &commitment_list));
    }
}

test "key share validation catches shapes finalize can never produce" {
    const E = curve.Secp256k1;
    var prng = std.Random.DefaultPrng.init(31337);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    const shares = try runDkgForTest(E, allocator, 2, 3, rng);
    defer {
        for (shares) |*s| s.deinit();
        allocator.free(shares);
    }
    try shares[0].validate();

    // Everything below is reachable only by deserializing bytes from
    // elsewhere, which is exactly why the check exists.
    var empty = shares[0];
    empty.vss_commitment = &.{};
    try std.testing.expectError(error.InvalidCommitmentLength, empty.validate());

    var short = shares[0];
    short.vss_commitment = shares[0].vss_commitment[0..1];
    try std.testing.expectError(error.InvalidCommitmentLength, short.validate());

    var wrong_key = shares[0];
    wrong_key.public_key = E.Point.generator;
    try std.testing.expectError(error.InconsistentShare, wrong_key.validate());

    // A secret_share that no longer lies on the committed polynomial (a
    // bit-flip on disk, or a substituted value) must be caught even though
    // every public field is intact - otherwise the share silently produces
    // invalid signatures in every session.
    var tampered = shares[0];
    tampered.secret_share = shares[0].secret_share.add(E.Scalar.one);
    try std.testing.expectError(error.InconsistentShare, tampered.validate());

    var bad_party = shares[0];
    bad_party.party = 9;
    try std.testing.expectError(error.InvalidParams, bad_party.validate());

    var bad_threshold = shares[0];
    bad_threshold.threshold = 0;
    try std.testing.expectError(error.InvalidParams, bad_threshold.validate());

    // An empty commitment must not underflow the Horner loop either.
    const com = vss.Commitment(E){ .points = &.{}, .allocator = allocator };
    try std.testing.expectError(error.EmptyCommitment, com.evaluate(E.Scalar.one));
    try std.testing.expect(!com.verifyShare(1, E.Scalar.one));
}

test "DKG rejects tampered VSS share" {
    const E = curve.Secp256k1;
    const D = Dkg(E);
    var prng = std.Random.DefaultPrng.init(77);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const eid = ExecutionId.random(rng);
    const n: u16 = 3;

    var r1: [n]D.Round1Result = undefined;
    for (0..n) |i| {
        r1[i] = try D.round1(allocator, .{ .party = @intCast(i + 1), .threshold = 2, .n = n }, eid, rng);
    }
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
    defer for (0..n) |i| r2[i].deinitMessages(allocator);

    // party 1 receives a corrupted share from party 2
    var bc: [n - 1]D.From(D.Round2Broadcast) = undefined;
    var p2p: [n - 1]D.From(D.Round2P2p) = undefined;
    var k: usize = 0;
    for (1..n) |j| {
        bc[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
        var share: ?E.Scalar = null;
        for (r2[j].p2p) |pm| {
            if (pm.to == 1) share = pm.msg.share;
        }
        p2p[k] = .{ .from = @intCast(j + 1), .msg = .{ .share = share.? } };
        k += 1;
    }
    p2p[0].msg.share = p2p[0].msg.share.add(E.Scalar.one); // tamper

    try std.testing.expectError(error.InvalidShare, D.round3(r2[0].state, &bc, &p2p));
    // on error the state is not consumed; clean up all parties' states
    r2[0].state.deinit();
    r2[1].state.deinit();
    r2[2].state.deinit();
}
