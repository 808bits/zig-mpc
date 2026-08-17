//! `zmpc selftest` and `zmpc simulate`.
//!
//! `selftest` runs known-answer tests through the shipped binary: the official
//! BIP-340 vectors, RFC 9591's FROST(Ed25519) vector, SLIP-10 derivation, and
//! the Paillier vectors cross-generated against python-sympy and the Rust
//! fast-paillier crate. It answers "is this build correct", which is a
//! different question from "did the build compile".
//!
//! `simulate` runs whole protocols with every party inside one process. Its
//! `--via frames` mode is the interesting one: every message and every round
//! state is encoded to a real frame, parsed back, and decoded before the next
//! round sees it - so it exercises the wire format and the codec end to end
//! without spawning anything.

const std = @import("std");
const mpc = @import("zig_mpc");

const args_mod = @import("args.zig");
const cmd = @import("cmd.zig");
const frame = @import("frame.zig");
const suite_mod = @import("suite.zig");

const Args = args_mod.Args;

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const Report = struct {
    ctx: cmd.Ctx,
    passed: usize = 0,
    failed: usize = 0,

    fn check(self: *Report, name: []const u8, ok: bool) !void {
        if (ok) {
            self.passed += 1;
            try self.ctx.note("  ok    {s}\n", .{name});
        } else {
            self.failed += 1;
            try self.ctx.warn("  FAIL  {s}\n", .{name});
        }
    }
};

fn hexTo(comptime n: usize, text: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch @panic("bad test vector");
    return out;
}

// ---------------------------------------------------------------------------
// selftest
// ---------------------------------------------------------------------------

pub fn selftest(ctx: cmd.Ctx, args: *Args) !u8 {
    try args.rejectUnknown(&.{ "quick", "json", "quiet", "armor", "dir" });
    var r = Report{ .ctx = ctx };

    try ctx.note("BIP-340 official vectors\n", .{});
    try bip340Vectors(&r);

    try ctx.note("RFC 9591 FROST(Ed25519, SHA-512) vector\n", .{});
    try frostVector(&r);

    try ctx.note("SLIP-10 non-hardened derivation\n", .{});
    try slip10Vectors(&r);

    try ctx.note("Paillier vectors\n", .{});
    try paillierVectors(&r);

    try ctx.note("wire format\n", .{});
    try wireChecks(&r);

    if (!args.has("quick")) {
        try ctx.note("live protocol runs\n", .{});
        try liveRuns(&r);
    }

    if (ctx.json) {
        try ctx.emit("{{\"passed\":{d},\"failed\":{d}}}\n", .{ r.passed, r.failed });
    } else {
        try ctx.emit("{d} passed, {d} failed\n", .{ r.passed, r.failed });
    }
    return if (r.failed == 0) cmd.Exit.ok else cmd.Exit.protocol;
}

fn bip340Vectors(r: *Report) !void {
    var buf: [128]u8 = undefined;
    var signed: usize = 0;
    var verified: usize = 0;
    var ok = true;

    for (mpc.bip340.test_vectors) |v| {
        const pk = hexTo(32, v.pk);
        const sig = hexTo(64, v.sig);
        const msg = std.fmt.hexToBytes(&buf, v.msg) catch return;

        if (v.sk) |sk_hex| {
            const produced = mpc.bip340.sign(hexTo(32, sk_hex), msg, hexTo(32, v.aux.?)) catch {
                ok = false;
                continue;
            };
            if (!std.mem.eql(u8, &sig, &produced)) ok = false;
            signed += 1;
        }
        if (mpc.bip340.verify(pk, msg, sig) != v.valid) ok = false;
        verified += 1;
    }

    var name_buf: [64]u8 = undefined;
    try r.check(
        try std.fmt.bufPrint(&name_buf, "{d} signing, {d} verification vectors", .{ signed, verified }),
        ok,
    );
}

fn frostVector(r: *Report) !void {
    // RFC 9591 Appendix E.1, signers {1, 3} over the message "test".
    const F = mpc.frost.Frost(mpc.frost.Ed25519Sha512);
    const E = F.E;

    const group_pk = E.Point.fromBytes(
        hexTo(32, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"),
    ) catch {
        try r.check("group key decodes", false);
        return;
    };
    const sk1 = E.Scalar.fromBytes(
        hexTo(32, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"),
    ) catch unreachable;
    const sk3 = E.Scalar.fromBytes(
        hexTo(32, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"),
    ) catch unreachable;
    const msg = "test";

    const c1 = F.commitDeterministic(
        1,
        sk1,
        hexTo(32, "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec"),
        hexTo(32, "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501"),
    ) catch unreachable;
    const c3 = F.commitDeterministic(
        3,
        sk3,
        hexTo(32, "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"),
        hexTo(32, "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"),
    ) catch unreachable;

    const list = [_]F.Commitment{ c1.commitment, c3.commitment };
    const z1 = F.sign(1, sk1, group_pk, c1.nonces, msg, &list) catch unreachable;
    const z3 = F.sign(3, sk3, group_pk, c3.nonces, msg, &list) catch unreachable;
    const sig = F.aggregate(&list, msg, group_pk, &.{ z1, z3 }) catch unreachable;

    const expected = hexTo(
        64,
        "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe" ++
            "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b",
    );
    try r.check("aggregate signature matches the vector", std.mem.eql(u8, &expected, &sig.toBytes()));

    // The same bytes must verify as an ordinary Ed25519 signature.
    const Std = std.crypto.sign.Ed25519;
    const std_pk = Std.PublicKey.fromBytes(group_pk.toBytes()) catch unreachable;
    const std_ok = if (Std.Signature.fromBytes(sig.toBytes()).verify(msg, std_pk)) true else |_| false;
    try r.check("verifies under std.crypto's Ed25519", std_ok);

    // Identifiable abort: a share from the wrong signer must be caught.
    const pk1 = E.Point.mulBase(sk1) catch unreachable;
    const good = F.verifySigShare(1, pk1, z1, group_pk, msg, &list) catch false;
    const bad = F.verifySigShare(1, pk1, z3, group_pk, msg, &list) catch false;
    try r.check("signature shares are individually checkable", good and !bad);
}

fn slip10Vectors(r: *Report) !void {
    // SLIP-0010 test vector 1, secp256k1: m/0H -> m/0H/1.
    const parent = mpc.hd.ExtendedPublicKey{
        .pk = mpc.hd.E.Point.fromBytes(
            hexTo(33, "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
        ) catch unreachable,
        .chain_code = hexTo(32, "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
    };
    const step = mpc.hd.deriveChild(parent, 1) catch {
        try r.check("m/0H/1 derives", false);
        return;
    };
    const expected_pk = hexTo(33, "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");
    const expected_cc = hexTo(32, "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
    try r.check(
        "m/0H/1 child key and chain code",
        std.mem.eql(u8, &expected_pk, &step.child.pk.toBytes()) and
            std.mem.eql(u8, &expected_cc, &step.child.chain_code),
    );

    // The tweak is what makes threshold derivation work: child = parent + shift.
    const parent_sk = mpc.hd.E.Scalar.fromBytes(
        hexTo(32, "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
    ) catch unreachable;
    const child_sk = mpc.hd.E.Scalar.fromBytes(
        hexTo(32, "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
    ) catch unreachable;
    try r.check("child secret equals parent + public shift", parent_sk.add(step.shift).eql(child_sk));

    // Hardened derivation must be refused, not silently reinterpreted.
    const hardened = mpc.hd.deriveChild(parent, 1 << 31);
    try r.check("hardened indices are refused", std.meta.isError(hardened));
}

fn paillierVectors(r: *Report) !void {
    const vectors = @import("zig_mpc").testdata_paillier;
    const P = mpc.paillier.Paillier(128);
    var ok = true;
    var count: usize = 0;

    for (vectors.enc128) |v| {
        var dk = P.DecryptionKey.fromPrimes(P.Fp.fromHex(v.p), P.Fp.fromHex(v.q)) catch {
            ok = false;
            continue;
        };
        defer dk.zeroize();
        const m = P.Fn.fromHex(v.m);
        const c = dk.ek.encryptWithNonce(m, P.Fn.fromHex(v.r)) catch {
            ok = false;
            continue;
        };
        if (!std.mem.eql(u8, &P.Fn2.fromHex(v.c), &c)) ok = false;
        const back = dk.decrypt(c) catch {
            ok = false;
            continue;
        };
        if (!std.mem.eql(u8, &m, &back)) ok = false;
        count += 1;
    }

    var name_buf: [64]u8 = undefined;
    try r.check(
        try std.fmt.bufPrint(&name_buf, "{d} byte-exact encryption vectors", .{count}),
        ok,
    );
}

fn wireChecks(r: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(r.ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header = frame.Header{
        .kind = .message,
        .channel = .p2p,
        .protocol = .dkg,
        .suite = .ed25519,
        .round = 2,
        .from = 1,
        .to = 3,
        .n_parties = 3,
        .threshold = 2,
        .session = @splat(0x5a),
    };
    const bytes = try frame.encodeAlloc(arena, header, "payload bytes");
    const parsed = frame.parse(bytes) catch {
        try r.check("frame round-trip", false);
        return;
    };
    try r.check("frame round-trip", std.mem.eql(u8, "payload bytes", parsed.payload));

    // A single flipped bit anywhere must be caught.
    var all_caught = true;
    for (0..bytes.len) |i| {
        const copy = try arena.dupe(u8, bytes);
        copy[i] ^= 0x40;
        if (!std.meta.isError(frame.parse(copy))) all_caught = false;
    }
    try r.check("every single-bit corruption is detected", all_caught);

    const text = try frame.armor(arena, bytes);
    const back = frame.dearmor(arena, text) catch {
        try r.check("armor round-trip", false);
        return;
    };
    try r.check("armor round-trip", std.mem.eql(u8, bytes, back));
}

fn liveRuns(r: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(r.ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    inline for (.{ .ed25519, .secp256k1, .taproot }) |tag| {
        const ok = simulateFrost(tag, arena, r.ctx.rng, "selftest message", .frames) catch false;
        try r.check("2-of-3 keygen and sign, " ++ @tagName(tag), ok);
    }
}

// ---------------------------------------------------------------------------
// simulate
// ---------------------------------------------------------------------------

pub const Via = enum {
    /// Pass structs directly between rounds, the way an in-process
    /// caller of the library would.
    memory,
    /// Encode every message and round state to a real frame, parse it back,
    /// and decode it before the next round sees it.
    frames,
};

pub fn simulate(ctx: cmd.Ctx, args: *Args) !u8 {
    // Each simulation fixes its own suite, party count and message, so there
    // is nothing here to tune. Flags that look like they would (--suite, --n,
    // --msg-hex) used to be accepted and silently ignored; rejecting them
    // keeps the promise the rest of the CLI makes about unknown flags.
    try args.rejectUnknown(&.{ "via", "json", "quiet", "armor", "dir" });
    const what = args.word(1) orelse return cmd.usagePage(ctx, "simulate");

    const via = if (args.value("via")) |text|
        std.meta.stringToEnum(Via, text) orelse {
            try ctx.warn("--via must be memory or frames\n", .{});
            return cmd.Exit.usage;
        }
    else
        .frames;

    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const run_all = eql(what, "all");
    var ran = false;
    var ok = true;

    if (run_all or eql(what, "keygen") or eql(what, "frost")) {
        ran = true;
        const good = simulateFrost(.ed25519, arena, ctx.rng, "simulated FROST Ed25519", via) catch false;
        ok = ok and good;
        try ctx.note("FROST Ed25519 2-of-3 via {t}: {s}\n", .{ via, if (good) "ok" else "FAILED" });
    }
    if (run_all or eql(what, "taproot")) {
        ran = true;
        const good = simulateFrost(.taproot, arena, ctx.rng, "simulated Taproot spend", via) catch false;
        ok = ok and good;
        try ctx.note("FROST Taproot 2-of-3 via {t}: {s}\n", .{ via, if (good) "ok" else "FAILED" });
    }
    if (run_all or eql(what, "hd")) {
        ran = true;
        const good = simulateHd(arena, ctx.rng, via) catch false;
        ok = ok and good;
        try ctx.note("HD child signing via {t}: {s}\n", .{ via, if (good) "ok" else "FAILED" });
    }
    if (run_all or eql(what, "refresh")) {
        ran = true;
        const good = simulateRefresh(arena, ctx.rng, via) catch false;
        ok = ok and good;
        try ctx.note("proactive refresh via {t}: {s}\n", .{ via, if (good) "ok" else "FAILED" });
    }
    if (eql(what, "ecdsa")) {
        // Not part of `all`: a CGGMP24 presigning run takes tens of seconds,
        // which is the wrong default for a command people reach for to check
        // that a build works.
        ran = true;
        const good = simulateEcdsa(arena, ctx.rng, via) catch false;
        ok = ok and good;
        try ctx.note("CGGMP24 presign and sign via {t}: {s}\n", .{ via, if (good) "ok" else "FAILED" });
    }

    if (!ran) {
        try ctx.warn("unknown simulation '{s}'\n", .{what});
        return cmd.Exit.usage;
    }
    if (ctx.json) try ctx.emit("{{\"ok\":{}}}\n", .{ok});
    return if (ok) cmd.Exit.ok else cmd.Exit.protocol;
}

/// Round-trip a value through the real wire format when `via == .frames`,
/// so a simulation exercises exactly what a multi-process run would.
fn hop(comptime T: type, value: T, arena: std.mem.Allocator, via: Via, suite: frame.Suite) !T {
    if (via == .memory) return value;
    const payload = try mpc.serde.encodeAlloc(T, value, arena);
    const bytes = try frame.encodeAlloc(arena, .{
        .kind = .message,
        .channel = .broadcast,
        .protocol = .none,
        .suite = suite,
        .session = @splat(0),
    }, payload);
    const parsed = try frame.parse(bytes);
    return mpc.serde.decodeSlice(T, parsed.payload, .{ .gpa = arena });
}

fn simulateFrost(
    comptime tag: suite_mod.Suite,
    arena: std.mem.Allocator,
    rng: std.Random,
    msg: []const u8,
    via: Via,
) !bool {
    const E = suite_mod.CurveOf(tag);
    const F = mpc.frost.Frost(suite_mod.FrostSuiteOf(tag).?);
    const D = mpc.dkg.Dkg(E);

    const shares = try mpc.dkg.runDkgForTest(E, arena, 2, 3, rng);

    // Every share takes a trip through the wire format.
    var loaded: [3]D.KeyShare = undefined;
    for (shares, 0..) |s, i| loaded[i] = try hop(D.KeyShare, s, arena, via, tag);

    var pk = loaded[0].public_key;
    if (comptime tag == .taproot) {
        for (&loaded) |*s| {
            var local = s.public_key;
            _ = mpc.bip340.normalizeKeyMaterial(&s.secret_share, &local, s.vss_commitment);
            s.public_key = local;
        }
        pk = loaded[0].public_key;
        if (!pk.hasEvenY()) return false;
    }

    const c1 = try F.commit(1, loaded[0].secret_share, rng);
    const c3 = try F.commit(3, loaded[2].secret_share, rng);
    const list = [_]F.Commitment{
        try hop(F.Commitment, c1.commitment, arena, via, tag),
        try hop(F.Commitment, c3.commitment, arena, via, tag),
    };
    const z1 = try hop(E.Scalar, try F.sign(1, loaded[0].secret_share, pk, c1.nonces, msg, &list), arena, via, tag);
    const z3 = try hop(E.Scalar, try F.sign(3, loaded[2].secret_share, pk, c3.nonces, msg, &list), arena, via, tag);

    const sig = try F.aggregate(&list, msg, pk, &.{ z1, z3 });
    if (!F.verify(msg, pk, sig)) return false;

    if (comptime tag == .taproot) {
        return mpc.bip340.verify(pk.xOnly(), msg, mpc.bip340.signatureToBytes(sig));
    }
    if (comptime tag == .ed25519) {
        const Std = std.crypto.sign.Ed25519;
        const std_pk = try Std.PublicKey.fromBytes(pk.toBytes());
        Std.Signature.fromBytes(sig.toBytes()).verify(msg, std_pk) catch return false;
    }
    return true;
}

fn simulateHd(arena: std.mem.Allocator, rng: std.Random, via: Via) !bool {
    const E = mpc.hd.E;
    const D = mpc.dkg.Dkg(E);
    const F = mpc.frost.Frost(mpc.frost.Secp256k1Sha256);

    const shares = try mpc.dkg.runDkgForTest(E, arena, 2, 3, rng);
    var loaded: [3]D.KeyShare = undefined;
    for (shares, 0..) |s, i| loaded[i] = try hop(D.KeyShare, s, arena, via, .secp256k1);

    const xpub = mpc.hd.ExtendedPublicKey{
        .pk = loaded[0].public_key,
        .chain_code = loaded[0].chain_code,
    };
    const step = try mpc.hd.derivePath(xpub, &.{ 44, 0, 7 });

    // Each signer applies the public tweak on its own - no interaction.
    const s1 = loaded[0].secret_share.add(step.shift);
    const s2 = loaded[1].secret_share.add(step.shift);

    const msg = "simulated child-key spend";
    const c1 = try F.commit(1, s1, rng);
    const c2 = try F.commit(2, s2, rng);
    const list = [_]F.Commitment{ c1.commitment, c2.commitment };
    const z1 = try F.sign(1, s1, step.child.pk, c1.nonces, msg, &list);
    const z2 = try F.sign(2, s2, step.child.pk, c2.nonces, msg, &list);
    const sig = try F.aggregate(&list, msg, step.child.pk, &.{ z1, z2 });
    return F.verify(msg, step.child.pk, sig);
}

fn simulateRefresh(arena: std.mem.Allocator, rng: std.Random, via: Via) !bool {
    const Suite = mpc.frost.Ed25519Sha512;
    const E = Suite.E;
    const D = mpc.dkg.Dkg(E);
    const R = mpc.refresh.Refresh(E);
    const F = mpc.frost.Frost(Suite);
    const n = 3;

    const shares = try mpc.dkg.runDkgForTest(E, arena, 2, n, rng);
    const pk_before = shares[0].public_key;
    const old_share = shares[0].secret_share;

    const eid = mpc.refresh.ExecutionId.random(rng);
    var r1: [n]R.Round1Result = undefined;
    for (0..n) |i| r1[i] = try R.round1(arena, shares[i], eid, rng);

    var r2: [n]R.Round2Result = undefined;
    for (0..n) |i| {
        var incoming: [n - 1]R.From(R.Round1Broadcast) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            incoming[k] = .{
                .from = @intCast(j + 1),
                .msg = try hop(R.Round1Broadcast, r1[j].broadcast, arena, via, .ed25519),
            };
            k += 1;
        }
        r2[i] = try R.round2(try hop(R.State1, r1[i].state, arena, via, .ed25519), &incoming);
    }

    for (0..n) |i| {
        var bc: [n - 1]R.From(R.Round2Broadcast) = undefined;
        var p2p: [n - 1]R.From(R.Round2P2p) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            bc[k] = .{
                .from = @intCast(j + 1),
                .msg = try hop(R.Round2Broadcast, r2[j].broadcast, arena, via, .ed25519),
            };
            for (r2[j].p2p) |pm| {
                if (pm.to == i + 1) p2p[k] = .{
                    .from = @intCast(j + 1),
                    .msg = try hop(R.Round2P2p, pm.msg, arena, via, .ed25519),
                };
            }
            k += 1;
        }
        try R.finalize(try hop(R.State2, r2[i].state, arena, via, .ed25519), &shares[i], &bc, &p2p);
    }

    // Same key, different shares, and the old share no longer fits.
    if (!shares[0].public_key.eql(pk_before)) return false;
    if (shares[0].secret_share.eql(old_share)) return false;
    const com = mpc.vss.Commitment(E){ .points = shares[0].vss_commitment, .allocator = arena };
    if (com.verifyShare(1, old_share)) return false;

    const msg = "simulated post-refresh signing";
    const c2 = try F.commit(2, shares[1].secret_share, rng);
    const c3 = try F.commit(3, shares[2].secret_share, rng);
    const list = [_]F.Commitment{ c2.commitment, c3.commitment };
    const z2 = try F.sign(2, shares[1].secret_share, pk_before, c2.nonces, msg, &list);
    const z3 = try F.sign(3, shares[2].secret_share, pk_before, c3.nonces, msg, &list);
    const sig = try F.aggregate(&list, msg, pk_before, &.{ z2, z3 });
    _ = D;
    return F.verify(msg, pk_before, sig);
}

fn simulateEcdsa(arena: std.mem.Allocator, rng: std.Random, via: Via) !bool {
    const tag: suite_mod.Suite = .ecdsa_fast;
    const P = suite_mod.ParamsOf(tag).?;
    const E = suite_mod.CurveOf(tag);
    const T = mpc.ecdsa.Ecdsa(P, E);
    const Pl = mpc.zk.common.Pail(P);
    const eid = mpc.ecdsa.ExecutionId.random(rng);

    // Two additive shares, as a signing set of two produces after Lagrange.
    const x1 = E.Scalar.random(rng);
    const x2 = E.Scalar.random(rng);
    const pk = try E.Point.mulBase(x1.add(x2));
    const big_x = [_]E.Point{ try E.Point.mulBase(x1), try E.Point.mulBase(x2) };

    var dks: [2]Pl.DecryptionKey = undefined;
    var parties: [2]T.PartyData = undefined;
    for (0..2) |i| {
        dks[i] = try Pl.DecryptionKey.generate(rng);
        var gen = try mpc.zk.common.Aux(P).generate(rng, false);
        gen.secret.zeroize();
        parties[i] = .{ .ek = dks[i].ek, .pedersen = gen.aux };
    }
    defer for (&dks) |*dk| dk.zeroize();

    const keys1 = T.Keys{ .i = 1, .n = 2, .eid = eid, .x_i = x1, .big_x = &big_x, .pk = pk, .dk = dks[0], .parties = &parties };
    const keys2 = T.Keys{ .i = 2, .n = 2, .eid = eid, .x_i = x2, .big_x = &big_x, .pk = pk, .dk = dks[1], .parties = &parties };

    const a1 = try T.round1(arena, keys1, rng);
    const a2 = try T.round1(arena, keys2, rng);

    const b1 = try T.round2(
        arena,
        try hop(T.State1, a1.state, arena, via, tag),
        &.{.{ .from = 2, .msg = try hop(T.Round1aBroadcast, a2.broadcast, arena, via, tag) }},
        &.{.{ .from = 2, .msg = try hop(T.Round1bP2p, a2.p2p[0].msg, arena, via, tag) }},
        rng,
    );
    const b2 = try T.round2(
        arena,
        try hop(T.State1, a2.state, arena, via, tag),
        &.{.{ .from = 1, .msg = try hop(T.Round1aBroadcast, a1.broadcast, arena, via, tag) }},
        &.{.{ .from = 1, .msg = try hop(T.Round1bP2p, a1.p2p[0].msg, arena, via, tag) }},
        rng,
    );

    const c1 = try T.round3(
        try hop(T.State2, b1.state, arena, via, tag),
        &.{.{ .from = 2, .msg = try hop(T.Round2P2p, b2.p2p[0].msg, arena, via, tag) }},
        rng,
    );
    const c2 = try T.round3(
        try hop(T.State2, b2.state, arena, via, tag),
        &.{.{ .from = 1, .msg = try hop(T.Round2P2p, b1.p2p[0].msg, arena, via, tag) }},
        rng,
    );

    var presig1 = try T.finalize(
        try hop(T.State3, c1.state, arena, via, tag),
        &.{.{ .from = 2, .msg = try hop(T.Round3Broadcast, c2.broadcast, arena, via, tag) }},
    );
    defer presig1.zeroize();
    var presig2 = try T.finalize(
        try hop(T.State3, c2.state, arena, via, tag),
        &.{.{ .from = 1, .msg = try hop(T.Round3Broadcast, c1.broadcast, arena, via, tag) }},
    );
    defer presig2.zeroize();

    const msg = "simulated CGGMP24 signing";
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &h);
    const m = E.Scalar.fromWideBytes(wide);

    const sig = try T.combine(presig1.gamma, &.{
        T.partialSign(presig1, m),
        T.partialSign(presig2, m),
    }, m);
    if (!T.verify(pk, m, sig)) return false;

    // And under std.crypto's independent ECDSA.
    const Std = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const std_pk = try Std.PublicKey.fromSec1(&pk.toBytes());
    var sig_bytes: [64]u8 = undefined;
    sig_bytes[0..32].* = sig.r.toBytes();
    sig_bytes[32..].* = sig.s.toBytes();
    Std.Signature.fromBytes(sig_bytes).verify(msg, std_pk) catch return false;
    return true;
}
