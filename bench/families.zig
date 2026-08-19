//! Signature-family benchmark: `zig build bench-families`.
//!
//! One machine, one harness, three signature schemes: FROST signing over
//! Ed25519 / secp256k1 / Taproot (2 signers of 3), and CGGMP24 threshold
//! ECDSA at the ecdsa_fast parameter set (2 parties: Paillier prime
//! generation, aux-info ceremony, presigning, signing). Together with
//! `bench-dkls` (DKLs23) this is the data behind the cross-scheme
//! comparison: what Schnorr-shaped signatures cost versus what ECDSA costs.

const std = @import("std");
const mpc = @import("zig_mpc");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn ms(nanos: u64) f64 {
    return @as(f64, @floatFromInt(nanos)) / 1e6;
}

/// Deal 2-of-3 Shamir shares for parties 1 and 3, group key f(0)*G.
/// For Taproot the secret is resampled until the group key has even Y.
fn Deal(comptime E: type) type {
    return struct {
        sk1: E.Scalar,
        sk3: E.Scalar,
        pk: E.Point,

        fn init(rng: std.Random, comptime even_y: bool) !@This() {
            while (true) {
                const a0 = E.Scalar.random(rng);
                const a1 = E.Scalar.random(rng);
                if (a0.isZero() or a1.isZero()) continue;
                const pk = try E.Point.mulBase(a0);
                if (even_y and !pk.hasEvenY()) continue;
                return .{
                    .sk1 = a0.add(a1.mul(E.Scalar.fromU64(1))),
                    .sk3 = a0.add(a1.mul(E.Scalar.fromU64(3))),
                    .pk = pk,
                };
            }
        }
    };
}

/// Full FROST signing: both signers commit, sign, aggregate, verify.
fn frostBench(comptime Suite: type, comptime even_y: bool, rng: std.Random, iters: usize) !f64 {
    const F = mpc.frost.Frost(Suite);
    const E = F.E;
    const deal = try Deal(E).init(rng, even_y);
    const msg = "family benchmark message";

    var total: u64 = 0;
    for (0..iters) |_| {
        const t0 = nowNs();
        const r1 = try F.commit(1, deal.sk1, rng);
        const r3 = try F.commit(3, deal.sk3, rng);
        const list = [_]F.Commitment{ r1.commitment, r3.commitment };
        const z1 = try F.sign(1, deal.sk1, deal.pk, r1.nonces, msg, &list);
        const z3 = try F.sign(3, deal.sk3, deal.pk, r3.nonces, msg, &list);
        const sig = try F.aggregate(&list, msg, deal.pk, &.{ z1, z3 });
        if (!F.verify(msg, deal.pk, sig)) return error.BadSignature;
        total += nowNs() - t0;
    }
    return ms(total / iters);
}

/// Real 3-party DKG, timed.
fn dkgBench(comptime E: type, gpa: std.mem.Allocator, rng: std.Random, iters: usize) !f64 {
    const D = mpc.dkg.Dkg(E);
    var total: u64 = 0;
    for (0..iters) |_| {
        const t0 = nowNs();
        const eid = mpc.dkg.ExecutionId.random(rng);
        var r1: [3]D.Round1Result = undefined;
        for (0..3) |i| r1[i] = try D.round1(gpa, .{ .party = @intCast(i + 1), .threshold = 2, .n = 3 }, eid, rng);
        var r2: [3]D.Round2Result = undefined;
        for (0..3) |i| {
            var incoming: [2]D.From(D.Round1Broadcast) = undefined;
            var k: usize = 0;
            for (0..3) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = r1[j].broadcast };
                k += 1;
            }
            r2[i] = try D.round2(r1[i].state, &incoming);
        }
        var r3: [3]D.Round3Result = undefined;
        for (0..3) |i| {
            var bcs: [2]D.From(D.Round2Broadcast) = undefined;
            var p2p: [2]D.From(D.Round2P2p) = undefined;
            var k: usize = 0;
            for (0..3) |j| {
                if (j == i) continue;
                bcs[k] = .{ .from = @intCast(j + 1), .msg = r2[j].broadcast };
                for (r2[j].p2p) |pm| {
                    if (pm.to == i + 1) p2p[k] = .{ .from = @intCast(j + 1), .msg = pm.msg };
                }
                k += 1;
            }
            r3[i] = try D.round3(r2[i].state, &bcs, &p2p);
        }
        var shares: [3]D.KeyShare = undefined;
        for (0..3) |i| {
            var incoming: [2]D.From(D.Round3Broadcast) = undefined;
            var k: usize = 0;
            for (0..3) |j| {
                if (j == i) continue;
                incoming[k] = .{ .from = @intCast(j + 1), .msg = r3[j].broadcast };
                k += 1;
            }
            shares[i] = try D.finalize(r3[i].state, &incoming);
        }
        total += nowNs() - t0;
        for (&shares) |*sh| sh.deinit();
    }
    return ms(total / iters);
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(0x77));
    const rng = prng.random();

    const dkg_ed = try dkgBench(mpc.curve.Ed25519, gpa, rng, 10);
    const dkg_k1 = try dkgBench(mpc.curve.Secp256k1, gpa, rng, 10);

    // ---------------- FROST across the three suites ----------------
    const frost_iters = 50;
    const ed = try frostBench(mpc.frost.Ed25519Sha512, false, rng, frost_iters);
    const k1 = try frostBench(mpc.frost.Secp256k1Sha256, false, rng, frost_iters);
    const tap = try frostBench(mpc.bip340.FrostTaprootSuite, true, rng, frost_iters);

    // ---------------- CGGMP24 at the ecdsa_fast parameter set ----------------
    // Same shapes as the CLI's ecdsa_fast suite: Params(576, 256, 512, 384),
    // 16 proof repetitions, non-safe primes. Two parties with additive
    // shares - the signing-time work is what scales, and both this and the
    // FROST/DKLs runs sign with exactly two participants.
    const P = mpc.zk.common.Params(576, 256, 512, 384);
    const A = mpc.auxgen.AuxGen(P, 16);
    const E = mpc.curve.Secp256k1;
    const T = mpc.ecdsa.Ecdsa(P, E);
    const Pl = mpc.zk.common.Pail(P);

    var t0 = nowNs();
    var primes1 = try A.Primes.generate(rng, false);
    var primes2 = try A.Primes.generate(rng, false);
    const primes_ms = ms((nowNs() - t0) / 2);
    defer primes1.zeroize();
    defer primes2.zeroize();

    t0 = nowNs();
    const eid = mpc.auxgen.ExecutionId.random(rng);
    const a1 = try A.round1(1, 2, eid, primes1, rng);
    const a2 = try A.round1(2, 2, eid, primes2, rng);
    const b1 = try A.round2(gpa, a1.state, &.{.{ .from = 2, .msg = a2.broadcast }});
    const b2 = try A.round2(gpa, a2.state, &.{.{ .from = 1, .msg = a1.broadcast }});
    const c1 = try A.round3(b1.state, rng, &.{.{ .from = 2, .msg = b2.broadcast }});
    const c2 = try A.round3(b2.state, rng, &.{.{ .from = 1, .msg = b1.broadcast }});
    const info1 = try A.finalize(c1.state, rng, &.{.{ .from = 2, .msg = c2.p2p[0].msg }});
    const info2 = try A.finalize(c2.state, rng, &.{.{ .from = 1, .msg = c1.p2p[0].msg }});
    const auxgen_ms = ms(nowNs() - t0);
    _ = info1;
    _ = info2;

    // Presigning keys: additive shares, Paillier keys from the primes above.
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
    const keys1 = T.Keys{ .i = 1, .n = 2, .eid = mpc.ecdsa.ExecutionId.random(rng), .x_i = x1, .big_x = &big_x, .pk = pk, .dk = dks[0], .parties = &parties };
    var keys2 = keys1;
    keys2.i = 2;
    keys2.x_i = x2;
    keys2.dk = dks[1];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const presign_iters = 3;
    var presign_total: u64 = 0;
    var sign_total: u64 = 0;
    for (0..presign_iters) |_| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();

        t0 = nowNs();
        const r1_1 = try T.round1(arena, keys1, rng);
        const r1_2 = try T.round1(arena, keys2, rng);
        const r2_1 = try T.round2(arena, r1_1.state, &.{.{ .from = 2, .msg = r1_2.broadcast }}, &.{.{ .from = 2, .msg = r1_2.p2p[0].msg }}, rng);
        const r2_2 = try T.round2(arena, r1_2.state, &.{.{ .from = 1, .msg = r1_1.broadcast }}, &.{.{ .from = 1, .msg = r1_1.p2p[0].msg }}, rng);
        const r3_1 = try T.round3(r2_1.state, &.{.{ .from = 2, .msg = r2_2.p2p[0].msg }}, rng);
        const r3_2 = try T.round3(r2_2.state, &.{.{ .from = 1, .msg = r2_1.p2p[0].msg }}, rng);
        var presig1 = try T.finalize(r3_1.state, &.{.{ .from = 2, .msg = r3_2.broadcast }});
        var presig2 = try T.finalize(r3_2.state, &.{.{ .from = 1, .msg = r3_1.broadcast }});
        presign_total += nowNs() - t0;

        t0 = nowNs();
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("family benchmark message", &h, .{});
        var wide: [64]u8 = @splat(0);
        @memcpy(wide[32..], &h);
        const m = E.Scalar.fromWideBytes(wide);
        const s1 = T.partialSign(presig1, m);
        const s2 = T.partialSign(presig2, m);
        const sig = try T.combine(presig1.gamma, &.{ s1, s2 }, m);
        if (!T.verify(pk, m, sig)) return error.BadSignature;
        sign_total += nowNs() - t0;
        presig1.zeroize();
        presig2.zeroize();
    }

    std.debug.print(
        "{{\"impl\":\"zig-mpc families\",\"dkg_ed25519_ms\":{d:.1},\"dkg_secp256k1_ms\":{d:.1},\"frost_ed25519_sign_ms\":{d:.2},\"frost_secp256k1_sign_ms\":{d:.2},\"frost_taproot_sign_ms\":{d:.2}," ++
            "\"cggmp_fast_primes_per_party_ms\":{d:.0},\"cggmp_fast_auxgen_ms\":{d:.0},\"cggmp_fast_presign_ms\":{d:.0},\"cggmp_fast_sign_ms\":{d:.2}}}\n",
        .{ dkg_ed, dkg_k1, ed, k1, tap, primes_ms, auxgen_ms, ms(presign_total / presign_iters), ms(sign_total / presign_iters) },
    );
}
