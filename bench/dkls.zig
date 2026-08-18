//! DKLs23 benchmark: `zig build bench` (add `-Dsecp=std` to compare the
//! std.crypto backend against libsecp256k1).
//!
//! 3-party DKG, 3-party pairwise setup, then repeated
//! 2-of-3 signings, every party driven sequentially in one process. The
//! same ceremony shape as the Rust reference benchmarks, so the numbers
//! compare.

const std = @import("std");
const mpc = @import("zig_mpc");

const E = mpc.curve.Secp256k1;
const D = mpc.dkg.Dkg(E);
const Setup = mpc.dkls.setup.Setup(E);
const S = mpc.dkls.sign.Signer(E);

const n: u16 = 3;
const threshold: u16 = 2;
const sign_iters = 10;
const backend_name = blk: {
    const b = @import("secp_backend");
    if (b.use_libsecp) break :blk "libsecp";
    if (b.use_glv) break :blk "glv";
    break :blk "std";
};

fn ms(nanos: u64) f64 {
    return @as(f64, @floatFromInt(nanos)) / 1e6;
}

/// std.time.Timer left std in 0.16; a monotonic clock read is all this needs.
const Timer = struct {
    base: u64,
    fn nowNs() u64 {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
    }
    fn start() Timer {
        return .{ .base = nowNs() };
    }
    fn reset(self: *Timer) void {
        self.base = nowNs();
    }
    fn read(self: *Timer) u64 {
        return nowNs() - self.base;
    }
};

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    var prng = std.Random.DefaultCsprng.init(@splat(0x42));
    const rng = prng.random();

    var timer = Timer.start();

    // ---------------- DKG ----------------
    timer.reset();
    const eid = mpc.dkg.ExecutionId.random(rng);
    var r1: [n]D.Round1Result = undefined;
    for (0..n) |i| r1[i] = try D.round1(gpa, .{ .party = @intCast(i + 1), .threshold = threshold, .n = n }, eid, rng);
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
    const dkg_ns = timer.read();

    // ---------------- pairwise setup ----------------
    timer.reset();
    var out1: [n]Setup.Out1 = undefined;
    for (0..n) |i| {
        out1[i] = try Setup.round1(gpa, .{ .party = @intCast(i + 1), .n = n, .threshold = threshold }, eid.bytes, rng);
    }
    var out2: [n]Setup.Out2 = undefined;
    for (0..n) |i| out2[i] = try Setup.round2(gpa, out1[i].state);

    // Position of party `to` within party `from`'s ascending counterparty list.
    const slot = struct {
        fn f(from: u16, to: u16) usize {
            var k: usize = 0;
            var j: u16 = 1;
            while (j <= n) : (j += 1) {
                if (j == from) continue;
                if (j == to) return k;
                k += 1;
            }
            unreachable;
        }
    }.f;

    var parties: [n]mpc.dkls.sign.Party(E) = undefined;
    for (0..n) |i| {
        const me: u16 = @intCast(i + 1);
        var from: [n - 1]u16 = undefined;
        var m1: [n - 1]mpc.dkls.setup.Round1(E) = undefined;
        var m2: [n - 1]mpc.dkls.setup.Round2(E) = undefined;
        var k: usize = 0;
        for (0..n) |j| {
            if (j == i) continue;
            const peer: u16 = @intCast(j + 1);
            from[k] = peer;
            m1[k] = out1[j].messages[slot(peer, me)];
            m2[k] = out2[j].messages[slot(peer, me)];
            k += 1;
        }
        parties[i] = try Setup.finalize(
            gpa,
            .{ .party = me, .n = n, .threshold = threshold },
            eid.bytes,
            shares[i].chain_code,
            shares[i].secret_share,
            shares[i].public_key,
            out1[i].state,
            &from,
            &m1,
            &m2,
        );
    }
    const setup_ns = timer.read();

    // ---------------- signing, 2-of-3, repeated ----------------
    const quorum = [_]u16{ 1, 2 };
    var msg_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("benchmark message", &msg_hash, .{});

    var sign_total: u64 = 0;
    var sign_min: u64 = std.math.maxInt(u64);
    for (0..sign_iters) |iter| {
        var sign_id: [32]u8 = @splat(@intCast(iter + 1));
        const data = mpc.dkls.sign.SignData{ .sign_id = sign_id, .quorum = &quorum, .message_hash = msg_hash };
        sign_id = @splat(0);

        timer.reset();
        var o1: [2]S.Out1 = undefined;
        for (quorum, 0..) |p, a| o1[a] = try S.phase1(gpa, parties[p - 1], data, rng);

        var o2: [2]S.Out2 = undefined;
        for (quorum, 0..) |p, a| {
            const other: u16 = if (p == 1) 2 else 1;
            const b: usize = if (a == 0) 1 else 0;
            o2[a] = try S.phase2(gpa, parties[p - 1], data, &o1[a].state, &.{other}, &.{o1[b].messages[0]}, rng);
        }
        for (&o1) |*o| o.deinit(gpa);

        var o3: [2]S.Out3 = undefined;
        for (quorum, 0..) |p, a| {
            const other: u16 = if (p == 1) 2 else 1;
            const b: usize = if (a == 0) 1 else 0;
            o3[a] = try S.phase3(gpa, parties[p - 1], data, &o2[a].state, &.{other}, &.{o2[b].messages[0]});
        }
        for (&o2) |*o| o.deinit(gpa);

        const bcast = [_]mpc.dkls.sign.Round3(E){ o3[0].broadcast, o3[1].broadcast };
        const sig0 = try S.phase4(parties[0], data, o3[0], &bcast);
        const sig1 = try S.phase4(parties[1], data, o3[1], &bcast);
        const elapsed = timer.read();

        if (!sig0.r.eql(sig1.r) or !sig0.s.eql(sig1.s)) return error.SignatureMismatch;
        sign_total += elapsed;
        sign_min = @min(sign_min, elapsed);
    }

    var buf: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf,
        \\{{"impl":"zig-mpc {s}","dkg_ms":{d:.1},"setup_ms":{d:.1},"sign_mean_ms":{d:.1},"sign_min_ms":{d:.1},"sign_iters":{d}}}
        \\
    , .{ backend_name, ms(dkg_ns), ms(setup_ns), ms(sign_total / sign_iters), ms(sign_min), sign_iters });
    std.debug.print("{s}", .{line});
}
