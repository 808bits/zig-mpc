//! `zmpc bip340 | paillier | vss | ffx | transcript` - the primitive layer.
//!
//! Everything the library can do that is not itself a multi-party protocol:
//! single-signer BIP-340, the Paillier cryptosystem with its homomorphisms,
//! Shamir/Feldman secret sharing, the big-integer routines the ZK proofs are
//! built on, and the transcript hash. Useful for scripting, for cross-checking
//! another implementation, and for understanding what the protocols are made
//! of.
//!
//! Values are hex on the way in and on the way out, so these compose with
//! ordinary shell tools.

const std = @import("std");
const mpc = @import("zig_mpc");

const args_mod = @import("args.zig");
const cmd = @import("cmd.zig");
const suite_mod = @import("suite.zig");

const Args = args_mod.Args;

/// One width for every big-integer command. Wide enough for a 4096-bit RSA-ish
/// modulus, which is more than any parameter set here needs.
const Big = mpc.ffx.Ffx(4096);

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Parse a hex string into a fixed-width big-endian big integer.
fn parseBig(ctx: cmd.Ctx, text: []const u8, what: []const u8) !Big.Bytes {
    if (text.len == 0 or text.len > Big.num_bytes * 2) {
        try ctx.warn("{s} must be 1..{d} hex characters\n", .{ what, Big.num_bytes * 2 });
        return error.Reported;
    }
    var out: Big.Bytes = @splat(0);
    // Right-align: hex is a big-endian integer, not a fixed-width buffer.
    var buf: [Big.num_bytes]u8 = undefined;
    const padded_len = (text.len + 1) / 2;
    var padded: [Big.num_bytes * 2]u8 = undefined;
    const pad = text.len % 2;
    if (pad == 1) padded[0] = '0';
    @memcpy(padded[pad..][0..text.len], text);
    const decoded = std.fmt.hexToBytes(buf[0..padded_len], padded[0 .. text.len + pad]) catch {
        try ctx.warn("{s} is not valid hex\n", .{what});
        return error.Reported;
    };
    @memcpy(out[Big.num_bytes - decoded.len ..], decoded);
    return out;
}

/// Print a big integer without its leading zero bytes.
fn printBig(ctx: cmd.Ctx, value: Big.Bytes) !u8 {
    var start: usize = 0;
    while (start < value.len - 1 and value[start] == 0) start += 1;
    try ctx.emit("{x}\n", .{value[start..]});
    return cmd.Exit.ok;
}

// ---------------------------------------------------------------------------
// bip340
// ---------------------------------------------------------------------------

pub fn bip340(ctx: cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse {
        try ctx.warn("usage: zmpc bip340 <pubkey|sign|verify> [options]\n", .{});
        return cmd.Exit.usage;
    };
    try args.rejectUnknown(&.{
        "sk", "pubkey", "msg-file", "msg-hex", "aux", "sig", "json", "quiet", "armor", "dir",
    });

    const E = mpc.bip340.E;

    if (eql(action, "pubkey")) {
        var sk: [32]u8 = undefined;
        cmd.hexExact(&sk, try args.require("sk")) catch {
            try ctx.warn("--sk must be 32 bytes of hex\n", .{});
            return cmd.Exit.usage;
        };
        const d = E.Scalar.fromBytes(sk) catch {
            try ctx.warn("--sk is not a valid secret key\n", .{});
            return cmd.Exit.bad_input;
        };
        const pk = E.Point.mulBase(d) catch {
            try ctx.warn("--sk is zero\n", .{});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&pk.xOnly()});
        return cmd.Exit.ok;
    }

    const msg = cmd.readMessage(ctx, args.value("msg-file"), args.value("msg-hex")) catch {
        try ctx.warn("give the message with --msg-file or --msg-hex\n", .{});
        return cmd.Exit.bad_input;
    };

    if (eql(action, "sign")) {
        var sk: [32]u8 = undefined;
        cmd.hexExact(&sk, try args.require("sk")) catch {
            try ctx.warn("--sk must be 32 bytes of hex\n", .{});
            return cmd.Exit.usage;
        };
        // BIP-340 mixes auxiliary randomness into the nonce; fresh randomness
        // is the recommended default, and a fixed value makes signing
        // deterministic for test vectors.
        var aux: [32]u8 = undefined;
        if (args.value("aux")) |text| {
            cmd.hexExact(&aux, text) catch {
                try ctx.warn("--aux must be 32 bytes of hex\n", .{});
                return cmd.Exit.usage;
            };
        } else {
            ctx.rng.bytes(&aux);
        }
        const sig = mpc.bip340.sign(sk, msg, aux) catch |e| {
            try ctx.warn("cannot sign: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&sig});
        return cmd.Exit.ok;
    }

    if (eql(action, "verify")) {
        var pk: [32]u8 = undefined;
        cmd.hexExact(&pk, try args.require("pubkey")) catch {
            try ctx.warn("--pubkey must be 32 bytes of hex (x-only)\n", .{});
            return cmd.Exit.usage;
        };
        const sig_text = try args.require("sig");
        var sig: [64]u8 = undefined;
        if (cmd.hexExact(&sig, sig_text)) |_| {} else |_| {
            const bytes = cmd.readFileBytes(ctx, sig_text) catch {
                try ctx.warn("--sig is neither 64 bytes of hex nor a readable file\n", .{});
                return cmd.Exit.bad_input;
            };
            if (bytes.len != 64) {
                try ctx.warn("a BIP-340 signature is 64 bytes; got {d}\n", .{bytes.len});
                return cmd.Exit.bad_input;
            }
            @memcpy(&sig, bytes);
        }
        if (!mpc.bip340.verify(pk, msg, sig)) {
            try ctx.warn("signature is INVALID\n", .{});
            return cmd.Exit.protocol;
        }
        try ctx.note("signature is valid\n", .{});
        if (ctx.json) try ctx.emit("{{\"valid\":true}}\n", .{});
        return cmd.Exit.ok;
    }

    try ctx.warn("unknown bip340 action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// paillier
// ---------------------------------------------------------------------------

/// Supported Paillier prime sizes. The modulus is twice the prime size.
const paillier_sizes = [_]comptime_int{ 128, 256, 512, 1024 };

pub fn paillier(ctx: cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc paillier <keygen|encrypt|decrypt|add|mul|addplain> [options]\n" ++
                "       moduli are 2x the prime size; --bits is the prime size\n",
            .{},
        );
        return cmd.Exit.usage;
    };
    try args.rejectUnknown(&.{
        "bits", "key",  "n",     "m",     "r",   "c", "c2", "k",
        "out",  "json", "quiet", "armor", "dir", "p", "q",
    });

    const bits = (try args.int(u16, "bits")) orelse 512;
    inline for (paillier_sizes) |size| {
        if (bits == size) return paillierFor(size, ctx, args, action);
    }
    try ctx.warn("--bits must be one of 128, 256, 512, 1024 (prime size)\n", .{});
    return cmd.Exit.usage;
}

fn paillierFor(comptime prime_bits: comptime_int, ctx: cmd.Ctx, args: *Args, action: []const u8) !u8 {
    const Pl = mpc.paillier.Paillier(prime_bits);

    // Values live in three widths: primes, mod N, and mod N².
    const parseIn = struct {
        fn go(comptime F: type, c: cmd.Ctx, text: []const u8, what: []const u8) !F.Bytes {
            const wide = try parseBig(c, text, what);
            return Big.narrow(F, wide) catch {
                try c.warn("{s} does not fit in {d} bits\n", .{ what, F.bits });
                return error.Reported;
            };
        }
    }.go;

    if (eql(action, "keygen")) {
        var dk = try Pl.DecryptionKey.generate(ctx.rng);
        defer dk.zeroize();
        const text = try std.fmt.allocPrint(ctx.gpa,
            \\# zmpc paillier key, {d}-bit primes ({d}-bit modulus)
            \\n: {x}
            \\p: {x}
            \\q: {x}
            \\
        , .{ prime_bits, 2 * prime_bits, &dk.ek.n, &dk.p, &dk.q });

        if (args.value("out")) |path| {
            try std.Io.Dir.cwd().writeFile(ctx.io, .{
                .sub_path = path,
                .data = text,
                .flags = .{ .permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
                    .fromMode(0o600)
                else
                    .default_file },
            });
            try ctx.note("key written to {s}\n", .{path});
            try ctx.emit("{x}\n", .{&dk.ek.n});
        } else {
            try ctx.emit("{s}", .{text});
        }
        return cmd.Exit.ok;
    }

    // Everything else needs at least the modulus.
    const KeyParts = struct { n: Pl.Fn.Bytes, p: ?Pl.Fp.Bytes = null, q: ?Pl.Fp.Bytes = null };
    const key: KeyParts = blk: {
        if (args.value("key")) |path| {
            const text = cmd.readFileBytes(ctx, path) catch {
                try ctx.warn("cannot read key file '{s}'\n", .{path});
                return cmd.Exit.bad_input;
            };
            var parts = KeyParts{ .n = @splat(0) };
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \r\t");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;
                const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
                const name = std.mem.trim(u8, trimmed[0..colon], " ");
                const value = std.mem.trim(u8, trimmed[colon + 1 ..], " ");
                if (eql(name, "n")) parts.n = try parseIn(Pl.Fn, ctx, value, "n");
                if (eql(name, "p")) parts.p = try parseIn(Pl.Fp, ctx, value, "p");
                if (eql(name, "q")) parts.q = try parseIn(Pl.Fp, ctx, value, "q");
            }
            break :blk parts;
        }
        break :blk .{ .n = try parseIn(Pl.Fn, ctx, try args.require("n"), "n") };
    };

    const ek = Pl.EncryptionKey.fromN(key.n) catch {
        try ctx.warn("n is not a usable Paillier modulus\n", .{});
        return cmd.Exit.bad_input;
    };

    if (eql(action, "encrypt")) {
        const m = try parseIn(Pl.Fn, ctx, try args.require("m"), "--m");
        const c = if (args.value("r")) |r_text| c: {
            // A caller-supplied nonce makes encryption reproducible, which is
            // what test vectors need. Never do this with real plaintexts.
            const r = try parseIn(Pl.Fn, ctx, r_text, "--r");
            break :c ek.encryptWithNonce(m, r) catch |e| {
                try ctx.warn("cannot encrypt: {t}\n", .{e});
                return cmd.Exit.bad_input;
            };
        } else c: {
            const enc = ek.encrypt(m, ctx.rng) catch |e| {
                try ctx.warn("cannot encrypt: {t}\n", .{e});
                return cmd.Exit.bad_input;
            };
            break :c enc.c;
        };
        try ctx.emit("{x}\n", .{&c});
        return cmd.Exit.ok;
    }

    if (eql(action, "decrypt")) {
        const p = key.p orelse {
            try ctx.warn("decryption needs the private key: pass --key with p and q\n", .{});
            return cmd.Exit.usage;
        };
        const q = key.q orelse {
            try ctx.warn("decryption needs the private key: pass --key with p and q\n", .{});
            return cmd.Exit.usage;
        };
        var dk = Pl.DecryptionKey.fromPrimes(p, q) catch {
            try ctx.warn("p and q do not form a usable key\n", .{});
            return cmd.Exit.bad_input;
        };
        defer dk.zeroize();
        const c = try parseIn(Pl.Fn2, ctx, try args.require("c"), "--c");
        const m = dk.decrypt(c) catch |e| {
            try ctx.warn("cannot decrypt: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&m});
        return cmd.Exit.ok;
    }

    if (eql(action, "add")) {
        // Enc(a) ⊕ Enc(b) = Enc(a + b): the additive homomorphism.
        const c1 = try parseIn(Pl.Fn2, ctx, try args.require("c"), "--c");
        const c2 = try parseIn(Pl.Fn2, ctx, try args.require("c2"), "--c2");
        try ctx.emit("{x}\n", .{&ek.homAdd(c1, c2)});
        return cmd.Exit.ok;
    }

    if (eql(action, "mul")) {
        // Enc(m)^k = Enc(k·m).
        const c = try parseIn(Pl.Fn2, ctx, try args.require("c"), "--c");
        const k = try parseIn(Pl.Fn, ctx, try args.require("k"), "--k");
        const out = ek.homMulScalar(c, &k) catch |e| {
            try ctx.warn("cannot multiply: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&out});
        return cmd.Exit.ok;
    }

    if (eql(action, "addplain")) {
        // Enc(m) · (1 + kN) = Enc(m + k).
        const c = try parseIn(Pl.Fn2, ctx, try args.require("c"), "--c");
        const k = try parseIn(Pl.Fn, ctx, try args.require("k"), "--k");
        const out = ek.homAddPlaintext(c, k) catch |e| {
            try ctx.warn("cannot add: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&out});
        return cmd.Exit.ok;
    }

    try ctx.warn("unknown paillier action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// vss
// ---------------------------------------------------------------------------

pub fn vss(ctx: cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc vss <split|reconstruct|verify> --curve C [options]\n",
            .{},
        );
        return cmd.Exit.usage;
    };
    try args.rejectUnknown(&.{
        "curve", "secret", "t",     "n",   "shares", "commitment", "index", "share",
        "json",  "quiet",  "armor", "dir",
    });

    const curve_name = args.valueOr("curve", "secp256k1");
    const st = suite_mod.parse(curve_name) orelse {
        try ctx.warn("unknown curve '{s}'; choose one of: {s}\n", .{ curve_name, suite_mod.names });
        return cmd.Exit.usage;
    };
    return switch (st) {
        inline else => |tag| vssFor(suite_mod.CurveOf(tag), ctx, args, action),
    };
}

fn parseScalar(comptime E: type, ctx: cmd.Ctx, text: []const u8, what: []const u8) !E.Scalar {
    var buf: [E.Scalar.encoded_length]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&buf, text) catch {
        try ctx.warn("{s} must be {d} bytes of hex\n", .{ what, E.Scalar.encoded_length });
        return error.Reported;
    };
    if (decoded.len != E.Scalar.encoded_length) {
        try ctx.warn("{s} must be {d} bytes of hex\n", .{ what, E.Scalar.encoded_length });
        return error.Reported;
    }
    return E.Scalar.fromBytes(buf) catch {
        try ctx.warn("{s} is not a canonical scalar for this curve\n", .{what});
        return error.Reported;
    };
}

fn vssFor(comptime E: type, ctx: cmd.Ctx, args: *Args, action: []const u8) !u8 {
    if (eql(action, "split")) {
        const t = try args.intRequired(u16, "t");
        const n = try args.intRequired(u16, "n");
        if (t < 1 or n < t) {
            try ctx.warn("need 1 <= t <= n\n", .{});
            return cmd.Exit.usage;
        }
        const secret = if (args.value("secret")) |text|
            try parseScalar(E, ctx, text, "--secret")
        else
            E.Scalar.random(ctx.rng);

        var poly = mpc.vss.Polynomial(E).initRandom(ctx.gpa, secret, t, ctx.rng) catch |e| {
            try ctx.warn("cannot split: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        defer poly.deinit();
        var com = try poly.commit(ctx.gpa);
        defer com.deinit();

        try ctx.note("{d}-of-{d} sharing; keep each share with its index\n", .{ t, n });
        try ctx.emit("public_key {x}\n", .{&com.publicKey().toBytes()});
        for (com.points) |p| try ctx.emit("commitment {x}\n", .{&p.toBytes()});
        var i: u16 = 1;
        while (i <= n) : (i += 1) {
            try ctx.emit("share {d} {x}\n", .{ i, &(try poly.share(i)).toBytes() });
        }
        return cmd.Exit.ok;
    }

    if (eql(action, "reconstruct")) {
        // --shares 1:<hex>,3:<hex>
        const text = try args.require("shares");
        var indices: std.ArrayList(u16) = .empty;
        var values: std.ArrayList(E.Scalar) = .empty;
        var it = std.mem.splitScalar(u8, text, ',');
        while (it.next()) |piece| {
            const trimmed = std.mem.trim(u8, piece, " ");
            if (trimmed.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse {
                try ctx.warn("--shares entries look like `index:hex`\n", .{});
                return cmd.Exit.usage;
            };
            const index = std.fmt.parseInt(u16, trimmed[0..colon], 10) catch {
                try ctx.warn("bad share index in '{s}'\n", .{trimmed});
                return cmd.Exit.usage;
            };
            try indices.append(ctx.gpa, index);
            try values.append(ctx.gpa, try parseScalar(E, ctx, trimmed[colon + 1 ..], "--shares"));
        }
        if (indices.items.len == 0) {
            try ctx.warn("--shares is empty\n", .{});
            return cmd.Exit.usage;
        }

        const secret = mpc.vss.reconstructAtZero(E, indices.items, values.items) catch |e| {
            try ctx.warn("cannot reconstruct: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("{x}\n", .{&secret.toBytes()});
        return cmd.Exit.ok;
    }

    if (eql(action, "verify")) {
        const index = try args.intRequired(u16, "index");
        const share = try parseScalar(E, ctx, try args.require("share"), "--share");

        var points: std.ArrayList(E.Point) = .empty;
        var it = std.mem.splitScalar(u8, try args.require("commitment"), ',');
        while (it.next()) |piece| {
            const trimmed = std.mem.trim(u8, piece, " ");
            if (trimmed.len == 0) continue;
            var buf: [E.Point.encoded_length]u8 = undefined;
            const decoded = std.fmt.hexToBytes(&buf, trimmed) catch {
                try ctx.warn("--commitment entries must be {d} bytes of hex\n", .{E.Point.encoded_length});
                return cmd.Exit.usage;
            };
            if (decoded.len != E.Point.encoded_length) {
                try ctx.warn("--commitment entries must be {d} bytes of hex\n", .{E.Point.encoded_length});
                return cmd.Exit.usage;
            }
            const point = E.Point.fromBytes(buf) catch {
                try ctx.warn("--commitment contains a point not on the curve\n", .{});
                return cmd.Exit.bad_input;
            };
            try points.append(ctx.gpa, point);
        }

        const com = mpc.vss.Commitment(E){ .points = points.items, .allocator = ctx.gpa };
        if (!com.verifyShare(index, share)) {
            try ctx.warn("share {d} is INCONSISTENT with the commitment\n", .{index});
            return cmd.Exit.protocol;
        }
        try ctx.note("share {d} is consistent with the commitment\n", .{index});
        if (ctx.json) try ctx.emit("{{\"valid\":true}}\n", .{});
        return cmd.Exit.ok;
    }

    try ctx.warn("unknown vss action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// ffx - the big-integer layer the ZK proofs are built on
// ---------------------------------------------------------------------------

pub fn ffx(ctx: cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse {
        try ctx.warn(
            "usage: zmpc ffx <prime|isprime|jacobi|gcd|inverse|sqrt|divrem> [options]\n",
            .{},
        );
        return cmd.Exit.usage;
    };
    try args.rejectUnknown(&.{
        "bits", "blum", "safe", "a", "b", "n", "m", "json", "quiet", "armor", "dir",
    });

    if (eql(action, "prime")) {
        const bits = (try args.int(u16, "bits")) orelse 256;
        if (bits < 16 or bits > Big.bits) {
            try ctx.warn("--bits must be between 16 and {d}\n", .{Big.bits});
            return cmd.Exit.usage;
        }
        if (args.has("safe")) {
            // p = 2q + 1 with q prime. Much slower, and what ring-Pedersen
            // setup wants.
            try ctx.note("generating a safe prime; this can take a while\n", .{});
            const p = Big.generateSafePrime(ctx.rng, bits) catch |e| {
                try ctx.warn("cannot generate: {t}\n", .{e});
                return cmd.Exit.internal;
            };
            return printBig(ctx, p);
        }
        // `blum` means p ≡ 3 (mod 4), which Paillier-Blum moduli require.
        const p = Big.generatePrime(ctx.rng, bits, args.has("blum")) catch |e| {
            try ctx.warn("cannot generate: {t}\n", .{e});
            return cmd.Exit.internal;
        };
        return printBig(ctx, p);
    }

    if (eql(action, "isprime")) {
        const n = try parseBig(ctx, try args.require("n"), "--n");
        const prime = Big.isProbablePrime(n, ctx.rng) catch |e| {
            try ctx.warn("cannot test: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        if (ctx.json) {
            try ctx.emit("{{\"probably_prime\":{}}}\n", .{prime});
        } else {
            try ctx.emit("{s}\n", .{if (prime) "probably prime" else "composite"});
        }
        return if (prime) cmd.Exit.ok else cmd.Exit.protocol;
    }

    if (eql(action, "jacobi")) {
        const a = try parseBig(ctx, try args.require("a"), "--a");
        const n = try parseBig(ctx, try args.require("n"), "--n");
        try ctx.emit("{d}\n", .{Big.jacobi(a, n)});
        return cmd.Exit.ok;
    }

    if (eql(action, "gcd")) {
        const a = try parseBig(ctx, try args.require("a"), "--a");
        const b = try parseBig(ctx, try args.require("b"), "--b");
        return printBig(ctx, Big.gcd(a, b));
    }

    if (eql(action, "inverse")) {
        const a = try parseBig(ctx, try args.require("a"), "--a");
        const m = try parseBig(ctx, try args.require("m"), "--m");
        const inv = Big.invertGeneral(a, m) catch |e| {
            try ctx.warn("no inverse: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        return printBig(ctx, inv);
    }

    if (eql(action, "sqrt")) {
        const a = try parseBig(ctx, try args.require("a"), "--a");
        return printBig(ctx, Big.sqrtFloor(a));
    }

    if (eql(action, "divrem")) {
        const a = try parseBig(ctx, try args.require("a"), "--a");
        const b = try parseBig(ctx, try args.require("b"), "--b");
        const result = Big.divRem(a, b) catch |e| {
            try ctx.warn("cannot divide: {t}\n", .{e});
            return cmd.Exit.bad_input;
        };
        try ctx.emit("quotient ", .{});
        _ = try printBig(ctx, result.q);
        try ctx.emit("remainder ", .{});
        return printBig(ctx, result.r);
    }

    try ctx.warn("unknown ffx action '{s}'\n", .{action});
    return cmd.Exit.usage;
}

// ---------------------------------------------------------------------------
// transcript
// ---------------------------------------------------------------------------

pub fn transcript(ctx: cmd.Ctx, args: *Args) !u8 {
    const action = args.word(1) orelse "hash";
    if (!eql(action, "hash")) {
        try ctx.warn("usage: zmpc transcript hash --domain D [--append label=hex ...]\n", .{});
        return cmd.Exit.usage;
    }
    try args.rejectUnknown(&.{ "domain", "append", "u64", "bytes", "json", "quiet", "armor", "dir" });

    // The domain is a compile-time constant in the library (it is a domain
    // separation tag, not data), so the CLI offers the generic one and mixes
    // the caller's tag in as the first labelled field.
    var t = mpc.transcript.Transcript.init("zig-mpc/cli/transcript/v1");
    t.appendBytes("domain", args.valueOr("domain", ""));

    // Repeated --append label=hex, in order.
    for (args.flags) |f| {
        if (!eql(f.name, "append") and !eql(f.name, "bytes")) continue;
        const text = f.value orelse continue;
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse {
            try ctx.warn("--append looks like label=hex\n", .{});
            return cmd.Exit.usage;
        };
        const label = text[0..eq];
        const hex_text = text[eq + 1 ..];
        const data = try ctx.gpa.alloc(u8, hex_text.len / 2);
        _ = std.fmt.hexToBytes(data, hex_text) catch {
            try ctx.warn("--append value for '{s}' is not hex\n", .{label});
            return cmd.Exit.usage;
        };
        t.appendBytes(label, data);
    }
    for (args.flags) |f| {
        if (!eql(f.name, "u64")) continue;
        const text = f.value orelse continue;
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse {
            try ctx.warn("--u64 looks like label=number\n", .{});
            return cmd.Exit.usage;
        };
        const value = std.fmt.parseInt(u64, text[eq + 1 ..], 10) catch {
            try ctx.warn("--u64 value is not a number\n", .{});
            return cmd.Exit.usage;
        };
        t.appendU64(text[0..eq], value);
    }

    var rng = t.challengeRng();
    var out: [32]u8 = undefined;
    rng.fill(&out);
    try ctx.emit("{x}\n", .{&out});
    return cmd.Exit.ok;
}
