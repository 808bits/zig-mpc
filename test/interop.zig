//! Cross-implementation tests against bitcoin-core/libsecp256k1, compiled
//! from source as a package dependency (see build.zig.zon). These complement
//! the stdlib cross-checks inside src/: the same signatures are checked
//! against a second, independent implementation.
//!
//! Covered, in both directions where it makes sense:
//!
//!   * ECDSA: a full 2-party CGGMP24 presign + sign, verified by
//!     libsecp256k1; libsecp256k1 signatures verified by our ECDSA verify.
//!   * BIP-340 Schnorr: byte-identical signatures on the official vectors
//!     (both implementations use the deterministic BIP-340 nonce), plus
//!     random-key round trips and FROST-Taproot threshold signatures
//!     verified by libsecp256k1.
//!   * Compressed SEC1 public key encoding.
//!
//! Not covered: FROST(secp256k1, SHA-256) per RFC 9591. Its challenge hash
//! differs from BIP-340, so libsecp256k1 has no verifier for it; those
//! signatures are covered by the RFC test vectors in src/frost.zig instead.

const std = @import("std");
const mpc = @import("zig_mpc");
const testing = std.testing;

const E = mpc.curve.Secp256k1;

// ---------------------------------------------------------------------------
// libsecp256k1 bindings (the small slice of the API these tests need)
// ---------------------------------------------------------------------------

const c = struct {
    const Context = opaque {};

    // SECP256K1_FLAGS_TYPE_CONTEXT; signing and verification both work with
    // the static context since libsecp256k1 0.2.
    const CONTEXT_NONE: c_uint = 1;
    // SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION
    const EC_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

    const Pubkey = extern struct { data: [64]u8 };
    const Signature = extern struct { data: [64]u8 };
    const XonlyPubkey = extern struct { data: [64]u8 };
    const Keypair = extern struct { data: [96]u8 };

    extern fn secp256k1_context_create(flags: c_uint) *Context;
    extern fn secp256k1_context_destroy(ctx: *Context) void;

    extern fn secp256k1_ec_pubkey_create(ctx: *const Context, pubkey: *Pubkey, seckey: *const [32]u8) c_int;
    extern fn secp256k1_ec_pubkey_parse(ctx: *const Context, pubkey: *Pubkey, input: [*]const u8, inputlen: usize) c_int;
    extern fn secp256k1_ec_pubkey_serialize(ctx: *const Context, output: [*]u8, outputlen: *usize, pubkey: *const Pubkey, flags: c_uint) c_int;

    extern fn secp256k1_ecdsa_signature_parse_compact(ctx: *const Context, sig: *Signature, input64: *const [64]u8) c_int;
    extern fn secp256k1_ecdsa_signature_serialize_compact(ctx: *const Context, output64: *[64]u8, sig: *const Signature) c_int;
    extern fn secp256k1_ecdsa_sign(ctx: *const Context, sig: *Signature, msghash32: *const [32]u8, seckey: *const [32]u8, noncefp: ?*const anyopaque, ndata: ?*const anyopaque) c_int;
    extern fn secp256k1_ecdsa_verify(ctx: *const Context, sig: *const Signature, msghash32: *const [32]u8, pubkey: *const Pubkey) c_int;

    extern fn secp256k1_keypair_create(ctx: *const Context, keypair: *Keypair, seckey: *const [32]u8) c_int;
    extern fn secp256k1_keypair_xonly_pub(ctx: *const Context, xonly: *XonlyPubkey, pk_parity: ?*c_int, keypair: *const Keypair) c_int;
    extern fn secp256k1_xonly_pubkey_parse(ctx: *const Context, xonly: *XonlyPubkey, input32: *const [32]u8) c_int;
    extern fn secp256k1_xonly_pubkey_serialize(ctx: *const Context, output32: *[32]u8, xonly: *const XonlyPubkey) c_int;
    extern fn secp256k1_schnorrsig_sign32(ctx: *const Context, sig64: *[64]u8, msg32: *const [32]u8, keypair: *const Keypair, aux_rand32: ?*const [32]u8) c_int;
    extern fn secp256k1_schnorrsig_verify(ctx: *const Context, sig64: *const [64]u8, msg: [*]const u8, msglen: usize, xonly: *const XonlyPubkey) c_int;
};

fn scalarFromDigest(digest: [32]u8) E.Scalar {
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &digest);
    return E.Scalar.fromWideBytes(wide);
}

fn hex(comptime max: usize, text: []const u8, out: *[max]u8) []const u8 {
    return std.fmt.hexToBytes(out, text) catch unreachable;
}

// ---------------------------------------------------------------------------
// Public key encoding
// ---------------------------------------------------------------------------

test "compressed SEC1 public keys match libsecp256k1" {
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);
    var prng = std.Random.DefaultPrng.init(101);
    const rng = prng.random();

    for (0..16) |_| {
        const sk = E.Scalar.random(rng);
        const ours = (try E.Point.mulBase(sk)).toBytes();

        var pk: c.Pubkey = undefined;
        try testing.expect(c.secp256k1_ec_pubkey_create(ctx, &pk, &sk.toBytes()) == 1);
        var theirs: [33]u8 = undefined;
        var len: usize = theirs.len;
        try testing.expect(c.secp256k1_ec_pubkey_serialize(ctx, &theirs, &len, &pk, c.EC_COMPRESSED) == 1);
        try testing.expectEqual(@as(usize, 33), len);
        try testing.expectEqualSlices(u8, &theirs, &ours);

        // and our encoding parses on their side
        var parsed: c.Pubkey = undefined;
        try testing.expect(c.secp256k1_ec_pubkey_parse(ctx, &parsed, &ours, ours.len) == 1);
    }
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

test "libsecp256k1 ECDSA signatures verify under our ECDSA verify" {
    // Any parameter set works: verification never touches Paillier.
    const T = mpc.ecdsa.Ecdsa(mpc.zk.common.Params(320, 256, 512, 384), E);
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);
    var prng = std.Random.DefaultPrng.init(202);
    const rng = prng.random();

    for (0..16) |_| {
        const sk = E.Scalar.random(rng);
        const pk = try E.Point.mulBase(sk);
        var digest: [32]u8 = undefined;
        rng.bytes(&digest);

        var their_sig: c.Signature = undefined;
        try testing.expect(c.secp256k1_ecdsa_sign(ctx, &their_sig, &digest, &sk.toBytes(), null, null) == 1);
        var compact: [64]u8 = undefined;
        try testing.expect(c.secp256k1_ecdsa_signature_serialize_compact(ctx, &compact, &their_sig) == 1);

        const sig = T.Signature{
            .r = try E.Scalar.fromBytes(compact[0..32].*),
            .s = try E.Scalar.fromBytes(compact[32..].*),
        };
        const m = scalarFromDigest(digest);
        try testing.expect(T.verify(pk, m, sig));
        try testing.expect(!T.verify(pk, m.add(E.Scalar.one), sig));
    }
}

test "2-party CGGMP24 signature verifies under libsecp256k1" {
    // Same protocol run as src/ecdsa.zig's end-to-end test (same small test
    // parameters; the CLI presets are exercised by `zmpc selftest`), but the
    // combined signature is handed to libsecp256k1 instead. That checks the
    // whole contract at once: compact (r, s) encoding, compressed public key
    // encoding, and low-s normalization, which secp256k1_ecdsa_verify
    // requires.
    const common = mpc.zk.common;
    const P = common.Params(320, 256, 512, 384);
    const T = mpc.ecdsa.Ecdsa(P, E);
    const Pl = common.Pail(P);
    var prng = std.Random.DefaultPrng.init(777002);
    const rng = prng.random();
    const allocator = testing.allocator;
    const n: u16 = 2;
    const eid = mpc.ecdsa.ExecutionId.random(rng);

    // trusted-dealer key setup, as in the src/ecdsa.zig test
    const x1 = E.Scalar.random(rng);
    const x2 = E.Scalar.random(rng);
    const pk = try E.Point.mulBase(x1.add(x2));
    const big_x = [_]E.Point{ try E.Point.mulBase(x1), try E.Point.mulBase(x2) };

    var dks: [n]Pl.DecryptionKey = undefined;
    var parties: [n]T.PartyData = undefined;
    for (0..n) |i| {
        dks[i] = try Pl.DecryptionKey.generate(rng);
        var gen = try common.Aux(P).generate(rng, false);
        gen.secret.zeroize();
        parties[i] = .{ .ek = dks[i].ek, .pedersen = gen.aux };
    }
    defer for (&dks) |*dk| dk.zeroize();

    const keys1 = T.Keys{ .i = 1, .n = n, .eid = eid, .x_i = x1, .big_x = &big_x, .pk = pk, .dk = dks[0], .parties = &parties };
    const keys2 = T.Keys{ .i = 2, .n = n, .eid = eid, .x_i = x2, .big_x = &big_x, .pk = pk, .dk = dks[1], .parties = &parties };

    const r1_1 = try T.round1(allocator, keys1, rng);
    defer allocator.free(r1_1.p2p);
    const r1_2 = try T.round1(allocator, keys2, rng);
    defer allocator.free(r1_2.p2p);

    const r2_1 = try T.round2(allocator, r1_1.state, &.{.{ .from = 2, .msg = r1_2.broadcast }}, &.{.{ .from = 2, .msg = r1_2.p2p[0].msg }}, rng);
    defer allocator.free(r2_1.p2p);
    const r2_2 = try T.round2(allocator, r1_2.state, &.{.{ .from = 1, .msg = r1_1.broadcast }}, &.{.{ .from = 1, .msg = r1_1.p2p[0].msg }}, rng);
    defer allocator.free(r2_2.p2p);

    const r3_1 = try T.round3(r2_1.state, &.{.{ .from = 2, .msg = r2_2.p2p[0].msg }}, rng);
    const r3_2 = try T.round3(r2_2.state, &.{.{ .from = 1, .msg = r2_1.p2p[0].msg }}, rng);

    var presig1 = try T.finalize(r3_1.state, &.{.{ .from = 2, .msg = r3_2.broadcast }});
    defer presig1.zeroize();
    var presig2 = try T.finalize(r3_2.state, &.{.{ .from = 1, .msg = r3_1.broadcast }});
    defer presig2.zeroize();

    const msg = "cggmp24 vs libsecp256k1";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    const m = scalarFromDigest(digest);

    const sig = try T.combine(presig1.gamma, &.{ T.partialSign(presig1, m), T.partialSign(presig2, m) }, m);
    try testing.expect(T.verify(pk, m, sig));

    // hand the compact signature and compressed public key to libsecp256k1
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);

    var compact: [64]u8 = undefined;
    compact[0..32].* = sig.r.toBytes();
    compact[32..].* = sig.s.toBytes();
    var their_sig: c.Signature = undefined;
    try testing.expect(c.secp256k1_ecdsa_signature_parse_compact(ctx, &their_sig, &compact) == 1);

    const pk_bytes = pk.toBytes();
    var their_pk: c.Pubkey = undefined;
    try testing.expect(c.secp256k1_ec_pubkey_parse(ctx, &their_pk, &pk_bytes, pk_bytes.len) == 1);

    try testing.expect(c.secp256k1_ecdsa_verify(ctx, &their_sig, &digest, &their_pk) == 1);
    var wrong = digest;
    wrong[0] ^= 1;
    try testing.expect(c.secp256k1_ecdsa_verify(ctx, &their_sig, &wrong, &their_pk) == 0);
}

// ---------------------------------------------------------------------------
// BIP-340 Schnorr
// ---------------------------------------------------------------------------

test "BIP-340: official vectors, byte-identical signatures from both sides" {
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);

    for (mpc.bip340.test_vectors) |v| {
        const sk_hex = v.sk orelse continue;
        var sk: [32]u8 = undefined;
        _ = hex(32, sk_hex, &sk);
        var aux: [32]u8 = undefined;
        _ = hex(32, v.aux.?, &aux);
        var msg_buf: [128]u8 = undefined;
        const msg = hex(128, v.msg, &msg_buf);

        const ours = try mpc.bip340.sign(sk, msg, aux);

        // our signature passes their verifier (any message length)
        var keypair: c.Keypair = undefined;
        try testing.expect(c.secp256k1_keypair_create(ctx, &keypair, &sk) == 1);
        var xonly: c.XonlyPubkey = undefined;
        try testing.expect(c.secp256k1_keypair_xonly_pub(ctx, &xonly, null, &keypair) == 1);
        try testing.expect(c.secp256k1_schnorrsig_verify(ctx, &ours, msg.ptr, msg.len, &xonly) == 1);

        // both implementations use the deterministic BIP-340 nonce, so on
        // 32-byte messages the signatures must match byte for byte
        if (msg.len == 32) {
            var theirs: [64]u8 = undefined;
            try testing.expect(c.secp256k1_schnorrsig_sign32(ctx, &theirs, msg[0..32], &keypair, &aux) == 1);
            try testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "BIP-340: libsecp256k1 signs, our verify accepts" {
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);
    var prng = std.Random.DefaultPrng.init(303);
    const rng = prng.random();

    for (0..16) |_| {
        const sk = E.Scalar.random(rng).toBytes();
        var msg: [32]u8 = undefined;
        rng.bytes(&msg);
        var aux: [32]u8 = undefined;
        rng.bytes(&aux);

        var keypair: c.Keypair = undefined;
        try testing.expect(c.secp256k1_keypair_create(ctx, &keypair, &sk) == 1);
        var xonly: c.XonlyPubkey = undefined;
        try testing.expect(c.secp256k1_keypair_xonly_pub(ctx, &xonly, null, &keypair) == 1);
        var pk_x: [32]u8 = undefined;
        try testing.expect(c.secp256k1_xonly_pubkey_serialize(ctx, &pk_x, &xonly) == 1);

        var sig: [64]u8 = undefined;
        try testing.expect(c.secp256k1_schnorrsig_sign32(ctx, &sig, &msg, &keypair, &aux) == 1);

        try testing.expect(mpc.bip340.verify(pk_x, &msg, sig));
        var wrong = msg;
        wrong[0] ^= 1;
        try testing.expect(!mpc.bip340.verify(pk_x, &wrong, sig));
    }
}

test "FROST-Taproot threshold signature verifies under libsecp256k1" {
    const F = mpc.bip340.FrostTaproot;
    const vss = mpc.vss;
    const ctx = c.secp256k1_context_create(c.CONTEXT_NONE);
    defer c.secp256k1_context_destroy(ctx);
    var prng = std.Random.DefaultPrng.init(404);
    const rng = prng.random();
    const allocator = testing.allocator;

    // several random keys, so both even- and odd-Y group keys occur
    for (0..8) |_| {
        const secret = E.Scalar.random(rng);
        var poly = try vss.Polynomial(E).initRandom(allocator, secret, 2, rng);
        defer poly.deinit();
        var com = try poly.commit(allocator);
        defer com.deinit();

        var pk = com.publicKey();
        var shares = [_]E.Scalar{ try poly.share(1), try poly.share(2), try poly.share(3) };
        var s1 = shares[0];
        if (mpc.bip340.normalizeKeyMaterial(&s1, &pk, com.points)) {
            shares[1] = shares[1].neg();
            shares[2] = shares[2].neg();
        }
        shares[0] = s1;

        const msg = "frost-taproot vs libsecp256k1";
        const c1 = try F.commit(1, shares[0], rng);
        const c3 = try F.commit(3, shares[2], rng);
        const commitment_list = [_]F.Commitment{ c1.commitment, c3.commitment };
        const z1 = try F.sign(1, shares[0], pk, c1.nonces, msg, &commitment_list);
        const z3 = try F.sign(3, shares[2], pk, c3.nonces, msg, &commitment_list);
        const sig = mpc.bip340.signatureToBytes(try F.aggregate(&commitment_list, msg, pk, &.{ z1, z3 }));

        var xonly: c.XonlyPubkey = undefined;
        try testing.expect(c.secp256k1_xonly_pubkey_parse(ctx, &xonly, &pk.xOnly()) == 1);
        try testing.expect(c.secp256k1_schnorrsig_verify(ctx, &sig, msg.ptr, msg.len, &xonly) == 1);
        const wrong = "some other message";
        try testing.expect(c.secp256k1_schnorrsig_verify(ctx, &sig, wrong.ptr, wrong.len, &xonly) == 0);
    }
}
