//! BIP-340 Schnorr signatures over secp256k1 (Bitcoin Taproot):
//! single-signer sign/verify plus a FROST ciphersuite producing
//! BIP-340-compatible threshold signatures.
//!
//! The FROST mode reuses the RFC 9591 two-round machinery with its own
//! domain-separation context; only the challenge derivation and even-Y
//! normalization follow BIP-340. There is no published standard for
//! FROST-BIP340 interop yet, so all participants must run this
//! implementation (or one that matches its transcript exactly).

const std = @import("std");
const curve = @import("curve.zig");
const frost = @import("frost.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const E = curve.Secp256k1;
const Ec = curve.Secp256k1;

/// BIP-340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data...).
pub fn taggedHash(comptime tag: []const u8, parts: []const []const u8) [32]u8 {
    const tag_hash = comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: [32]u8 = undefined;
        var h = Sha256.init(.{});
        h.update(tag);
        h.final(&out);
        break :blk out;
    };
    var h = Sha256.init(.{});
    h.update(&tag_hash);
    h.update(&tag_hash);
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn scalarFromHash(hash: [32]u8) E.Scalar {
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[32..], &hash); // 32-byte big-endian integer, reduced mod n
    return E.Scalar.fromWideBytes(wide);
}

/// e = int(taggedHash("BIP0340/challenge", r_x || pk_x || msg)) mod n.
pub fn challengeScalar(r_x: [32]u8, pk_x: [32]u8, msg: []const u8) E.Scalar {
    return scalarFromHash(taggedHash("BIP0340/challenge", &.{ &r_x, &pk_x, msg }));
}

/// lift_x: decode an x-only public key to the even-Y curve point.
pub fn liftX(x: [32]u8) !E.Point {
    return E.Point.fromXOnly(x);
}

/// Single-signer BIP-340 signing (used for test-vector validation and as a
/// non-threshold convenience).
pub fn sign(secret_key: [32]u8, msg: []const u8, aux_rand: [32]u8) ![64]u8 {
    const d0 = try E.Scalar.fromBytes(secret_key);
    if (d0.isZero()) return error.InvalidSecretKey;
    const P = try E.Point.mulBase(d0);
    const d = if (P.hasEvenY()) d0 else d0.neg();

    const aux_hash = taggedHash("BIP0340/aux", &.{&aux_rand});
    var t: [32]u8 = d.toBytes();
    for (&t, aux_hash) |*b, a| b.* ^= a;

    const pk_x = P.xOnly();
    const rand = taggedHash("BIP0340/nonce", &.{ &t, &pk_x, msg });
    const k0 = scalarFromHash(rand);
    if (k0.isZero()) return error.BadNonce;

    const R = try E.Point.mulBase(k0);
    const k = if (R.hasEvenY()) k0 else k0.neg();
    const r_x = R.xOnly();

    const e = challengeScalar(r_x, pk_x, msg);
    var sig: [64]u8 = undefined;
    sig[0..32].* = r_x;
    sig[32..].* = k.add(e.mul(d)).toBytes();
    return sig;
}

/// BIP-340 verification.
pub fn verify(public_key_x: [32]u8, msg: []const u8, sig: [64]u8) bool {
    const P = liftX(public_key_x) catch return false;
    // r must be a canonical field element, s a canonical scalar.
    if (!E.feCanonical(sig[0..32].*)) return false;
    const s = E.Scalar.fromBytes(sig[32..].*) catch return false;
    const e = challengeScalar(sig[0..32].*, public_key_x, msg);
    // R = sG - eP; must not be infinite, must have even Y, x(R) == r.
    const R = E.Point.mulDoubleBasePublic(E.Point.generator, s, P, e.neg()) catch return false;
    if (R.isIdentity()) return false;
    if (!R.hasEvenY()) return false;
    return std.crypto.timing_safe.eql([32]u8, R.xOnly(), sig[0..32].*);
}

/// FROST ciphersuite producing BIP-340 signatures. zig-mpc-specific transcript
/// (no interop standard exists); challenge and verification are pure BIP-340.
pub const FrostTaprootSuite = struct {
    pub const E = curve.Secp256k1;
    pub const context = "zig-mpc/FROST-secp256k1-BIP340/v1";
    pub const hash_len = 32;
    pub const Hasher = Sha256;
    pub const normalize_even_r = true;

    pub fn hashInit(comptime dom: []const u8) Hasher {
        var h = Sha256.init(.{});
        h.update(context);
        h.update(dom);
        return h;
    }

    pub fn hashFinal(h: *Hasher) [hash_len]u8 {
        var out: [hash_len]u8 = undefined;
        h.final(&out);
        return out;
    }

    fn hashToScalar(comptime dom: []const u8, parts: []const []const u8) Ec.Scalar {
        const uniform = frost.expandMessageXmdSha256(48, parts, context ++ dom);
        var wide: [64]u8 = @splat(0);
        @memcpy(wide[16..], &uniform);
        return Ec.Scalar.fromWideBytes(wide);
    }

    pub fn h1(parts: []const []const u8) Ec.Scalar {
        return hashToScalar("rho", parts);
    }

    pub fn h3(parts: []const []const u8) Ec.Scalar {
        return hashToScalar("nonce", parts);
    }

    /// BIP-340 challenge over x-only encodings. Parity of R is irrelevant
    /// here (x-only), which is what makes the signer-side nonce negation
    /// consistent.
    pub fn challenge(R: Ec.Point, group_pk: Ec.Point, msg: []const u8) Ec.Scalar {
        return challengeScalar(R.xOnly(), group_pk.xOnly(), msg);
    }

    pub fn verify(msg: []const u8, pk: Ec.Point, R: Ec.Point, z: Ec.Scalar) bool {
        var sig: [64]u8 = undefined;
        sig[0..32].* = R.xOnly();
        sig[32..].* = z.toBytes();
        return @import("bip340.zig").verify(pk.xOnly(), msg, sig);
    }
};

pub const FrostTaproot = frost.Frost(FrostTaprootSuite);

/// Encode a FROST-Taproot signature in the 64-byte BIP-340 wire format.
pub fn signatureToBytes(sig: FrostTaproot.Signature) [64]u8 {
    var out: [64]u8 = undefined;
    out[0..32].* = sig.R.xOnly();
    out[32..].* = sig.z.toBytes();
    return out;
}

/// BIP-340 secret keys correspond to even-Y public keys. If the DKG produced
/// an odd-Y group key, negate the key material (secret share, public key, and
/// the whole Feldman commitment) so that signing matches the x-only public
/// key. Every participant must apply this. Returns true if negation occurred.
pub fn normalizeKeyMaterial(secret_share: *E.Scalar, public_key: *E.Point, vss_commitment: []E.Point) bool {
    if (public_key.hasEvenY()) return false;
    secret_share.* = secret_share.neg();
    public_key.* = public_key.neg();
    for (vss_commitment) |*p| p.* = p.neg();
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// One official BIP-340 test vector. Public so that a consumer (the CLI's
/// `selftest`) can re-run the suite at runtime, not just at `zig build test`.
pub const TestVector = struct {
    sk: ?[]const u8,
    pk: []const u8,
    aux: ?[]const u8,
    msg: []const u8,
    sig: []const u8,
    valid: bool,
};

/// Official BIP-340 test vectors (bitcoin/bips bip-0340/test-vectors.csv).
pub const test_vectors = [_]TestVector{
    .{ .sk = "0000000000000000000000000000000000000000000000000000000000000003", .pk = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", .aux = "0000000000000000000000000000000000000000000000000000000000000000", .msg = "0000000000000000000000000000000000000000000000000000000000000000", .sig = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", .valid = true },
    .{ .sk = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = "0000000000000000000000000000000000000000000000000000000000000001", .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", .valid = true },
    .{ .sk = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", .pk = "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", .aux = "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", .msg = "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", .sig = "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", .valid = true },
    .{ .sk = "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", .pk = "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", .aux = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", .msg = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", .sig = "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", .valid = true },
    .{ .sk = null, .pk = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", .aux = null, .msg = "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", .sig = "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", .valid = true },
    .{ .sk = null, .pk = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false }, // pk not on curve
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", .valid = false }, // has_even_y(R) false
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", .valid = false }, // negated message
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", .valid = false }, // negated s
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", .valid = false }, // sG - eP infinite
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", .valid = false }, // sG - eP infinite
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false }, // r not an x-coordinate
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false }, // r == field size
    .{ .sk = null, .pk = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", .valid = false }, // s == curve order
    .{ .sk = null, .pk = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", .aux = null, .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .sig = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false }, // pk x exceeds field size
    .{ .sk = "0340034003400340034003400340034003400340034003400340034003400340", .pk = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux = "0000000000000000000000000000000000000000000000000000000000000000", .msg = "", .sig = "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", .valid = true },
    .{ .sk = "0340034003400340034003400340034003400340034003400340034003400340", .pk = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux = "0000000000000000000000000000000000000000000000000000000000000000", .msg = "11", .sig = "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", .valid = true },
    .{ .sk = "0340034003400340034003400340034003400340034003400340034003400340", .pk = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux = "0000000000000000000000000000000000000000000000000000000000000000", .msg = "0102030405060708090A0B0C0D0E0F1011", .sig = "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", .valid = true },
    .{ .sk = "0340034003400340034003400340034003400340034003400340034003400340", .pk = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux = "0000000000000000000000000000000000000000000000000000000000000000", .msg = "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", .sig = "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", .valid = true },
};

fn hexBuf(comptime max: usize, hex: []const u8, out: *[max]u8) []const u8 {
    return std.fmt.hexToBytes(out, hex) catch unreachable;
}

test "BIP-340 official test vectors (sign + verify)" {
    for (test_vectors) |v| {
        var pk_buf: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&pk_buf, v.pk) catch unreachable;
        var sig_buf: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&sig_buf, v.sig) catch unreachable;
        var msg_storage: [128]u8 = undefined;
        const msg = hexBuf(128, v.msg, &msg_storage);

        if (v.sk) |sk_hex| {
            var sk: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&sk, sk_hex) catch unreachable;
            var aux: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&aux, v.aux.?) catch unreachable;
            const produced = try sign(sk, msg, aux);
            try std.testing.expectEqualSlices(u8, &sig_buf, &produced);
        }

        try std.testing.expectEqual(v.valid, verify(pk_buf, msg, sig_buf));
    }
}

test "FROST-Taproot: DKG-free dealer keys, threshold sign, BIP-340 verify" {
    const F = FrostTaproot;
    var prng = std.Random.DefaultPrng.init(31337);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const vss = @import("vss.zig");

    // run several random keys so both even- and odd-Y group keys occur
    for (0..8) |_| {
        const secret = E.Scalar.random(rng);
        var poly = try vss.Polynomial(E).initRandom(allocator, secret, 2, rng);
        defer poly.deinit();
        var com = try poly.commit(allocator);
        defer com.deinit();

        var pk = com.publicKey();
        var shares = [_]E.Scalar{ try poly.share(1), try poly.share(2), try poly.share(3) };
        // normalize to even-Y key material (each party negates its own share)
        var s1 = shares[0];
        const negated = normalizeKeyMaterial(&s1, &pk, com.points);
        shares[0] = s1;
        if (negated) {
            shares[1] = shares[1].neg();
            shares[2] = shares[2].neg();
        }
        try std.testing.expect(pk.hasEvenY());

        const msg = "taproot threshold test";
        const c1 = try F.commit(1, shares[0], rng);
        const c3 = try F.commit(3, shares[2], rng);
        const commitment_list = [_]F.Commitment{ c1.commitment, c3.commitment };
        const z1 = try F.sign(1, shares[0], pk, c1.nonces, msg, &commitment_list);
        const z3 = try F.sign(3, shares[2], pk, c3.nonces, msg, &commitment_list);

        // share-level verification (identifiable abort) against normalized commitment
        const pk1 = try com.evaluate(try vss.shareIndex(E, 1));
        try std.testing.expect(try F.verifySigShare(1, pk1, z1, pk, msg, &commitment_list));

        const sig = try F.aggregate(&commitment_list, msg, pk, &.{ z1, z3 });
        try std.testing.expect(F.verify(msg, pk, sig));

        // final signature is valid plain BIP-340
        try std.testing.expect(verify(pk.xOnly(), msg, signatureToBytes(sig)));
        try std.testing.expect(!verify(pk.xOnly(), "wrong msg", signatureToBytes(sig)));
    }
}

test "FROST-Taproot after DKG" {
    const dkg = @import("dkg.zig");
    const D = dkg.Dkg(E);
    _ = D;
    const F = FrostTaproot;
    var prng = std.Random.DefaultPrng.init(2024);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    // run the full DKG helper from dkg.zig's test infrastructure by
    // re-executing the protocol here with 3 parties, t = 2
    const shares = try dkg.runDkgForTest(E, allocator, 2, 3, rng);
    defer {
        for (shares) |*s| s.deinit();
        allocator.free(shares);
    }

    // normalize every party's key material for BIP-340
    var pk = shares[0].public_key;
    var negated = false;
    for (shares, 0..) |*s, i| {
        var local_pk = s.public_key;
        const did = normalizeKeyMaterial(&s.secret_share, &local_pk, s.vss_commitment);
        s.public_key = local_pk;
        if (i == 0) {
            negated = did;
            pk = local_pk;
        }
    }
    try std.testing.expect(pk.hasEvenY());

    const msg = "dkg taproot";
    const c2 = try F.commit(2, shares[1].secret_share, rng);
    const c3 = try F.commit(3, shares[2].secret_share, rng);
    const commitment_list = [_]F.Commitment{ c2.commitment, c3.commitment };
    const z2 = try F.sign(2, shares[1].secret_share, pk, c2.nonces, msg, &commitment_list);
    const z3 = try F.sign(3, shares[2].secret_share, pk, c3.nonces, msg, &commitment_list);
    const sig = try F.aggregate(&commitment_list, msg, pk, &.{ z2, z3 });
    try std.testing.expect(verify(pk.xOnly(), msg, signatureToBytes(sig)));
}
