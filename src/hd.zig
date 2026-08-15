//! BIP-32 / SLIP-10 non-hardened HD derivation for threshold keys
//! (secp256k1). Non-hardened child keys differ from the parent by a PUBLIC
//! additive shift, so threshold signers can derive children without any
//! interaction: one designated signer adds the shift to its additive share
//! (or the shift is applied when combining).
//!
//! Hardened derivation requires the private key and is impossible for
//! threshold keys - by design.

const std = @import("std");
const curve = @import("curve.zig");

const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
pub const E = curve.Secp256k1;

pub const ExtendedPublicKey = struct {
    pk: E.Point,
    chain_code: [32]u8,
};

pub const ChildShift = struct {
    /// Additive tweak: child_sk = parent_sk + shift (mod n).
    shift: E.Scalar,
    child: ExtendedPublicKey,
};

pub const Error = error{
    HardenedIndex,
    /// I_L >= n or child key is the identity (probability ~2^-127);
    /// per BIP-32 the caller should skip to the next index.
    InvalidChild,
};

/// One non-hardened CKDpub step.
pub fn deriveChild(parent: ExtendedPublicKey, index: u32) Error!ChildShift {
    if (index >= 1 << 31) return error.HardenedIndex;

    var data: [37]u8 = undefined;
    data[0..33].* = parent.pk.toBytes();
    std.mem.writeInt(u32, data[33..37], index, .big);

    var i_out: [64]u8 = undefined;
    HmacSha512.create(&i_out, &data, &parent.chain_code);

    // I_L interpreted as big-endian; must be < n (reject the negligible case
    // rather than silently reducing, per BIP-32)
    const shift = E.Scalar.fromBytes(i_out[0..32].*) catch return error.InvalidChild;

    const shift_pt = if (shift.isZero()) E.Point.identity else E.Point.mulBase(shift) catch return error.InvalidChild;
    const child_pk = parent.pk.add(shift_pt);
    if (child_pk.isIdentity()) return error.InvalidChild;

    return .{
        .shift = shift,
        .child = .{ .pk = child_pk, .chain_code = i_out[32..64].* },
    };
}

pub const PathShift = struct {
    /// Total additive tweak over the whole path.
    shift: E.Scalar,
    child: ExtendedPublicKey,
};

/// Derive along a path of non-hardened indices, accumulating the shift.
pub fn derivePath(parent: ExtendedPublicKey, path: []const u32) Error!PathShift {
    var acc = E.Scalar.zero;
    var cur = parent;
    for (path) |index| {
        const step = try deriveChild(cur, index);
        acc = acc.add(step.shift);
        cur = step.child;
    }
    return .{ .shift = acc, .child = cur };
}

// ---------------------------------------------------------------------------
// Tests (SLIP-0010 test vector 1, secp256k1)
// ---------------------------------------------------------------------------

fn hexPk(comptime hex: []const u8) E.Point {
    var b: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return E.Point.fromBytes(b) catch unreachable;
}

fn hex32(comptime hex: []const u8) [32]u8 {
    var b: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

test "SLIP-10 vector 1: non-hardened steps match" {
    // m/0H -> m/0H/1
    {
        const parent = ExtendedPublicKey{
            .pk = hexPk("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
            .chain_code = hex32("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
        };
        const step = try deriveChild(parent, 1);
        try std.testing.expectEqualSlices(u8, &hex32("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"), &step.child.chain_code);
        try std.testing.expect(step.child.pk.eql(hexPk("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")));

        // shift consistency vs the vector's private keys:
        // child_priv == parent_priv + shift
        const parent_sk = try E.Scalar.fromBytes(hex32("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"));
        const child_sk = try E.Scalar.fromBytes(hex32("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"));
        try std.testing.expect(parent_sk.add(step.shift).eql(child_sk));
    }
    // m/0H/1/2H -> m/0H/1/2H/2
    {
        const parent = ExtendedPublicKey{
            .pk = hexPk("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"),
            .chain_code = hex32("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"),
        };
        const step = try deriveChild(parent, 2);
        try std.testing.expectEqualSlices(u8, &hex32("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"), &step.child.chain_code);
        try std.testing.expect(step.child.pk.eql(hexPk("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")));

        // and one more step: /2 -> /1000000000, via derivePath
        const two_steps = try derivePath(parent, &.{ 2, 1000000000 });
        try std.testing.expectEqualSlices(u8, &hex32("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"), &two_steps.child.chain_code);
        try std.testing.expect(two_steps.child.pk.eql(hexPk("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011")));

        const parent_sk = try E.Scalar.fromBytes(hex32("cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"));
        const child_sk = try E.Scalar.fromBytes(hex32("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"));
        try std.testing.expect(parent_sk.add(two_steps.shift).eql(child_sk));
    }

    // hardened index rejected
    const any = ExtendedPublicKey{ .pk = E.Point.generator, .chain_code = @splat(7) };
    try std.testing.expectError(error.HardenedIndex, deriveChild(any, 1 << 31));
}

test "threshold signing under a derived child key" {
    const frost = @import("frost.zig");
    const vss = @import("vss.zig");
    const F = frost.Frost(frost.Secp256k1Sha256);
    var prng = std.Random.DefaultPrng.init(818181);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    // parent key, then derive a child along a path
    const parent_secret = E.Scalar.random(rng);
    var cc: [32]u8 = undefined;
    rng.bytes(&cc);
    const parent = ExtendedPublicKey{ .pk = try E.Point.mulBase(parent_secret), .chain_code = cc };
    const step = try derivePath(parent, &.{ 44, 0, 7 });

    // key relation: child_pk == (parent_secret + shift)·G
    const child_secret = parent_secret.add(step.shift);
    try std.testing.expect((try E.Point.mulBase(child_secret)).eql(step.child.pk));

    // threshold-share the child secret and sign under the derived key
    var poly = try vss.Polynomial(E).initRandom(allocator, child_secret, 2, rng);
    defer poly.deinit();
    const msg = "hd child signing";
    const c1 = try F.commit(1, poly.share(1), rng);
    const c2 = try F.commit(2, poly.share(2), rng);
    const list = [_]F.Commitment{ c1.commitment, c2.commitment };
    const z1 = try F.sign(1, poly.share(1), step.child.pk, c1.nonces, msg, &list);
    const z2 = try F.sign(2, poly.share(2), step.child.pk, c2.nonces, msg, &list);
    const sig = try F.aggregate(&list, msg, step.child.pk, &.{ z1, z2 });
    try std.testing.expect(F.verify(msg, step.child.pk, sig));
}
