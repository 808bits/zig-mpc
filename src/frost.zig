//! FROST two-round threshold Schnorr signing, RFC 9591.
//!
//! Implemented ciphersuites:
//!   - FROST(Ed25519, SHA-512)   - RFC 8032-compatible signatures
//!   - FROST(secp256k1, SHA-256) - RFC 9591 Schnorr signatures
//!
//! (A BIP-340/Taproot mode lives in bip340.zig.)
//!
//! Transport, participant selection, and share distribution are the caller's
//! responsibility; the commitment list passed to sign/aggregate MUST be sorted
//! ascending by identifier and identical for all participants.

const std = @import("std");
const curve = @import("curve.zig");
const vss = @import("vss.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// expand_message_xmd from RFC 9380 §5.3.1, instantiated with SHA-256,
/// producing `len` bytes (len <= 255*32).
pub fn expandMessageXmdSha256(comptime len: usize, parts: []const []const u8, dst: []const u8) [len]u8 {
    const b = 32; // SHA-256 output
    const s = 64; // SHA-256 block size
    const ell = comptime std.math.divCeil(usize, len, b) catch unreachable;
    comptime std.debug.assert(ell <= 255);
    std.debug.assert(dst.len <= 255);

    var h0 = Sha256.init(.{});
    const z_pad: [s]u8 = @splat(0);
    h0.update(&z_pad);
    for (parts) |p| h0.update(p);
    h0.update(&[_]u8{ @intCast(len >> 8), @intCast(len & 0xff), 0 }); // l_i_b_str || I2OSP(0,1)
    h0.update(dst);
    h0.update(&[_]u8{@intCast(dst.len)});
    var b0: [b]u8 = undefined;
    h0.final(&b0);

    var out: [len]u8 = undefined;
    var bi: [b]u8 = undefined;
    var i: u8 = 1;
    var written: usize = 0;
    var prev: [b]u8 = @splat(0); // b_(i-1), starts as zero so first xor yields b0
    while (written < len) : (i += 1) {
        var h = Sha256.init(.{});
        var xored: [b]u8 = undefined;
        for (0..b) |k| xored[k] = b0[k] ^ prev[k];
        // For i == 1 the input is b_0 itself (prev is zero).
        h.update(&xored);
        h.update(&[_]u8{i});
        h.update(dst);
        h.update(&[_]u8{@intCast(dst.len)});
        h.final(&bi);
        prev = bi;
        const n = @min(b, len - written);
        @memcpy(out[written..][0..n], bi[0..n]);
        written += n;
    }
    return out;
}

/// FROST(Ed25519, SHA-512), RFC 9591 §6.1.
pub const Ed25519Sha512 = struct {
    pub const E = curve.Ed25519;
    pub const context = "FROST-ED25519-SHA512-v1";
    pub const hash_len = 64;
    pub const Hasher = Sha512;

    pub fn hashInit(comptime dom: []const u8) Hasher {
        var h = Sha512.init(.{});
        h.update(context);
        h.update(dom);
        return h;
    }

    pub fn hashFinal(h: *Hasher) [hash_len]u8 {
        var out: [hash_len]u8 = undefined;
        h.final(&out);
        return out;
    }

    fn hashToScalar(comptime dom: []const u8, parts: []const []const u8) E.Scalar {
        var h = hashInit(dom);
        for (parts) |p| h.update(p);
        return E.Scalar.fromWideBytes(hashFinal(&h));
    }

    pub fn h1(parts: []const []const u8) E.Scalar {
        return hashToScalar("rho", parts);
    }

    /// Challenge hash: plain SHA-512, no context (RFC 8032 compatibility).
    pub fn h2(parts: []const []const u8) E.Scalar {
        var h = Sha512.init(.{});
        for (parts) |p| h.update(p);
        var out: [64]u8 = undefined;
        h.final(&out);
        return E.Scalar.fromWideBytes(out);
    }

    pub fn h3(parts: []const []const u8) E.Scalar {
        return hashToScalar("nonce", parts);
    }

    /// RFC 8032 challenge: SHA-512(R || A || msg).
    pub fn challenge(R: E.Point, group_pk: E.Point, msg: []const u8) E.Scalar {
        const r_enc = R.toBytes();
        const pk_enc = group_pk.toBytes();
        return h2(&.{ &r_enc, &pk_enc, msg });
    }

    /// Cofactored verification per RFC 8032: [8][z]B == [8]R + [8][c]A.
    pub fn verify(msg: []const u8, pk: E.Point, R: E.Point, z: E.Scalar) bool {
        const c = challenge(R, pk, msg);
        // V = zB - cA - R; accept iff [8]V == identity.
        const zb_minus_ca = E.Point.mulDoubleBasePublic(E.Point.generator, z, pk, c.neg()) catch return false;
        var v = zb_minus_ca.sub(R);
        for (0..3) |_| v = v.add(v);
        return v.isIdentity();
    }
};

/// FROST(secp256k1, SHA-256), RFC 9591 §6.5.
pub const Secp256k1Sha256 = struct {
    pub const E = curve.Secp256k1;
    pub const context = "FROST-secp256k1-SHA256-v1";
    pub const hash_len = 32;
    pub const Hasher = Sha256;

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

    fn hashToScalar(comptime dom: []const u8, parts: []const []const u8) E.Scalar {
        const uniform = expandMessageXmdSha256(48, parts, context ++ dom);
        var wide: [64]u8 = @splat(0);
        @memcpy(wide[16..], &uniform); // left-pad: 48-byte big-endian integer
        return E.Scalar.fromWideBytes(wide);
    }

    pub fn h1(parts: []const []const u8) E.Scalar {
        return hashToScalar("rho", parts);
    }

    pub fn h2(parts: []const []const u8) E.Scalar {
        return hashToScalar("chal", parts);
    }

    pub fn h3(parts: []const []const u8) E.Scalar {
        return hashToScalar("nonce", parts);
    }

    /// RFC 9591 challenge: H2(R || PK || msg).
    pub fn challenge(R: E.Point, group_pk: E.Point, msg: []const u8) E.Scalar {
        const r_enc = R.toBytes();
        const pk_enc = group_pk.toBytes();
        return h2(&.{ &r_enc, &pk_enc, msg });
    }

    /// Prime-order group Schnorr verification (RFC 9591 Appendix B):
    /// accept iff R == [z]G - [c]PK.
    pub fn verify(msg: []const u8, pk: E.Point, R: E.Point, z: E.Scalar) bool {
        const c = challenge(R, pk, msg);
        const rp = E.Point.mulDoubleBasePublic(E.Point.generator, z, pk, c.neg()) catch return false;
        return rp.eql(R) and !R.isIdentity();
    }
};

pub fn Frost(comptime Suite: type) type {
    return struct {
        pub const E = Suite.E;

        /// BIP-340-style suites require the group commitment R to have an
        /// even Y coordinate; signers negate their nonces when it does not.
        const normalize_even_r = @hasDecl(Suite, "normalize_even_r") and Suite.normalize_even_r;

        pub const SecretNonces = struct {
            hiding: E.Scalar,
            binding: E.Scalar,

            pub fn zeroize(self: *SecretNonces) void {
                self.hiding.zeroize();
                self.binding.zeroize();
            }
        };

        /// One participant's round-1 broadcast.
        pub const Commitment = struct {
            identifier: u16,
            hiding: E.Point,
            binding: E.Point,
        };

        pub const Signature = struct {
            R: E.Point,
            z: E.Scalar,

            pub const encoded_length = E.Point.encoded_length + E.Scalar.encoded_length;

            pub fn toBytes(self: Signature) [encoded_length]u8 {
                var out: [encoded_length]u8 = undefined;
                out[0..E.Point.encoded_length].* = self.R.toBytes();
                out[E.Point.encoded_length..].* = self.z.toBytes();
                return out;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) !Signature {
                return .{
                    .R = try E.Point.fromBytes(bytes[0..E.Point.encoded_length].*),
                    .z = try E.Scalar.fromBytes(bytes[E.Point.encoded_length..].*),
                };
            }
        };

        fn serializeId(id: u16) [E.Scalar.encoded_length]u8 {
            return E.Scalar.fromU64(id).toBytes();
        }

        /// RFC 9591 §4.1: nonce = H3(random_bytes || serialized secret share).
        pub fn nonceGenerate(sk: E.Scalar, randomness: [32]u8) E.Scalar {
            const sk_enc = sk.toBytes();
            return Suite.h3(&.{ &randomness, &sk_enc });
        }

        pub const CommitResult = struct { nonces: SecretNonces, commitment: Commitment };

        /// Round 1 with caller-supplied randomness (for tests / derandomized
        /// deployments). Returns secret nonces and the public commitment.
        pub fn commitDeterministic(
            identifier: u16,
            sk: E.Scalar,
            hiding_randomness: [32]u8,
            binding_randomness: [32]u8,
        ) !CommitResult {
            const hiding = nonceGenerate(sk, hiding_randomness);
            const binding = nonceGenerate(sk, binding_randomness);
            return .{
                .nonces = .{ .hiding = hiding, .binding = binding },
                .commitment = .{
                    .identifier = identifier,
                    .hiding = try E.Point.mulBase(hiding),
                    .binding = try E.Point.mulBase(binding),
                },
            };
        }

        /// Round 1: generate nonces and commitments.
        pub fn commit(identifier: u16, sk: E.Scalar, rng: std.Random) !CommitResult {
            var hr: [32]u8 = undefined;
            var br: [32]u8 = undefined;
            rng.bytes(&hr);
            rng.bytes(&br);
            return commitDeterministic(identifier, sk, hr, br);
        }

        const rho_prefix_len = E.Point.encoded_length + 2 * Suite.hash_len;

        fn validateCommitmentList(commitment_list: []const Commitment) !void {
            if (commitment_list.len == 0) return error.EmptyCommitmentList;
            for (commitment_list, 0..) |c, i| {
                if (c.identifier == 0) return error.InvalidIdentifier;
                if (i > 0 and commitment_list[i - 1].identifier >= c.identifier)
                    return error.UnsortedCommitmentList;
            }
        }

        /// rho_input_prefix = pk_enc || H4(msg) || H5(encoded commitment list).
        fn bindingFactorPrefix(group_pk: E.Point, commitment_list: []const Commitment, msg: []const u8) [rho_prefix_len]u8 {
            var msg_h = Suite.hashInit("msg");
            msg_h.update(msg);
            const msg_hash = Suite.hashFinal(&msg_h);

            var com_h = Suite.hashInit("com");
            for (commitment_list) |c| {
                const id_enc = serializeId(c.identifier);
                const hid_enc = c.hiding.toBytes();
                const bind_enc = c.binding.toBytes();
                com_h.update(&id_enc);
                com_h.update(&hid_enc);
                com_h.update(&bind_enc);
            }
            const com_hash = Suite.hashFinal(&com_h);

            var prefix: [rho_prefix_len]u8 = undefined;
            prefix[0..E.Point.encoded_length].* = group_pk.toBytes();
            prefix[E.Point.encoded_length..][0..Suite.hash_len].* = msg_hash;
            prefix[E.Point.encoded_length + Suite.hash_len ..][0..Suite.hash_len].* = com_hash;
            return prefix;
        }

        fn bindingFactor(prefix: *const [rho_prefix_len]u8, identifier: u16) E.Scalar {
            const id_enc = serializeId(identifier);
            return Suite.h1(&.{ prefix, &id_enc });
        }

        /// R = sum_i (D_i + rho_i * E_i).
        fn groupCommitment(commitment_list: []const Commitment, prefix: *const [rho_prefix_len]u8) !E.Point {
            var acc: ?E.Point = null;
            for (commitment_list) |c| {
                const rho = bindingFactor(prefix, c.identifier);
                const bound = try c.binding.mulPublic(rho);
                const term = c.hiding.add(bound);
                acc = if (acc) |a| a.add(term) else term;
            }
            return acc.?;
        }

        pub fn challenge(R: E.Point, group_pk: E.Point, msg: []const u8) E.Scalar {
            return Suite.challenge(R, group_pk, msg);
        }

        fn interpolatingValue(commitment_list: []const Commitment, identifier: u16) !E.Scalar {
            var indices_buf: [256]u16 = undefined;
            if (commitment_list.len > indices_buf.len) return error.TooManyParticipants;
            var j: ?usize = null;
            for (commitment_list, 0..) |c, i| {
                indices_buf[i] = c.identifier;
                if (c.identifier == identifier) j = i;
            }
            const jj = j orelse return error.ParticipantNotInList;
            return vss.lagrangeAtZero(E, indices_buf[0..commitment_list.len], jj);
        }

        /// Round 2 (RFC 9591 §5.2): produce this participant's signature share.
        pub fn sign(
            identifier: u16,
            sk_i: E.Scalar,
            group_pk: E.Point,
            nonces: SecretNonces,
            msg: []const u8,
            commitment_list: []const Commitment,
        ) !E.Scalar {
            try validateCommitmentList(commitment_list);
            // RFC 9591 §5.2: the signer must confirm that the commitment carried
            // in the list for its own identifier was actually derived from the
            // nonces it is about to use. Without this a coordinator can replay
            // one set of nonces against several different commitment lists;
            // each reply is a fresh linear equation in the long-term share, and
            // a handful of them solve for sk_i. Binding the nonces to a single
            // commitment (and thus a single group commitment R) is what makes
            // reuse detectable here.
            const own = for (commitment_list) |c| {
                if (c.identifier == identifier) break c;
            } else return error.MissingOwnCommitment;
            if (!own.hiding.eql(try E.Point.mulBase(nonces.hiding)) or
                !own.binding.eql(try E.Point.mulBase(nonces.binding)))
                return error.NonceCommitmentMismatch;
            const prefix = bindingFactorPrefix(group_pk, commitment_list, msg);
            const rho_i = bindingFactor(&prefix, identifier);
            const R = try groupCommitment(commitment_list, &prefix);
            const lambda_i = try interpolatingValue(commitment_list, identifier);
            const c = challenge(R, group_pk, msg);
            var hiding = nonces.hiding;
            var binding = nonces.binding;
            if (comptime normalize_even_r) {
                if (!R.hasEvenY()) {
                    hiding = hiding.neg();
                    binding = binding.neg();
                }
            }
            return hiding.add(binding.mul(rho_i)).add(lambda_i.mul(sk_i).mul(c));
        }

        /// Aggregation (RFC 9591 §5.3). `sig_shares[i]` corresponds to
        /// `commitment_list[i]`.
        pub fn aggregate(
            commitment_list: []const Commitment,
            msg: []const u8,
            group_pk: E.Point,
            sig_shares: []const E.Scalar,
        ) !Signature {
            try validateCommitmentList(commitment_list);
            if (sig_shares.len != commitment_list.len) return error.ShareCountMismatch;
            const prefix = bindingFactorPrefix(group_pk, commitment_list, msg);
            var R = try groupCommitment(commitment_list, &prefix);
            if (comptime normalize_even_r) {
                if (!R.hasEvenY()) R = R.neg();
            }
            var z = E.Scalar.zero;
            for (sig_shares) |s| z = z.add(s);
            return .{ .R = R, .z = z };
        }

        /// Identifiable abort (RFC 9591 §5.4): check one participant's share.
        /// `pk_i` is that participant's public key share (f(i) * G, obtainable
        /// from the Feldman commitment).
        pub fn verifySigShare(
            identifier: u16,
            pk_i: E.Point,
            sig_share: E.Scalar,
            group_pk: E.Point,
            msg: []const u8,
            commitment_list: []const Commitment,
        ) !bool {
            try validateCommitmentList(commitment_list);
            const prefix = bindingFactorPrefix(group_pk, commitment_list, msg);
            const R = try groupCommitment(commitment_list, &prefix);
            const c = challenge(R, group_pk, msg);
            const lambda_i = try interpolatingValue(commitment_list, identifier);

            var comm_i: ?Commitment = null;
            for (commitment_list) |cm| {
                if (cm.identifier == identifier) comm_i = cm;
            }
            const cm = comm_i orelse return error.ParticipantNotInList;
            const rho_i = bindingFactor(&prefix, identifier);

            // z_i * G == (D_i + rho_i * E_i) + (c * lambda_i) * X_i
            // (with the commitment term negated when R was normalized to even Y)
            const lhs = E.Point.mulBase(sig_share) catch return false;
            const bound = cm.binding.mulPublic(rho_i) catch return false;
            var commit_term = cm.hiding.add(bound);
            if (comptime normalize_even_r) {
                if (!R.hasEvenY()) commit_term = commit_term.neg();
            }
            const key_term = pk_i.mulPublic(c.mul(lambda_i)) catch return false;
            const rhs = commit_term.add(key_term);
            return lhs.eql(rhs);
        }

        pub fn verify(msg: []const u8, group_pk: E.Point, sig: Signature) bool {
            return Suite.verify(msg, group_pk, sig.R, sig.z);
        }
    };
}

// ---------------------------------------------------------------------------
// RFC 9591 Appendix E test vectors
// ---------------------------------------------------------------------------

fn hexScalar(comptime E: type, comptime hex: []const u8) E.Scalar {
    var b: [E.Scalar.encoded_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return E.Scalar.fromBytes(b) catch unreachable;
}

fn hexPoint(comptime E: type, comptime hex: []const u8) E.Point {
    var b: [E.Point.encoded_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return E.Point.fromBytes(b) catch unreachable;
}

fn hex32(comptime hex: []const u8) [32]u8 {
    var b: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

test "RFC 9591 E.1: FROST(Ed25519, SHA-512)" {
    const F = Frost(Ed25519Sha512);
    const E = curve.Ed25519;

    const group_sk = hexScalar(E, "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304");
    const group_pk = hexPoint(E, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673");
    const msg = [_]u8{ 0x74, 0x65, 0x73, 0x74 }; // "test"

    // sanity: secret key matches public key
    try std.testing.expect((try E.Point.mulBase(group_sk)).eql(group_pk));

    const sk1 = hexScalar(E, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509");
    const sk3 = hexScalar(E, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02");

    // sanity: shares reconstruct the group secret
    const rec = try vss.reconstructAtZero(E, &.{ 1, 3 }, &.{ sk1, sk3 });
    try std.testing.expect(rec.eql(group_sk));

    // round 1
    const r1 = try F.commitDeterministic(
        1,
        sk1,
        hex32("0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec"),
        hex32("69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501"),
    );
    const r3 = try F.commitDeterministic(
        3,
        sk3,
        hex32("86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"),
        hex32("13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"),
    );

    try std.testing.expect(r1.nonces.hiding.eql(hexScalar(E, "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407")));
    try std.testing.expect(r1.nonces.binding.eql(hexScalar(E, "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301")));
    try std.testing.expect(r1.commitment.hiding.eql(hexPoint(E, "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3")));
    try std.testing.expect(r1.commitment.binding.eql(hexPoint(E, "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932")));
    try std.testing.expect(r3.nonces.hiding.eql(hexScalar(E, "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e")));
    try std.testing.expect(r3.nonces.binding.eql(hexScalar(E, "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d")));

    const commitment_list = [_]F.Commitment{ r1.commitment, r3.commitment };

    // round 2
    const z1 = try F.sign(1, sk1, group_pk, r1.nonces, &msg, &commitment_list);
    const z3 = try F.sign(3, sk3, group_pk, r3.nonces, &msg, &commitment_list);
    try std.testing.expect(z1.eql(hexScalar(E, "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603")));
    try std.testing.expect(z3.eql(hexScalar(E, "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007")));

    // identifiable-abort share verification
    const pk1 = try E.Point.mulBase(sk1);
    const pk3 = try E.Point.mulBase(sk3);
    try std.testing.expect(try F.verifySigShare(1, pk1, z1, group_pk, &msg, &commitment_list));
    try std.testing.expect(try F.verifySigShare(3, pk3, z3, group_pk, &msg, &commitment_list));
    try std.testing.expect(!try F.verifySigShare(1, pk1, z3, group_pk, &msg, &commitment_list));

    // aggregate + verify
    const sig = try F.aggregate(&commitment_list, &msg, group_pk, &.{ z1, z3 });
    const expected_sig = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe" ++
        "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_sig);
    try std.testing.expectEqualSlices(u8, &expected, &sig.toBytes());
    try std.testing.expect(F.verify(&msg, group_pk, sig));

    // the signature is a valid RFC 8032 Ed25519 signature under std's verifier
    const StdEd25519 = std.crypto.sign.Ed25519;
    const std_pk = try StdEd25519.PublicKey.fromBytes(group_pk.toBytes());
    const std_sig = StdEd25519.Signature.fromBytes(sig.toBytes());
    try std_sig.verify(&msg, std_pk);

    // tampered message rejected
    try std.testing.expect(!F.verify("tost", group_pk, sig));
}

test "RFC 9591 E.5: FROST(secp256k1, SHA-256)" {
    const F = Frost(Secp256k1Sha256);
    const E = curve.Secp256k1;

    const group_sk = hexScalar(E, "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114");
    const group_pk = hexPoint(E, "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
    const msg = [_]u8{ 0x74, 0x65, 0x73, 0x74 };

    try std.testing.expect((try E.Point.mulBase(group_sk)).eql(group_pk));

    const sk1 = hexScalar(E, "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c");
    const sk3 = hexScalar(E, "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc");
    const rec = try vss.reconstructAtZero(E, &.{ 1, 3 }, &.{ sk1, sk3 });
    try std.testing.expect(rec.eql(group_sk));

    const r1 = try F.commitDeterministic(
        1,
        sk1,
        hex32("7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2"),
        hex32("47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5"),
    );
    const r3 = try F.commitDeterministic(
        3,
        sk3,
        hex32("e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544"),
        hex32("7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9"),
    );

    try std.testing.expect(r1.nonces.hiding.eql(hexScalar(E, "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0")));
    try std.testing.expect(r1.nonces.binding.eql(hexScalar(E, "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80")));
    try std.testing.expect(r1.commitment.hiding.eql(hexPoint(E, "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904")));
    try std.testing.expect(r1.commitment.binding.eql(hexPoint(E, "02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e")));
    try std.testing.expect(r3.nonces.hiding.eql(hexScalar(E, "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2")));
    try std.testing.expect(r3.nonces.binding.eql(hexScalar(E, "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98")));

    const commitment_list = [_]F.Commitment{ r1.commitment, r3.commitment };

    const z1 = try F.sign(1, sk1, group_pk, r1.nonces, &msg, &commitment_list);
    const z3 = try F.sign(3, sk3, group_pk, r3.nonces, &msg, &commitment_list);
    try std.testing.expect(z1.eql(hexScalar(E, "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197")));
    try std.testing.expect(z3.eql(hexScalar(E, "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d")));

    const sig = try F.aggregate(&commitment_list, &msg, group_pk, &.{ z1, z3 });
    const expected_sig = "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14" ++
        "d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324";
    var expected: [65]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_sig);
    try std.testing.expectEqualSlices(u8, &expected, &sig.toBytes());
    try std.testing.expect(F.verify(&msg, group_pk, sig));
    try std.testing.expect(!F.verify("tost", group_pk, sig));
}

test "commitment list validation" {
    const F = Frost(Secp256k1Sha256);
    const E = curve.Secp256k1;
    var prng = std.Random.DefaultPrng.init(5);
    const rng = prng.random();

    const sk = E.Scalar.random(rng);
    const r1 = try F.commit(1, sk, rng);
    const r2 = try F.commit(2, sk, rng);

    // unsorted list rejected
    const unsorted = [_]F.Commitment{ r2.commitment, r1.commitment };
    try std.testing.expectError(error.UnsortedCommitmentList, F.sign(1, sk, E.Point.generator, r1.nonces, "m", &unsorted));

    // duplicate identifier rejected
    const dup = [_]F.Commitment{ r1.commitment, r1.commitment };
    try std.testing.expectError(error.UnsortedCommitmentList, F.sign(1, sk, E.Point.generator, r1.nonces, "m", &dup));
}

test "sign rejects nonces that do not match the commitment list" {
    const F = Frost(Secp256k1Sha256);
    const E = curve.Secp256k1;
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();

    const sk = E.Scalar.random(rng);
    const a = try F.commit(1, sk, rng);
    const b = try F.commit(2, sk, rng);
    const list = [_]F.Commitment{ a.commitment, b.commitment };

    // Signing with a *different* set of nonces than the ones committed in the
    // list is what nonce reuse looks like; it must be rejected, not answered.
    const other = try F.commit(1, sk, rng);
    try std.testing.expectError(
        error.NonceCommitmentMismatch,
        F.sign(1, sk, E.Point.generator, other.nonces, "m", &list),
    );

    // A list that omits the signer's own identifier is rejected too.
    const only_two = [_]F.Commitment{b.commitment};
    try std.testing.expectError(
        error.MissingOwnCommitment,
        F.sign(1, sk, E.Point.generator, a.nonces, "m", &only_two),
    );

    // The matching nonces still sign.
    _ = try F.sign(1, sk, E.Point.generator, a.nonces, "m", &list);
}
