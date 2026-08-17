// Node smoke test for zmpc.wasm: runs the full ceremony - trustless 2-of-3
// DKG among three parties, then two-signer FROST signing - for every suite,
// through the same wrapper the browser demo uses, plus the CGGMP24 ECDSA
// signing path against CLI-produced presignature fixtures.
import { readFile } from "node:fs/promises";
import { Zmpc, SUITES, deliver } from "./ceremony.js";

const wasmBytes = await readFile(new URL("../zig-out/bin/zmpc.wasm", import.meta.url));
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const z = new Zmpc(instance.exports);

let fails = 0;
function ok(cond, what) {
  if (cond) {
    console.log(`  ok    ${what}`);
  } else {
    console.error(`  FAIL  ${what}`);
    fails++;
  }
}
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString("hex");

// ---- full ceremony: 2-of-3 DKG + FROST signing by parties {1,3} ----
const PARTIES = [1, 2, 3];
const SIGNERS = [1, 3];

for (const [name, suite] of Object.entries(SUITES)) {
  console.log(`ceremony: ${name}`);
  const session = z.randomSession();

  // DKG round 1: every party commits; one broadcast frame each.
  const r1 = new Map(PARTIES.map((p) => [p, z.dkgRound1(suite, p, 3, 2, session)]));
  ok(
    z.frameName(r1.get(1).frames[0]).endsWith("-dkg-r1-b-f1-t0.zmpc"),
    "round-1 frame is named like the CLI's",
  );
  let inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r1.get(p).frames])), PARTIES);

  // Round 2: open commitments, send each peer its secret share (p2p).
  const r2 = new Map(PARTIES.map((p) => [p, z.dkgRound2(suite, r1.get(p).state, inboxes.get(p))]));
  const p2p = r2.get(1).frames.filter((f) => z.frameMeta(f).channel === "p2p");
  ok(p2p.length === 2 && new Set(p2p.map((f) => z.frameMeta(f).to)).size === 2,
    "round 2 emits one addressed share per peer");
  inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r2.get(p).frames])), PARTIES);

  // Round 3: verify everything received.
  const r3 = new Map(PARTIES.map((p) => [p, z.dkgRound3(suite, r2.get(p).state, inboxes.get(p))]));
  inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r3.get(p).frames])), PARTIES);

  // Finalize: every party gets its share; all agree on the public key.
  const fin = new Map(PARTIES.map((p) => [p, z.dkgFinalize(suite, r3.get(p).state, inboxes.get(p))]));
  const pk = fin.get(1).pubkey;
  ok(
    PARTIES.every((p) => hex(fin.get(p).pubkey) === hex(pk)),
    `all parties agree on the public key (${hex(pk).slice(0, 16)}...)`,
  );
  ok(hex(z.sharePubkey(fin.get(2).keyshare)) === hex(pk), "share_pubkey reads it back");

  // FROST signing by parties 1 and 3.
  const msg = utf8(`pay 1 SOL to alice (${name})`);
  const signSession = z.randomSession();
  const commits = new Map(SIGNERS.map((p) => [p, z.signCommit(suite, fin.get(p).keyshare, msg, signSession)]));
  const commitFrames = SIGNERS.map((p) => commits.get(p).frames[0]);

  const shares = new Map(SIGNERS.map((p) => [
    p,
    z.signShare(suite, commits.get(p).state, fin.get(p).keyshare, msg, commitFrames),
  ]));
  ok(commits.get(1).state.every((b) => b === 0), "nonce state is zeroed after signing");
  const shareFrames = SIGNERS.map((p) => shares.get(p).frames[0]);

  const sig = z.signAggregate(suite, fin.get(1).keyshare, msg, commitFrames, shareFrames);
  ok(z.verify(suite, pk, msg, sig) === 0, `signature verifies (${sig.length} bytes)`);
  ok(z.verify(suite, pk, utf8("tampered"), sig) === -3, "tampered message is rejected");

  // Reusing the (now zeroed) nonce state must fail, not sign again.
  let reused = false;
  try {
    z.signShare(suite, commits.get(1).state, fin.get(1).keyshare, msg, commitFrames);
    reused = true;
  } catch {}
  ok(!reused, "zeroed nonce state cannot sign again");
}

// ---- independent verifiers ----
{
  // Ed25519: the threshold signature must verify under Node's own crypto.
  const suite = SUITES.ed25519;
  const session = z.randomSession();
  const r1 = new Map(PARTIES.map((p) => [p, z.dkgRound1(suite, p, 3, 2, session)]));
  let inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r1.get(p).frames])), PARTIES);
  const r2 = new Map(PARTIES.map((p) => [p, z.dkgRound2(suite, r1.get(p).state, inboxes.get(p))]));
  inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r2.get(p).frames])), PARTIES);
  const r3 = new Map(PARTIES.map((p) => [p, z.dkgRound3(suite, r2.get(p).state, inboxes.get(p))]));
  inboxes = deliver(z, new Map(PARTIES.map((p) => [p, r3.get(p).frames])), PARTIES);
  const fin = new Map(PARTIES.map((p) => [p, z.dkgFinalize(suite, r3.get(p).state, inboxes.get(p))]));

  const msg = utf8("independent verification");
  const signSession = z.randomSession();
  const commits = new Map(SIGNERS.map((p) => [p, z.signCommit(suite, fin.get(p).keyshare, msg, signSession)]));
  const commitFrames = SIGNERS.map((p) => commits.get(p).frames[0]);
  const shareFrames = SIGNERS.map(
    (p) => z.signShare(suite, commits.get(p).state, fin.get(p).keyshare, msg, commitFrames).frames[0],
  );
  const sig = z.signAggregate(suite, fin.get(1).keyshare, msg, commitFrames, shareFrames);

  const { createPublicKey, verify: nodeVerify } = await import("node:crypto");
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(fin.get(1).pubkey),
  ]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  ok(nodeVerify(null, msg, key, sig), "node crypto accepts the DKG'd threshold Ed25519 signature");
}

// ---- CGGMP24 ECDSA: sign with a presignature, combine, verify ----
// Fixtures: two presignature.zmpc frames from a `zmpc presign` run over a
// throwaway 2-of-3 ecdsa_fast key (signers {1,3}), the group public key, and
// the message those presignatures were produced to sign.
{
  console.log("ecdsa: presignature signing");
  const fromHex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
  const presigs = [
    fromHex(
      "5a4d50430105020006000101000001000000030002003c00e38c9606931e009f668ea59ff5e99bfbc8415dde4778df6443756cec370e7cb261000000027662bd15febede549ac807e5209a2251388160c6c20ddc303505c36b17070ab9a03cbc9eabea264edef5453ad980c618bcf163bb22fcf92b0108701cb39ec7b05dbc5969dd3f08e4155973462a90e9c565f71afbeba2adf3eca37e33b08de344db7c95c667b5980104bfaca9b66f71d7c179568037b67d298731052c97136eaf",
    ),
    fromHex(
      "5a4d50430105020006000101000003000000030002003c00e38c9606931e009f668ea59ff5e99bfbc8415dde4778df6443756cec370e7cb261000000027662bd15febede549ac807e5209a2251388160c6c20ddc303505c36b17070ab93c908d1d561f4c6879e5bd26bdcdad6cf5b04fc79f45c037038fc359e361635ce2d4b6d9f53066e825f81038f113546404a399b44805eeb47495f50a991aa2f3f87c27ef47b2239e62bd9079c7cb022cd48d61030c95143f67baced0aae0810f",
    ),
  ];
  const pk = fromHex("029a68b07a649f7dbb24f20af8eb93f2ab0f77f93629104788a817f37bbcc02f30");
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", utf8("transfer 0.1 ETH to bob")),
  );

  const partials = presigs.map((p) => z.ecdsaPartialSign(p, digest));
  const sig = z.ecdsaCombine(partials, digest, pk);
  ok(z.ecdsaVerify(pk, digest, sig) === 0, "combined ECDSA signature verifies");
  const bad = Uint8Array.from(digest);
  bad[0] ^= 1;
  ok(z.ecdsaVerify(pk, bad, sig) === -3, "tampered ECDSA digest is rejected");

  // cross-check with Node's own secp256k1 ECDSA (independent verifier)
  const { createPublicKey, createVerify } = await import("node:crypto");
  const der = (() => {
    const int = (b) => {
      let i = 0;
      while (i < 31 && b[i] === 0) i++;
      const body = b[i] & 0x80 ? Buffer.concat([Buffer.from([0]), b.slice(i)]) : Buffer.from(b.slice(i));
      return Buffer.concat([Buffer.from([0x02, body.length]), body]);
    };
    const rr = int(sig.slice(0, 32));
    const ss = int(sig.slice(32));
    return Buffer.concat([Buffer.from([0x30, rr.length + ss.length]), rr, ss]);
  })();
  const spki = Buffer.concat([
    Buffer.from("3036301006072a8648ce3d020106052b8104000a032200", "hex"),
    Buffer.from(pk),
  ]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  const v = createVerify("sha256");
  v.update(utf8("transfer 0.1 ETH to bob"));
  ok(v.verify(key, der), "node crypto accepts the threshold ECDSA signature");
}

if (fails === 0) {
  console.log("wasm smoke test: all checks passed");
} else {
  console.error(`wasm smoke test: ${fails} failure(s)`);
  process.exit(1);
}
