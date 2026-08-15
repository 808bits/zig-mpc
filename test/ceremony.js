// Thin JS wrapper over zmpc.wasm's exports: staging buffers in linear
// memory, reading back the output registry, and naming each protocol step.
// Shared by the browser demo (inlined by build.sh) and the node smoke test.
//
// Every function taking `frames` accepts an array of Uint8Array wire frames -
// the same bytes the zmpc CLI writes as files. Round state is an opaque
// secret blob the caller holds between rounds and never sends anywhere.

export const SUITES = { ed25519: 0x0001, secp256k1: 0x0002, taproot: 0x0005 };
export const SUITE_NAMES = { 1: "ed25519", 2: "secp256k1", 5: "taproot" };
export const KINDS = {
  1: "message", 2: "state", 3: "key_share", 4: "aux_info",
  5: "presignature", 6: "primes", 7: "hello", 8: "signature",
};
export const CHANNELS = { 0: "broadcast", 1: "p2p", 2: "artifact" };
export const PROTOCOLS = { 1: "dkg", 2: "refresh", 3: "auxgen", 4: "presign", 5: "sign", 6: "none" };

export class Zmpc {
  constructor(wasmExports) {
    this.ex = wasmExports;
  }

  /// Views over linear memory are only valid until the next allocation: any
  /// `alloc` (or any export that allocates internally) can grow the memory and
  /// detach every view taken before it. Always take one of these after the
  /// last allocation, and never hold one across a call into wasm.
  mem() {
    return new Uint8Array(this.ex.memory.buffer);
  }

  view() {
    return new DataView(this.ex.memory.buffer);
  }

  alloc(bytesOrLen) {
    const len = typeof bytesOrLen === "number" ? bytesOrLen : bytesOrLen.length;
    const ptr = this.ex.zmpc_alloc(len);
    if (!ptr) throw new Error("zmpc_alloc failed");
    if (typeof bytesOrLen !== "number") this.mem().set(bytesOrLen, ptr);
    return ptr;
  }

  free(ptr, len) {
    this.ex.zmpc_free(ptr, len);
  }

  read(ptr, len) {
    return this.mem().slice(ptr, ptr + len);
  }

  /// Stage an array of buffers; returns pointers to parallel u32 arrays.
  ///
  /// Every buffer is staged before the first write: `alloc` can grow linear
  /// memory, and growing it detaches any view taken beforehand. Pointers
  /// survive growth (they are offsets), so only the view has to be taken late.
  stageList(buffers) {
    const ptrs = this.alloc(4 * buffers.length);
    const lens = this.alloc(4 * buffers.length);
    const staged = buffers.map((b) => this.alloc(b));
    const v = this.view();
    staged.forEach((p, i) => {
      v.setUint32(ptrs + 4 * i, p, true);
      v.setUint32(lens + 4 * i, buffers[i].length, true);
    });
    return { ptrs, lens, count: buffers.length };
  }

  /// Copy the output registry out of linear memory.
  outputs() {
    const n = this.ex.zmpc_out_count();
    const out = [];
    for (let i = 0; i < n; i++) {
      out.push(this.read(this.ex.zmpc_out_ptr(i), this.ex.zmpc_out_len(i)));
    }
    this.ex.zmpc_out_clear();
    return out;
  }

  check(rc, what) {
    if (rc !== 0) throw new Error(`${what} failed (rc=${rc})`);
  }

  randomSession() {
    const id = new Uint8Array(32);
    globalThis.crypto.getRandomValues(id);
    return id;
  }

  entropy() {
    const e = new Uint8Array(32);
    globalThis.crypto.getRandomValues(e);
    return e;
  }

  // -- introspection ---------------------------------------------------------

  frameMeta(bytes) {
    const out = this.alloc(18);
    this.check(this.ex.zmpc_frame_meta(this.alloc(bytes), bytes.length, out), "frame_meta");
    const v = this.view();
    const u16 = (i) => v.getUint16(out + 2 * i, true);
    return {
      kind: KINDS[u16(0)] ?? u16(0),
      channel: CHANNELS[u16(1)] ?? u16(1),
      protocol: PROTOCOLS[u16(2)] ?? u16(2),
      suite: SUITE_NAMES[u16(3)] ?? u16(3),
      round: u16(4),
      from: u16(5),
      to: u16(6),
      n: u16(7),
      threshold: u16(8),
    };
  }

  frameName(bytes) {
    const out = this.alloc(64);
    const outLen = this.alloc(4);
    this.check(this.ex.zmpc_frame_name(this.alloc(bytes), bytes.length, out, outLen), "frame_name");
    return new TextDecoder().decode(this.read(out, this.view().getUint32(outLen, true)));
  }

  sharePubkey(shareFrame) {
    const out = this.alloc(33);
    const outLen = this.alloc(4);
    this.check(this.ex.zmpc_share_pubkey(this.alloc(shareFrame), shareFrame.length, out, outLen), "share_pubkey");
    return this.read(out, this.view().getUint32(outLen, true));
  }

  // -- DKG -------------------------------------------------------------------

  dkgRound1(suite, party, n, threshold, session) {
    const rc = this.ex.zmpc_dkg_round1(suite, party, n, threshold, this.alloc(session), this.alloc(this.entropy()));
    this.check(rc, `dkg round1 (party ${party})`);
    const [state, bc] = this.outputs();
    return { state, frames: [bc] };
  }

  dkgRound2(suite, state, frames) {
    const list = this.stageList(frames);
    const rc = this.ex.zmpc_dkg_round2(suite, this.alloc(state), state.length, list.ptrs, list.lens, list.count);
    this.check(rc, "dkg round2");
    const [next, ...out] = this.outputs();
    return { state: next, frames: out };
  }

  dkgRound3(suite, state, frames) {
    const list = this.stageList(frames);
    const rc = this.ex.zmpc_dkg_round3(suite, this.alloc(state), state.length, list.ptrs, list.lens, list.count);
    this.check(rc, "dkg round3");
    const [next, bc] = this.outputs();
    return { state: next, frames: [bc] };
  }

  dkgFinalize(suite, state, frames) {
    const list = this.stageList(frames);
    const pk = this.alloc(33);
    const pkLen = this.alloc(4);
    const rc = this.ex.zmpc_dkg_finalize(suite, this.alloc(state), state.length, list.ptrs, list.lens, list.count, pk, pkLen);
    this.check(rc, "dkg finalize");
    const [keyshare] = this.outputs();
    return { keyshare, pubkey: this.read(pk, this.view().getUint32(pkLen, true)) };
  }

  // -- FROST signing ---------------------------------------------------------

  signCommit(suite, keyshare, msg, session) {
    const rc = this.ex.zmpc_sign_commit(
      suite, this.alloc(keyshare), keyshare.length, this.alloc(msg), msg.length,
      this.alloc(session), this.alloc(this.entropy()),
    );
    this.check(rc, "sign commit");
    const [state, commit] = this.outputs();
    return { state, frames: [commit] };
  }

  /// Consumes (zeroes) the wasm-side copy of `state`; the caller should
  /// discard its own copy too - FROST nonces are single-use.
  signShare(suite, state, keyshare, msg, commitFrames) {
    const list = this.stageList(commitFrames);
    const statePtr = this.alloc(state);
    const rc = this.ex.zmpc_sign_share(
      suite, statePtr, state.length, this.alloc(keyshare), keyshare.length,
      this.alloc(msg), msg.length, list.ptrs, list.lens, list.count,
    );
    this.check(rc, "sign share");
    state.fill(0);
    const [share] = this.outputs();
    return { frames: [share] };
  }

  signAggregate(suite, keyshare, msg, commitFrames, shareFrames) {
    const commits = this.stageList(commitFrames);
    const shares = this.stageList(shareFrames);
    const sig = this.alloc(65);
    const sigLen = this.alloc(4);
    const rc = this.ex.zmpc_sign_aggregate(
      suite, this.alloc(keyshare), keyshare.length, this.alloc(msg), msg.length,
      commits.ptrs, commits.lens, shares.ptrs, shares.lens, commits.count,
      sig, sigLen,
    );
    this.check(rc, "sign aggregate");
    return this.read(sig, this.view().getUint32(sigLen, true));
  }

  verify(suite, pubkey, msg, sig) {
    return this.ex.zmpc_verify(
      suite, this.alloc(pubkey), pubkey.length, this.alloc(msg), msg.length,
      this.alloc(sig), sig.length,
    );
  }

  // -- CGGMP24 ECDSA (signing with a CLI-produced presignature) -------------

  ecdsaPartialSign(presigFrame, digest32) {
    const p = this.alloc(presigFrame);
    const slots = this.alloc(8);
    const rc = this.ex.zmpc_ecdsa_partial_sign(p, presigFrame.length, this.alloc(digest32), slots, slots + 4);
    this.check(rc, "ecdsa partial_sign");
    return this.read(this.view().getUint32(slots, true), this.view().getUint32(slots + 4, true));
  }

  ecdsaCombine(partialFrames, digest32, pk33) {
    const list = this.stageList(partialFrames);
    const sig = this.alloc(64);
    const rc = this.ex.zmpc_ecdsa_combine(
      list.ptrs, list.lens, list.count, this.alloc(digest32),
      pk33 ? this.alloc(pk33) : 0, sig,
    );
    this.check(rc, "ecdsa combine");
    return this.read(sig, 64);
  }

  ecdsaVerify(pk33, digest32, sig64) {
    return this.ex.zmpc_ecdsa_verify(this.alloc(pk33), this.alloc(digest32), this.alloc(sig64));
  }
}

/// Deliver frames the way the CLI's e2e test does: a broadcast frame goes to
/// every other party's inbox; a p2p frame only to the party it names.
/// `outboxes` is a Map/object of party -> frames; returns party -> inbox.
export function deliver(zmpc, outboxes, parties) {
  const inboxes = new Map(parties.map((p) => [p, []]));
  for (const from of parties) {
    for (const f of outboxes.get(from) ?? []) {
      const meta = zmpc.frameMeta(f);
      for (const to of parties) {
        if (to === from) continue;
        if (meta.to === 0 || meta.to === to) inboxes.get(to).push(f);
      }
    }
  }
  return inboxes;
}
