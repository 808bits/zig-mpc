# zig-mpc

Threshold signing in Zig, built on the standard library's cryptography:

| Scheme | Chains | Protocol | Validation |
|---|---|---|---|
| **EdDSA Ed25519** | Solana, Cardano, TON, Near | FROST (RFC 9591) | RFC 9591 vectors byte-exact; verifies under `std.crypto`'s Ed25519 |
| **Schnorr BIP-340** | Bitcoin Taproot | FROST (Taproot mode) | all 19 official BIP-340 vectors; threshold sigs verify as plain BIP-340 |
| **ECDSA secp256k1** | Bitcoin, Ethereum, EVM, Cosmos | CGGMP24 | end-to-end presign+sign; verifies under `std.crypto`'s ECDSA |

Plus: trustless 3-round DKG (curve-generic, shared by FROST and CGGMP),
proactive key refresh, BIP-32/SLIP-10 non-hardened HD derivation
(SLIP-10 vectors), a canonical wire format for every protocol message, a
WebAssembly build that runs the full ceremony (DKG, FROST signing, CGGMP24
signing) in a browser or Node, and `zmpc`, a CLI that runs each party as its
own process on its own machine.

**Status: pre-audit.** Complete and tested, but never audited and not yet
hardened (see Roadmap). Do not deploy against real funds.

## `zmpc` - the CLI

Key generation and signing happen on different machines. Each party owns a
session directory; each protocol round is one command that reads the messages
that have arrived and writes the ones it produces.

```
zmpc init --dir p1 --suite ed25519 --party 1 --n 3 --threshold 2
  # prints a session id; every other party passes it with --session

zmpc dkg round1 --dir p1     # ... deliver frames ...
zmpc dkg round2 --dir p1
zmpc dkg round3 --dir p1
zmpc dkg finalize --dir p1   # writes artifacts/keyshare.zmpc, prints the public key
```

Then, on any two of the three machines:

```
zmpc sign init --dir s1 --share p1/artifacts/keyshare.zmpc \
      --signers 1,3 --msg-file tx.bin
zmpc sign commit --dir s1
zmpc sign share --dir s1
zmpc sign aggregate --dir s1        # writes artifacts/signature.bin

zmpc verify --suite ed25519 --pubkey <hex> --msg-file tx.bin --sig signature.bin
```

Creating a session needs an explicit `--dir`, so that `zmpc init` never
scatters `session.json`, `in/`, `out/`, `state/` and `artifacts/` into
whatever directory you were standing in; pass `--dir .` if you do mean here.
Every other command defaults `--dir` to `.`. To drive several parties from
one directory without repeating the flag, export `ZMPC_DIR` in a shell per
party:

```
export ZMPC_DIR=party1
zmpc init --suite ed25519 --party 1 --n 3 --threshold 2
zmpc dkg run                  # no --dir needed; --dir still wins if given
```

`zmpc help` lists every command and the order they run in.
`zmpc help <command>`, or equivalently `zmpc <command> --help`, documents
every option that command takes; `zmpc help suites` explains which suite to
pick and `zmpc help exit` what each exit code means. `zig build cli -- <args>`
runs it from the source tree; `zig build` installs it to `zig-out/bin/zmpc`.

### How the processes talk

```
session-dir/
  session.json   who this party is, which run this is
  in/            frames received from peers
  out/           frames this party produced
  state/         round state carried between invocations  (SECRET, 0600)
  artifacts/     key share, aux info, presignatures, signatures
```

A round reads `in/` and `state/`, then writes `out/` and `state/`. Getting
one party's `out/` into its peers' `in/` is deliberately not zmpc's job.
Frames are inert, self-describing files named identically on both sides, so
delivery is a plain copy (`scp`, a shared mount, a USB stick for an
air-gapped signer) or the built-in relay:

```
zmpc relay --listen 0.0.0.0:7000 --spool /var/lib/zmpc     # on a hub
zmpc node --dir p1 --relay hub:7000                        # on each party
```

`zmpc node` runs a whole protocol to completion, pushing and pulling the exact
same frames the file mode writes. The relay's spool is byte-identical to what
a session's `out/` contains, so you can switch transports mid-protocol.
`zmpc push` / `zmpc pull` expose the two halves if you want to drive the loop
yourself.

Exit codes are meaningful: 75 means "still waiting for messages" (retry
later), 65 means the protocol aborted, 2 is a usage error.

Add `--armor` to write frames as base64 text instead of binary, for transports
that mangle bytes. `zmpc inspect <file>` decodes any frame's header.

### Command reference

Suites: `ed25519`, `secp256k1`, `taproot`, `p256`, `p384` (keygen only),
`ecdsa_fast` and `ecdsa_prod` for CGGMP24.

Four options are accepted by every command:

| option | meaning |
|---|---|
| `--dir DIR` | the session directory to operate on (default: `$ZMPC_DIR`, else `.`; required when creating a session) |
| `--armor` | write frames as base64 text (`.zmpc.asc`) instead of binary |
| `--json` | machine-readable result on stdout, human text on stderr |
| `--quiet` | suppress progress notes |

`ZMPC_DIR` is the only environment variable zmpc reads: it supplies `--dir`
when the flag is absent, so one shell per party can drop the flag entirely.

Exit codes: `0` success, `1` internal error, `2` usage error, `64` unreadable
or malformed input, `65` protocol abort (bad proof, share, or signature),
`75` waiting on messages from peers; deliver frames and re-run.

#### Sessions

**`zmpc init`** - create a session directory for one party.

| option | meaning |
|---|---|
| `--suite S` | required; one of the suites above |
| `--party I` | required; this party's index, `1..n` |
| `--n N` | required; how many parties in total (at least 2) |
| `--threshold T` | required; how many are needed to sign, `1..n` |
| `--dir D` | required; where to create the session (`--dir .` for here). `ZMPC_DIR` satisfies it too |
| `--protocol P` | `dkg` (default) or `auxgen`; `refresh`, `presign` and `sign` sessions are created by their own `init` subcommands instead |
| `--session HEX` | the 64-hex run id printed by the first party's `init`; omit to mint a new one |

**`zmpc status`** - report this session's round progress, inbox contents, and
exactly which frames the next round is still waiting for. The `next` line
spells out the command to run, ready to paste:

```
state     1 round(s) done
next      zmpc dkg round2 --dir p1
ready     no - deliver the frames below first
```

Under `--json` the same thing appears as `"next_step":"round2"`, or `null`
once the session is complete. No options beyond the common four.

#### Protocol rounds

Each protocol is a family of subcommands, one per round. Every round command
takes `--dir`; a round that lacks its inputs exits `75` and lists what is
missing. `run` executes every round whose inputs have arrived and stops at
the first one still waiting, so with frame delivery in between, calling `run`
repeatedly on each machine completes the whole protocol.

**`zmpc dkg round1|round2|round3|finalize|run`** - distributed key
generation, any suite. `finalize` writes `artifacts/keyshare.zmpc` and prints
the group public key. No options beyond the common four.

**`zmpc refresh init|round1|round2|finalize|run`** - proactive share
refresh: same public key, new shares, old shares dead. Every party of the key
must take part. `finalize` rewrites `artifacts/keyshare.zmpc` and keeps the
previous share as `keyshare.zmpc.old`.

| option | meaning |
|---|---|
| `--share FILE` | `init`: required; the key share to refresh. Rounds: override the recorded path |
| `--session HEX` | `init`: join the run started by the first party |

**`zmpc auxgen primes|round1|round2|round3|finalize|run`** - CGGMP24
auxiliary info (Paillier keys, ring-Pedersen parameters, ZK proofs).
`finalize` writes `artifacts/auxinfo.zmpc`. The session is created with
`zmpc init --protocol auxgen`.

| option | meaning |
|---|---|
| `--primes FILE` | rounds: use pre-generated primes instead of generating during round1 |
| `--suite S` | `primes` only: required |
| `--out FILE` | `primes` only: where to write (default: `primes.zmpc`) |

**`zmpc presign init|round1|round2|round3|finalize|run`** - CGGMP24
presigning; message-independent, so it can run ahead of time. `finalize`
writes `artifacts/presignature.zmpc`, which `zmpc ecdsa sign` later consumes.

| option | meaning |
|---|---|
| `--share FILE` | `init`: required; an `ecdsa_fast`/`ecdsa_prod` key share |
| `--aux FILE` | `init`: required; this party's `auxinfo.zmpc`. Rounds: override |
| `--signers 1,3` | `init`: required; the exact signing set, which must include this party |
| `--session HEX` | `init`: join the run started by the first signer |

**`zmpc sign init|commit|share|aggregate|run`** - FROST two-round signing
(`ed25519`, `secp256k1`, `taproot` shares). `share` destroys the nonces as it
emits the signature share; `aggregate` writes `artifacts/signature.bin`.

| option | meaning |
|---|---|
| `--share FILE` | `init`: required; the key share to sign with. Rounds: override |
| `--signers 1,3` | `init`: required; must include this party, at least `threshold` entries |
| `--msg-file FILE` / `--msg-hex HEX` | `init`: required; the exact bytes to sign, identical for every signer |
| `--session HEX` | `init`: join the run started by the first signer |

#### Signing and keys

**`zmpc ecdsa sign`** - produce one party's partial ECDSA signature from a
presignature. The presignature is deleted as it is consumed.

| option | meaning |
|---|---|
| `--presig FILE` | required; a `presignature.zmpc` |
| `--msg-file` / `--msg-hex` / `--digest HEX` | the message (SHA-256 is applied), or the 32-byte digest directly |
| `--out FILE` | where to write the partial (default: `partial.zmpc`) |
| `--keep` | keep the presignature (testing only; signing two messages with one presignature reveals the key) |

**`zmpc ecdsa combine`** - combine the partials into a signature.

| option | meaning |
|---|---|
| `--partials a.zmpc,b.zmpc` | required; every signer's partial |
| `--msg-file` / `--msg-hex` / `--digest HEX` | the same message the partials signed |
| `--pubkey-share FILE` | a key share whose public key verifies the result (recommended) |
| `--out FILE` | where to write (default: `signature.bin`) |

**`zmpc ecdsa verify`** - check an ECDSA signature. `--pubkey HEX` (SEC1),
`--sig FILE`, and the message as above.

**`zmpc verify`** - check a FROST/Taproot signature against a public key
alone. `--suite S`, `--pubkey HEX`, `--sig FILE`, `--msg-file`/`--msg-hex`;
all but the message required.

**`zmpc share info|pubkey|verify`** - print a key share's metadata, print
just its public key, or check the share against its own VSS commitment. Takes
`--share FILE`, or `--dir DIR` to use that session's `artifacts/keyshare.zmpc`.

**`zmpc hd pubkey|derive`** - BIP-32/SLIP-10 non-hardened derivation.
`pubkey` prints the child public key; `derive` writes a child key share that
signs for it.

| option | meaning |
|---|---|
| `--share FILE` | the parent share (or `--dir` as with `share`) |
| `--path m/44/0/7` | required; hardened segments (`44'`) are refused |
| `--out FILE` | required for `derive`; where to write the child share |

#### Primitives

Hex in, hex out; these compose with ordinary shell tools.

**`zmpc bip340 pubkey|sign|verify`** - single-signer BIP-340.

| option | meaning |
|---|---|
| `--sk HEX` | `pubkey`, `sign`: the 32-byte secret key |
| `--msg-file` / `--msg-hex` | `sign`, `verify`: the message |
| `--aux HEX` | `sign`: fixed 32-byte auxiliary randomness (default: fresh random) |
| `--pubkey HEX` | `verify`: the 32-byte x-only key |
| `--sig HEX\|FILE` | `verify`: 64 bytes of hex, or a file holding them |

**`zmpc paillier keygen|encrypt|decrypt|add|mul|addplain`** - the Paillier
cryptosystem with its homomorphisms.

| option | meaning |
|---|---|
| `--bits B` | prime size: 128, 256, 512 (default) or 1024; the modulus is twice that |
| `--out FILE` | `keygen`: write the key file (0600) instead of printing it |
| `--key FILE` | a `keygen` key file; `decrypt` needs it for `p` and `q` |
| `--n HEX` | the public modulus, if not using `--key` |
| `--m HEX` | `encrypt`: the plaintext |
| `--r HEX` | `encrypt`: fixed nonce for reproducibility (test vectors only) |
| `--c HEX`, `--c2 HEX` | ciphertext operands |
| `--k HEX` | `mul`, `addplain`: the plaintext scalar |

**`zmpc vss split|reconstruct|verify`** - Shamir/Feldman secret sharing.

| option | meaning |
|---|---|
| `--curve C` | any suite name (default: `secp256k1`) |
| `--t T`, `--n N` | `split`: required; threshold and share count |
| `--secret HEX` | `split`: the scalar to share (default: random) |
| `--shares 1:HEX,3:HEX` | `reconstruct`: `index:value` pairs, at least `t` of them |
| `--index I`, `--share HEX` | `verify`: the share to check |
| `--commitment HEX,HEX` | `verify`: the Feldman commitment points |

**`zmpc ffx prime|isprime|jacobi|gcd|inverse|sqrt|divrem`** - the
big-integer layer the ZK proofs are built on.

| option | meaning |
|---|---|
| `--bits B` | `prime`: size to generate (default: 256) |
| `--blum` | `prime`: p = 3 mod 4, as Paillier-Blum moduli require |
| `--safe` | `prime`: a safe prime p = 2q + 1 (slow) |
| `--a`, `--b`, `--n`, `--m` | hex operands, per operation |

**`zmpc transcript hash`** - the Fiat-Shamir transcript hash, for
cross-checking another implementation.

| option | meaning |
|---|---|
| `--domain D` | domain-separation tag, mixed in first |
| `--append label=HEX` | append labelled bytes; repeatable, order matters |
| `--u64 label=N` | append a labelled integer; repeatable |

#### Relay transport (optional)

**`zmpc relay`** - the store-and-forward TCP hub. `--listen HOST:PORT`
(default `127.0.0.1:7000`), `--spool DIR` (default `zmpc-spool`).

**`zmpc push`** / **`zmpc pull`** - upload this session's `out/` to a relay /
download frames addressed to this party into `in/`. Both take `--relay
HOST:PORT` (required) and `--dir`.

**`zmpc node`** - run this session's whole protocol to completion over a
relay: run what's ready, push, pull, repeat.

| option | meaning |
|---|---|
| `--relay HOST:PORT` | required |
| `--share`, `--aux`, `--primes` | forwarded to the protocol rounds, as above |
| `--poll-ms MS` | delay between pulls while waiting (default: 500) |
| `--timeout-s S` | give up after this long with no progress (default: 600) |

#### Tools

**`zmpc simulate keygen|frost|taproot|hd|refresh|ecdsa|all`** - whole
protocols in one process; see [In-process runs](#in-process-runs). `--via
memory|frames` (default: `frames`).

**`zmpc selftest`** - known-answer vectors through this binary. `--quick`
skips the live protocol runs.

**`zmpc inspect FILE`** - decode any frame's header: kind, protocol, round,
sender, recipient, session, payload size.

**`zmpc version`**, **`zmpc help [command|suites|exit]`**.

### Example ceremony: a 2-of-3 ECDSA key over TCP

This walkthrough creates one secp256k1 ECDSA key (the kind Bitcoin,
Ethereum and every EVM chain use) split across three holders: alice
(party 1), bob (party 2), carol (party 3). Any two can sign; no machine
ever holds the whole private key, at any point, including during key
generation. Alice and carol then sign a transaction.

Frames travel over the built-in TCP relay, so nothing is copied by hand:
every block below can be pasted into a shell as-is. The demo runs on one
machine with one folder per party; on a real deployment each party pastes
only its own lines on its own machine, and `127.0.0.1` becomes the hub's
address. The whole run takes a minute or two; CGGMP24 spends its time on
Paillier keys and ZK proofs, not on the network.

The demo uses `--suite ecdsa_fast`, which is not a security level. For
anything real, use `ecdsa_prod` and pre-generate its primes offline
(`zmpc auxgen primes`, see [parameter sets](#cggmp24-parameter-sets)).

#### The relay hub

In a separate terminal (or on any machine every party can reach), start the
store-and-forward hub:

```sh
zmpc relay --listen 127.0.0.1:7100 --spool spool
```

The relay holds no keys and does no cryptography; its spool contains the
same inert frames a session's `out/` does, grouped per session id. But it
*sees* every frame, and DKG's point-to-point frames carry secret shares, so
in production the relay link needs a tunnel (see
[Security properties](#security-properties-you-have-to-provide)).

#### Phase 1 - key generation (all three parties)

Alice's `init` mints the ceremony's session id; the other parties join with
`--session`. On separate machines the id travels by chat or email; it
identifies the run, it is not a secret. Then each party runs one `zmpc node`
command, which executes every DKG round, pushing and pulling frames through
the relay until the protocol completes:

```sh
SID=$(zmpc init --dir alice-key --suite ecdsa_fast --party 1 --n 3 --threshold 2 --quiet)
zmpc init --dir bob-key   --suite ecdsa_fast --party 2 --n 3 --threshold 2 --session "$SID" --quiet
zmpc init --dir carol-key --suite ecdsa_fast --party 3 --n 3 --threshold 2 --session "$SID" --quiet

zmpc node --dir alice-key --relay 127.0.0.1:7100 --quiet &
zmpc node --dir bob-key   --relay 127.0.0.1:7100 --quiet &
zmpc node --dir carol-key --relay 127.0.0.1:7100 --quiet &
wait
```

Each party's directory now holds the one artifact that matters, plus the
spent protocol frames:

```
alice-key/
  session.json                          this party's manifest
  artifacts/keyshare.zmpc               the result: secret, never leaves this machine
  out/cad056d4-dkg-r1-b-f1-t0.zmpc      frames alice sent    (delivered by the relay)
  out/...                               (r2 broadcast, r2 p2p to parties 2 and 3, r3)
  in/cad056d4-dkg-r1-b-f2-t0.zmpc       frames alice received
  in/...
```

These are the same files the manual `cp` transport would produce. The frame
name encodes protocol, round, sender and recipient (`-t0` broadcast, `-tN`
point-to-point for party N), and `zmpc inspect` decodes any of them. The
secret `state/` files that existed between rounds were deleted when finalize
consumed them.

Every machine must report the same public key, and each share should check
out against its own commitment:

```sh
PK=$(zmpc share pubkey --dir alice-key)
echo "$PK"                              # 02fde939...86c2, 33-byte SEC1, same on all three
zmpc share pubkey --dir carol-key       # must match
zmpc share verify --dir bob-key
```

#### Phase 2 - auxiliary info (all three parties)

CGGMP24 signing needs per-party Paillier keys and ring-Pedersen parameters,
each proved well-formed to the others in zero knowledge. This is a one-time
setup after keygen, structurally identical to phase 1; only the
`--protocol auxgen` flag differs:

```sh
SIDX=$(zmpc init --dir alice-aux --protocol auxgen --suite ecdsa_fast --party 1 --n 3 --threshold 2 --quiet)
zmpc init --dir bob-aux   --protocol auxgen --suite ecdsa_fast --party 2 --n 3 --threshold 2 --session "$SIDX" --quiet
zmpc init --dir carol-aux --protocol auxgen --suite ecdsa_fast --party 3 --n 3 --threshold 2 --session "$SIDX" --quiet

zmpc node --dir alice-aux --relay 127.0.0.1:7100 --quiet &
zmpc node --dir bob-aux   --relay 127.0.0.1:7100 --quiet &
zmpc node --dir carol-aux --relay 127.0.0.1:7100 --quiet &
wait
```

Each party gets `artifacts/auxinfo.zmpc` (its Paillier decryption key -
secret, stays put) and `artifacts/primes.zmpc` (the generated primes, cached
so a future auxgen can reuse them).

#### Phase 3 - presigning (the two signers)

Presigning is message-independent: alice and carol can run it in the
morning and sign the actual transaction in the evening. `presign init`
takes each signer's key share and aux info, and the exact signing set:

```sh
SIDY=$(zmpc presign init --dir alice-presign --share alice-key/artifacts/keyshare.zmpc \
      --aux alice-aux/artifacts/auxinfo.zmpc --signers 1,3 --quiet)
zmpc presign init --dir carol-presign --share carol-key/artifacts/keyshare.zmpc \
      --aux carol-aux/artifacts/auxinfo.zmpc --signers 1,3 --session "$SIDY" --quiet

zmpc node --dir alice-presign --relay 127.0.0.1:7100 --quiet &
zmpc node --dir carol-presign --relay 127.0.0.1:7100 --quiet &
wait
```

Bob is not involved: `--signers 1,3` names the set, and 2-of-3 means any
two suffice. Each signer now holds `artifacts/presignature.zmpc`,
single-use and secret. Using one presignature for two different messages
reveals the private key, which is why the next step deletes it on use.

#### Phase 4 - sign, combine, verify

Signing with a presignature is non-interactive: each signer produces a
partial signature locally, offline, with one command. The message bytes
reach both signers out of band and must be identical:

```sh
printf 'transfer 0.1 ETH to bob' > tx.bin

zmpc ecdsa sign --presig alice-presign/artifacts/presignature.zmpc \
      --msg-file tx.bin --out alice-partial.zmpc
zmpc ecdsa sign --presig carol-presign/artifacts/presignature.zmpc \
      --msg-file tx.bin --out carol-partial.zmpc
```

Each command consumes its presignature: `presignature.zmpc` is gone
afterwards, by design. The partials are not secret; each signer sends its
partial to whoever combines (a ~150-byte file, so mail it, paste it with
`--armor`, anything):

```sh
zmpc ecdsa combine --partials alice-partial.zmpc,carol-partial.zmpc \
      --msg-file tx.bin --pubkey-share alice-key/artifacts/keyshare.zmpc --out ecdsa.sig

zmpc ecdsa verify --pubkey "$PK" --msg-file tx.bin --sig ecdsa.sig
```

`ecdsa.sig` is 64 bytes of ordinary ECDSA (`r || s`); any Bitcoin or
Ethereum node verifies it with no idea a ceremony was involved. `combine`
also checks the result against the group key before writing it (that's what
`--pubkey-share` is for), and a partial produced over different bytes makes
it abort rather than emit a bad signature.

#### Who runs what, and what travels

| phase | runs on | command(s) | secret output (stays put) | what travels, and how |
|---|---|---|---|---|
| hub | any reachable machine | `relay` | - | all round frames, automatically |
| 1 keygen | all three | `init`, `node` | `keyshare.zmpc` | session id, out of band |
| 2 auxgen | all three | `init --protocol auxgen`, `node` | `auxinfo.zmpc` | session id, out of band |
| 3 presign | the two signers | `presign init`, `node` | `presignature.zmpc` (single-use) | session id, out of band |
| 4 sign | the two signers, offline | `ecdsa sign` | - (presignature consumed) | message + partials, out of band |
| 5 combine | anyone with the partials | `ecdsa combine`, `ecdsa verify` | - | `ecdsa.sig`, public |

The relay is convenience, not architecture: kill it, and the *same*
sessions continue with `zmpc dkg run` / `zmpc auxgen run` / `zmpc presign
run` per round, moving `out/` to peers' `in/` by `scp` or USB stick as
described [above](#how-the-processes-talk). `test/e2e.sh` runs this whole
flow (file-mode and relay-mode) on every test run.

### Security properties you have to provide

The library assumes things this transport does not give you, and pretending
otherwise would be worse than saying so:

- **p2p messages are confidential in the protocol's model, not in transit.**
  DKG and refresh send secret VSS shares point-to-point. Anyone who can read
  `in/`, the relay's spool, or the wire can reconstruct the key from enough of
  them. Use a tunnel, an encrypted disk, or an air gap.
- **Broadcast must be consistent.** The protocols assume a party cannot send
  one thing to you and another to someone else. Neither transport enforces
  that; the reliability echo round is on the roadmap. What zmpc does do is
  make the contradictions it *can* see undeniable: an inbox holding two
  different frames for the same (round, sender, recipient) is refused, and
  neither `push` nor `pull` will silently replace an existing frame with
  different bytes; a second version is kept alongside the first so the check
  fires instead of the substitution going unnoticed. The relay also refuses a
  frame whose header names a sender other than the client pushing it.
- **`state/` is secret and unencrypted.** It holds DKG polynomial
  coefficients, Paillier decryption keys, and FROST nonces. It is created
  0600, which is a speed bump, not encryption at rest.
- **Nonces and presignatures are single-use, and zmpc enforces it.**
  `sign share` destroys the nonce state as it emits the signature share, and
  `ecdsa sign` deletes the presignature it consumed. Signing two messages with
  either one reveals the private key.

## Layout

```
src/
  curve.zig       comptime curve interface over std.crypto.ecc
                  (secp256k1, P-256, P-384, Ed25519)
  transcript.zig  unambiguous transcript hashing, Fiat-Shamir
  message.zig     From/To message envelopes shared by every protocol
  vss.zig         Shamir/Feldman VSS, Lagrange interpolation
  dkg.zig         3-round distributed key generation
  frost.zig       FROST two-round signing (RFC 9591): Ed25519 + secp256k1
  bip340.zig      BIP-340 sign/verify + FROST-Taproot ciphersuite
  ffx.zig         bignum extras over std.crypto.ff: xgcd/inverse, Jacobi,
                  Miller-Rabin, Blum/safe primes, division, isqrt
  paillier.zig    Paillier cryptosystem (validated against python-sympy
                  and the Rust fast-paillier crate, byte-exact)
  zk/             CGGMP24 proof suite: Πprm Πmod Πfac Πelog Πenc-elg Πaff-g
  auxgen.zig      CGGMP24 aux-info generation (Paillier + ring-Pedersen)
  ecdsa.zig       CGGMP24 (3+1)-round presigning/signing
  refresh.zig     proactive share refresh (zero-sharing)
  hd.zig          BIP-32/SLIP-10 non-hardened derivation
  serde.zig       canonical wire encoding for every message, state and share
  wasm.zig        the WebAssembly interface: DKG, FROST signing, verification,
                  CGGMP24 signing, all over the CLI's wire frames
cli/
  main.zig        argv dispatch; one file per protocol alongside it
  frame.zig       the 60-byte frame envelope, armor, file naming
  session.zig     session directories, inboxes, round prerequisites
  relay.zig       store-and-forward TCP hub and its client
test/
  e2e.sh          multi-process end-to-end run, one process per party
  ceremony.js     JS wrapper over the wasm exports
  smoke.mjs       full ceremony through the wasm module under node
  interop.zig     cross-checks against bitcoin-core/libsecp256k1
```

`zig build test` runs the full suite. Pinned to Zig 0.16.0.

The interop tests (`zig build interop`, also part of `zig build test`)
verify the same signatures against a second independent implementation:
[bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1),
fetched as a package and compiled from source. A CGGMP24 threshold ECDSA
signature and a FROST-Taproot threshold Schnorr signature must verify
under libsecp256k1; libsecp256k1's ECDSA and BIP-340 signatures must
verify under this library; and on the official BIP-340 vectors both
implementations must produce byte-identical signatures. FROST per RFC
9591 is absent by necessity: its challenge hash differs from BIP-340,
so libsecp256k1 has no verifier for it.

### WebAssembly

`zig build wasm` produces `zig-out/bin/zmpc.wasm` (~200 KB,
`wasm32-freestanding`); `zig build wasm-test` runs the full ceremony through
it under node. There is no separate C ABI; the wasm exports are the
library's only foreign interface.

The exports cover the full ceremony for `ed25519`, `secp256k1` and
`taproot` (the suite is a parameter):

```
zmpc_dkg_round1..round3, zmpc_dkg_finalize    trustless DKG: keyshare.zmpc + group key
zmpc_sign_commit / share / aggregate          FROST signing: 64/65-byte signature
zmpc_verify                                   check a signature with only the public key
zmpc_ecdsa_partial_sign / combine / verify    CGGMP24 signing with a CLI presignature
zmpc_frame_meta / frame_name / share_pubkey   decode routing headers, name frames
zmpc_alloc / free, zmpc_out_*                 linear-memory staging and outputs
```

Everything speaks the CLI's frame format: a `keyshare.zmpc` produced by DKG
in the browser works in a `zmpc sign` session between real machines, and
vice versa (round *state* is an opaque secret blob the caller holds between
rounds and never sends). Single-use secrets stay single-use: `sign_share`
zeroes the nonce state as it signs, `ecdsa_partial_sign` zeroes the consumed
presignature. All randomness is caller-supplied and must come from a CSPRNG.
`test/ceremony.js` wraps the byte-level conventions in a small JS class,
used by `test/smoke.mjs` and, in a de-moduled copy, by the browser demo.

That demo is the interactive article at 808bits.com, which ships its own copy
of `zmpc.wasm`: it walks the whole story with alice, bob and carol. Pick a
suite, run the 2-of-3 DKG round by round (every frame shown with its CLI file
name, who sent it, who it is delivered to, and which parts never leave a
party's machine), then sign with any two of them and try to break the result.

`sh test/e2e.sh` runs every flow with each party in a separate process and
separate directory, moving frames only by `cp`, which makes it the test that
actually demonstrates cross-machine operation. `sh test/e2e.sh fast` skips
CGGMP24.

`zmpc selftest` re-runs the RFC 9591, BIP-340, SLIP-10 and Paillier vectors
through the shipped binary.

## In-process runs

`zmpc simulate` runs a whole flow with every party inside one process, with
no directories, no network, and nothing to clean up:

```
zmpc simulate all           # everything except CGGMP24 (which is slow)
zmpc simulate frost         # 2-of-3 DKG + FROST Ed25519 signing
zmpc simulate taproot       # 2-of-3 DKG + FROST Taproot (BIP-340)
zmpc simulate hd            # BIP-32/SLIP-10 derivation + child signing
zmpc simulate refresh       # proactive share refresh
zmpc simulate ecdsa         # CGGMP24 presign + sign (tens of seconds)
```

By default these route every message, and every round state, through the real
frame format (encoded, parsed back, decoded) before the next round sees them,
so a simulated run exercises the wire format exactly as a multi-process one
does. `--via memory` passes structs directly instead, which is the faster
path and the one that isolates protocol bugs from serialization bugs.

## Design notes

- **Stdlib-first.** All curve arithmetic, hashing, HMAC and the
  constant-time Montgomery bignum core come from `std.crypto`; this repo
  adds only what the protocols need on top.
- **Protocol sources of truth**: the CGGMP24 LaTeX spec and the
  Kudelski-audited Rust implementation (dfns `cggmp21`, branch cggmp24)
  for ECDSA; RFC 9591 and BIP-340 for FROST. The 24 matters: the 2021
  paper revision has a known key-extraction flaw.
- **Message-passing API.** Protocol rounds are pure functions over
  explicit state; the caller provides transport. Incoming messages are
  `From(T)` and outgoing p2p messages are `To(T)`, so the compiler catches a
  direction mix-up that would otherwise surface as a failed proof rounds later.
- **Round state is serializable.** No round state holds a pointer, precisely
  so a caller can write it to disk between rounds and continue in another
  process. `src/serde.zig` walks the types with `@typeInfo`; anything it
  cannot encode is a compile error rather than silent corruption. Decoding
  needs no arena: `serde.free` releases what a decode produced, and a decode
  that fails unwinds its own allocations, so the malformed-input tests run
  under `std.testing.allocator` with leak detection on.
- **Timing.** Paillier encryption/decryption and all secret-exponent
  modexp use ff's constant-time paths. The ZK layer and keygen are
  variable-time, matching the audited reference implementation (which
  declares timing out of scope). Byte-level helpers are documented
  per-function.

### CGGMP24 parameter sets

`ecdsa_fast` (576-bit primes) is for testing and demos and is **not** a
security level. `ecdsa_prod` is a 2048-bit Paillier modulus with safe primes.
Three constraints pin the sizes down: ℓ >= 256 because signing encrypts full
curve scalars, ε large enough for the curve-linked proofs, and
`n_bits - 1 >= 4ℓ` which Πfac's verifier enforces. That last one is now a
compile-time check in `src/zk/fac.zig`, so an unworkable parameter set fails
to build instead of producing proofs that are always rejected.

Generating `ecdsa_prod` primes takes minutes; `zmpc auxgen primes --suite
ecdsa_prod --out primes.zmpc` does it once, offline, and `auxgen round1
--primes primes.zmpc` picks them up.

## Roadmap to production

- reliability (echo) rounds for the broadcast steps
- identifiable-abort blame paths in CGGMP24 signing
- fuzzing of the message-deserialization entry points
- Valgrind/dudect constant-time verification of the ffx/paillier secret paths
- encryption at rest for key shares and round state
- authenticated transport (the frame format reserves a flag bit for an
  HMAC tag under a pre-shared key)
- external security audit

## License

TBD.
