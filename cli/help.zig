//! Help text.
//!
//! `zmpc help` prints the overview: what the tool is, the order the commands
//! run in, and one line per command. Every option a command accepts lives on
//! its own page, reached with `zmpc help <command>` or `zmpc <command>
//! --help`. Splitting it this way keeps the overview short enough to read
//! while still documenting every flag somewhere obvious.
//!
//! Each page lists required options first, then optional ones with their
//! defaults. The four options every command accepts (--dir, --armor, --json,
//! --quiet) are described once, in the overview, and only mentioned on a page
//! when the command does something specific with them.

const std = @import("std");

pub const overview =
    \\zmpc - threshold signing: Schnorr via FROST, ECDSA via CGGMP24
    \\
    \\usage: zmpc <command> [<step>] [options]
    \\       zmpc help <command>      every option for that command
    \\       zmpc <command> --help    the same page
    \\
    \\Each party runs zmpc in its own session directory; a ceremony is a
    \\fixed sequence of commands, run whole (`dkg run`) or round by round.
    \\To watch the Schnorr ceremonies run in one process: zmpc simulate all
    \\(the ECDSA one is slow, so it is `zmpc simulate ecdsa` on its own)
    \\
    \\  Schnorr (FROST):    init -> dkg -> sign -> verify
    \\  ECDSA (CGGMP24):    init -> dkg -> auxgen -> presign -> ecdsa
    \\
    \\sessions
    \\  init          create one party's session directory. Needs --dir DIR
    \\                --suite NAME --party N --n N --threshold N; the suite
    \\                is the scheme and curve, fixed for everything after:
    \\                  ed25519, secp256k1, taproot   FROST Schnorr
    \\                  ecdsa_fast, ecdsa_prod        CGGMP24 ECDSA
    \\                  p256, p384                    keygen only
    \\                `zmpc help suites` explains which to pick
    \\  status        what this session has done and is waiting for
    \\
    \\key generation       (each: round1 round2 [round3] finalize | run)
    \\  dkg           distributed key generation, any suite
    \\  refresh       re-randomize shares; same public key, old shares dead
    \\  auxgen        CGGMP24 only: per-party Paillier/Pedersen setup; slow
    \\                at prod sizes, `auxgen primes` pre-generates the primes
    \\  presign       CGGMP24 only: one presignature per future message
    \\
    \\signing and keys
    \\  sign          FROST Schnorr: init | commit | share | aggregate | run
    \\  ecdsa         CGGMP24 ECDSA: sign | combine | verify
    \\                (each signature consumes one presignature)
    \\  verify        check a FROST/Taproot signature against a public key
    \\  share         key share utilities: info | pubkey | verify
    \\  hd            pubkey | derive             (BIP-32/SLIP-10, non-hardened)
    \\
    \\primitives (standalone, no session needed)
    \\  bip340        pubkey | sign | verify
    \\  paillier      keygen | encrypt | decrypt | add | mul | addplain
    \\  vss           split | reconstruct | verify
    \\  ffx           prime | isprime | jacobi | gcd | inverse | sqrt | divrem
    \\  transcript    hash
    \\
    \\relay transport (optional; plain file copying works too)
    \\  relay         store-and-forward hub, on 127.0.0.1:7000 by default
    \\  push          upload this session's out/ to a relay
    \\  pull          download frames addressed to this party into in/
    \\  node          run a whole protocol to completion over a relay
    \\
    \\tools
    \\  simulate      run whole ceremonies in one process
    \\  selftest      known-answer tests against this binary
    \\  inspect       decode any frame file
    \\  version
    \\
    \\common options (accepted by every command)
    \\  --dir DIR     session directory (default: $ZMPC_DIR, else .)
    \\  --armor       write frames as base64 text instead of binary
    \\  --json        machine-readable result on stdout, human text on stderr
    \\  --quiet       suppress progress notes
    \\
    \\environment
    \\  ZMPC_DIR      the session directory to use when --dir is absent.
    \\                Export it once per shell and every command for that
    \\                party gets shorter:
    \\                  export ZMPC_DIR=party1
    \\                  zmpc init --suite ed25519 --party 1 --n 3 --threshold 2
    \\                  zmpc dkg run
    \\                --dir still wins where you give it.
    \\
    \\other help topics
    \\  suites        the seven suites and what each one signs
    \\  exit          what each exit code means
    \\
    \\A round reads in/ and state/, then writes out/ and state/. Deliver a
    \\party's out/ files into its peers' in/ directories by any means you
    \\trust - the frames are inert and named identically on both sides.
    \\Exit 75 means "still waiting for messages", not failure.
    \\
;

/// One `zmpc help <name>` page.
pub const Topic = struct {
    name: []const u8,
    text: []const u8,
};

pub const topics = [_]Topic{
    .{ .name = "init", .text =
    \\zmpc init - create one party's session directory
    \\
    \\usage: zmpc init --dir DIR --suite NAME --party N --n N --threshold N
    \\                 [options]
    \\
    \\Run this once per party, each in its own directory. Every party must
    \\agree on the suite, n, threshold and session id; only --party differs.
    \\Creating a session fixes all of them for every later command.
    \\
    \\required
    \\  --suite NAME      scheme and curve; see `zmpc help suites`
    \\  --party N         which party this directory is, 1..n
    \\  --n N             total parties, at least 2
    \\  --threshold N     signers needed later, 1..n
    \\  --dir DIR         where to create the session. Required, because a
    \\                    session is five entries and defaulting to the
    \\                    current directory scatters them wherever you
    \\                    happen to be standing. `--dir .` if you do mean
    \\                    here; exporting ZMPC_DIR counts as saying it.
    \\
    \\optional
    \\  --protocol NAME   dkg | refresh | auxgen | presign | sign
    \\                    (default: dkg). Use it for dkg and auxgen;
    \\                    refresh, presign and sign have their own `init`
    \\                    that reads the shape from an existing key share.
    \\  --session HEX     64 hex characters shared by every party (default:
    \\                    random, printed on stdout). Run init on one party,
    \\                    then pass the printed id to the others.
    \\
    \\Prints the session id on stdout. Running several parties on one
    \\machine is just several directories side by side:
    \\
    \\  zmpc init --dir party1 --suite ed25519 --party 1 --n 3 --threshold 2
    \\  zmpc init --dir party2 --suite ed25519 --party 2 --n 3 --threshold 2 \
    \\            --session <the id party1 printed>
    \\
    \\then either pass --dir to each later command, or export ZMPC_DIR in
    \\one shell per party.
    },

    .{ .name = "suites", .text =
    \\zmpc suites - the scheme and curve a session uses
    \\
    \\A suite is chosen once, with --suite at `zmpc init`, and is recorded
    \\in every frame, so parties running different suites fail immediately
    \\rather than deep inside a proof. It selects both the signature scheme
    \\and the curve, and therefore which commands the session can run.
    \\
    \\  ed25519       FROST Schnorr on Ed25519 (RFC 9591)
    \\      -> dkg, refresh, sign, verify, share
    \\  secp256k1     FROST Schnorr on secp256k1 (RFC 9591)
    \\  taproot       FROST Schnorr on secp256k1, BIP-340 encoding, as
    \\                Bitcoin Taproot expects
    \\      -> dkg, refresh, sign, verify, share, hd
    \\
    \\  ecdsa_fast    CGGMP24 threshold ECDSA on secp256k1, 1152-bit
    \\                Paillier modulus, 16 proof repetitions, no safe
    \\                primes. A speed setting for tests and demos; it is
    \\                NOT a security level.
    \\  ecdsa_prod    the same, with a 2048-bit Paillier modulus, 80
    \\                repetitions and safe primes. This is the one a real
    \\                deployment wants; auxgen is much slower.
    \\      -> dkg, refresh, auxgen, presign, ecdsa, hd, share
    \\
    \\  p256          NIST P-256
    \\  p384          NIST P-384
    \\      -> dkg, refresh, share only. No FROST ciphersuite is published
    \\         for these here, so they cannot sign.
    \\
    \\Pick by what has to verify the signature: ECDSA verifiers (Ethereum,
    \\pre-Taproot Bitcoin, TLS stacks) need ecdsa_prod; Bitcoin Taproot
    \\needs taproot; anything that speaks RFC 9591 FROST, or a verifier you
    \\control, can use ed25519 or secp256k1, which are far simpler and
    \\faster because they need no Paillier setup.
    \\
    \\Other commands that take --suite: `auxgen primes` (which parameter
    \\set to size the primes for), `verify` (how to read the public key and
    \\signature). `vss` takes the same names as --curve.
    },

    .{ .name = "status", .text =
    \\zmpc status - what this session has done and is waiting for
    \\
    \\usage: zmpc status [--dir DIR]
    \\
    \\Prints the session id, protocol and suite, this party's number, how
    \\many frames are in in/, and which peers' frames are still missing.
    \\The `next` line is the command to run, spelled out and ready to
    \\paste, including the --dir you asked with:
    \\
    \\  state     1 round(s) done
    \\  next      zmpc dkg round2 --dir party1
    \\  ready     no - deliver the frames below first
    \\
    \\`ready` says whether that command can run yet, or is still waiting
    \\on peers. Waiting is not a failure: the exit code is 0 whatever the
    \\answer, as long as there is a session to report on.
    \\
    \\optional
    \\  --dir DIR         session directory (default: .)
    \\  --json            one JSON object instead of the text form. Its
    \\                    "next_step" field is the bare subcommand, e.g.
    \\                    "round2", or null when the session is finished.
    },

    .{ .name = "dkg", .text =
    \\zmpc dkg - distributed key generation
    \\
    \\usage: zmpc dkg <round1|round2|round3|finalize|run> [--dir DIR]
    \\
    \\Needs a session created with `zmpc init --protocol dkg`. Works for
    \\every suite. Each round reads in/ and state/, then writes out/ and
    \\state/; deliver out/ to the peers before the next round. `run` does
    \\every round it can and stops with exit 75 when it needs peer frames.
    \\
    \\Produces the key share this party keeps, written to
    \\<dir>/artifacts/keyshare.zmpc, which `sign`, `presign`, `refresh`,
    \\`hd` and `share` all read. That is the path to pass to their
    \\--share options.
    \\
    \\optional
    \\  --dir DIR         session directory (default: .)
    \\  --armor           write frames as base64 text instead of binary
    },

    .{ .name = "refresh", .text =
    \\zmpc refresh - re-randomize shares without changing the public key
    \\
    \\usage: zmpc refresh init --share FILE [options]
    \\       zmpc refresh <round1|round2|finalize|run> [--dir DIR]
    \\
    \\Every party must take part. Afterwards the old shares are useless and
    \\the public key is unchanged, which is what limits how long a stolen
    \\share stays valuable.
    \\
    \\`refresh init` reads the party number, n and threshold out of the key
    \\share, so it needs no --party/--n/--threshold.
    \\
    \\refresh init
    \\  --share FILE      the key share to refresh                (required)
    \\  --session HEX     64 hex characters shared by every party
    \\                    (default: random, printed on stdout)
    \\  --dir DIR         where to create the session. Required, as for
    \\                    `zmpc init`; ZMPC_DIR counts as saying it.
    \\
    \\rounds
    \\  --share FILE      read the key share from here instead of the
    \\                    session directory
    \\  --dir DIR         session directory (default: .)
    },

    .{ .name = "auxgen", .text =
    \\zmpc auxgen - CGGMP24 auxiliary information (Paillier and Pedersen)
    \\
    \\usage: zmpc auxgen primes --suite NAME [--out FILE]
    \\       zmpc auxgen <round1|round2|round3|finalize|run> [options]
    \\
    \\Only for the ecdsa_fast and ecdsa_prod suites. Needs a session made
    \\with `zmpc init --protocol auxgen`. Run it once per key; presigning
    \\reads what it produces.
    \\
    \\Generating the primes dominates the runtime, especially at ecdsa_prod
    \\sizes, where they are safe primes. `auxgen primes` does just that part
    \\and writes them to a file, so it can run ahead of the ceremony; the
    \\rounds then pick them up with --primes.
    \\
    \\auxgen primes
    \\  --suite NAME      ecdsa_fast or ecdsa_prod: which sizes to generate
    \\                    (required)
    \\  --out FILE        where to write them (default: primes.zmpc)
    \\
    \\rounds
    \\  --primes FILE     use primes prepared by `auxgen primes`
    \\  --dir DIR         session directory (default: .)
    \\  --armor           write frames as base64 text instead of binary
    },

    .{ .name = "presign", .text =
    \\zmpc presign - CGGMP24 presigning, before the message is known
    \\
    \\usage: zmpc presign init --share FILE --aux FILE --signers 1,3 [options]
    \\       zmpc presign <round1|round2|round3|finalize|run> [options]
    \\
    \\Only for the ecdsa_fast and ecdsa_prod suites, and only after auxgen.
    \\Produces one presignature, which `zmpc ecdsa sign` then spends on one
    \\message. Never sign two messages with one presignature: that reveals
    \\the private key.
    \\
    \\`presign init` reads the party number, n and threshold out of the key
    \\share. Every party in --signers must pass the same list.
    \\
    \\presign init
    \\  --share FILE      this party's key share                  (required)
    \\  --aux FILE        the aux info from auxgen                (required)
    \\  --signers LIST    comma-separated party numbers, e.g. 1,3; at least
    \\                    `threshold` of them, and must include this party
    \\                    (required)
    \\  --session HEX     64 hex characters shared by every signer
    \\                    (default: random, printed on stdout)
    \\  --dir DIR         where to create the session. Required, as for
    \\                    `zmpc init`; ZMPC_DIR counts as saying it.
    \\
    \\rounds
    \\  --share FILE      read the key share from here instead
    \\  --aux FILE        read the aux info from here instead
    \\  --dir DIR         session directory (default: .)
    \\  --armor           write frames as base64 text instead of binary
    },

    .{ .name = "sign", .text =
    \\zmpc sign - FROST Schnorr threshold signing
    \\
    \\usage: zmpc sign init --share FILE --signers 1,3 --msg-hex HEX [options]
    \\       zmpc sign <commit|share|aggregate|run> [options]
    \\
    \\For the ed25519, secp256k1 and taproot suites. For ECDSA use
    \\`zmpc presign` and `zmpc ecdsa` instead.
    \\
    \\One signing session signs one message. Never reuse a session or its
    \\nonces for a second message; run `sign init` again.
    \\
    \\sign init
    \\  --share FILE      this party's key share                  (required)
    \\  --signers LIST    comma-separated party numbers, e.g. 1,3; at least
    \\                    `threshold` of them, and must include this party
    \\                    (required)
    \\  --msg-file FILE   the message to sign, read from a file
    \\  --msg-hex HEX     the message to sign, as hex
    \\                    (one of the two is required; if both are given,
    \\                    --msg-file wins rather than erroring, so pass
    \\                    only the one you mean)
    \\  --session HEX     64 hex characters shared by every signer
    \\                    (default: random, printed on stdout)
    \\  --dir DIR         where to create the session. Required, as for
    \\                    `zmpc init`; ZMPC_DIR counts as saying it.
    \\
    \\steps: commit, share, aggregate (or `run`)
    \\  --share FILE      read the key share from here instead
    \\  --dir DIR         session directory (default: .)
    \\  --armor           write frames as base64 text instead of binary
    \\
    \\`aggregate` writes the signature to <dir>/artifacts/signature.bin:
    \\64 bytes for ed25519 and taproot (BIP-340 wire format), 65 for
    \\secp256k1, whose FROST encoding carries a full compressed point.
    \\Check it with `zmpc verify --suite ... --pubkey ... --sig ...`.
    },

    .{ .name = "ecdsa", .text =
    \\zmpc ecdsa - spend a presignature on a message, and combine the parts
    \\
    \\usage: zmpc ecdsa sign --presig FILE (--msg-hex H | --msg-file F | --digest H)
    \\       zmpc ecdsa combine --partials A,B [options]
    \\       zmpc ecdsa verify --pubkey HEX --sig FILE [options]
    \\
    \\The message can be given three ways, and every party must end up
    \\signing the same bytes: --msg-file or --msg-hex hash the bytes with
    \\SHA-256, while --digest takes the 32-byte hash directly. Use --digest
    \\when the chain defines its own hash, for example Ethereum, which
    \\signs keccak256 of the RLP-encoded transaction.
    \\
    \\Passing more than one is not an error: --digest wins over the others,
    \\and --msg-file over --msg-hex. Pass only the one you mean.
    \\
    \\ecdsa sign          (each signer, once)
    \\  --presig FILE     the presignature to spend               (required)
    \\  --msg-file FILE   message to hash with SHA-256
    \\  --msg-hex HEX     message to hash with SHA-256, as hex
    \\  --digest HEX      32-byte digest to sign as-is
    \\                    (one of the three is required)
    \\  --out FILE        where to write the partial signature
    \\                    (default: partial.zmpc)
    \\  --keep            do not delete the presignature afterwards.
    \\                    Testing only: signing twice with one presignature
    \\                    reveals the private key.
    \\
    \\ecdsa combine       (anyone, once all partials are in hand)
    \\  --partials LIST   comma-separated partial signature files (required)
    \\  --msg-file/--msg-hex/--digest   the same message as above (required)
    \\  --pubkey-share FILE  a key share, to verify the result before
    \\                    writing it. Strongly recommended: a missing or
    \\                    wrong partial produces an invalid signature
    \\                    rather than an error.
    \\  --out FILE        where to write the 64 raw bytes
    \\                    (default: signature.bin)
    \\
    \\ecdsa verify
    \\  --pubkey HEX      the group public key, compressed SEC1 hex
    \\                    (required)
    \\  --sig FILE        the 64-byte signature file             (required)
    \\  --msg-file/--msg-hex/--digest   the same message as above (required)
    \\
    \\Signatures are low-s normalized, as Ethereum and Bitcoin require. The
    \\recovery id `v` is not produced; recover it by trying both values
    \\against the known public key.
    },

    .{ .name = "verify", .text =
    \\zmpc verify - check a FROST or Taproot signature
    \\
    \\usage: zmpc verify --suite NAME --pubkey HEX --sig FILE
    \\                   (--msg-file FILE | --msg-hex HEX)
    \\
    \\For Schnorr signatures from `zmpc sign`. ECDSA signatures are checked
    \\with `zmpc ecdsa verify` instead. Needs no session.
    \\
    \\required
    \\  --suite NAME      ed25519, secp256k1 or taproot: how to read the
    \\                    public key and signature
    \\  --pubkey HEX      the group public key. 32 bytes x-only for
    \\                    taproot, otherwise the compressed encoding
    \\                    `zmpc share pubkey` prints.
    \\  --sig FILE        the signature file, as `sign aggregate` wrote it:
    \\                    64 bytes for ed25519 and taproot, 65 for
    \\                    secp256k1
    \\  --msg-file FILE   the message that was signed, from a file
    \\  --msg-hex HEX     the message that was signed, as hex
    \\                    (give one; --msg-file wins if both appear)
    \\
    \\Exit code 0 if the signature is valid, 65 if it is not.
    },

    .{ .name = "share", .text =
    \\zmpc share - inspect and check a key share
    \\
    \\usage: zmpc share <info|pubkey|verify> [--share FILE | --dir DIR]
    \\
    \\actions
    \\  info              suite, party number and count, threshold, public
    \\                    key (plus the x-only key for taproot), chain
    \\                    code, session id and rid
    \\  pubkey            just the group public key, hex. x-only for
    \\                    taproot shares, compressed otherwise; this is what
    \\                    `zmpc verify --pubkey` wants.
    \\  verify            recompute the share against its own VSS
    \\                    commitment; exit 65 if it does not match
    \\
    \\optional
    \\  --share FILE      the key share to read (default:
    \\                    <dir>/artifacts/keyshare.zmpc)
    \\  --dir DIR         session directory (default: .)
    \\  --json            one JSON object instead of the text form. `info`
    \\                    only; `pubkey` prints bare hex either way.
    },

    .{ .name = "hd", .text =
    \\zmpc hd - BIP-32/SLIP-10 derivation from a threshold key
    \\
    \\usage: zmpc hd <pubkey|derive> --path m/44/0/7 [options]
    \\
    \\SLIP-10 here is defined over secp256k1, so the share must be from a
    \\secp256k1, taproot, ecdsa_fast or ecdsa_prod session; ed25519, p256
    \\and p384 shares are refused.
    \\
    \\Non-hardened derivation only: hardened steps need the master private
    \\key, which no single party has. Every party must derive the same path
    \\to end up with matching child shares.
    \\
    \\actions
    \\  pubkey            print the child public key
    \\  derive            write a child key share, usable for signing
    \\
    \\required
    \\  --path PATH       derivation path, e.g. m/44/0/7
    \\  --out FILE        where to write the child share (derive only)
    \\
    \\optional
    \\  --share FILE      the key share to derive from (default:
    \\                    <dir>/artifacts/keyshare.zmpc)
    \\  --dir DIR         session directory (default: .)
    \\  --json            one JSON object instead of the text form
    },

    .{ .name = "bip340", .text =
    \\zmpc bip340 - single-key BIP-340 Schnorr, no threshold involved
    \\
    \\usage: zmpc bip340 pubkey --sk HEX
    \\       zmpc bip340 sign --sk HEX (--msg-hex H | --msg-file F) [--aux HEX]
    \\       zmpc bip340 verify --pubkey HEX --sig X (--msg-hex H | --msg-file F)
    \\
    \\A plain BIP-340 implementation for checking vectors and for producing
    \\a signature to compare against. Takes no session.
    \\
    \\  --sk HEX          32-byte secret key, hex   (pubkey, sign: required)
    \\  --pubkey HEX      32-byte x-only public key (verify: required)
    \\  --sig VALUE       64 bytes of hex, or a file holding 64 raw bytes
    \\                    (verify: required)
    \\  --msg-file FILE   the message, from a file
    \\  --msg-hex HEX     the message, as hex
    \\                    (sign and verify need one of the two; --msg-file
    \\                    wins if both are given)
    \\  --aux HEX         32 bytes of auxiliary randomness for the nonce
    \\                    (default: fresh randomness). Fix it to reproduce
    \\                    a test vector.
    \\
    \\Exit code 0 if a signature is valid, 65 if it is not.
    },

    .{ .name = "paillier", .text =
    \\zmpc paillier - the additively homomorphic cipher CGGMP24 runs on
    \\
    \\usage: zmpc paillier <keygen|encrypt|decrypt|add|mul|addplain> [options]
    \\
    \\Exposed for experimenting and for cross-checking vectors; the
    \\protocols use the library directly. All values are hex.
    \\
    \\  --bits N          prime size: 128, 256, 512 or 1024 (default: 512).
    \\                    The modulus is twice this.
    \\
    \\keygen              writes `n:`, `p:` and `q:` lines
    \\  --out FILE        write the key there, mode 0600 (default: stdout)
    \\
    \\encrypt             Enc(m)
    \\  --m HEX           the plaintext                           (required)
    \\  --n HEX           the modulus, or use --key
    \\  --key FILE        a keygen file to read the modulus from
    \\  --r HEX           fixed nonce, for reproducible output. Test vectors
    \\                    only; never with a real plaintext.
    \\
    \\decrypt             needs the private key
    \\  --key FILE        a keygen file with p and q               (required)
    \\  --c HEX           the ciphertext                           (required)
    \\
    \\add                 Enc(a) + Enc(b) = Enc(a+b)
    \\  --c HEX, --c2 HEX the two ciphertexts                      (required)
    \\  --n HEX or --key FILE   the modulus                        (required)
    \\
    \\mul                 Enc(m)^k = Enc(k*m)
    \\  --c HEX           the ciphertext                           (required)
    \\  --k HEX           the plaintext multiplier                 (required)
    \\  --n HEX or --key FILE   the modulus                        (required)
    \\
    \\addplain            Enc(m) * (1+kN) = Enc(m+k)
    \\  --c HEX           the ciphertext                           (required)
    \\  --k HEX           the plaintext addend                     (required)
    \\  --n HEX or --key FILE   the modulus                        (required)
    },

    .{ .name = "vss", .text =
    \\zmpc vss - Feldman verifiable secret sharing
    \\
    \\usage: zmpc vss split --t T --n N [--secret HEX] [--curve C]
    \\       zmpc vss reconstruct --shares 1:HEX,3:HEX [--curve C]
    \\       zmpc vss verify --index I --share HEX --commitment HEX,HEX [--curve C]
    \\
    \\The sharing layer under DKG, on its own. Every value is hex, and
    \\indices start at 1.
    \\
    \\  --curve NAME      any suite name; only its curve is used
    \\                    (default: secp256k1)
    \\
    \\split               prints the public key, the commitment points and
    \\                    one line per share
    \\  --t T             how many shares reconstruct the secret  (required)
    \\  --n N             how many shares to produce, n >= t      (required)
    \\  --secret HEX      the secret to split (default: random)
    \\
    \\reconstruct         prints the secret
    \\  --shares LIST     comma-separated index:hex pairs, at least t of
    \\                    them, e.g. 1:ab..,3:cd..              (required)
    \\
    \\verify              exit 65 if the share does not fit the commitment
    \\  --index I         which share this is                    (required)
    \\  --share HEX       the share value                        (required)
    \\  --commitment LIST comma-separated commitment points      (required)
    },

    .{ .name = "ffx", .text =
    \\zmpc ffx - the big-integer layer the zero-knowledge proofs use
    \\
    \\usage: zmpc ffx <prime|isprime|jacobi|gcd|inverse|sqrt|divrem> [options]
    \\
    \\Values are hex, in and out. Handy for building test vectors and for
    \\understanding what the proofs are doing.
    \\
    \\prime               generate a probable prime
    \\  --bits N          size, 16 to 4096 (default: 256)
    \\  --blum            require p = 3 mod 4, as Paillier-Blum moduli need
    \\  --safe            generate a safe prime, p = 2q+1 with q prime, as
    \\                    ring-Pedersen setup needs. Much slower, and it
    \\                    takes precedence over --blum.
    \\
    \\isprime             exit 0 if probably prime, 65 if composite
    \\  --n HEX           the number to test                      (required)
    \\
    \\jacobi              the Jacobi symbol (a/n)
    \\  --a HEX, --n HEX                                          (required)
    \\
    \\gcd                 greatest common divisor
    \\  --a HEX, --b HEX                                          (required)
    \\
    \\inverse             a^-1 mod m
    \\  --a HEX, --m HEX                                          (required)
    \\
    \\sqrt                integer square root, rounded down
    \\  --a HEX                                                   (required)
    \\
    \\divrem              quotient and remainder of a / b
    \\  --a HEX, --b HEX                                          (required)
    },

    .{ .name = "transcript", .text =
    \\zmpc transcript hash - the Fiat-Shamir transcript, by hand
    \\
    \\usage: zmpc transcript hash [--domain D] [--append label=hex ...]
    \\                            [--u64 label=number ...]
    \\
    \\Absorbs the fields in the order given and prints the 32-byte
    \\challenge that comes out, which is how a proof's challenge is derived.
    \\Useful for reproducing a transcript by hand.
    \\
    \\  --domain TEXT     domain separation tag, absorbed first
    \\                    (default: empty)
    \\  --append L=HEX    absorb hex bytes under label L; repeatable, and
    \\                    order matters (--bytes is an accepted alias)
    \\  --u64 L=NUMBER    absorb a decimal number under label L; repeatable.
    \\                    All --u64 fields are absorbed after all --append
    \\                    ones.
    },

    .{ .name = "relay", .text =
    \\zmpc relay - a store-and-forward hub for parties that cannot copy files
    \\
    \\usage: zmpc relay [--listen HOST:PORT] [--spool DIR]
    \\
    \\The relay only moves frames around. Frames are authenticated by the
    \\protocols themselves, so a relay cannot forge or usefully tamper with
    \\them, but it does see who talks to whom and can withhold frames.
    \\It is optional: copying out/ into peers' in/ by any other means works
    \\identically.
    \\
    \\optional
    \\  --listen ADDR     address to bind (default: 127.0.0.1:7000)
    \\  --spool DIR       where undelivered frames wait (default:
    \\                    zmpc-spool)
    \\
    \\Parties reach it with `zmpc push`, `zmpc pull` and `zmpc node`.
    },

    .{ .name = "push", .text =
    \\zmpc push - upload this session's out/ frames to a relay
    \\
    \\usage: zmpc push --relay HOST:PORT [--dir DIR]
    \\
    \\required
    \\  --relay ADDR      the relay's address
    \\
    \\optional
    \\  --dir DIR         session directory (default: .)
    \\
    \\Prints how many frames went out. See also `zmpc pull` and, to do
    \\both around every round automatically, `zmpc node`.
    },

    .{ .name = "pull", .text =
    \\zmpc pull - download frames addressed to this party into in/
    \\
    \\usage: zmpc pull --relay HOST:PORT [--dir DIR]
    \\
    \\required
    \\  --relay ADDR      the relay's address
    \\
    \\optional
    \\  --dir DIR         session directory (default: .)
    \\
    \\Prints how many frames were new. Every pull downloads the whole set
    \\addressed to this party; a frame already in in/ with identical bytes
    \\is left alone, and one that differs is kept beside it as
    \\conflictN-* rather than overwriting anything.
    },

    .{ .name = "node", .text =
    \\zmpc node - run a whole protocol to completion over a relay
    \\
    \\usage: zmpc node --relay HOST:PORT [options]
    \\
    \\Runs whatever protocol the session was created for: run the next
    \\round, push what it produced, pull what arrived, repeat until the
    \\protocol is complete. This is the unattended equivalent of alternating
    \\`<protocol> run`, `push` and `pull` by hand.
    \\
    \\required
    \\  --relay ADDR      the relay's address
    \\
    \\optional
    \\  --dir DIR         session directory (default: .)
    \\  --poll-ms N       how long to wait between pulls while nothing has
    \\                    arrived (default: 500)
    \\  --timeout-s N     give up after this long with no progress
    \\                    (default: 600), exiting 75
    \\  --share FILE      key share override, for presign, sign and refresh
    \\  --aux FILE        aux info override, for presign
    \\  --primes FILE     primes from `auxgen primes`, for auxgen
    },

    .{ .name = "simulate", .text =
    \\zmpc simulate - run a whole ceremony in one process
    \\
    \\usage: zmpc simulate <keygen|frost|taproot|hd|refresh|ecdsa|all>
    \\                     [--via memory|frames]
    \\
    \\Every party lives in the same process, so there is nothing to set up
    \\and nothing to copy. The fastest way to see what a ceremony does, and
    \\a quick check that a build works.
    \\
    \\what to run
    \\  keygen, frost     2-of-3 DKG and FROST Ed25519 signing
    \\  taproot           2-of-3 DKG and FROST Taproot (BIP-340) signing
    \\  hd                BIP-32/SLIP-10 derivation and child signing
    \\  refresh           proactive share refresh
    \\  ecdsa             CGGMP24 presign and sign; tens of seconds, which
    \\                    is why `all` leaves it out
    \\  all               everything except ecdsa
    \\
    \\optional
    \\  --via MODE        frames (default) encodes every message and round
    \\                    state to a real frame and parses it back, so the
    \\                    wire format is exercised too; memory passes values
    \\                    directly.
    \\
    \\The parties, threshold and message are fixed per simulation; use the
    \\real commands to choose your own.
    },

    .{ .name = "selftest", .text =
    \\zmpc selftest - known-answer tests against this binary
    \\
    \\usage: zmpc selftest [--quick]
    \\
    \\Re-runs the published vectors through the shipped binary rather than
    \\through a test build: BIP-340, RFC 9591 FROST, SLIP-10 derivation, the
    \\Paillier vectors and the wire format, then a set of live protocol
    \\runs. Exit 65 if anything fails.
    \\
    \\optional
    \\  --quick           stop after the vectors, skipping the live runs
    \\  --json            one JSON object instead of the text form
    },

    .{ .name = "inspect", .text =
    \\zmpc inspect - decode any frame file
    \\
    \\usage: zmpc inspect FILE
    \\
    \\Prints the frame header: kind, protocol and round, suite, channel,
    \\sender and recipient, parties and threshold, session id and payload
    \\size. Works on any file zmpc wrote, armored or binary, and never
    \\decodes the payload, so it is safe on frames from anyone.
    \\
    \\optional
    \\  --json            one JSON object instead of the text form
    },

    .{ .name = "version", .text =
    \\zmpc version - print the version and exit
    \\
    \\usage: zmpc version
    },

    .{ .name = "exit", .text =
    \\zmpc exit codes
    \\
    \\  0   success
    \\  1   everything not mapped to a code below. Some are bugs worth
    \\      reporting, but ordinary mistakes land here too: no session in
    \\      --dir, a missing --share or --aux file, a malformed key share,
    \\      a --digest that is not 32 bytes of hex. Read the message.
    \\  2   bad usage: an unknown flag, a missing option, an impossible
    \\      combination, or a step run out of order
    \\  64  a file was missing, unreadable, or not what it claimed to be
    \\  65  the protocol aborted: an invalid proof, share or signature. In
    \\      a ceremony this means someone sent something wrong.
    \\  75  not an error: frames from peers have not arrived yet. Deliver
    \\      them and run the same command again.
    \\
    \\A script driving a ceremony should treat 75 as "retry later" and
    \\anything else non-zero as a stop.
    },
};

/// The page for `name`, or null if there is none.
pub fn page(name: []const u8) ?[]const u8 {
    for (topics) |t| {
        if (std.mem.eql(u8, t.name, name)) return t.text;
    }
    return null;
}

/// Every topic name, for the "no such topic" message.
pub fn writeTopicList(w: *std.Io.Writer) !void {
    try w.writeAll("help topics:");
    for (topics, 0..) |t, i| {
        try w.writeAll(if (i % 6 == 0) "\n  " else " ");
        try w.writeAll(t.name);
    }
    try w.writeAll("\n");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "every command in the overview has a help page" {
    // The overview lists commands two spaces in, followed by more spaces;
    // each one should be reachable with `zmpc help <command>`. Options
    // (`--dir`) and environment variables (`ZMPC_DIR`) are listed the same
    // way and are not commands, so only lowercase names count.
    var lines = std.mem.splitScalar(u8, overview, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "  ")) continue;
        const rest = line[2..];
        if (rest.len == 0 or rest[0] == ' ' or rest[0] == '-') continue;
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const name = rest[0..end];
        // Section bodies also indent by two; only lines whose first word is
        // followed by a run of spaces are entries.
        if (rest.len < end + 2 or rest[end + 1] != ' ') continue;
        for (name) |c| {
            if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') break;
        } else {
            if (page(name) == null) {
                std.debug.print("no help page for '{s}'\n", .{name});
                return error.MissingHelpPage;
            }
        }
    }
}

test "topic names are unique" {
    for (topics, 0..) |a, i| {
        for (topics[i + 1 ..]) |b| {
            try testing.expect(!std.mem.eql(u8, a.name, b.name));
        }
    }
}

test "pages name their own command and are not stubs" {
    for (topics) |t| {
        // `version` is legitimately three lines; anything shorter than a
        // title plus one line of body is a stub.
        try testing.expect(t.text.len > 40);
        // Each page opens with `zmpc <name>` (or, for pure topics, the name).
        try testing.expect(std.mem.indexOf(u8, t.text[0..40], t.name) != null);
    }
}
