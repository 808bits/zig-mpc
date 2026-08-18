#!/bin/sh
# End-to-end test of the zmpc CLI with every party in its own process.
#
# This is the test that actually proves the thing the CLI exists for: key
# generation on one machine and signing on another. Each party gets its own
# session directory and never shares memory with the others; the only contact
# between them is `cp` of frame files from one party's out/ into another's in/.
# Swap that `cp` for `scp` and the parties are on different machines.
#
#   sh test/e2e.sh              everything (a few minutes; CGGMP24 is slow)
#   sh test/e2e.sh fast         skip the CGGMP24 ECDSA flow
#
# Exits non-zero on the first failure.

set -eu

ZMPC=${ZMPC:-"$(cd "$(dirname "$0")/.." && pwd)/zig-out/bin/zmpc"}
MODE=${1:-all}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

[ -x "$ZMPC" ] || { echo "no zmpc binary at $ZMPC; run 'zig build' first" >&2; exit 1; }
cd "$WORK"

pass=0
say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }
same() { [ "$2" = "$3" ] && ok "$1" || { printf '   %s\n   %s\n' "$2" "$3" >&2; fail "$1"; }; }

# Deliver every party's outbox to the right inboxes, given a map of
# `party:directory` pairs. Broadcast frames (-t0) go to everyone else; a p2p
# frame goes only to the party it is addressed to. The map is explicit because
# a signing set can be sparse - {1,3} has no party 2.
deliver() {
  for pair in $1; do
    d=${pair#*:}
    for f in "$d"/out/*; do
      [ -e "$f" ] || continue
      base=$(basename "$f")
      to=$(echo "$base" | sed -n 's/.*-t\([0-9][0-9]*\)\.zmpc.*/\1/p')
      for other in $1; do
        n=${other%%:*}
        e=${other#*:}
        if [ "$to" = "0" ]; then
          if [ "$e" != "$d" ]; then cp "$f" "$e/in/$base"; fi
        elif [ "$n" = "$to" ]; then
          cp "$f" "$e/in/$base"
        fi
      done
    done
  done
  # A trailing false test would otherwise become this function's exit status
  # and, under `set -e`, end the script.
  return 0
}

# Run one round for every party in the map, then deliver what they produced.
step() {
  map=$1; shift
  for pair in $map; do
    d=${pair#*:}
    "$ZMPC" "$@" --dir "$d" --quiet >/dev/null || fail "$* failed in $d"
  done
  deliver "$map"
}

# --------------------------------------------------------------------------
say "self-test (known-answer vectors through this binary)"
if "$ZMPC" selftest --quiet >/dev/null; then ok "vectors"; else fail "selftest"; fi

# --------------------------------------------------------------------------
say "help"

# A command given too little to act on prints its whole page, not just the
# first thing it missed, and prints it to stderr so stdout stays capturable.
out=$("$ZMPC" init 2>/dev/null || true)
err=$("$ZMPC" init 2>&1 >/dev/null || true)
set +e; "$ZMPC" init >/dev/null 2>&1; code=$?; set -e
same "a command with no options exits 2" "$code" "2"
[ -z "$out" ] && ok "nothing on stdout" || fail "usage text went to stdout"
case "$err" in
  *"missing required option '--suite'"*"--threshold N"*"--session HEX"*)
    ok "stderr names the missing option, then lists every option" ;;
  *) printf '   %s\n' "$err" >&2; fail "no full page on stderr" ;;
esac

# The same page, asked for deliberately, goes to stdout and is not an error.
set +e; "$ZMPC" help init >/dev/null 2>&1; code=$?; set -e
same "asking for help is not an error" "$code" "0"
same "init --help and help init agree" \
     "$("$ZMPC" init --help)" "$("$ZMPC" help init)"

# A missing step behaves the same way as a missing option.
case "$("$ZMPC" dkg 2>&1 >/dev/null || true)" in
  *"round1"*"finalize"*) ok "a command with no step prints its page" ;;
  *) fail "no page for a bare subcommand" ;;
esac

# --------------------------------------------------------------------------
say "session location"

# Creating a session without saying where must refuse, and must not leave
# anything behind in the current directory.
mkdir scatter && cd scatter
set +e
"$ZMPC" init --suite ed25519 --party 1 --n 3 --threshold 2 >/dev/null 2>&1
code=$?
set -e
same "init without --dir exits 2" "$code" "2"
[ ! -e session.json ] && [ ! -d in ] && ok "nothing scattered into the cwd" \
  || fail "init wrote into the current directory"

# ZMPC_DIR stands in for --dir, for every command, and --dir still wins.
ZMPC_DIR=envparty "$ZMPC" init --suite ed25519 --party 1 --n 3 --threshold 2 --quiet >/dev/null
[ -f envparty/session.json ] && ok "ZMPC_DIR satisfies init" || fail "ZMPC_DIR ignored by init"
same "ZMPC_DIR drives later commands too" \
     "$(ZMPC_DIR=envparty "$ZMPC" status --json | sed -n 's/.*"party":\([0-9]*\).*/\1/p')" "1"
"$ZMPC" init --dir flagparty --suite ed25519 --party 2 --n 3 --threshold 2 --quiet >/dev/null
same "--dir wins over ZMPC_DIR" \
     "$(ZMPC_DIR=envparty "$ZMPC" status --dir flagparty --json | sed -n 's/.*"party":\([0-9]*\).*/\1/p')" "2"
cd ..

# --------------------------------------------------------------------------
say "2-of-3 distributed key generation, three processes (ed25519)"
SID=$("$ZMPC" init --dir p1 --suite ed25519 --party 1 --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "p$i" --suite ed25519 --party "$i" --n 3 --threshold 2 \
      --session "$SID" --quiet >/dev/null
done

# `status` names the command to run next, ready to paste.
same "status suggests the first command" \
     "$("$ZMPC" status --dir p1 | sed -n 's/^next  *//p')" "zmpc dkg round1 --dir p1"

# A round before its inputs arrive must report "waiting", not fail.
"$ZMPC" dkg round1 --dir p1 --quiet >/dev/null

same "status advances to the next command" \
     "$("$ZMPC" status --dir p1 | sed -n 's/^next  *//p')" "zmpc dkg round2 --dir p1"
same "and names it for scripts too" \
     "$("$ZMPC" status --dir p1 --json | sed -n 's/.*"next_step":"\([a-z0-9]*\)".*/\1/p')" "round2"

# What it suggests must be a command the CLI actually accepts: run it (it
# will report "waiting", which is exit 75, not a usage error).
set +e
$("$ZMPC" status --dir p1 | sed -n 's/^next  *zmpc //p' | sed "s|^|$ZMPC |") --quiet >/dev/null 2>&1
code=$?
set -e
same "the suggested command is runnable" "$code" "75"
set +e; "$ZMPC" dkg round2 --dir p1 >/dev/null 2>&1; code=$?; set -e
[ "$code" = "75" ] && ok "waiting on peers exits 75" || fail "expected exit 75, got $code"
"$ZMPC" dkg round1 --dir p2 --quiet >/dev/null
"$ZMPC" dkg round1 --dir p3 --quiet >/dev/null
deliver "1:p1 2:p2 3:p3"

step "1:p1 2:p2 3:p3" dkg round2
step "1:p1 2:p2 3:p3" dkg round3
step "1:p1 2:p2 3:p3" dkg finalize

PK=$("$ZMPC" share pubkey --dir p1)
same "all three parties agree on the public key" "$PK" "$("$ZMPC" share pubkey --dir p3)"
if "$ZMPC" share verify --dir p2 --quiet; then ok "share is consistent with its commitment"; else fail "share verify"; fi

# Re-running a completed round must be refused, not silently redone.
set +e; "$ZMPC" dkg round2 --dir p1 >/dev/null 2>&1; code=$?; set -e
[ "$code" = "2" ] && ok "re-running a finished round is refused" || fail "expected exit 2, got $code"

# --------------------------------------------------------------------------
say "FROST Ed25519 signing with parties {1,3}"
printf 'pay 1 SOL to alice' > msg.bin
SID=$("$ZMPC" sign init --dir s1 --share p1/artifacts/keyshare.zmpc \
      --signers 1,3 --msg-file msg.bin --quiet)
"$ZMPC" sign init --dir s3 --share p3/artifacts/keyshare.zmpc --signers 1,3 \
      --msg-file msg.bin --session "$SID" --quiet >/dev/null

step "1:s1 3:s3" sign commit
step "1:s1 3:s3" sign share
step "1:s1 3:s3" sign aggregate

if "$ZMPC" verify --suite ed25519 --pubkey "$PK" --msg-file msg.bin \
      --sig s1/artifacts/signature.bin --quiet
then ok "signature verifies against the public key alone"; else fail "verify"; fi

printf 'pay 100 SOL to mallory' > tampered.bin
set +e
"$ZMPC" verify --suite ed25519 --pubkey "$PK" --msg-file tampered.bin \
    --sig s1/artifacts/signature.bin >/dev/null 2>&1; code=$?
set -e
[ "$code" = "65" ] && ok "a tampered message is rejected" || fail "expected exit 65, got $code"

# The nonces are gone after signing; reusing the session must be impossible.
set +e; "$ZMPC" sign share --dir s1 >/dev/null 2>&1; code=$?; set -e
[ "$code" = "2" ] && ok "nonces cannot be reused" || fail "expected exit 2, got $code"

# --------------------------------------------------------------------------
say "armored frames (base64 text, for transports that mangle binary)"
SIDA=$("$ZMPC" init --dir a1 --suite secp256k1 --party 1 --n 2 --threshold 2 --quiet)
"$ZMPC" init --dir a2 --suite secp256k1 --party 2 --n 2 --threshold 2 \
      --session "$SIDA" --quiet >/dev/null
for r in round1 round2 round3 finalize; do
  for d in a1 a2; do
    "$ZMPC" dkg "$r" --dir "$d" --armor --quiet >/dev/null || fail "armored dkg $r"
  done
  deliver "1:a1 2:a2"
done
if ls a1/out/*.asc >/dev/null 2>&1; then ok "frames written as armored text"; else fail "no armored frames"; fi
same "armored run produces a usable key" \
     "$("$ZMPC" share pubkey --dir a1)" "$("$ZMPC" share pubkey --dir a2)"

# --------------------------------------------------------------------------
say "Bitcoin Taproot (BIP-340) 2-of-3"
SIDT=$("$ZMPC" init --dir t1 --suite taproot --party 1 --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "t$i" --suite taproot --party "$i" --n 3 --threshold 2 \
      --session "$SIDT" --quiet >/dev/null
done
for r in round1 round2 round3 finalize; do step "1:t1 2:t2 3:t3" dkg "$r"; done
TPK=$("$ZMPC" share pubkey --dir t1)
if [ ${#TPK} = 64 ]; then ok "public key is x-only (32 bytes)"; else fail "expected an x-only key"; fi

printf 'taproot spend' > tap.bin
SIDS=$("$ZMPC" sign init --dir u2 --share t2/artifacts/keyshare.zmpc \
      --signers 2,3 --msg-file tap.bin --quiet)
"$ZMPC" sign init --dir u3 --share t3/artifacts/keyshare.zmpc --signers 2,3 \
      --msg-file tap.bin --session "$SIDS" --quiet >/dev/null
step "2:u2 3:u3" sign commit
step "2:u2 3:u3" sign share
step "2:u2 3:u3" sign aggregate
if "$ZMPC" verify --suite taproot --pubkey "$TPK" --msg-file tap.bin \
      --sig u2/artifacts/signature.bin --quiet; then ok "verifies as plain BIP-340"
else fail "BIP-340 verify"; fi

# --------------------------------------------------------------------------
say "HD derivation (no interaction between signers)"
C1=$("$ZMPC" hd pubkey --share t1/artifacts/keyshare.zmpc --path m/44/0/7)
C2=$("$ZMPC" hd pubkey --share t2/artifacts/keyshare.zmpc --path m/44/0/7)
same "every party derives the same child key" "$C1" "$C2"
set +e
"$ZMPC" hd pubkey --share t1/artifacts/keyshare.zmpc --path "m/44'/0" >/dev/null 2>&1; code=$?
set -e
[ "$code" = "2" ] && ok "hardened derivation is refused" || fail "expected exit 2, got $code"

"$ZMPC" hd derive --share t2/artifacts/keyshare.zmpc --path m/44/0/7 --out c2.zmpc --quiet >/dev/null
"$ZMPC" hd derive --share t3/artifacts/keyshare.zmpc --path m/44/0/7 --out c3.zmpc --quiet >/dev/null
CPK=$("$ZMPC" share pubkey --share c2.zmpc)
printf 'child key spend' > child.bin
SIDC=$("$ZMPC" sign init --dir v2 --share c2.zmpc --signers 2,3 --msg-file child.bin --quiet)
"$ZMPC" sign init --dir v3 --share c3.zmpc --signers 2,3 --msg-file child.bin \
      --session "$SIDC" --quiet >/dev/null
step "2:v2 3:v3" sign commit
step "2:v2 3:v3" sign share
step "2:v2 3:v3" sign aggregate
if "$ZMPC" verify --suite taproot --pubkey "$CPK" --msg-file child.bin \
      --sig v2/artifacts/signature.bin --quiet; then ok "the derived child key signs"
else fail "child-key verify"; fi

# --------------------------------------------------------------------------
say "proactive refresh"
BEFORE=$("$ZMPC" share pubkey --dir p1)
cp p1/artifacts/keyshare.zmpc before.zmpc
SIDR=$("$ZMPC" refresh init --dir r1 --share p1/artifacts/keyshare.zmpc --quiet)
for i in 2 3; do
  "$ZMPC" refresh init --dir "r$i" --share "p$i/artifacts/keyshare.zmpc" \
      --session "$SIDR" --quiet >/dev/null
done
for r in round1 round2 finalize; do step "1:r1 2:r2 3:r3" refresh "$r"; done

same "public key survives the refresh" "$BEFORE" "$("$ZMPC" share pubkey --dir p1)"
if cmp -s before.zmpc p1/artifacts/keyshare.zmpc; then fail "share did not change"
else ok "every share is new"; fi
if [ -f p1/artifacts/keyshare.zmpc.old ]; then ok "the previous share is kept as a backup"
else fail "no backup of the old share"; fi

printf 'after the refresh' > post.bin
SIDP=$("$ZMPC" sign init --dir w1 --share p1/artifacts/keyshare.zmpc \
      --signers 1,3 --msg-file post.bin --quiet)
"$ZMPC" sign init --dir w3 --share p3/artifacts/keyshare.zmpc --signers 1,3 \
      --msg-file post.bin --session "$SIDP" --quiet >/dev/null
step "1:w1 3:w3" sign commit
step "1:w1 3:w3" sign share
step "1:w1 3:w3" sign aggregate
if "$ZMPC" verify --suite ed25519 --pubkey "$BEFORE" --msg-file post.bin \
      --sig w1/artifacts/signature.bin --quiet; then ok "refreshed shares still sign"
else fail "post-refresh verify"; fi

# --------------------------------------------------------------------------
say "relay transport (same frames, over TCP)"
PORT=$((20000 + $$ % 20000))
"$ZMPC" relay --listen "127.0.0.1:$PORT" --spool spool >relay.log 2>&1 &
RELAY=$!
sleep 1
SIDN=$("$ZMPC" init --dir n1 --suite ed25519 --party 1 --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "n$i" --suite ed25519 --party "$i" --n 3 --threshold 2 \
      --session "$SIDN" --quiet >/dev/null
done
NODES=""
for i in 1 2 3; do
  "$ZMPC" node --dir "n$i" --relay "127.0.0.1:$PORT" --poll-ms 200 --timeout-s 120 \
      --quiet >/dev/null 2>&1 &
  NODES="$NODES $!"
done
# Wait only for the nodes: a bare `wait` would also wait for the relay, which
# runs until it is killed.
for pid in $NODES; do wait "$pid" || fail "a node exited non-zero"; done
NPK=$("$ZMPC" share pubkey --dir n1)
same "three nodes over TCP agree on a key" "$NPK" "$("$ZMPC" share pubkey --dir n3)"

# And sign over the same transport, so nothing in this section ever touched a
# shared filesystem.
printf 'signed entirely over TCP' > relay-msg.bin
SIDNS=$("$ZMPC" sign init --dir o1 --share n1/artifacts/keyshare.zmpc \
      --signers 1,3 --msg-file relay-msg.bin --quiet)
"$ZMPC" sign init --dir o3 --share n3/artifacts/keyshare.zmpc --signers 1,3 \
      --msg-file relay-msg.bin --session "$SIDNS" --quiet >/dev/null
NODES=""
for d in o1 o3; do
  "$ZMPC" node --dir "$d" --relay "127.0.0.1:$PORT" --poll-ms 200 --timeout-s 120 \
      --quiet >/dev/null 2>&1 &
  NODES="$NODES $!"
done
for pid in $NODES; do wait "$pid" || fail "a signing node exited non-zero"; done
kill "$RELAY" 2>/dev/null || true
if "$ZMPC" verify --suite ed25519 --pubkey "$NPK" --msg-file relay-msg.bin \
      --sig o1/artifacts/signature.bin --quiet
then ok "a signature produced entirely over TCP verifies"
else fail "relay-signed verify"; fi
if ls spool/*/*.zmpc >/dev/null 2>&1
then ok "the relay spool holds the same frames the file transport writes"
else fail "the relay spooled nothing"; fi

# --------------------------------------------------------------------------
if [ "$MODE" != "fast" ]; then
say "CGGMP24 threshold ECDSA (slow: Paillier keys and ZK proofs)"
SIDE=$("$ZMPC" init --dir e1 --suite ecdsa_fast --party 1 --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "e$i" --suite ecdsa_fast --party "$i" --n 3 --threshold 2 \
      --session "$SIDE" --quiet >/dev/null
done
for r in round1 round2 round3 finalize; do step "1:e1 2:e2 3:e3" dkg "$r"; done
EPK=$("$ZMPC" share pubkey --dir e1)
ok "keygen done"

SIDX=$("$ZMPC" init --dir x1 --protocol auxgen --suite ecdsa_fast --party 1 \
      --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "x$i" --protocol auxgen --suite ecdsa_fast --party "$i" \
      --n 3 --threshold 2 --session "$SIDX" --quiet >/dev/null
done
for r in round1 round2 round3 finalize; do step "1:x1 2:x2 3:x3" auxgen "$r"; done
ok "aux-info generated and cross-verified"

SIDY=$("$ZMPC" presign init --dir y1 --share e1/artifacts/keyshare.zmpc \
      --aux x1/artifacts/auxinfo.zmpc --signers 1,3 --quiet)
"$ZMPC" presign init --dir y3 --share e3/artifacts/keyshare.zmpc \
      --aux x3/artifacts/auxinfo.zmpc --signers 1,3 --session "$SIDY" --quiet >/dev/null
for r in round1 round2 round3 finalize; do step "1:y1 3:y3" presign "$r"; done
ok "presignature ready"

printf 'transfer 0.1 ETH to bob' > tx.bin
"$ZMPC" ecdsa sign --presig y1/artifacts/presignature.zmpc --msg-file tx.bin \
      --out part1.zmpc --quiet >/dev/null
"$ZMPC" ecdsa sign --presig y3/artifacts/presignature.zmpc --msg-file tx.bin \
      --out part3.zmpc --quiet >/dev/null
if [ -f y1/artifacts/presignature.zmpc ] || [ -f y3/artifacts/presignature.zmpc ]
then fail "a presignature was not consumed"
else ok "every used presignature is deleted"; fi

"$ZMPC" ecdsa combine --partials part1.zmpc,part3.zmpc --msg-file tx.bin \
      --pubkey-share e1/artifacts/keyshare.zmpc --out ecdsa.sig --quiet >/dev/null
if "$ZMPC" ecdsa verify --pubkey "$EPK" --msg-file tx.bin --sig ecdsa.sig --quiet
then ok "ECDSA signature verifies"; else fail "ECDSA verify"; fi

set +e
"$ZMPC" ecdsa verify --pubkey "$EPK" --msg-file tampered.bin --sig ecdsa.sig >/dev/null 2>&1
code=$?
set -e
[ "$code" = "65" ] && ok "a tampered ECDSA message is rejected" || fail "expected 65, got $code"

# A signing set that does not include party 1 exercises the mapping between
# real party numbers (in frames) and positions within the signing set (what
# the library's rounds use). An off-by-one there would only show up here.
SIDZ=$("$ZMPC" presign init --dir z2 --share e2/artifacts/keyshare.zmpc \
      --aux x2/artifacts/auxinfo.zmpc --signers 2,3 --quiet)
"$ZMPC" presign init --dir z3 --share e3/artifacts/keyshare.zmpc \
      --aux x3/artifacts/auxinfo.zmpc --signers 2,3 --session "$SIDZ" --quiet >/dev/null
for r in round1 round2 round3 finalize; do step "2:z2 3:z3" presign "$r"; done

printf 'signed without party 1' > tx23.bin
"$ZMPC" ecdsa sign --presig z2/artifacts/presignature.zmpc --msg-file tx23.bin \
      --out pa2.zmpc --quiet >/dev/null
"$ZMPC" ecdsa sign --presig z3/artifacts/presignature.zmpc --msg-file tx23.bin \
      --out pa3.zmpc --quiet >/dev/null
"$ZMPC" ecdsa combine --partials pa2.zmpc,pa3.zmpc --msg-file tx23.bin \
      --pubkey-share e2/artifacts/keyshare.zmpc --out sig23.bin --quiet >/dev/null
if "$ZMPC" ecdsa verify --pubkey "$EPK" --msg-file tx23.bin --sig sig23.bin --quiet
then ok "a signing set without party 1 produces the same key's signature"
else fail "signers {2,3}"; fi

say "DKLs23 threshold ECDSA (slow: 256 oblivious transfers per pair)"
SIDD=$("$ZMPC" init --dir d1 --suite dkls --party 1 --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "d$i" --suite dkls --party "$i" --n 3 --threshold 2 \
      --session "$SIDD" --quiet >/dev/null
done
for r in round1 round2 round3 finalize; do step "1:d1 2:d2 3:d3" dkg "$r"; done
DPK=$("$ZMPC" share pubkey --dir d1)
ok "keygen done (dkls suite)"

SIDS=$("$ZMPC" init --dir k1 --protocol dkls_setup --suite dkls --party 1 \
      --n 3 --threshold 2 --quiet)
for i in 2 3; do
  "$ZMPC" init --dir "k$i" --protocol dkls_setup --suite dkls --party "$i" \
      --n 3 --threshold 2 --session "$SIDS" --quiet >/dev/null
done
for r in round1 round2 finalize; do
  for i in 1 2 3; do
    "$ZMPC" dkls setup "$r" --dir "k$i" --share "d$i/artifacts/keyshare.zmpc" \
        --quiet >/dev/null
  done
  deliver "1:k1 2:k2 3:k3"
done
ok "pairwise setup complete for all three parties"

# Exactly 32 bytes: a signer must treat this as a message to hash, never as
# a precomputed digest, or verification fails.
printf 'exactly thirty-two bytes long!!!' > dtx.bin
SIDV=$("$ZMPC" dkls sign init --dir m1 --share d1/artifacts/keyshare.zmpc \
      --setup k1/artifacts/dkls-setup.zmpc --signers 1,3 --msg-file dtx.bin --quiet)
"$ZMPC" dkls sign init --dir m3 --share d3/artifacts/keyshare.zmpc \
      --setup k3/artifacts/dkls-setup.zmpc --signers 1,3 --msg-file dtx.bin \
      --session "$SIDV" --quiet >/dev/null
for r in phase1 phase2 phase3 finalize; do
  for d in m1 m3; do "$ZMPC" dkls sign "$r" --dir "$d" --quiet >/dev/null; done
  deliver "1:m1 3:m3"
done

# Both signers must land on the identical signature; they combine the same
# broadcast components, so any divergence means a routing or ordering bug.
same "both signers produce the same signature" \
     "$(od -An -tx1 -v < m1/artifacts/signature.bin | tr -d ' \n')" \
     "$(od -An -tx1 -v < m3/artifacts/signature.bin | tr -d ' \n')"

if "$ZMPC" verify --suite dkls --pubkey "$DPK" --msg-file dtx.bin \
      --sig m1/artifacts/signature.bin --quiet
then ok "DKLs23 signature verifies as ordinary ECDSA"; else fail "dkls verify"; fi

set +e
"$ZMPC" verify --suite dkls --pubkey "$DPK" --msg-file tampered.bin \
      --sig m1/artifacts/signature.bin >/dev/null 2>&1
code=$?
set -e
[ "$code" = "65" ] && ok "a tampered DKLs23 message is rejected" || fail "expected 65, got $code"

# The setup artifact is quorum-independent: a different pair must be able to
# sign from the same setup with no extra rounds.
SIDW=$("$ZMPC" dkls sign init --dir q2 --share d2/artifacts/keyshare.zmpc \
      --setup k2/artifacts/dkls-setup.zmpc --signers 2,3 --msg-file dtx.bin --quiet)
"$ZMPC" dkls sign init --dir q3 --share d3/artifacts/keyshare.zmpc \
      --setup k3/artifacts/dkls-setup.zmpc --signers 2,3 --msg-file dtx.bin \
      --session "$SIDW" --quiet >/dev/null
for r in phase1 phase2 phase3 finalize; do
  for d in q2 q3; do "$ZMPC" dkls sign "$r" --dir "$d" --quiet >/dev/null; done
  deliver "2:q2 3:q3"
done
if "$ZMPC" verify --suite dkls --pubkey "$DPK" --msg-file dtx.bin \
      --sig q2/artifacts/signature.bin --quiet
then ok "a different quorum reuses the same setup"; else fail "signers {2,3}"; fi
fi

printf '\n\033[1m%d checks passed\033[0m\n' "$pass"
