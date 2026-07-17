#!/bin/sh
# Fixture-based tests for ../verify.sh. POSIX sh; run under dash.
#
# Generates a THROWAWAY minisign keypair named test-fixture-key inside a
# temp directory for the duration of this run only -- it is never written
# anywhere under the repository, only under $WORK (mktemp -d), which is
# removed on exit.
#
# Usage: sh tests/run_tests.sh   (or: dash tests/run_tests.sh)

set -u

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
VERIFY="$TESTS_DIR/../verify.sh"

# shellcheck source=tests/lib.sh
. "$TESTS_DIR/lib.sh"

command -v minisign >/dev/null 2>&1 || {
	echo "SKIP - minisign not installed; cannot run fixture tests" >&2
	exit 0
}

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

SECKEY="$WORK/test-fixture-key.key"
PUBKEY="$WORK/test-fixture-key.pub"
minisign -G -W -p "$PUBKEY" -s "$SECKEY" -c "test-fixture-key (throwaway, tests-only)" >/dev/null
PIN=$(sha256sum "$PUBKEY" | awk '{print $1}')

# ---------------------------------------------------------------------------
# T1: a correctly-built, correctly-signed pack verifies clean, offline.
# ---------------------------------------------------------------------------
d=$WORK/t1
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T1 valid pack: exit code" 0 "$rc"
assert_contains "T1 valid pack: pin PASS" "$out" "PASS 1 pin"
assert_contains "T1 valid pack: manifest SKIP (offline)" "$out" "SKIP 2 manifest"
assert_contains "T1 valid pack: attestation sig PASS" "$out" "PASS 3 signature(attestation.json)"
assert_contains "T1 valid pack: pack sig PASS" "$out" "PASS 3 signature(pack)"
assert_contains "T1 valid pack: chain PASS" "$out" "PASS 4 chain"
assert_contains "T1 valid pack: anchor SKIP (no ots)" "$out" "SKIP 5 anchor"

# ---------------------------------------------------------------------------
# T2: pin mismatch -- attestation.json declares a bogus pubkey_sha256.
# ---------------------------------------------------------------------------
d=$WORK/t2
mkdir -p "$d"
build_ledger "$d" >/dev/null
bogus_pin=$(printf 'not-the-real-key' | sha256sum | awk '{print $1}')
build_attestation "$d" "$(jq -r '.hash' <"$d/ledger.jsonl" | tail -n1)" "$bogus_pin" "test-fixture-key" "2026-03-01T00:00:00Z"
printf '%%PDF-1.4 dummy\n' >"$d/evidence-pack.pdf"
cp "$PUBKEY" "$d/pubkey.pub"
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/attestation.json" -x "$d/attestation.json.minisig" >/dev/null
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/evidence-pack.pdf" -x "$d/evidence-pack.pdf.minisig" >/dev/null
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T2 pin mismatch: exit code" 1 "$rc"
assert_contains "T2 pin mismatch: pin FAIL" "$out" "FAIL 1 pin"
assert_contains "T2 pin mismatch: signatures still PASS" "$out" "PASS 3 signature(attestation.json)"

# ---------------------------------------------------------------------------
# T3: attestation.json signature fails (content changed after signing).
# ---------------------------------------------------------------------------
d=$WORK/t3
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
jq '.event_count = 999' "$d/attestation.json" >"$d/attestation.json.tmp" && mv "$d/attestation.json.tmp" "$d/attestation.json"
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T3 tampered attestation: exit code" 1 "$rc"
assert_contains "T3 tampered attestation: sig FAIL" "$out" "FAIL 3 signature(attestation.json)"

# ---------------------------------------------------------------------------
# T4: evidence pack signature fails (pdf changed after signing).
# ---------------------------------------------------------------------------
d=$WORK/t4
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
printf '%%PDF-1.4 tampered\n' >"$d/evidence-pack.pdf"
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T4 tampered pack: exit code" 1 "$rc"
assert_contains "T4 tampered pack: sig FAIL" "$out" "FAIL 3 signature(pack)"

# ---------------------------------------------------------------------------
# T5: chain check fails -- a ledger event's stored hash no longer matches
# its (tampered) content.
# ---------------------------------------------------------------------------
d=$WORK/t5
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
sed 's/left-pad/right-pad/' "$d/ledger.jsonl" >"$d/ledger.jsonl.tmp" && mv "$d/ledger.jsonl.tmp" "$d/ledger.jsonl"
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T5 tampered ledger event: exit code" 1 "$rc"
assert_contains "T5 tampered ledger event: chain FAIL" "$out" "FAIL 4 chain"
assert_contains "T5 tampered ledger event: hash mismatch detail" "$out" "hash mismatch"

# ---------------------------------------------------------------------------
# T6: chain check fails -- prev_hash link is broken but each event's own
# hash is still self-consistent (isolates the prev_hash-mismatch branch).
# ---------------------------------------------------------------------------
d=$WORK/t6
mkdir -p "$d"
e1=$(build_event "" "evt-0001" "alert.detected" "2026-01-01T00:00:00Z")
e2=$(build_event "deadbeef00000000000000000000000000000000000000000000000000000" "evt-0002" "alert.resolved" "2026-01-05T00:00:00Z")
h2=$(printf '%s' "$e2" | jq -r '.hash')
printf '%s\n%s\n' "$e1" "$e2" >"$d/ledger.jsonl"
build_attestation "$d" "$h2" "$PIN" "test-fixture-key" "2026-03-01T00:00:00Z"
printf '%%PDF-1.4 dummy\n' >"$d/evidence-pack.pdf"
cp "$PUBKEY" "$d/pubkey.pub"
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/attestation.json" -x "$d/attestation.json.minisig" >/dev/null
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/evidence-pack.pdf" -x "$d/evidence-pack.pdf.minisig" >/dev/null
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T6 broken prev_hash link: exit code" 1 "$rc"
assert_contains "T6 broken prev_hash link: chain FAIL" "$out" "FAIL 4 chain"
assert_contains "T6 broken prev_hash link: detail" "$out" "prev_hash mismatch"

# ---------------------------------------------------------------------------
# T7: chain check fails -- attestation.json's ledger_head disagrees with the
# (internally consistent) recomputed head.
# ---------------------------------------------------------------------------
d=$WORK/t7
mkdir -p "$d"
build_ledger "$d" >/dev/null
build_attestation "$d" "0000000000000000000000000000000000000000000000000000000000000" "$PIN" "test-fixture-key" "2026-03-01T00:00:00Z"
printf '%%PDF-1.4 dummy\n' >"$d/evidence-pack.pdf"
cp "$PUBKEY" "$d/pubkey.pub"
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/attestation.json" -x "$d/attestation.json.minisig" >/dev/null
minisign -S -s "$SECKEY" -W -t "tc" -m "$d/evidence-pack.pdf" -x "$d/evidence-pack.pdf.minisig" >/dev/null
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T7 ledger_head disagreement: exit code" 1 "$rc"
assert_contains "T7 ledger_head disagreement: chain FAIL" "$out" "FAIL 4 chain"
assert_contains "T7 ledger_head disagreement: detail" "$out" "!= attestation.json ledger_head"

# ---------------------------------------------------------------------------
# T8: missing input file -> exit 3.
# ---------------------------------------------------------------------------
d=$WORK/t8
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
out=$("$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/does-not-exist.jsonl" 2>&1)
rc=$?
assert_exit "T8 missing ledger file: exit code" 3 "$rc"

# ---------------------------------------------------------------------------
# T9: zero arguments -> usage on stdout, exit 3.
# ---------------------------------------------------------------------------
out=$("$VERIFY" 2>/dev/null)
rc=$?
assert_exit "T9 zero args: exit code" 3 "$rc"
assert_contains "T9 zero args: usage printed" "$out" "Usage: verify.sh"

# ---------------------------------------------------------------------------
# T10: -h -> usage on stdout, exit 0.
# ---------------------------------------------------------------------------
out=$("$VERIFY" -h 2>/dev/null)
rc=$?
assert_exit "T10 -h: exit code" 0 "$rc"
assert_contains "T10 -h: usage printed" "$out" "Usage: verify.sh"

# ---------------------------------------------------------------------------
# T11: -f with no network route to the real manifest host -> SKIP, not FAIL.
# (No fake curl on PATH here -- this hits the real, hardcoded URL and is
# expected to fail to connect in a sandboxed test environment.)
# ---------------------------------------------------------------------------
d=$WORK/t11
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
out=$("$VERIFY" -f "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_contains "T11 -f unreachable: manifest SKIP" "$out" "2 manifest"
case "$out" in
*"PASS 2 manifest"*)
	echo "FAIL - T11 -f unreachable: manifest should not PASS without real network access"
	TESTS_FAILED=$((TESTS_FAILED + 1))
	TESTS_RUN=$((TESTS_RUN + 1))
	;;
*)
	echo "ok   - T11 -f unreachable: manifest did not PASS"
	TESTS_RUN=$((TESTS_RUN + 1))
	;;
esac

# ---------------------------------------------------------------------------
# T12/T13: manifest check logic, exercised via a stubbed `curl` on PATH that
# serves a local fixture manifest instead of hitting the network.
# ---------------------------------------------------------------------------
FAKEBIN=$WORK/fakebin
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/sh
# Test stub: ignore the URL, copy $FAKE_MANIFEST to the -o destination.
out=""
prev=""
for arg in "$@"; do
	if [ "$prev" = "-o" ]; then
		out=$arg
	fi
	prev=$arg
done
[ -n "$out" ] && cp "$FAKE_MANIFEST" "$out"
exit 0
EOF
chmod +x "$FAKEBIN/curl"

d=$WORK/t12
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
jq -n --arg pin "$PIN" '{spec_version: 1, issuer: "Displace Technologies LLC",
	updated: "2026-03-01T00:00:00Z",
	keys: [{key_id: "test-fixture-key", alg: "ed25519", format: "minisign",
	        created: "2026-01-01", status: "active", valid_from: "2026-01-01",
	        valid_to: null, pubkey_file: "test-fixture-key.pub",
	        pubkey_sha256: $pin, ots_proof: "test-fixture-key.pub.ots",
	        revocation: null}]}' >"$d/manifest.json"
out=$(FAKE_MANIFEST="$d/manifest.json" PATH="$FAKEBIN:$PATH" "$VERIFY" -f "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T12 manifest active+in-window: exit code" 0 "$rc"
assert_contains "T12 manifest active+in-window: PASS" "$out" "PASS 2 manifest"

d=$WORK/t13
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
jq -n --arg pin "$PIN" '{spec_version: 1, issuer: "Displace Technologies LLC",
	updated: "2026-03-01T00:00:00Z",
	keys: [{key_id: "test-fixture-key", alg: "ed25519", format: "minisign",
	        created: "2026-01-01", status: "revoked", valid_from: "2026-01-01",
	        valid_to: "2026-02-01", pubkey_file: "test-fixture-key.pub",
	        pubkey_sha256: $pin, ots_proof: "test-fixture-key.pub.ots",
	        revocation: {date: "2026-02-01", reason: "test", signatures_valid_before: "2026-02-01", notice: "revocation-test-fixture-key.txt"}}]}' >"$d/manifest.json"
out=$(FAKE_MANIFEST="$d/manifest.json" PATH="$FAKEBIN:$PATH" "$VERIFY" -f "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T13 manifest revoked, generated_at outside window: exit code" 2 "$rc"
assert_contains "T13 manifest revoked: FAIL" "$out" "FAIL 2 manifest"

# ---------------------------------------------------------------------------
# T14: anchor check logic, exercised via a stubbed `ots` on PATH.
# ---------------------------------------------------------------------------
cat >"$FAKEBIN/ots" <<'EOF'
#!/bin/sh
# Test stub: "verify -f HEADFILE PROOF" succeeds iff PROOF contains "VALID".
if [ "$1" = "verify" ]; then
	shift
	proof=""
	prev=""
	for arg in "$@"; do
		if [ "$prev" != "-f" ]; then
			proof=$arg
		fi
		prev=$arg
	done
	grep -qx VALID "$proof" 2>/dev/null && exit 0
	exit 1
fi
exit 1
EOF
chmod +x "$FAKEBIN/ots"

d=$WORK/t14a
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
printf 'VALID\n' >"$d/head.ots"
out=$(PATH="$FAKEBIN:$PATH" "$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T14a anchor valid proof: exit code" 0 "$rc"
assert_contains "T14a anchor valid proof: PASS" "$out" "PASS 5 anchor"

d=$WORK/t14b
mkdir -p "$d"
build_valid_pack "$d" "$SECKEY" "$PUBKEY" "$PIN"
printf 'INVALID\n' >"$d/head.ots"
out=$(PATH="$FAKEBIN:$PATH" "$VERIFY" "$d/attestation.json" "$d/evidence-pack.pdf" "$d/pubkey.pub" "$d/ledger.jsonl" 2>&1)
rc=$?
assert_exit "T14b anchor invalid proof: exit code" 1 "$rc"
assert_contains "T14b anchor invalid proof: FAIL" "$out" "FAIL 5 anchor"

# ---------------------------------------------------------------------------
echo
echo "$TESTS_RUN assertions, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
