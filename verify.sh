#!/bin/sh
# Attestable evidence-pack verifier.
#
# Implements the verifier contract in
# docs/SPEC_Attestable_Key_Publication.md #6. POSIX sh only; tested under
# dash. Dependencies: sh, minisign, sha256sum, jq. `ots` is optional -- the
# anchor check (#5) is SKIPped with a warning if it is not installed.
# `curl` or `wget` is optional -- needed only for -f (online manifest fetch);
# without one of them, or without -f, the manifest check (#2) is SKIPped
# with a warning, since the pin check (#1) is the root of trust, not the
# manifest.
#
# Canonicalization for the chain check (#4) follows TDD #8's "fixed-key-order
# serializer" option: `jq -cS` (recursively sorted keys, compact, no added
# trailing newline) over each ledger event with its "hash" field set to the
# empty string. This MUST match whatever the ledger-producing tooling
# (attestable-ops, a private repo) actually implements -- see README.

set -u

PROG_NAME=$(basename "$0")
MANIFEST_URL="https://keys.displace.tech/keys.json"

EXIT_HASH=1
EXIT_KEY=2
EXIT_DEP=3

usage() {
	cat <<'EOF'
Usage: verify.sh [-f] <attestation.json> <evidence-pack.pdf> <pubkey-file> <ledger-export.jsonl>

  -f    Attempt to fetch https://keys.displace.tech/keys.json (requires curl
        or wget) for the online manifest check. Without -f, or if the fetch
        fails, the manifest check is SKIPped with a warning: the pin check
        (#1) is the root of trust, not the manifest.
  -h    Show this help and exit 0.

Verifies an Attestable evidence pack per SPEC_Attestable_Key_Publication.md #6:
  1. pin check        pubkey fingerprint matches attestation.json's pin
  2. manifest check   (online only) key status + validity window in keys.json
  3. signature checks minisign verification of attestation.json and the pack
  4. chain check      recomputed ledger head hash matches attestation.json
  5. anchor check     (if `ots` is installed) OpenTimestamps proof of the head

Expected alongside the given files (same directory, standard suffixes):
  <attestation.json>.minisig
  <evidence-pack.pdf>.minisig
  the OTS proof file named by attestation.json's "ots_proof" field

Exit codes:
  0  all checks pass
  1  a signature or hash check failed
  2  the key was not found in the manifest, or is outside its valid window
  3  a required dependency or input file is missing
EOF
}

# fail_dep MESSAGE -- unrecoverable: print, exit 3 immediately.
fail_dep() {
	echo "$PROG_NAME: $1" >&2
	exit "$EXIT_DEP"
}

# report STATUS CHECK_NAME DETAIL -- print one contract line; track worst exit.
WORST_EXIT=0
report() {
	report_status=$1
	report_check=$2
	report_detail=$3
	printf '%-4s %s: %s\n' "$report_status" "$report_check" "$report_detail"
	case "$report_status" in
	FAIL)
		case "$report_check" in
		"2 manifest")
			[ "$WORST_EXIT" -lt "$EXIT_KEY" ] && WORST_EXIT=$EXIT_KEY
			;;
		*)
			[ "$WORST_EXIT" -lt "$EXIT_HASH" ] && WORST_EXIT=$EXIT_HASH
			;;
		esac
		;;
	esac
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

if [ $# -eq 0 ]; then
	usage
	exit "$EXIT_DEP"
fi

FETCH=0
while getopts "fh" opt; do
	case "$opt" in
	f) FETCH=1 ;;
	h)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit "$EXIT_DEP"
		;;
	esac
done
shift $((OPTIND - 1))

if [ $# -ne 4 ]; then
	usage >&2
	fail_dep "expected 4 positional arguments, got $#"
fi

ATTESTATION=$1
PACK=$2
PUBKEY=$3
LEDGER=$4

ATTESTATION_SIG="${ATTESTATION}.minisig"
PACK_SIG="${PACK}.minisig"

# ---------------------------------------------------------------------------
# Preflight: dependencies and input files
# ---------------------------------------------------------------------------

for dep in jq sha256sum minisign; do
	command -v "$dep" >/dev/null 2>&1 || fail_dep "missing required dependency: $dep"
done

for f in "$ATTESTATION" "$PACK" "$PUBKEY" "$LEDGER" "$ATTESTATION_SIG" "$PACK_SIG"; do
	[ -r "$f" ] || fail_dep "missing or unreadable input file: $f"
done

jq -e . "$ATTESTATION" >/dev/null 2>&1 || fail_dep "$ATTESTATION is not valid JSON"

PIN_EXPECTED=$(jq -r '.signature.pubkey_sha256 // empty' "$ATTESTATION")
KEY_ID=$(jq -r '.signature.key_id // empty' "$ATTESTATION")
LEDGER_HEAD_EXPECTED=$(jq -r '.ledger_head // empty' "$ATTESTATION")
GENERATED_AT=$(jq -r '.generated_at // empty' "$ATTESTATION")

[ -n "$PIN_EXPECTED" ] || fail_dep "$ATTESTATION is missing .signature.pubkey_sha256"
[ -n "$KEY_ID" ] || fail_dep "$ATTESTATION is missing .signature.key_id"
[ -n "$LEDGER_HEAD_EXPECTED" ] || fail_dep "$ATTESTATION is missing .ledger_head"

# ---------------------------------------------------------------------------
# 1. Pin check
# ---------------------------------------------------------------------------

PUBKEY_HASH=$(sha256sum "$PUBKEY" | awk '{print $1}')

if [ "$PUBKEY_HASH" = "$PIN_EXPECTED" ]; then
	report PASS "1 pin" "$PUBKEY ($PUBKEY_HASH) matches attestation pin"
else
	report FAIL "1 pin" "$PUBKEY sha256 ($PUBKEY_HASH) != attestation pin ($PIN_EXPECTED)"
fi

# ---------------------------------------------------------------------------
# 2. Manifest check (online only)
# ---------------------------------------------------------------------------

if [ "$FETCH" -ne 1 ]; then
	report SKIP "2 manifest" "offline (pass -f to fetch $MANIFEST_URL); pin check (#1) is the root of trust"
else
	FETCH_TOOL=""
	command -v curl >/dev/null 2>&1 && FETCH_TOOL=curl
	if [ -z "$FETCH_TOOL" ]; then
		command -v wget >/dev/null 2>&1 && FETCH_TOOL=wget
	fi

	if [ -z "$FETCH_TOOL" ]; then
		report SKIP "2 manifest" "neither curl nor wget available to fetch $MANIFEST_URL; pin check (#1) is the root of trust"
	else
		MANIFEST_TMP=$(mktemp)
		FETCH_OK=1
		if [ "$FETCH_TOOL" = curl ]; then
			curl -fsS --max-time 10 -o "$MANIFEST_TMP" "$MANIFEST_URL" >/dev/null 2>&1 || FETCH_OK=0
		else
			wget -q --timeout=10 --tries=1 -O "$MANIFEST_TMP" "$MANIFEST_URL" >/dev/null 2>&1 || FETCH_OK=0
		fi

		if [ "$FETCH_OK" -ne 1 ] || ! jq -e . "$MANIFEST_TMP" >/dev/null 2>&1; then
			report SKIP "2 manifest" "could not fetch or parse $MANIFEST_URL; pin check (#1) is the root of trust"
		else
			ENTRY=$(jq -c --arg kid "$KEY_ID" '.keys[] | select(.key_id == $kid)' "$MANIFEST_TMP")
			if [ -z "$ENTRY" ]; then
				report FAIL "2 manifest" "key_id $KEY_ID not present in $MANIFEST_URL"
			else
				M_STATUS=$(printf '%s' "$ENTRY" | jq -r '.status')
				M_FROM=$(printf '%s' "$ENTRY" | jq -r '.valid_from')
				M_TO=$(printf '%s' "$ENTRY" | jq -r '.valid_to // empty')
				GEN_DATE=${GENERATED_AT%%T*}

				if [ "$M_STATUS" = "revoked" ]; then
					SIG_VALID_BEFORE=$(printf '%s' "$ENTRY" | jq -r '.revocation.signatures_valid_before // empty')
					if [ -n "$SIG_VALID_BEFORE" ] && expr "$GEN_DATE" '<' "$SIG_VALID_BEFORE" >/dev/null; then
						report PASS "2 manifest" "key $KEY_ID revoked, but generated_at $GEN_DATE predates signatures_valid_before $SIG_VALID_BEFORE"
					else
						report FAIL "2 manifest" "key $KEY_ID is revoked and does not cover generated_at $GEN_DATE"
					fi
				elif [ -z "$GEN_DATE" ]; then
					report FAIL "2 manifest" "attestation has no generated_at to check against the validity window"
				elif expr "$GEN_DATE" '<' "$M_FROM" >/dev/null; then
					report FAIL "2 manifest" "generated_at $GEN_DATE precedes valid_from $M_FROM"
				elif [ -n "$M_TO" ] && expr "$M_TO" '<' "$GEN_DATE" >/dev/null; then
					report FAIL "2 manifest" "generated_at $GEN_DATE is after valid_to $M_TO"
				else
					report PASS "2 manifest" "key $KEY_ID status=$M_STATUS covers generated_at $GEN_DATE"
				fi
			fi
		fi
		rm -f "$MANIFEST_TMP"
	fi
fi

# ---------------------------------------------------------------------------
# 3. Signature checks
# ---------------------------------------------------------------------------

MS_OUT=$(minisign -Vm "$ATTESTATION" -x "$ATTESTATION_SIG" -p "$PUBKEY" 2>&1)
MS_RC=$?
MS_COMMENT=$(printf '%s\n' "$MS_OUT" | grep -i '^Trusted comment:' || true)
if [ "$MS_RC" -eq 0 ]; then
	report PASS "3 signature(attestation.json)" "$MS_COMMENT"
else
	report FAIL "3 signature(attestation.json)" "$(printf '%s' "$MS_OUT" | head -n1)"
fi

MS_OUT=$(minisign -Vm "$PACK" -x "$PACK_SIG" -p "$PUBKEY" 2>&1)
MS_RC=$?
MS_COMMENT=$(printf '%s\n' "$MS_OUT" | grep -i '^Trusted comment:' || true)
if [ "$MS_RC" -eq 0 ]; then
	report PASS "3 signature(pack)" "$MS_COMMENT"
else
	report FAIL "3 signature(pack)" "$(printf '%s' "$MS_OUT" | head -n1)"
fi

# ---------------------------------------------------------------------------
# 4. Chain check
# ---------------------------------------------------------------------------

CHAIN_OK=1
CHAIN_DETAIL=""
PREV_HASH=""
HEAD_HASH=""
LINE_NO=0

while IFS= read -r RAW_LINE || [ -n "$RAW_LINE" ]; do
	[ -z "$RAW_LINE" ] && continue
	LINE_NO=$((LINE_NO + 1))

	if ! printf '%s\n' "$RAW_LINE" | jq -e . >/dev/null 2>&1; then
		CHAIN_OK=0
		CHAIN_DETAIL="malformed JSON on ledger line $LINE_NO"
		break
	fi

	STORED_HASH=$(printf '%s\n' "$RAW_LINE" | jq -r '.hash // empty')
	STORED_PREV=$(printf '%s\n' "$RAW_LINE" | jq -r '.prev_hash // empty')

	if [ -z "$STORED_HASH" ]; then
		CHAIN_OK=0
		CHAIN_DETAIL="ledger line $LINE_NO has no hash field"
		break
	fi

	CANONICAL=$(printf '%s\n' "$RAW_LINE" | jq -cS '. + {hash: ""}')
	COMPUTED_HASH=$(printf '%s' "$CANONICAL" | sha256sum | awk '{print $1}')

	if [ "$COMPUTED_HASH" != "$STORED_HASH" ]; then
		CHAIN_OK=0
		EVENT_ID=$(printf '%s\n' "$RAW_LINE" | jq -r '.event_id // "?"')
		CHAIN_DETAIL="hash mismatch at ledger line $LINE_NO (event_id $EVENT_ID)"
		break
	fi

	if [ "$LINE_NO" -gt 1 ] && [ "$STORED_PREV" != "$PREV_HASH" ]; then
		CHAIN_OK=0
		CHAIN_DETAIL="prev_hash mismatch at ledger line $LINE_NO"
		break
	fi

	PREV_HASH=$STORED_HASH
	HEAD_HASH=$STORED_HASH
done <"$LEDGER"

if [ "$LINE_NO" -eq 0 ]; then
	CHAIN_OK=0
	CHAIN_DETAIL="ledger export $LEDGER contains no events"
fi

if [ "$CHAIN_OK" -eq 1 ] && [ "$HEAD_HASH" != "$LEDGER_HEAD_EXPECTED" ]; then
	CHAIN_OK=0
	CHAIN_DETAIL="recomputed head ($HEAD_HASH) != attestation.json ledger_head ($LEDGER_HEAD_EXPECTED)"
fi

if [ "$CHAIN_OK" -eq 1 ]; then
	report PASS "4 chain" "$LINE_NO events, recomputed head $HEAD_HASH matches attestation.json"
else
	report FAIL "4 chain" "$CHAIN_DETAIL"
fi

# ---------------------------------------------------------------------------
# 5. Anchor check (optional dependency: ots)
# ---------------------------------------------------------------------------

if ! command -v ots >/dev/null 2>&1; then
	report SKIP "5 anchor" "ots not installed; OpenTimestamps proof not verified"
else
	OTS_PROOF_NAME=$(jq -r '.ots_proof // empty' "$ATTESTATION")
	ATTESTATION_DIR=$(dirname "$ATTESTATION")
	OTS_PROOF_PATH="$ATTESTATION_DIR/$OTS_PROOF_NAME"

	if [ -z "$OTS_PROOF_NAME" ]; then
		report FAIL "5 anchor" "attestation.json has no ots_proof field"
	elif [ ! -r "$OTS_PROOF_PATH" ]; then
		report FAIL "5 anchor" "ots proof file not found: $OTS_PROOF_PATH"
	else
		OTS_HEAD_TMP=$(mktemp)
		printf '%s\n' "$LEDGER_HEAD_EXPECTED" >"$OTS_HEAD_TMP"
		if ots verify -f "$OTS_HEAD_TMP" "$OTS_PROOF_PATH" >/dev/null 2>&1; then
			report PASS "5 anchor" "OpenTimestamps proof $OTS_PROOF_PATH verifies the ledger head"
		else
			report FAIL "5 anchor" "OpenTimestamps verification failed for $OTS_PROOF_PATH"
		fi
		rm -f "$OTS_HEAD_TMP"
	fi
fi

exit "$WORST_EXIT"
