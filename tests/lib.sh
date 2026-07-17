# Shared helpers for verify.sh fixture tests. Sourced by run_tests.sh.
# POSIX sh. The keypair these tests generate is named test-fixture-key and is
# a throwaway, generated fresh under $WORK on every run -- it is never
# written outside tests/, and tests/ itself is not part of the published
# repository layout (see README).

# canon_hash JSON_OBJECT -- mirror verify.sh's own canonicalization exactly:
# jq -cS with "hash" REMOVED (attestable-ops's normative convention, not
# set to an empty string), hashed with no trailing newline.
canon_hash() {
	canon_hash_json=$1
	canon=$(printf '%s\n' "$canon_hash_json" | jq -cS 'del(.hash)')
	printf '%s' "$canon" | sha256sum | awk '{print $1}'
}

# build_event PREV_HASH EVENT_ID TYPE OCCURRED_AT -- one TDD #8 ledger event,
# with its own "hash" field correctly computed over the canonical form.
build_event() {
	be_prev=$1
	be_event_id=$2
	be_type=$3
	be_occurred=$4
	be_base=$(jq -n \
		--argjson v 1 \
		--arg org "cust-zero" \
		--arg event_id "$be_event_id" \
		--arg type "$be_type" \
		--arg source "dependabot" \
		--arg repo "cust-zero/example-repo" \
		--arg vid "CVE-2026-0001" \
		--arg pkg "left-pad" \
		--arg eco "npm" \
		--arg sev "high" \
		--arg occurred "$be_occurred" \
		--arg prev "$be_prev" \
		'{v: $v, org: $org, event_id: $event_id, type: $type, source: $source,
		  repo: $repo,
		  vuln: {id: $vid, package: $pkg, ecosystem: $eco, severity: $sev},
		  occurred_at: $occurred, recorded_at: $occurred, resolution: null,
		  prev_hash: $prev, hash: ""}')
	be_hash=$(canon_hash "$be_base")
	printf '%s\n' "$be_base" | jq -c --arg h "$be_hash" '.hash = $h'
}

# build_ledger DIR -- writes DIR/ledger.jsonl (2 correctly-chained events),
# prints the recomputed head hash on stdout.
build_ledger() {
	bl_dir=$1
	bl_e1=$(build_event "" "evt-0001" "alert.detected" "2026-01-01T00:00:00Z")
	bl_h1=$(printf '%s' "$bl_e1" | jq -r '.hash')
	bl_e2=$(build_event "$bl_h1" "evt-0002" "alert.resolved" "2026-01-05T00:00:00Z")
	bl_h2=$(printf '%s' "$bl_e2" | jq -r '.hash')
	printf '%s\n%s\n' "$bl_e1" "$bl_e2" >"$bl_dir/ledger.jsonl"
	printf '%s' "$bl_h2"
}

# build_attestation DIR HEAD PIN KEY_ID GENERATED_AT -- writes DIR/attestation.json.
build_attestation() {
	ba_dir=$1
	ba_head=$2
	ba_pin=$3
	ba_key_id=$4
	ba_generated=$5
	jq -n \
		--arg org "cust-zero" \
		--arg from "2026-01-01" \
		--arg to "2026-07-16" \
		--arg head "$ba_head" \
		--arg gen "$ba_generated" \
		--arg keyid "$ba_key_id" \
		--arg pin "$ba_pin" \
		'{org: $org, window: {from: $from, to: $to}, ledger_head: $head,
		  event_count: 2,
		  metrics: {cves_surfaced: 1, resolved_in_sla: 1,
		            mttr_days_by_severity: {high: 4}, open_material: 0},
		  ots_proof: "head.ots", generated_at: $gen,
		  signature: {alg: "ed25519", format: "minisign", key_id: $keyid,
		              pubkey_sha256: $pin,
		              keys_url: "https://keys.displace.tech/keys.json"}}' \
		>"$ba_dir/attestation.json"
}

# build_valid_pack DIR SECKEY PUBKEY PIN -- a complete, internally-consistent,
# correctly-signed fixture pack in DIR. Individual tests then mutate copies
# of it to exercise specific failure branches.
build_valid_pack() {
	bp_dir=$1
	bp_seckey=$2
	bp_pubkey=$3
	bp_pin=$4

	bp_head=$(build_ledger "$bp_dir")
	build_attestation "$bp_dir" "$bp_head" "$bp_pin" "test-fixture-key" "2026-03-01T00:00:00Z"

	printf '%%PDF-1.4 dummy evidence pack fixture\n' >"$bp_dir/evidence-pack.pdf"
	cp "$bp_pubkey" "$bp_dir/pubkey.pub"
	: >"$bp_dir/head.ots"

	minisign -S -s "$bp_seckey" -W -t "attestable test-fixture pack=cust-zero generated=2026-03-01T00:00:00Z" \
		-m "$bp_dir/attestation.json" -x "$bp_dir/attestation.json.minisig" >/dev/null
	minisign -S -s "$bp_seckey" -W -t "attestable test-fixture pack=cust-zero generated=2026-03-01T00:00:00Z" \
		-m "$bp_dir/evidence-pack.pdf" -x "$bp_dir/evidence-pack.pdf.minisig" >/dev/null
}

TESTS_RUN=0
TESTS_FAILED=0

# assert_exit LABEL EXPECTED_CODE ACTUAL_CODE
assert_exit() {
	ae_label=$1
	ae_expected=$2
	ae_actual=$3
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$ae_expected" = "$ae_actual" ]; then
		echo "ok   - $ae_label (exit $ae_actual)"
	else
		echo "FAIL - $ae_label: expected exit $ae_expected, got $ae_actual"
		TESTS_FAILED=$((TESTS_FAILED + 1))
	fi
}

# assert_contains LABEL HAYSTACK NEEDLE
assert_contains() {
	ac_label=$1
	ac_haystack=$2
	ac_needle=$3
	TESTS_RUN=$((TESTS_RUN + 1))
	case "$ac_haystack" in
	*"$ac_needle"*)
		echo "ok   - $ac_label (contains '$ac_needle')"
		;;
	*)
		echo "FAIL - $ac_label: expected output to contain '$ac_needle'"
		TESTS_FAILED=$((TESTS_FAILED + 1))
		;;
	esac
}
