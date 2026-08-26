#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m2-route-governance-checkpoint-history.py"
HEAD_KEY="$ROOT/config/m2-route-governance-root-next-test-public.pem"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CHECKPOINT_SIGNATURE_B64="kygbq033of4cXWTPzG+lJ+A93E9UDsMTrRajsvRbLbP6141VLEeXPWCI63i9Jeaf/YZhP8w3cQs/wnoWU/VAAQ=="
HEAD_KEY_SHA="$(sha256sum "$HEAD_KEY" | awk '{print $1}')"

write_checkpoint() {
  local output="$1" epoch="${2:-2}" sequence="${3:-1}" launch="${4:-NO}" checkpoint_id="${5:-izzos-m2-route-governance-checkpoint-host-test-02-01}"
  cat > "$output" <<EOF
route-governance-root-anti-rollback-checkpoint-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ANTI_ROLLBACK_CHECKPOINT_V1
checkpoint-id: $checkpoint_id
root-transition-sha256: 4324ea1d2bb46c9787232a3f3c342f160a409059faed8a00f36916aad5719513
previous-checkpoint-sha256: 1edebdd2bb843500e6e4e52538f2792ac9ffa515265050b71986d455d7e9249a
active-governance-root-key-id: izzos-m2-route-governance-host-test-02
active-governance-root-public-key-sha256: $HEAD_KEY_SHA
active-governance-root-manifest-sha256: 35b735ed5481983db61d1d9d557c5ecee5cc4024238a08dbc2ee519f13725eb9
minimum-governance-epoch: $epoch
minimum-governance-sequence: $sequence
published-at-utc: 2026-08-25T00:03:01Z
valid-until-utc: 2027-01-01T00:00:00Z
publication-state: HOST_TEST_REPOSITORY_CHECKPOINT_ONLY
emergency-recovery-policy: EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
EOF
}

write_report() {
  local output="$1" checkpoint="$2" classification="${3:-M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED}" launch="${4:-NO}"
  local checkpoint_sha
  checkpoint_sha="$(sha256sum "$checkpoint" | awk '{print $1}')"
  cat > "$output" <<EOF
replacement-governance-root-public-key-sha256: $HEAD_KEY_SHA
anti-rollback-checkpoint-sha256: $checkpoint_sha
next-governance-epoch: 2
next-governance-sequence: 1
verification-timestamp-utc: 2026-08-25T00:03:02Z
checkpoint-signature-verification: PASS
continuity-environment: HOST_TEST_ONLY_NOT_PRODUCTION
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
classification: $classification
EOF
}

write_checkpoint "$TMP/checkpoint.txt"
printf '%s' "$CHECKPOINT_SIGNATURE_B64" | base64 -d > "$TMP/checkpoint-signature.bin"
write_report "$TMP/m15-report.txt" "$TMP/checkpoint.txt"

run_verify() {
  local output="$1" report="${2:-$TMP/m15-report.txt}" checkpoint="${3:-$TMP/checkpoint.txt}" signature="${4:-$TMP/checkpoint-signature.bin}" timestamp="${5:-2026-08-25T00:03:03Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" "$report" "$checkpoint" "$signature" "$timestamp" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^head-checkpoint-signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^classification: M2_ROUTE_GOVERNANCE_CHECKPOINT_HISTORY_HOST_TEST_PASS_PRODUCTION_PUBLICATION_REQUIRED$' "$TMP/pass.txt"

write_checkpoint "$TMP/fork.txt" 2 1 NO izzos-m2-route-governance-checkpoint-host-test-fork
write_report "$TMP/fork-report.txt" "$TMP/fork.txt"
if run_verify "$TMP/fork-out.txt" "$TMP/fork-report.txt" "$TMP/fork.txt" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted an alternate head at the published epoch/sequence' >&2
  exit 1
fi

write_checkpoint "$TMP/rollback.txt" 1 9
write_report "$TMP/rollback-report.txt" "$TMP/rollback.txt"
if run_verify "$TMP/rollback-out.txt" "$TMP/rollback-report.txt" "$TMP/rollback.txt" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted a rollback head' >&2
  exit 1
fi

write_checkpoint "$TMP/unsafe.txt" 2 1 YES
write_report "$TMP/unsafe-report.txt" "$TMP/unsafe.txt" M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED YES
if run_verify "$TMP/unsafe-out.txt" "$TMP/unsafe-report.txt" "$TMP/unsafe.txt" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted launch authorization' >&2
  exit 1
fi

write_report "$TMP/bad-upstream.txt" "$TMP/checkpoint.txt" M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_BLOCKED
if run_verify "$TMP/bad-upstream-out.txt" "$TMP/bad-upstream.txt" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted a blocked upstream M15 report' >&2
  exit 1
fi

head -c 63 "$TMP/checkpoint-signature.bin" > "$TMP/truncated-signature.bin"
if run_verify "$TMP/signature-out.txt" "$TMP/m15-report.txt" "$TMP/checkpoint.txt" "$TMP/truncated-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted an invalid checkpoint signature' >&2
  exit 1
fi

if run_verify "$TMP/expired-out.txt" "$TMP/m15-report.txt" "$TMP/checkpoint.txt" "$TMP/checkpoint-signature.bin" 2027-01-01T00:00:01Z >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate accepted an expired head checkpoint' >&2
  exit 1
fi

if run_verify "$TMP/checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: M16 history gate allowed its output to overwrite an input' >&2
  exit 1
fi

echo 'M2 governance checkpoint-history tests: PASS'
