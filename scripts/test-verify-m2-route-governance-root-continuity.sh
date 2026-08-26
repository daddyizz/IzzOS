#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m2-route-governance-root-continuity.py"
ENROLLMENT="$ROOT/config/m2-route-governance-root-enrollment.txt"
CURRENT_KEY="$ROOT/config/m2-route-governance-root-test-public.pem"
REPLACEMENT_KEY="$ROOT/config/m2-route-governance-root-next-test-public.pem"
CUSTODIAN_1_KEY="$ROOT/config/m2-route-governance-recovery-custodian-1-test-public.pem"
CUSTODIAN_2_KEY="$ROOT/config/m2-route-governance-recovery-custodian-2-test-public.pem"
CUSTODIAN_3_KEY="$ROOT/config/m2-route-governance-recovery-custodian-3-test-public.pem"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CUSTODIAN_1_SIGNATURE_B64="DlMv9HTPAI9gUWPryhinT0e1swWs58vJOP00IaxCvWoq8xuYQ6d0QInnjD/cp95Bt4yyhm7SeQiH+UW2ltBlCQ=="
CUSTODIAN_2_SIGNATURE_B64="c7tlFER9myag5fnYcM6AZ/+S/vuoeM5az8cCi57SBwmb6skO7Mqw0e+fsP+/f9Q00jqOgzZkCJY4DTBSZabZCg=="
CUSTODIAN_3_SIGNATURE_B64="YVMWau5BLFqnPcRuXt78X3g2411lZ/Lq1XVf6lFUm6EjX8Nvsnr7dtCJ09JH+dLzAlTdUDhB/ytjw5EiUh54Aw=="
REPLACEMENT_SIGNATURE_B64="lScXKZCw9/VV+SA3/gCWQCqNWNqmT4QdqIUWzFqlhJEQz8xVHJymKgszqo4ILhXFu7k+ZYa5iBrlALKKNACWCQ=="
CHECKPOINT_SIGNATURE_B64="kygbq033of4cXWTPzG+lJ+A93E9UDsMTrRajsvRbLbP6141VLEeXPWCI63i9Jeaf/YZhP8w3cQs/wnoWU/VAAQ=="
CURRENT_SHA="$(sha256sum "$CURRENT_KEY" | awk '{print $1}')"
REPLACEMENT_SHA="$(sha256sum "$REPLACEMENT_KEY" | awk '{print $1}')"
ENROLLMENT_SHA="$(sha256sum "$ENROLLMENT" | awk '{print $1}')"
CUSTODIAN_1_SHA="$(sha256sum "$CUSTODIAN_1_KEY" | awk '{print $1}')"
CUSTODIAN_2_SHA="$(sha256sum "$CUSTODIAN_2_KEY" | awk '{print $1}')"
CUSTODIAN_3_SHA="$(sha256sum "$CUSTODIAN_3_KEY" | awk '{print $1}')"
PREVIOUS_CHECKPOINT_SHA="$(printf 'izzos-m15-previous-host-test-checkpoint' | sha256sum | awk '{print $1}')"

write_root_manifest() {
  local output="$1" key_id="$2" key_sha="$3" trust_state="$4" custody="$5"
  cat > "$output" <<EOF
route-governance-root-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1
governance-root-key-id: $key_id
governance-root-role: M2_ROUTE_ATTESTER_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $key_sha
valid-from-utc: 2025-01-01T00:00:00Z
valid-until-utc: 2028-01-01T00:00:00Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-state: $trust_state
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
key-custody: $custody
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_m14_report() {
  local output="$1" current_manifest="$2"
  local manifest_sha
  manifest_sha="$(sha256sum "$current_manifest" | awk '{print $1}')"
  cat > "$output" <<EOF
governance-root-manifest-sha256: $manifest_sha
governance-root-public-key-sha256: $CURRENT_SHA
repository-enrollment-record-sha256: $ENROLLMENT_SHA
repository-enrolled-public-key-sha256: $CURRENT_SHA
repository-enrollment-id: izzos-m2-route-governance-host-test-01
repository-enrollment-environment: HOST_TEST_ONLY_NOT_PRODUCTION
physical-device-truth: NOT_MEASURED_BY_ENROLLMENT_VERIFIER
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
classification: M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_PASS_PRODUCTION_ROOT_REQUIRED
EOF
}

write_transition() {
  local output="$1" m14_report="$2" current_manifest="$3" replacement_manifest="$4" previous_status="${5:-REVOKED_EFFECTIVE_AT_TRANSITION}" launch="${6:-NO}"
  local report_sha current_manifest_sha replacement_manifest_sha
  report_sha="$(sha256sum "$m14_report" | awk '{print $1}')"
  current_manifest_sha="$(sha256sum "$current_manifest" | awk '{print $1}')"
  replacement_manifest_sha="$(sha256sum "$replacement_manifest" | awk '{print $1}')"
  cat > "$output" <<EOF
route-governance-root-transition-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_TRANSITION_V1
transition-id: izzos-m2-route-governance-host-test-02-01
source-enrollment-report-sha256: $report_sha
repository-enrollment-record-sha256: $ENROLLMENT_SHA
previous-governance-root-key-id: izzos-m2-route-governance-host-test-01
previous-governance-root-public-key-sha256: $CURRENT_SHA
previous-governance-root-manifest-sha256: $current_manifest_sha
previous-governance-root-status: $previous_status
replacement-governance-root-key-id: izzos-m2-route-governance-host-test-02
replacement-governance-root-public-key-sha256: $REPLACEMENT_SHA
replacement-governance-root-manifest-sha256: $replacement_manifest_sha
previous-governance-epoch: 1
previous-governance-sequence: 1
next-governance-epoch: 2
next-governance-sequence: 1
transition-mode: EMERGENCY_RECOVERY_2_OF_3
rotation-policy: CURRENT_ROOT_SIGNATURE_WAIVED_AFTER_DECLARED_COMPROMISE
emergency-recovery-policy: EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED
recovery-custodian-1-public-key-sha256: $CUSTODIAN_1_SHA
recovery-custodian-2-public-key-sha256: $CUSTODIAN_2_SHA
recovery-custodian-3-public-key-sha256: $CUSTODIAN_3_SHA
effective-at-utc: 2026-08-25T00:03:00Z
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
EOF
}

write_checkpoint() {
  local output="$1" transition="$2" replacement_manifest="$3" epoch="${4:-2}" sequence="${5:-1}" published="${6:-2026-08-25T00:03:01Z}"
  local transition_sha replacement_manifest_sha
  transition_sha="$(sha256sum "$transition" | awk '{print $1}')"
  replacement_manifest_sha="$(sha256sum "$replacement_manifest" | awk '{print $1}')"
  cat > "$output" <<EOF
route-governance-root-anti-rollback-checkpoint-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ANTI_ROLLBACK_CHECKPOINT_V1
checkpoint-id: izzos-m2-route-governance-checkpoint-host-test-02-01
root-transition-sha256: $transition_sha
previous-checkpoint-sha256: $PREVIOUS_CHECKPOINT_SHA
active-governance-root-key-id: izzos-m2-route-governance-host-test-02
active-governance-root-public-key-sha256: $REPLACEMENT_SHA
active-governance-root-manifest-sha256: $replacement_manifest_sha
minimum-governance-epoch: $epoch
minimum-governance-sequence: $sequence
published-at-utc: $published
valid-until-utc: 2027-01-01T00:00:00Z
publication-state: HOST_TEST_REPOSITORY_CHECKPOINT_ONLY
emergency-recovery-policy: EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_root_manifest "$TMP/current-manifest.txt" izzos-m2-route-governance-host-test-01 "$CURRENT_SHA" CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT EXTERNAL_TO_ROUTE_ATTESTER
write_root_manifest "$TMP/replacement-manifest.txt" izzos-m2-route-governance-host-test-02 "$REPLACEMENT_SHA" SCHEDULED_REPLACEMENT_PENDING_REPOSITORY_PUBLICATION OFFLINE_EXTERNAL_TO_REPOSITORY_ATTESTER_AND_LAUNCH_OPERATOR
write_m14_report "$TMP/m14-report.txt" "$TMP/current-manifest.txt"
write_transition "$TMP/transition.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$TMP/replacement-manifest.txt"
write_checkpoint "$TMP/checkpoint.txt" "$TMP/transition.txt" "$TMP/replacement-manifest.txt"

printf '%s' "$CUSTODIAN_1_SIGNATURE_B64" | base64 -d > "$TMP/custodian-1-signature.bin"
printf '%s' "$CUSTODIAN_2_SIGNATURE_B64" | base64 -d > "$TMP/custodian-2-signature.bin"
printf '%s' "$CUSTODIAN_3_SIGNATURE_B64" | base64 -d > "$TMP/custodian-3-signature.bin"
printf '%s' "$REPLACEMENT_SIGNATURE_B64" | base64 -d > "$TMP/replacement-signature.bin"
printf '%s' "$CHECKPOINT_SIGNATURE_B64" | base64 -d > "$TMP/checkpoint-signature.bin"

run_verify() {
  local output="$1" report="${2:-$TMP/m14-report.txt}" current_manifest="${3:-$TMP/current-manifest.txt}" current_key="${4:-$CURRENT_KEY}" replacement_manifest="${5:-$TMP/replacement-manifest.txt}" replacement_key="${6:-$REPLACEMENT_KEY}" transition="${7:-$TMP/transition.txt}" custodian_1_signature="${8:-$TMP/custodian-1-signature.bin}" custodian_2_signature="${9:-$TMP/custodian-2-signature.bin}" custodian_3_signature="${10:-$TMP/custodian-3-signature.bin}" replacement_signature="${11:-$TMP/replacement-signature.bin}" checkpoint="${12:-$TMP/checkpoint.txt}" checkpoint_signature="${13:-$TMP/checkpoint-signature.bin}" verification="${14:-2026-08-25T00:03:02Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" "$report" "$current_manifest" "$current_key" \
    "$replacement_manifest" "$replacement_key" "$transition" "$custodian_1_signature" \
    "$custodian_2_signature" "$custodian_3_signature" "$replacement_signature" \
    "$checkpoint" "$checkpoint_signature" "$verification" "$output"
}

if ! run_verify "$TMP/pass.txt" >/dev/null; then
  cat "$TMP/pass.txt" >&2
  exit 1
fi
grep -q '^recovery-custodian-valid-signature-count: 3$' "$TMP/pass.txt"
grep -q '^replacement-root-possession-signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^checkpoint-signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^classification: M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED$' "$TMP/pass.txt"

if run_verify "$TMP/quorum-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/transition.txt" "$TMP/checkpoint-signature.bin" "$TMP/checkpoint-signature.bin" "$TMP/custodian-3-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted fewer than two recovery custodian signatures' >&2
  exit 1
fi

sed 's/transition-mode: EMERGENCY_RECOVERY_2_OF_3/transition-mode: UNSAFE_UNREVIEWED_RECOVERY/' "$TMP/transition.txt" > "$TMP/tampered-transition.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/tampered-transition.txt" >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted changed signed transition bytes' >&2
  exit 1
fi

write_transition "$TMP/nonrevoked-transition.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$TMP/replacement-manifest.txt" NOT_REVOKED
write_checkpoint "$TMP/nonrevoked-checkpoint.txt" "$TMP/nonrevoked-transition.txt" "$TMP/replacement-manifest.txt"
if run_verify "$TMP/nonrevoked-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/nonrevoked-transition.txt" "$TMP/custodian-1-signature.bin" "$TMP/custodian-2-signature.bin" "$TMP/custodian-3-signature.bin" "$TMP/replacement-signature.bin" "$TMP/nonrevoked-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted a non-revoked previous root' >&2
  exit 1
fi

write_checkpoint "$TMP/rollback-checkpoint.txt" "$TMP/transition.txt" "$TMP/replacement-manifest.txt" 1 1
if run_verify "$TMP/rollback-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/transition.txt" "$TMP/custodian-1-signature.bin" "$TMP/custodian-2-signature.bin" "$TMP/custodian-3-signature.bin" "$TMP/replacement-signature.bin" "$TMP/rollback-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted a rollback checkpoint' >&2
  exit 1
fi

write_transition "$TMP/unsafe-transition.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$TMP/replacement-manifest.txt" REVOKED_EFFECTIVE_AT_TRANSITION YES
write_checkpoint "$TMP/unsafe-checkpoint.txt" "$TMP/unsafe-transition.txt" "$TMP/replacement-manifest.txt"
if run_verify "$TMP/unsafe-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/unsafe-transition.txt" "$TMP/custodian-1-signature.bin" "$TMP/custodian-2-signature.bin" "$TMP/custodian-3-signature.bin" "$TMP/replacement-signature.bin" "$TMP/unsafe-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted launch authorization' >&2
  exit 1
fi

if run_verify "$TMP/expired-out.txt" "$TMP/m14-report.txt" "$TMP/current-manifest.txt" "$CURRENT_KEY" "$TMP/replacement-manifest.txt" "$REPLACEMENT_KEY" "$TMP/transition.txt" "$TMP/custodian-1-signature.bin" "$TMP/custodian-2-signature.bin" "$TMP/custodian-3-signature.bin" "$TMP/replacement-signature.bin" "$TMP/checkpoint.txt" "$TMP/checkpoint-signature.bin" 2027-01-01T00:00:01Z >/dev/null 2>&1; then
  echo 'ERROR: M15 continuity gate accepted an expired checkpoint' >&2
  exit 1
fi

echo 'M2 governance-root continuity and anti-rollback tests: PASS'
