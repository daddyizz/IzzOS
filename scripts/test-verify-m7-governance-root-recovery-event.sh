#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-governance-root-recovery-event.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for name in previous-root replacement-root custodian1 custodian2 custodian3 rogue; do
  "$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/$name-private.pem" 2>/dev/null
  "$OPENSSL" pkey -in "$TMP/$name-private.pem" -pubout -out "$TMP/$name-public.pem" 2>/dev/null
done

file_sha() {
  sha256sum "$1" | awk '{print $1}'
}

PREVIOUS_ROOT_SHA="$(file_sha "$TMP/previous-root-public.pem")"
REPLACEMENT_ROOT_SHA="$(file_sha "$TMP/replacement-root-public.pem")"
CUSTODIAN1_SHA="$(file_sha "$TMP/custodian1-public.pem")"
CUSTODIAN2_SHA="$(file_sha "$TMP/custodian2-public.pem")"
CUSTODIAN3_SHA="$(file_sha "$TMP/custodian3-public.pem")"

cat > "$TMP/previous-root-manifest.txt" <<EOF
key-governance-root-schema: IZZOS_M7_KEY_GOVERNANCE_ROOT_V1
governance-root-key-id: izzos-m7-governance-root-previous-01
governance-root-role: M7_OFFLINE_KEY_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $PREVIOUS_ROOT_SHA
valid-from-utc: 2026-01-01T00:00:00Z
valid-until-utc: 2030-01-01T00:00:00Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-source: REPOSITORY_REVIEWED_SHA256_PIN
governance-scope: M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY
key-custody: OFFLINE_EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
PREVIOUS_ROOT_MANIFEST_SHA="$(file_sha "$TMP/previous-root-manifest.txt")"

cat > "$TMP/replacement-root-manifest.txt" <<EOF
key-governance-root-schema: IZZOS_M7_KEY_GOVERNANCE_ROOT_V1
governance-root-key-id: izzos-m7-governance-root-recovered-02
governance-root-role: M7_OFFLINE_KEY_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $REPLACEMENT_ROOT_SHA
valid-from-utc: 2026-08-25T00:04:30Z
valid-until-utc: 2030-08-25T00:04:30Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-source: RECOVERY_QUORUM_ACTIVATED_SHA256_PIN
governance-scope: M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY
key-custody: OFFLINE_EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
REPLACEMENT_MANIFEST_SHA="$(file_sha "$TMP/replacement-root-manifest.txt")"

cat > "$TMP/previous-checkpoint.txt" <<EOF
anti-rollback-checkpoint-schema: IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1
checkpoint-id: izzos-m7-checkpoint-previous-02-07
minimum-accepted-governance-epoch: 2
minimum-accepted-governance-sequence: 7
checkpoint-updated-at-utc: 2026-08-25T00:02:30Z
EOF
PREVIOUS_CHECKPOINT_SHA="$(file_sha "$TMP/previous-checkpoint.txt")"

cat > "$TMP/policy.txt" <<EOF
checkpoint-publication-recovery-policy-schema: IZZOS_M7_CHECKPOINT_PUBLICATION_AND_ROOT_RECOVERY_POLICY_V1
governance-epoch: 2
governance-sequence: 7
governance-root-key-id: izzos-m7-governance-root-previous-01
governance-root-public-key-sha256: $PREVIOUS_ROOT_SHA
root-recovery-mode: PREAUTHORIZED_2_OF_3_CUSTODIAN_ROOT_REPLACEMENT
root-recovery-threshold: 2
recovery-custodian-1-id: izzos-m7-recovery-custodian-test-01
recovery-custodian-1-public-key-sha256: $CUSTODIAN1_SHA
recovery-custodian-2-id: izzos-m7-recovery-custodian-test-02
recovery-custodian-2-public-key-sha256: $CUSTODIAN2_SHA
recovery-custodian-3-id: izzos-m7-recovery-custodian-test-03
recovery-custodian-3-public-key-sha256: $CUSTODIAN3_SHA
recovery-event-requirements: NEW_ROOT_MANIFEST_PLUS_2_OF_3_DETACHED_ED25519
compromise-response: REVOKE_PREVIOUS_ROOT_BEFORE_REPLACEMENT_ACTIVATION
EOF
POLICY_SHA="$(file_sha "$TMP/policy.txt")"

cat > "$TMP/publication-report.txt" <<EOF
anti-rollback-checkpoint-sha256: $PREVIOUS_CHECKPOINT_SHA
governance-root-manifest-sha256: $PREVIOUS_ROOT_MANIFEST_SHA
governance-root-public-key-sha256: $PREVIOUS_ROOT_SHA
publication-recovery-policy-sha256: $POLICY_SHA
governance-epoch: 2
governance-sequence: 7
verification-timestamp-utc: 2026-08-25T00:04:00Z
governance-root-policy-signature: PASS
publication-quorum-state: EXACT_ROOT_APPROVED_POLICY_WITH_2_OF_3_OR_GREATER_WITNESS_SIGNATURES
root-recovery-policy-state: PREAUTHORIZED_POLICY_ONLY_NO_RECOVERY_EVENT
root-recovery-event-authorized: NO
replacement-governance-root-activated: NO
wrapper-execution-authorization: NO
persistent-writes: FORBIDDEN
launch-authorization: NO
classification: M7_CHECKPOINT_PUBLICATION_QUORUM_ROOT_RECOVERY_POLICY_PASS_EXTERNAL_DISTRIBUTION_REQUIRED
EOF
PUBLICATION_REPORT_SHA="$(file_sha "$TMP/publication-report.txt")"

write_event() {
  local output="$1" previous_status="${2:-REVOKED_EFFECTIVE_AT_RECOVERY}" recovered_epoch="${3:-3}" recovered_sequence="${4:-1}" launch="${5:-NO}" reason="${6:-ROOT_KEY_COMPROMISE}"
  cat > "$output" <<EOF
governance-root-recovery-event-schema: IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_EVENT_V1
recovery-event-id: izzos-m7-root-recovery-test-03-01
source-publication-policy-sha256: $POLICY_SHA
source-publication-verification-sha256: $PUBLICATION_REPORT_SHA
previous-anti-rollback-checkpoint-sha256: $PREVIOUS_CHECKPOINT_SHA
previous-governance-epoch: 2
previous-governance-sequence: 7
recovered-governance-epoch: $recovered_epoch
recovered-governance-sequence: $recovered_sequence
previous-governance-root-key-id: izzos-m7-governance-root-previous-01
previous-governance-root-public-key-sha256: $PREVIOUS_ROOT_SHA
previous-governance-root-status: $previous_status
replacement-governance-root-key-id: izzos-m7-governance-root-recovered-02
replacement-governance-root-public-key-sha256: $REPLACEMENT_ROOT_SHA
replacement-governance-root-manifest-sha256: $REPLACEMENT_MANIFEST_SHA
recovery-mode: TWO_OF_THREE_CUSTODIAN_ROOT_REPLACEMENT
recovery-reason: $reason
declared-at-utc: 2026-08-25T00:05:00Z
effective-at-utc: 2026-08-25T00:05:15Z
custodian-signature-policy: REQUIRED_2_OF_3_DETACHED_ED25519
replacement-root-possession-proof: REQUIRED_DETACHED_ED25519
recovery-scope: M7_GOVERNANCE_ROOT_REPLACEMENT_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
wrapper-execution-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

write_checkpoint() {
  local output="$1" event_file="$2" epoch="${3:-3}" sequence="${4:-1}" previous_status="${5:-REVOKED_EFFECTIVE_AT_RECOVERY}"
  local event_sha
  event_sha="$(file_sha "$event_file")"
  cat > "$output" <<EOF
governance-root-recovery-checkpoint-schema: IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1
checkpoint-id: izzos-m7-root-recovery-checkpoint-test-03-01
recovery-event-sha256: $event_sha
previous-anti-rollback-checkpoint-sha256: $PREVIOUS_CHECKPOINT_SHA
minimum-governance-epoch: $epoch
minimum-governance-sequence: $sequence
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $REPLACEMENT_ROOT_SHA
active-governance-root-manifest-sha256: $REPLACEMENT_MANIFEST_SHA
previous-governance-root-key-id: izzos-m7-governance-root-previous-01
previous-governance-root-status: $previous_status
checkpoint-updated-at-utc: 2026-08-25T00:05:30Z
checkpoint-source: RECOVERY_QUORUM_AND_REPLACEMENT_ROOT_SIGNED_PIN
rollback-policy: REJECT_PRE_RECOVERY_ROOT_AND_LOWER_EPOCH
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
}

sign_recovery() {
  local event_file="$1" checkpoint_file="$2" custodian1_signature="$3" custodian2_signature="$4" custodian3_signature="$5" replacement_event_signature="$6" replacement_checkpoint_signature="$7"
  local custodian1_private="${8:-$TMP/custodian1-private.pem}" custodian2_private="${9:-$TMP/custodian2-private.pem}" custodian3_private="${10:-NONE}" replacement_event_private="${11:-$TMP/replacement-root-private.pem}" replacement_checkpoint_private="${12:-$TMP/replacement-root-private.pem}"
  if [[ "$custodian1_private" == "NONE" ]]; then : > "$custodian1_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$custodian1_private" -rawin -in "$event_file" -out "$custodian1_signature" 2>/dev/null; fi
  if [[ "$custodian2_private" == "NONE" ]]; then : > "$custodian2_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$custodian2_private" -rawin -in "$event_file" -out "$custodian2_signature" 2>/dev/null; fi
  if [[ "$custodian3_private" == "NONE" ]]; then : > "$custodian3_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$custodian3_private" -rawin -in "$event_file" -out "$custodian3_signature" 2>/dev/null; fi
  "$OPENSSL" pkeyutl -sign -inkey "$replacement_event_private" -rawin -in "$event_file" -out "$replacement_event_signature" 2>/dev/null
  "$OPENSSL" pkeyutl -sign -inkey "$replacement_checkpoint_private" -rawin -in "$checkpoint_file" -out "$replacement_checkpoint_signature" 2>/dev/null
}

write_event "$TMP/event.txt"
write_checkpoint "$TMP/recovered-checkpoint.txt" "$TMP/event.txt"
sign_recovery "$TMP/event.txt" "$TMP/recovered-checkpoint.txt" "$TMP/custodian1-signature.bin" "$TMP/custodian2-signature.bin" "$TMP/custodian3-signature.bin" "$TMP/replacement-event-signature.bin" "$TMP/replacement-checkpoint-signature.bin"

run_verify() {
  local output="$1" event_file="${2:-$TMP/event.txt}" recovered_checkpoint="${3:-$TMP/recovered-checkpoint.txt}" custodian1_signature="${4:-$TMP/custodian1-signature.bin}" custodian2_signature="${5:-$TMP/custodian2-signature.bin}" custodian3_signature="${6:-$TMP/custodian3-signature.bin}" replacement_event_signature="${7:-$TMP/replacement-event-signature.bin}" replacement_checkpoint_signature="${8:-$TMP/replacement-checkpoint-signature.bin}" verification="${9:-2026-08-25T00:06:00Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/publication-report.txt" "$TMP/policy.txt" "$TMP/previous-checkpoint.txt" \
    "$TMP/previous-root-manifest.txt" "$TMP/previous-root-public.pem" \
    "$TMP/replacement-root-manifest.txt" "$TMP/replacement-root-public.pem" "$event_file" \
    "$TMP/custodian1-public.pem" "$custodian1_signature" \
    "$TMP/custodian2-public.pem" "$custodian2_signature" \
    "$TMP/custodian3-public.pem" "$custodian3_signature" \
    "$replacement_event_signature" "$recovered_checkpoint" "$replacement_checkpoint_signature" \
    "$verification" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^recovery-event-custodian-quorum-passes: PASS$' "$TMP/pass.txt"
grep -q '^custodian-signatures-valid: 2$' "$TMP/pass.txt"
grep -q '^previous-governance-root-state: REVOKED$' "$TMP/pass.txt"
grep -q '^replacement-governance-root-state: CRYPTOGRAPHICALLY_BOUND_PENDING_REPUBLICATION$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_GOVERNANCE_ROOT_RECOVERY_EVENT_PASS_REPUBLICATION_REQUIRED$' "$TMP/pass.txt"

sign_recovery "$TMP/event.txt" "$TMP/recovered-checkpoint.txt" "$TMP/one-custodian1.bin" "$TMP/one-custodian2.bin" "$TMP/one-custodian3.bin" "$TMP/one-replacement-event.bin" "$TMP/one-replacement-checkpoint.bin" "$TMP/custodian1-private.pem" "$TMP/rogue-private.pem" NONE
if run_verify "$TMP/one-out.txt" "$TMP/event.txt" "$TMP/recovered-checkpoint.txt" "$TMP/one-custodian1.bin" "$TMP/one-custodian2.bin" "$TMP/one-custodian3.bin" "$TMP/one-replacement-event.bin" "$TMP/one-replacement-checkpoint.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted fewer than two pinned custodian signatures' >&2
  exit 1
fi
grep -q '^recovery-event-custodian-quorum-passes: FAIL$' "$TMP/one-out.txt"

write_event "$TMP/not-revoked-event.txt" ACTIVE
write_checkpoint "$TMP/not-revoked-checkpoint.txt" "$TMP/not-revoked-event.txt" 3 1 ACTIVE
sign_recovery "$TMP/not-revoked-event.txt" "$TMP/not-revoked-checkpoint.txt" "$TMP/not-revoked-c1.bin" "$TMP/not-revoked-c2.bin" "$TMP/not-revoked-c3.bin" "$TMP/not-revoked-event-root.bin" "$TMP/not-revoked-checkpoint-root.bin"
if run_verify "$TMP/not-revoked-out.txt" "$TMP/not-revoked-event.txt" "$TMP/not-revoked-checkpoint.txt" "$TMP/not-revoked-c1.bin" "$TMP/not-revoked-c2.bin" "$TMP/not-revoked-c3.bin" "$TMP/not-revoked-event-root.bin" "$TMP/not-revoked-checkpoint-root.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted a non-revoked previous root' >&2
  exit 1
fi
grep -q '^recovery-event-revokes-exact-previous-root: FAIL$' "$TMP/not-revoked-out.txt"

write_event "$TMP/rollback-event.txt" REVOKED_EFFECTIVE_AT_RECOVERY 2 1
write_checkpoint "$TMP/rollback-checkpoint.txt" "$TMP/rollback-event.txt" 2 1
sign_recovery "$TMP/rollback-event.txt" "$TMP/rollback-checkpoint.txt" "$TMP/rollback-c1.bin" "$TMP/rollback-c2.bin" "$TMP/rollback-c3.bin" "$TMP/rollback-event-root.bin" "$TMP/rollback-checkpoint-root.bin"
if run_verify "$TMP/rollback-out.txt" "$TMP/rollback-event.txt" "$TMP/rollback-checkpoint.txt" "$TMP/rollback-c1.bin" "$TMP/rollback-c2.bin" "$TMP/rollback-c3.bin" "$TMP/rollback-event-root.bin" "$TMP/rollback-checkpoint-root.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted a non-advancing recovery epoch' >&2
  exit 1
fi
grep -q '^recovery-event-monotonically-advances-one-epoch: FAIL$' "$TMP/rollback-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/event.txt" -out "$TMP/rogue-replacement-event.bin" 2>/dev/null
if run_verify "$TMP/rogue-replacement-out.txt" "$TMP/event.txt" "$TMP/recovered-checkpoint.txt" "$TMP/custodian1-signature.bin" "$TMP/custodian2-signature.bin" "$TMP/custodian3-signature.bin" "$TMP/rogue-replacement-event.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted a rogue replacement-root possession signature' >&2
  exit 1
fi
grep -q '^replacement-root-possession-signature-passes: FAIL$' "$TMP/rogue-replacement-out.txt"

write_event "$TMP/unsafe-event.txt" REVOKED_EFFECTIVE_AT_RECOVERY 3 1 YES
write_checkpoint "$TMP/unsafe-checkpoint.txt" "$TMP/unsafe-event.txt"
sign_recovery "$TMP/unsafe-event.txt" "$TMP/unsafe-checkpoint.txt" "$TMP/unsafe-c1.bin" "$TMP/unsafe-c2.bin" "$TMP/unsafe-c3.bin" "$TMP/unsafe-event-root.bin" "$TMP/unsafe-checkpoint-root.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/unsafe-event.txt" "$TMP/unsafe-checkpoint.txt" "$TMP/unsafe-c1.bin" "$TMP/unsafe-c2.bin" "$TMP/unsafe-c3.bin" "$TMP/unsafe-event-root.bin" "$TMP/unsafe-checkpoint-root.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted a quorum-signed launch claim' >&2
  exit 1
fi
grep -q '^recovery-event-forbids-write-slot-wrapper-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

cp "$TMP/recovered-checkpoint.txt" "$TMP/changed-checkpoint.txt"
printf 'changed: yes\n' >> "$TMP/changed-checkpoint.txt"
if run_verify "$TMP/changed-checkpoint-out.txt" "$TMP/event.txt" "$TMP/changed-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted changed recovered-checkpoint bytes' >&2
  exit 1
fi
grep -q '^recovered-checkpoint-is-canonical: FAIL$' "$TMP/changed-checkpoint-out.txt"
grep -q '^recovered-checkpoint-source-policy-and-signature-pass: FAIL$' "$TMP/changed-checkpoint-out.txt"

cp "$TMP/event.txt" "$TMP/duplicate-event.txt"
printf 'recovered-governance-epoch: 3\n' >> "$TMP/duplicate-event.txt"
write_checkpoint "$TMP/duplicate-checkpoint.txt" "$TMP/duplicate-event.txt"
sign_recovery "$TMP/duplicate-event.txt" "$TMP/duplicate-checkpoint.txt" "$TMP/duplicate-c1.bin" "$TMP/duplicate-c2.bin" "$TMP/duplicate-c3.bin" "$TMP/duplicate-event-root.bin" "$TMP/duplicate-checkpoint-root.bin"
if run_verify "$TMP/duplicate-out.txt" "$TMP/duplicate-event.txt" "$TMP/duplicate-checkpoint.txt" "$TMP/duplicate-c1.bin" "$TMP/duplicate-c2.bin" "$TMP/duplicate-c3.bin" "$TMP/duplicate-event-root.bin" "$TMP/duplicate-checkpoint-root.bin" >/dev/null 2>&1; then
  echo 'ERROR: root-recovery gate accepted duplicate recovery-event fields' >&2
  exit 1
fi
grep -q '^recovery-event-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"
grep -q '^recovery-event-is-canonical: FAIL$' "$TMP/duplicate-out.txt"

echo 'PASS: M7 governance-root recovery event gate'
