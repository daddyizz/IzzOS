#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-key-rotation-governance.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
SCHEDULED_MODE="DUAL_CONTROL_SCHEDULED_HANDOVER"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for name in previous active root rogue; do
  "$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/$name-private.pem" 2>/dev/null
  "$OPENSSL" pkey -in "$TMP/$name-private.pem" -pubout -out "$TMP/$name-public.pem" 2>/dev/null
done

PREVIOUS_SHA="$(sha256sum "$TMP/previous-public.pem" | awk '{print $1}')"
ACTIVE_SHA="$(sha256sum "$TMP/active-public.pem" | awk '{print $1}')"
ROOT_SHA="$(sha256sum "$TMP/root-public.pem" | awk '{print $1}')"
printf 'm7-previous-governance-state\n' > "$TMP/previous-state.txt"
PREVIOUS_STATE_SHA="$(sha256sum "$TMP/previous-state.txt" | awk '{print $1}')"

cat > "$TMP/active-manifest.txt" <<EOF
trusted-authority-key-schema: IZZOS_M7_TRUSTED_AUTHORITY_KEY_V1
authority-key-id: izzos-m7-attester-active-02
authority-role: M7_INDEPENDENT_CAPTURE_AND_EXECUTION_ATTESTER
signature-algorithm: ED25519
public-key-sha256: $ACTIVE_SHA
valid-from-utc: 2026-08-25T00:00:00Z
valid-until-utc: 2027-08-25T00:00:00Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-source: REPOSITORY_REVIEWED_SHA256_PIN
attestation-scope: M7_BOUND_TOKEN_CONSUMPTION_AND_WRAPPER_EVIDENCE_RESULT_ONLY
key-custody: EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
ACTIVE_MANIFEST_SHA="$(sha256sum "$TMP/active-manifest.txt" | awk '{print $1}')"

cat > "$TMP/root-manifest.txt" <<EOF
key-governance-root-schema: IZZOS_M7_KEY_GOVERNANCE_ROOT_V1
governance-root-key-id: izzos-m7-governance-root-test-01
governance-root-role: M7_OFFLINE_KEY_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $ROOT_SHA
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

cat > "$TMP/attestation-report.txt" <<EOF
trusted-key-manifest-sha256: $ACTIVE_MANIFEST_SHA
authority-public-key-sha256: $ACTIVE_SHA
authority-key-id: izzos-m7-attester-active-02
attested-at-utc: 2026-08-25T00:02:00Z
signature-verification: PASS
attestation-endorsement: CRYPTOGRAPHICALLY_VERIFIED_TO_REPOSITORY_PINNED_KEY
wrapper-execution-authorization: NO
launch-authorization: NO
classification: M7_AUTHORITY_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED
EOF

write_rotation() {
  local output="$1" mode="${2:-DUAL_CONTROL_SCHEDULED_HANDOVER}" reason="${3:-SCHEDULED_KEY_ROTATION}" epoch="${4:-2}" sequence="${5:-7}" previous_status="${6:-REVOKED_EFFECTIVE_AT_ROTATION}" launch="${7:-NO}" active_sha="${8:-$ACTIVE_SHA}" active_manifest_sha="${9:-$ACTIVE_MANIFEST_SHA}" previous_policy="${10:-REQUIRED_DETACHED_ED25519}"
  cat > "$output" <<EOF
key-rotation-record-schema: IZZOS_M7_AUTHORITY_KEY_ROTATION_RECORD_V1
governance-root-key-id: izzos-m7-governance-root-test-01
governance-epoch: $epoch
governance-sequence: $sequence
previous-governance-state-sha256: $PREVIOUS_STATE_SHA
previous-authority-key-id: izzos-m7-attester-previous-01
previous-authority-public-key-sha256: $PREVIOUS_SHA
previous-authority-key-status: $previous_status
active-authority-key-id: izzos-m7-attester-active-02
active-authority-public-key-sha256: $active_sha
active-authority-key-manifest-sha256: $active_manifest_sha
rotation-mode: $mode
rotation-reason: $reason
issued-at-utc: 2026-08-25T00:01:00Z
effective-at-utc: 2026-08-25T00:01:30Z
previous-key-handover-signature-policy: $previous_policy
governance-root-approval-signature-policy: REQUIRED_DETACHED_ED25519
rotation-scope: M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

sign_rotation() {
  local rotation="$1" previous_signature="$2" root_signature="$3" previous_private="${4:-$TMP/previous-private.pem}" root_private="${5:-$TMP/root-private.pem}"
  if [[ "$previous_private" != "NONE" ]]; then
    "$OPENSSL" pkeyutl -sign -inkey "$previous_private" -rawin -in "$rotation" -out "$previous_signature" 2>/dev/null
  else
    : > "$previous_signature"
  fi
  "$OPENSSL" pkeyutl -sign -inkey "$root_private" -rawin -in "$rotation" -out "$root_signature" 2>/dev/null
}

write_checkpoint() {
  local output="$1" rotation="$2" epoch="${3:-2}" sequence="${4:-7}" active_sha="${5:-$ACTIVE_SHA}"
  local rotation_sha
  rotation_sha="$(sha256sum "$rotation" | awk '{print $1}')"
  cat > "$output" <<EOF
anti-rollback-checkpoint-schema: IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1
checkpoint-id: izzos-m7-key-checkpoint-test-02-07
minimum-accepted-governance-epoch: $epoch
minimum-accepted-governance-sequence: $sequence
latest-key-rotation-record-sha256: $rotation_sha
previous-governance-state-sha256: $PREVIOUS_STATE_SHA
active-authority-key-id: izzos-m7-attester-active-02
active-authority-public-key-sha256: $active_sha
governance-root-key-id: izzos-m7-governance-root-test-01
checkpoint-updated-at-utc: 2026-08-25T00:02:30Z
checkpoint-source: REPOSITORY_REVIEWED_MONOTONIC_PIN
rollback-policy: REJECT_ANY_NONMATCHING_OR_LOWER_STATE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
}

write_rotation "$TMP/rotation.txt"
sign_rotation "$TMP/rotation.txt" "$TMP/previous-signature.bin" "$TMP/root-signature.bin"
write_checkpoint "$TMP/checkpoint.txt" "$TMP/rotation.txt"

run_verify() {
  local output="$1" attestation="${2:-$TMP/attestation-report.txt}" active_manifest="${3:-$TMP/active-manifest.txt}" active_key="${4:-$TMP/active-public.pem}" previous_key="${5:-$TMP/previous-public.pem}" root_manifest="${6:-$TMP/root-manifest.txt}" root_key="${7:-$TMP/root-public.pem}" rotation="${8:-$TMP/rotation.txt}" previous_signature="${9:-$TMP/previous-signature.bin}" root_signature="${10:-$TMP/root-signature.bin}" checkpoint="${11:-$TMP/checkpoint.txt}" verification="${12:-2026-08-25T00:03:00Z}"
  local previous_state="${13:-$TMP/previous-state.txt}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" "$attestation" "$active_manifest" "$active_key" "$previous_key" "$previous_state" "$root_manifest" "$root_key" "$rotation" "$previous_signature" "$root_signature" "$checkpoint" "$verification" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^rotation-previous-key-signature-policy-passes: PASS$' "$TMP/pass.txt"
grep -q '^rotation-root-signature-policy-and-signature-pass: PASS$' "$TMP/pass.txt"
grep -q '^checkpoint-pins-exact-latest-rotation: PASS$' "$TMP/pass.txt"
grep -q '^previous-key-signature-state: VERIFIED_DUAL_CONTROL_HANDOVER$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED$' "$TMP/pass.txt"

write_rotation "$TMP/emergency-rotation.txt" ROOT_AUTHORIZED_COMPROMISE_REVOCATION COMPROMISE_RECOVERY 3 8 REVOKED_EFFECTIVE_AT_ROTATION NO "$ACTIVE_SHA" "$ACTIVE_MANIFEST_SHA" FORBIDDEN_COMPROMISED_KEY
sign_rotation "$TMP/emergency-rotation.txt" "$TMP/emergency-previous-signature.bin" "$TMP/emergency-root-signature.bin" NONE
write_checkpoint "$TMP/emergency-checkpoint.txt" "$TMP/emergency-rotation.txt" 3 8
run_verify "$TMP/emergency-pass.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/emergency-rotation.txt" "$TMP/emergency-previous-signature.bin" "$TMP/emergency-root-signature.bin" "$TMP/emergency-checkpoint.txt" >/dev/null
grep -q '^previous-key-signature-state: WAIVED_BY_ROOT_COMPROMISE_REVOCATION$' "$TMP/emergency-pass.txt"
grep -q '^classification: M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED$' "$TMP/emergency-pass.txt"

write_checkpoint "$TMP/rollback-checkpoint.txt" "$TMP/rotation.txt" 1 6
if run_verify "$TMP/rollback-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/rotation.txt" "$TMP/previous-signature.bin" "$TMP/root-signature.bin" "$TMP/rollback-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted a lower rollback checkpoint' >&2
  exit 1
fi
grep -q '^checkpoint-minimum-epoch-and-sequence-match-rotation: FAIL$' "$TMP/rollback-out.txt"

cp "$TMP/previous-state.txt" "$TMP/changed-previous-state.txt"
printf 'changed\n' >> "$TMP/changed-previous-state.txt"
if run_verify "$TMP/changed-state-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/rotation.txt" "$TMP/previous-signature.bin" "$TMP/root-signature.bin" "$TMP/checkpoint.txt" 2026-08-25T00:03:00Z "$TMP/changed-previous-state.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted changed previous-state bytes' >&2
  exit 1
fi
grep -q '^rotation-binds-exact-nonempty-previous-state: FAIL$' "$TMP/changed-state-out.txt"

sed 's/rotation-reason: SCHEDULED_KEY_ROTATION/rotation-reason: CUSTODY_TRANSFER/' "$TMP/rotation.txt" > "$TMP/tampered-rotation.txt"
write_checkpoint "$TMP/tampered-checkpoint.txt" "$TMP/tampered-rotation.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/tampered-rotation.txt" "$TMP/previous-signature.bin" "$TMP/root-signature.bin" "$TMP/tampered-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted changed signed rotation bytes' >&2
  exit 1
fi
grep -q '^rotation-previous-key-signature-policy-passes: FAIL$' "$TMP/tampered-out.txt"
grep -q '^rotation-root-signature-policy-and-signature-pass: FAIL$' "$TMP/tampered-out.txt"

sign_rotation "$TMP/rotation.txt" "$TMP/rogue-previous-signature.bin" "$TMP/valid-root-signature.bin" "$TMP/rogue-private.pem"
if run_verify "$TMP/rogue-previous-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/rotation.txt" "$TMP/rogue-previous-signature.bin" "$TMP/valid-root-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted a rogue previous-key signature' >&2
  exit 1
fi
grep -q '^rotation-previous-key-signature-policy-passes: FAIL$' "$TMP/rogue-previous-out.txt"

sign_rotation "$TMP/rotation.txt" "$TMP/valid-previous-signature.bin" "$TMP/rogue-root-signature.bin" "$TMP/previous-private.pem" "$TMP/rogue-private.pem"
if run_verify "$TMP/rogue-root-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/rotation.txt" "$TMP/valid-previous-signature.bin" "$TMP/rogue-root-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted a rogue governance-root signature' >&2
  exit 1
fi
grep -q '^rotation-root-signature-policy-and-signature-pass: FAIL$' "$TMP/rogue-root-out.txt"

write_rotation "$TMP/not-revoked.txt" "$SCHEDULED_MODE" SCHEDULED_KEY_ROTATION 2 7 ACTIVE
sign_rotation "$TMP/not-revoked.txt" "$TMP/not-revoked-previous.bin" "$TMP/not-revoked-root.bin"
write_checkpoint "$TMP/not-revoked-checkpoint.txt" "$TMP/not-revoked.txt"
if run_verify "$TMP/not-revoked-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/not-revoked.txt" "$TMP/not-revoked-previous.bin" "$TMP/not-revoked-root.bin" "$TMP/not-revoked-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted a non-revoked previous key' >&2
  exit 1
fi
grep -q '^rotation-revokes-exact-distinct-previous-key: FAIL$' "$TMP/not-revoked-out.txt"

write_rotation "$TMP/unsafe-rotation.txt" "$SCHEDULED_MODE" SCHEDULED_KEY_ROTATION 2 7 REVOKED_EFFECTIVE_AT_ROTATION YES
sign_rotation "$TMP/unsafe-rotation.txt" "$TMP/unsafe-previous.bin" "$TMP/unsafe-root.bin"
write_checkpoint "$TMP/unsafe-checkpoint.txt" "$TMP/unsafe-rotation.txt"
if run_verify "$TMP/unsafe-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/unsafe-rotation.txt" "$TMP/unsafe-previous.bin" "$TMP/unsafe-root.bin" "$TMP/unsafe-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted a signed launch claim' >&2
  exit 1
fi
grep -q '^rotation-forbids-write-slot-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

sed "s/authority-public-key-sha256: $ACTIVE_SHA/authority-public-key-sha256: $PREVIOUS_SHA/" "$TMP/attestation-report.txt" > "$TMP/old-key-attestation.txt"
if run_verify "$TMP/old-key-out.txt" "$TMP/old-key-attestation.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted attestation from the revoked key' >&2
  exit 1
fi
grep -q '^attestation-is-bound-to-active-key-and-manifest: FAIL$' "$TMP/old-key-out.txt"

cp "$TMP/rotation.txt" "$TMP/duplicate-rotation.txt"
printf 'governance-sequence: 7\n' >> "$TMP/duplicate-rotation.txt"
sign_rotation "$TMP/duplicate-rotation.txt" "$TMP/duplicate-previous.bin" "$TMP/duplicate-root.bin"
write_checkpoint "$TMP/duplicate-checkpoint.txt" "$TMP/duplicate-rotation.txt"
if run_verify "$TMP/duplicate-out.txt" "$TMP/attestation-report.txt" "$TMP/active-manifest.txt" "$TMP/active-public.pem" "$TMP/previous-public.pem" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$TMP/duplicate-rotation.txt" "$TMP/duplicate-previous.bin" "$TMP/duplicate-root.bin" "$TMP/duplicate-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: key-governance gate accepted duplicate rotation fields' >&2
  exit 1
fi
grep -q '^rotation-record-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"
grep -q '^rotation-record-is-canonical: FAIL$' "$TMP/duplicate-out.txt"

echo 'PASS: M7 authority-key rotation, revocation and anti-rollback governance gate'
