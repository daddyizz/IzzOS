#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-checkpoint-publication-root-recovery.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for name in root witness1 witness2 witness3 recovery1 recovery2 recovery3 rogue; do
  "$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/$name-private.pem" 2>/dev/null
  "$OPENSSL" pkey -in "$TMP/$name-private.pem" -pubout -out "$TMP/$name-public.pem" 2>/dev/null
done

file_sha() {
  sha256sum "$1" | awk '{print $1}'
}

ROOT_SHA="$(file_sha "$TMP/root-public.pem")"
WITNESS1_SHA="$(file_sha "$TMP/witness1-public.pem")"
WITNESS2_SHA="$(file_sha "$TMP/witness2-public.pem")"
WITNESS3_SHA="$(file_sha "$TMP/witness3-public.pem")"
RECOVERY1_SHA="$(file_sha "$TMP/recovery1-public.pem")"
RECOVERY2_SHA="$(file_sha "$TMP/recovery2-public.pem")"
RECOVERY3_SHA="$(file_sha "$TMP/recovery3-public.pem")"

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

cat > "$TMP/checkpoint.txt" <<EOF
anti-rollback-checkpoint-schema: IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1
checkpoint-id: izzos-m7-key-checkpoint-test-02-07
minimum-accepted-governance-epoch: 2
minimum-accepted-governance-sequence: 7
latest-key-rotation-record-sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
previous-governance-state-sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
active-authority-key-id: izzos-m7-attester-active-02
active-authority-public-key-sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
governance-root-key-id: izzos-m7-governance-root-test-01
checkpoint-updated-at-utc: 2026-08-25T00:02:30Z
checkpoint-source: REPOSITORY_REVIEWED_MONOTONIC_PIN
rollback-policy: REJECT_ANY_NONMATCHING_OR_LOWER_STATE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
CHECKPOINT_SHA="$(file_sha "$TMP/checkpoint.txt")"

cat > "$TMP/governance-report.txt" <<EOF
anti-rollback-checkpoint-sha256: $CHECKPOINT_SHA
governance-root-public-key-sha256: $ROOT_SHA
governance-epoch: 2
governance-sequence: 7
verification-timestamp-utc: 2026-08-25T00:03:00Z
anti-rollback-state: EXACT_SUPPLIED_REPOSITORY_CHECKPOINT_MATCH
wrapper-execution-authorization: NO
persistent-writes: FORBIDDEN
launch-authorization: NO
classification: M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED
EOF
GOVERNANCE_SHA="$(file_sha "$TMP/governance-report.txt")"

write_policy() {
  local output="$1" launch="${2:-NO}" checkpoint_sha="${3:-$CHECKPOINT_SHA}" governance_sha="${4:-$GOVERNANCE_SHA}"
  cat > "$output" <<EOF
checkpoint-publication-recovery-policy-schema: IZZOS_M7_CHECKPOINT_PUBLICATION_AND_ROOT_RECOVERY_POLICY_V1
policy-id: izzos-m7-checkpoint-publication-test-02-07
governance-verification-report-sha256: $governance_sha
anti-rollback-checkpoint-sha256: $checkpoint_sha
checkpoint-id: izzos-m7-key-checkpoint-test-02-07
governance-epoch: 2
governance-sequence: 7
policy-issued-at-utc: 2026-08-25T00:03:10Z
checkpoint-published-at-utc: 2026-08-25T00:03:15Z
publication-valid-until-utc: 2026-08-25T00:13:15Z
publication-window-max-seconds: 900
publication-record-source: REPOSITORY_REVIEWED_AND_INDEPENDENT_WITNESS_QUORUM
publication-signature-algorithm: ED25519
publication-quorum-threshold: 2
publication-witness-1-id: izzos-m7-publication-witness-test-01
publication-witness-1-public-key-sha256: $WITNESS1_SHA
publication-witness-2-id: izzos-m7-publication-witness-test-02
publication-witness-2-public-key-sha256: $WITNESS2_SHA
publication-witness-3-id: izzos-m7-publication-witness-test-03
publication-witness-3-public-key-sha256: $WITNESS3_SHA
governance-root-key-id: izzos-m7-governance-root-test-01
governance-root-public-key-sha256: $ROOT_SHA
governance-root-approval-policy: REQUIRED_DETACHED_ED25519
root-recovery-mode: PREAUTHORIZED_2_OF_3_CUSTODIAN_ROOT_REPLACEMENT
root-recovery-threshold: 2
recovery-custodian-1-id: izzos-m7-recovery-custodian-test-01
recovery-custodian-1-public-key-sha256: $RECOVERY1_SHA
recovery-custodian-2-id: izzos-m7-recovery-custodian-test-02
recovery-custodian-2-public-key-sha256: $RECOVERY2_SHA
recovery-custodian-3-id: izzos-m7-recovery-custodian-test-03
recovery-custodian-3-public-key-sha256: $RECOVERY3_SHA
recovery-event-requirements: NEW_ROOT_MANIFEST_PLUS_2_OF_3_DETACHED_ED25519
compromise-response: REVOKE_PREVIOUS_ROOT_BEFORE_REPLACEMENT_ACTIVATION
unseen-newer-checkpoint-discovery: NOT_PROVEN_BY_THIS_SUPPLIED_QUORUM
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
wrapper-execution-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

sign_policy() {
  local policy="$1" root_signature="$2" witness1_signature="$3" witness2_signature="$4" witness3_signature="$5"
  local root_private="${6:-$TMP/root-private.pem}" witness1_private="${7:-$TMP/witness1-private.pem}" witness2_private="${8:-$TMP/witness2-private.pem}" witness3_private="${9:-NONE}"
  "$OPENSSL" pkeyutl -sign -inkey "$root_private" -rawin -in "$policy" -out "$root_signature" 2>/dev/null
  if [[ "$witness1_private" == "NONE" ]]; then : > "$witness1_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness1_private" -rawin -in "$policy" -out "$witness1_signature" 2>/dev/null; fi
  if [[ "$witness2_private" == "NONE" ]]; then : > "$witness2_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness2_private" -rawin -in "$policy" -out "$witness2_signature" 2>/dev/null; fi
  if [[ "$witness3_private" == "NONE" ]]; then : > "$witness3_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness3_private" -rawin -in "$policy" -out "$witness3_signature" 2>/dev/null; fi
}

write_policy "$TMP/policy.txt"
sign_policy "$TMP/policy.txt" "$TMP/root-signature.bin" "$TMP/witness1-signature.bin" "$TMP/witness2-signature.bin" "$TMP/witness3-signature.bin"

run_verify() {
  local output="$1" governance="${2:-$TMP/governance-report.txt}" checkpoint="${3:-$TMP/checkpoint.txt}" policy="${4:-$TMP/policy.txt}" root_signature="${5:-$TMP/root-signature.bin}" witness1_signature="${6:-$TMP/witness1-signature.bin}" witness2_signature="${7:-$TMP/witness2-signature.bin}" witness3_signature="${8:-$TMP/witness3-signature.bin}" verification="${9:-2026-08-25T00:04:00Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$governance" "$checkpoint" "$TMP/root-manifest.txt" "$TMP/root-public.pem" "$policy" \
    "$TMP/witness1-public.pem" "$witness1_signature" \
    "$TMP/witness2-public.pem" "$witness2_signature" \
    "$TMP/witness3-public.pem" "$witness3_signature" \
    "$TMP/recovery1-public.pem" "$TMP/recovery2-public.pem" "$TMP/recovery3-public.pem" \
    "$root_signature" "$verification" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^publication-quorum-is-two-of-three-and-passes: PASS$' "$TMP/pass.txt"
grep -q '^publication-witness-signatures-valid: 2$' "$TMP/pass.txt"
grep -q '^root-recovery-event-authorized: NO$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_CHECKPOINT_PUBLICATION_QUORUM_ROOT_RECOVERY_POLICY_PASS_EXTERNAL_DISTRIBUTION_REQUIRED$' "$TMP/pass.txt"

if run_verify "$TMP/stale-out.txt" "$TMP/governance-report.txt" "$TMP/checkpoint.txt" "$TMP/policy.txt" "$TMP/root-signature.bin" "$TMP/witness1-signature.bin" "$TMP/witness2-signature.bin" "$TMP/witness3-signature.bin" 2026-08-25T00:14:00Z >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted an expired publication window' >&2
  exit 1
fi
grep -q '^publication-window-is-fresh-bounded-and-ordered: FAIL$' "$TMP/stale-out.txt"

sign_policy "$TMP/policy.txt" "$TMP/quorum-root.bin" "$TMP/quorum-witness1.bin" "$TMP/quorum-witness2.bin" "$TMP/quorum-witness3.bin" "$TMP/root-private.pem" "$TMP/witness1-private.pem" "$TMP/rogue-private.pem" NONE
if run_verify "$TMP/quorum-out.txt" "$TMP/governance-report.txt" "$TMP/checkpoint.txt" "$TMP/policy.txt" "$TMP/quorum-root.bin" "$TMP/quorum-witness1.bin" "$TMP/quorum-witness2.bin" "$TMP/quorum-witness3.bin" >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted fewer than two pinned witness signatures' >&2
  exit 1
fi
grep -q '^publication-quorum-is-two-of-three-and-passes: FAIL$' "$TMP/quorum-out.txt"

cp "$TMP/checkpoint.txt" "$TMP/changed-checkpoint.txt"
printf 'changed: yes\n' >> "$TMP/changed-checkpoint.txt"
if run_verify "$TMP/changed-checkpoint-out.txt" "$TMP/governance-report.txt" "$TMP/changed-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted changed checkpoint bytes' >&2
  exit 1
fi
grep -q '^upstream-governance-pins-exact-checkpoint: FAIL$' "$TMP/changed-checkpoint-out.txt"
grep -q '^policy-binds-exact-governance-report-and-checkpoint: FAIL$' "$TMP/changed-checkpoint-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/policy.txt" -out "$TMP/rogue-root-signature.bin" 2>/dev/null
if run_verify "$TMP/rogue-root-out.txt" "$TMP/governance-report.txt" "$TMP/checkpoint.txt" "$TMP/policy.txt" "$TMP/rogue-root-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted a rogue governance-root signature' >&2
  exit 1
fi
grep -q '^governance-root-approval-policy-and-signature-pass: FAIL$' "$TMP/rogue-root-out.txt"

write_policy "$TMP/unsafe-policy.txt" YES
sign_policy "$TMP/unsafe-policy.txt" "$TMP/unsafe-root.bin" "$TMP/unsafe-witness1.bin" "$TMP/unsafe-witness2.bin" "$TMP/unsafe-witness3.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/governance-report.txt" "$TMP/checkpoint.txt" "$TMP/unsafe-policy.txt" "$TMP/unsafe-root.bin" "$TMP/unsafe-witness1.bin" "$TMP/unsafe-witness2.bin" "$TMP/unsafe-witness3.bin" >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted a root-and-quorum-signed launch claim' >&2
  exit 1
fi
grep -q '^policy-forbids-write-slot-wrapper-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

cp "$TMP/policy.txt" "$TMP/duplicate-policy.txt"
printf 'publication-quorum-threshold: 2\n' >> "$TMP/duplicate-policy.txt"
sign_policy "$TMP/duplicate-policy.txt" "$TMP/duplicate-root.bin" "$TMP/duplicate-witness1.bin" "$TMP/duplicate-witness2.bin" "$TMP/duplicate-witness3.bin"
if run_verify "$TMP/duplicate-out.txt" "$TMP/governance-report.txt" "$TMP/checkpoint.txt" "$TMP/duplicate-policy.txt" "$TMP/duplicate-root.bin" "$TMP/duplicate-witness1.bin" "$TMP/duplicate-witness2.bin" "$TMP/duplicate-witness3.bin" >/dev/null 2>&1; then
  echo 'ERROR: checkpoint-publication gate accepted duplicate policy fields' >&2
  exit 1
fi
grep -q '^policy-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"
grep -q '^policy-is-canonical: FAIL$' "$TMP/duplicate-out.txt"

echo 'PASS: M7 checkpoint publication quorum and governance-root recovery policy gate'
