#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-recovered-checkpoint-republication.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for name in replacement-root witness1 witness2 witness3 rogue; do
  "$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/$name-private.pem" 2>/dev/null
  "$OPENSSL" pkey -in "$TMP/$name-private.pem" -pubout -out "$TMP/$name-public.pem" 2>/dev/null
done

file_sha() {
  sha256sum "$1" | awk '{print $1}'
}

ROOT_SHA="$(file_sha "$TMP/replacement-root-public.pem")"
WITNESS1_SHA="$(file_sha "$TMP/witness1-public.pem")"
WITNESS2_SHA="$(file_sha "$TMP/witness2-public.pem")"
WITNESS3_SHA="$(file_sha "$TMP/witness3-public.pem")"

cat > "$TMP/replacement-root-manifest.txt" <<EOF
key-governance-root-schema: IZZOS_M7_KEY_GOVERNANCE_ROOT_V1
governance-root-key-id: izzos-m7-governance-root-recovered-02
governance-root-role: M7_OFFLINE_KEY_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $ROOT_SHA
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
ROOT_MANIFEST_SHA="$(file_sha "$TMP/replacement-root-manifest.txt")"

cat > "$TMP/recovery-event.txt" <<EOF
governance-root-recovery-event-schema: IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_EVENT_V1
recovered-governance-epoch: 3
recovered-governance-sequence: 1
previous-governance-root-status: REVOKED_EFFECTIVE_AT_RECOVERY
replacement-governance-root-key-id: izzos-m7-governance-root-recovered-02
replacement-governance-root-public-key-sha256: $ROOT_SHA
replacement-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
EOF
EVENT_SHA="$(file_sha "$TMP/recovery-event.txt")"

cat > "$TMP/recovered-checkpoint.txt" <<EOF
governance-root-recovery-checkpoint-schema: IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1
checkpoint-id: izzos-m7-root-recovery-checkpoint-test-03-01
recovery-event-sha256: $EVENT_SHA
minimum-governance-epoch: 3
minimum-governance-sequence: 1
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
previous-governance-root-status: REVOKED_EFFECTIVE_AT_RECOVERY
checkpoint-updated-at-utc: 2026-08-25T00:05:30Z
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
CHECKPOINT_SHA="$(file_sha "$TMP/recovered-checkpoint.txt")"

cat > "$TMP/recovery-report.txt" <<EOF
governance-root-recovery-event-sha256: $EVENT_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
replacement-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
replacement-governance-root-public-key-sha256: $ROOT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
verification-timestamp-utc: 2026-08-25T00:06:00Z
previous-governance-root-state: REVOKED
replacement-governance-root-state: CRYPTOGRAPHICALLY_BOUND_PENDING_REPUBLICATION
wrapper-execution-authorization: NO
persistent-writes: FORBIDDEN
launch-authorization: NO
classification: M7_GOVERNANCE_ROOT_RECOVERY_EVENT_PASS_REPUBLICATION_REQUIRED
EOF
RECOVERY_REPORT_SHA="$(file_sha "$TMP/recovery-report.txt")"

write_republication() {
  local output="$1" epoch="${2:-3}" sequence="${3:-1}" launch="${4:-NO}" checkpoint_sha="${5:-$CHECKPOINT_SHA}" witness3_sha="${6:-$WITNESS3_SHA}"
  cat > "$output" <<EOF
recovered-checkpoint-republication-schema: IZZOS_M7_RECOVERED_CHECKPOINT_REPUBLICATION_V1
republication-id: izzos-m7-recovered-checkpoint-republication-test-03-01
root-recovery-verification-sha256: $RECOVERY_REPORT_SHA
governance-root-recovery-event-sha256: $EVENT_SHA
recovered-checkpoint-sha256: $checkpoint_sha
recovered-governance-epoch: $epoch
recovered-governance-sequence: $sequence
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
previous-governance-root-status: REVOKED_EFFECTIVE_AT_RECOVERY
republication-issued-at-utc: 2026-08-25T00:06:10Z
republication-published-at-utc: 2026-08-25T00:06:15Z
republication-valid-until-utc: 2026-08-25T00:16:15Z
republication-window-max-seconds: 900
republication-source: RECOVERY_ROOT_SIGNED_AND_INDEPENDENT_WITNESS_QUORUM
signature-algorithm: ED25519
witness-quorum-threshold: 2
republication-witness-1-id: izzos-m7-republication-witness-test-01
republication-witness-1-public-key-sha256: $WITNESS1_SHA
republication-witness-2-id: izzos-m7-republication-witness-test-02
republication-witness-2-public-key-sha256: $WITNESS2_SHA
republication-witness-3-id: izzos-m7-republication-witness-test-03
republication-witness-3-public-key-sha256: $witness3_sha
replacement-root-approval-policy: REQUIRED_DETACHED_ED25519
continuity-policy: REJECT_PRE_RECOVERY_ROOT_AND_ALL_LOWER_EPOCHS
unseen-newer-checkpoint-discovery: NOT_PROVEN_BY_THIS_SUPPLIED_QUORUM
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
wrapper-execution-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

sign_republication() {
  local record="$1" root_signature="$2" witness1_signature="$3" witness2_signature="$4" witness3_signature="$5"
  local root_private="${6:-$TMP/replacement-root-private.pem}" witness1_private="${7:-$TMP/witness1-private.pem}" witness2_private="${8:-$TMP/witness2-private.pem}" witness3_private="${9:-NONE}"
  "$OPENSSL" pkeyutl -sign -inkey "$root_private" -rawin -in "$record" -out "$root_signature" 2>/dev/null
  if [[ "$witness1_private" == "NONE" ]]; then : > "$witness1_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness1_private" -rawin -in "$record" -out "$witness1_signature" 2>/dev/null; fi
  if [[ "$witness2_private" == "NONE" ]]; then : > "$witness2_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness2_private" -rawin -in "$record" -out "$witness2_signature" 2>/dev/null; fi
  if [[ "$witness3_private" == "NONE" ]]; then : > "$witness3_signature"; else "$OPENSSL" pkeyutl -sign -inkey "$witness3_private" -rawin -in "$record" -out "$witness3_signature" 2>/dev/null; fi
}

write_republication "$TMP/republication.txt"
sign_republication "$TMP/republication.txt" "$TMP/root-signature.bin" "$TMP/witness1-signature.bin" "$TMP/witness2-signature.bin" "$TMP/witness3-signature.bin"

run_verify() {
  local output="$1" checkpoint="${2:-$TMP/recovered-checkpoint.txt}" record="${3:-$TMP/republication.txt}" root_signature="${4:-$TMP/root-signature.bin}" witness1_signature="${5:-$TMP/witness1-signature.bin}" witness2_signature="${6:-$TMP/witness2-signature.bin}" witness3_signature="${7:-$TMP/witness3-signature.bin}" verification="${8:-2026-08-25T00:07:00Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/recovery-report.txt" "$TMP/recovery-event.txt" "$checkpoint" \
    "$TMP/replacement-root-manifest.txt" "$TMP/replacement-root-public.pem" "$record" \
    "$TMP/witness1-public.pem" "$witness1_signature" \
    "$TMP/witness2-public.pem" "$witness2_signature" \
    "$TMP/witness3-public.pem" "$witness3_signature" \
    "$root_signature" "$verification" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^republication-witness-quorum-is-two-of-three-and-passes: PASS$' "$TMP/pass.txt"
grep -q '^republication-witness-signatures-valid: 2$' "$TMP/pass.txt"
grep -q '^replacement-governance-root-state: REPUBLISHED_TO_FRESH_SUPPLIED_WITNESS_QUORUM$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_RECOVERED_CHECKPOINT_REPUBLICATION_QUORUM_PASS_EXTERNAL_DISTRIBUTION_REQUIRED$' "$TMP/pass.txt"

if run_verify "$TMP/stale-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/republication.txt" "$TMP/root-signature.bin" "$TMP/witness1-signature.bin" "$TMP/witness2-signature.bin" "$TMP/witness3-signature.bin" 2026-08-25T00:17:00Z >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted an expired record' >&2
  exit 1
fi
grep -q '^republication-times-are-fresh-bounded-and-ordered: FAIL$' "$TMP/stale-out.txt"

sed \
  -e 's/republication-issued-at-utc: 2026-08-25T00:06:10Z/republication-issued-at-utc: 2026-08-25T00:22:00Z/' \
  -e 's/republication-published-at-utc: 2026-08-25T00:06:15Z/republication-published-at-utc: 2026-08-25T00:22:05Z/' \
  -e 's/republication-valid-until-utc: 2026-08-25T00:16:15Z/republication-valid-until-utc: 2026-08-25T00:32:05Z/' \
  "$TMP/republication.txt" > "$TMP/delayed.txt"
sign_republication "$TMP/delayed.txt" "$TMP/delayed-root.bin" "$TMP/delayed-w1.bin" "$TMP/delayed-w2.bin" "$TMP/delayed-w3.bin"
if run_verify "$TMP/delayed-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/delayed.txt" "$TMP/delayed-root.bin" "$TMP/delayed-w1.bin" "$TMP/delayed-w2.bin" "$TMP/delayed-w3.bin" 2026-08-25T00:23:00Z >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted a publication delayed beyond the recovery window' >&2
  exit 1
fi
grep -q '^republication-times-are-fresh-bounded-and-ordered: FAIL$' "$TMP/delayed-out.txt"

sign_republication "$TMP/republication.txt" "$TMP/one-root.bin" "$TMP/one-w1.bin" "$TMP/one-w2.bin" "$TMP/one-w3.bin" "$TMP/replacement-root-private.pem" "$TMP/witness1-private.pem" "$TMP/rogue-private.pem" NONE
if run_verify "$TMP/one-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/republication.txt" "$TMP/one-root.bin" "$TMP/one-w1.bin" "$TMP/one-w2.bin" "$TMP/one-w3.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted fewer than two pinned witnesses' >&2
  exit 1
fi
grep -q '^republication-witness-quorum-is-two-of-three-and-passes: FAIL$' "$TMP/one-out.txt"

cp "$TMP/recovered-checkpoint.txt" "$TMP/changed-checkpoint.txt"
printf 'changed: yes\n' >> "$TMP/changed-checkpoint.txt"
if run_verify "$TMP/changed-out.txt" "$TMP/changed-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted changed checkpoint bytes' >&2
  exit 1
fi
grep -q '^upstream-report-binds-exact-event-checkpoint-manifest-and-root-key: FAIL$' "$TMP/changed-out.txt"
grep -q '^republication-binds-exact-recovery-report-event-and-checkpoint: FAIL$' "$TMP/changed-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/republication.txt" -out "$TMP/rogue-root.bin" 2>/dev/null
if run_verify "$TMP/rogue-root-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/republication.txt" "$TMP/rogue-root.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted a rogue replacement-root signature' >&2
  exit 1
fi
grep -q '^replacement-root-approval-signature-passes: FAIL$' "$TMP/rogue-root-out.txt"

write_republication "$TMP/wrong-epoch.txt" 2 1
sign_republication "$TMP/wrong-epoch.txt" "$TMP/wrong-root.bin" "$TMP/wrong-w1.bin" "$TMP/wrong-w2.bin" "$TMP/wrong-w3.bin"
if run_verify "$TMP/wrong-epoch-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/wrong-epoch.txt" "$TMP/wrong-root.bin" "$TMP/wrong-w1.bin" "$TMP/wrong-w2.bin" "$TMP/wrong-w3.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted a lower epoch' >&2
  exit 1
fi
grep -q '^all-recovery-epoch-and-sequence-bindings-match: FAIL$' "$TMP/wrong-epoch-out.txt"

write_republication "$TMP/unsafe.txt" 3 1 YES
sign_republication "$TMP/unsafe.txt" "$TMP/unsafe-root.bin" "$TMP/unsafe-w1.bin" "$TMP/unsafe-w2.bin" "$TMP/unsafe-w3.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/unsafe.txt" "$TMP/unsafe-root.bin" "$TMP/unsafe-w1.bin" "$TMP/unsafe-w2.bin" "$TMP/unsafe-w3.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted a signed launch claim' >&2
  exit 1
fi
grep -q '^republication-forbids-write-slot-wrapper-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

write_republication "$TMP/reused-key.txt" 3 1 NO "$CHECKPOINT_SHA" "$WITNESS1_SHA"
sign_republication "$TMP/reused-key.txt" "$TMP/reused-root.bin" "$TMP/reused-w1.bin" "$TMP/reused-w2.bin" "$TMP/reused-w3.bin"
if run_verify "$TMP/reused-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/reused-key.txt" "$TMP/reused-root.bin" "$TMP/reused-w1.bin" "$TMP/reused-w2.bin" "$TMP/reused-w3.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted a reused witness pin' >&2
  exit 1
fi
grep -q '^republication-witness-identities-and-key-pins-are-exact-and-distinct: FAIL$' "$TMP/reused-out.txt"

cp "$TMP/republication.txt" "$TMP/duplicate.txt"
printf 'witness-quorum-threshold: 2\n' >> "$TMP/duplicate.txt"
sign_republication "$TMP/duplicate.txt" "$TMP/duplicate-root.bin" "$TMP/duplicate-w1.bin" "$TMP/duplicate-w2.bin" "$TMP/duplicate-w3.bin"
if run_verify "$TMP/duplicate-out.txt" "$TMP/recovered-checkpoint.txt" "$TMP/duplicate.txt" "$TMP/duplicate-root.bin" "$TMP/duplicate-w1.bin" "$TMP/duplicate-w2.bin" "$TMP/duplicate-w3.bin" >/dev/null 2>&1; then
  echo 'ERROR: recovered-checkpoint republication gate accepted duplicate fields' >&2
  exit 1
fi
grep -q '^republication-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"
grep -q '^republication-is-canonical: FAIL$' "$TMP/duplicate-out.txt"

echo 'PASS: M7 recovered-checkpoint republication quorum gate'
