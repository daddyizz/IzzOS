#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-recovered-checkpoint-external-distribution.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for name in replacement-root channel1 channel2 channel3 rogue; do
  "$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/$name-private.pem" 2>/dev/null
  "$OPENSSL" pkey -in "$TMP/$name-private.pem" -pubout -out "$TMP/$name-public.pem" 2>/dev/null
done

file_sha() {
  sha256sum "$1" | awk '{print $1}'
}

value() {
  local file="$1" label="$2"
  awk -F ': ' -v label="$label" '$1 == label {print substr($0, length(label) + 3)}' "$file"
}

ROOT_SHA="$(file_sha "$TMP/replacement-root-public.pem")"
CHANNEL1_SHA="$(file_sha "$TMP/channel1-public.pem")"
CHANNEL2_SHA="$(file_sha "$TMP/channel2-public.pem")"
CHANNEL3_SHA="$(file_sha "$TMP/channel3-public.pem")"

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

cat > "$TMP/recovered-checkpoint.txt" <<EOF
governance-root-recovery-checkpoint-schema: IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1
minimum-governance-epoch: 3
minimum-governance-sequence: 1
EOF
CHECKPOINT_SHA="$(file_sha "$TMP/recovered-checkpoint.txt")"

cat > "$TMP/republication.txt" <<EOF
recovered-checkpoint-republication-schema: IZZOS_M7_RECOVERED_CHECKPOINT_REPUBLICATION_V1
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
previous-governance-root-status: REVOKED_EFFECTIVE_AT_RECOVERY
republication-published-at-utc: 2026-08-25T00:06:15Z
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
REPUBLICATION_SHA="$(file_sha "$TMP/republication.txt")"

cat > "$TMP/republication-report.txt" <<EOF
republication-record-sha256: $REPUBLICATION_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
replacement-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
replacement-governance-root-public-key-sha256: $ROOT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
verification-timestamp-utc: 2026-08-25T00:07:00Z
replacement-governance-root-state: REPUBLISHED_TO_FRESH_SUPPLIED_WITNESS_QUORUM
wrapper-execution-authorization: NO
persistent-writes: FORBIDDEN
launch-authorization: NO
classification: M7_RECOVERED_CHECKPOINT_REPUBLICATION_QUORUM_PASS_EXTERNAL_DISTRIBUTION_REQUIRED
EOF
REPORT_SHA="$(file_sha "$TMP/republication-report.txt")"

write_policy() {
  local output="$1"
  local operator3="${2:-izzos-m7-distributor-operator-test-03}"
  local origin3="${3:-https://checkpoint-c.example.net/izzos/m7/recovered-checkpoint.txt}"
  local launch="${4:-NO}"
  cat > "$output" <<EOF
external-distribution-policy-schema: IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_POLICY_V1
distribution-policy-id: izzos-m7-external-distribution-policy-test-03-01
republication-verification-sha256: $REPORT_SHA
republication-record-sha256: $REPUBLICATION_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
distribution-policy-issued-at-utc: 2026-08-25T00:07:10Z
distribution-receipt-max-lag-seconds: 3600
distribution-receipt-max-age-seconds: 3600
required-independent-channel-count: 3
signature-algorithm: ED25519
distribution-channel-1-id: izzos-m7-distribution-channel-test-01
distribution-channel-1-operator-id: izzos-m7-distributor-operator-test-01
distribution-channel-1-origin: https://checkpoint-a.example.org/izzos/m7/recovered-checkpoint.txt
distribution-channel-1-public-key-sha256: $CHANNEL1_SHA
distribution-channel-2-id: izzos-m7-distribution-channel-test-02
distribution-channel-2-operator-id: izzos-m7-distributor-operator-test-02
distribution-channel-2-origin: https://checkpoint-b.example.com/izzos/m7/recovered-checkpoint.txt
distribution-channel-2-public-key-sha256: $CHANNEL2_SHA
distribution-channel-3-id: izzos-m7-distribution-channel-test-03
distribution-channel-3-operator-id: $operator3
distribution-channel-3-origin: $origin3
distribution-channel-3-public-key-sha256: $CHANNEL3_SHA
channel-independence-policy: DISTINCT_OPERATOR_ID_ORIGIN_HOST_AND_ED25519_KEY_REQUIRED
continuous-monitoring-state: NOT_PROVEN_BY_ONE_SHOT_RECEIPTS
unseen-newer-checkpoint-discovery: NOT_PROVEN_BY_SUPPLIED_DISTRIBUTION_RECEIPTS
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
wrapper-execution-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

write_receipt() {
  local policy="$1" index="$2" output="$3" observed="$4"
  local launch="${5:-NO}"
  local policy_sha channel_id operator_id origin key_sha
  policy_sha="$(file_sha "$policy")"
  channel_id="$(value "$policy" "distribution-channel-$index-id")"
  operator_id="$(value "$policy" "distribution-channel-$index-operator-id")"
  origin="$(value "$policy" "distribution-channel-$index-origin")"
  key_sha="$(value "$policy" "distribution-channel-$index-public-key-sha256")"
  cat > "$output" <<EOF
external-distribution-receipt-schema: IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_RECEIPT_V1
distribution-policy-sha256: $policy_sha
distribution-channel-id: $channel_id
distribution-operator-id: $operator_id
distribution-origin: $origin
distribution-public-key-sha256: $key_sha
republication-verification-sha256: $REPORT_SHA
republication-record-sha256: $REPUBLICATION_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
observed-at-utc: $observed
checkpoint-content-available: YES_EXACT_SHA256
transport-policy: HTTPS_TLS_REQUIRED
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
EOF
}

write_receipt_set() {
  local policy="$1" prefix="$2" observed3="${3:-2026-08-25T00:08:20Z}" receipt3_launch="${4:-NO}"
  write_receipt "$policy" 1 "$TMP/$prefix-receipt1.txt" 2026-08-25T00:08:00Z
  write_receipt "$policy" 2 "$TMP/$prefix-receipt2.txt" 2026-08-25T00:08:10Z
  write_receipt "$policy" 3 "$TMP/$prefix-receipt3.txt" "$observed3" "$receipt3_launch"
}

sign_set() {
  local policy="$1" prefix="$2"
  "$OPENSSL" pkeyutl -sign -inkey "$TMP/replacement-root-private.pem" -rawin -in "$policy" -out "$TMP/$prefix-root-policy-signature.bin" 2>/dev/null
  for index in 1 2 3; do
    "$OPENSSL" pkeyutl -sign -inkey "$TMP/channel$index-private.pem" -rawin -in "$TMP/$prefix-receipt$index.txt" -out "$TMP/$prefix-receipt$index-signature.bin" 2>/dev/null
  done
}

run_verify() {
  local output="$1" policy="${2:-$TMP/policy.txt}" prefix="${3:-base}"
  local checkpoint="${4:-$TMP/recovered-checkpoint.txt}"
  local root_signature="${5:-$TMP/$prefix-root-policy-signature.bin}"
  local signature1="${6:-$TMP/$prefix-receipt1-signature.bin}"
  local signature2="${7:-$TMP/$prefix-receipt2-signature.bin}"
  local signature3="${8:-$TMP/$prefix-receipt3-signature.bin}"
  local verification="${9:-2026-08-25T00:09:00Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/republication-report.txt" "$TMP/republication.txt" "$checkpoint" \
    "$TMP/replacement-root-manifest.txt" "$TMP/replacement-root-public.pem" \
    "$policy" "$root_signature" \
    "$TMP/channel1-public.pem" "$TMP/$prefix-receipt1.txt" "$signature1" \
    "$TMP/channel2-public.pem" "$TMP/$prefix-receipt2.txt" "$signature2" \
    "$TMP/channel3-public.pem" "$TMP/$prefix-receipt3.txt" "$signature3" \
    "$verification" "$output"
}

write_policy "$TMP/policy.txt"
write_receipt_set "$TMP/policy.txt" base
sign_set "$TMP/policy.txt" base

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^all-three-independent-distribution-receipt-signatures-pass: PASS$' "$TMP/pass.txt"
grep -q '^distribution-receipt-signatures-valid: 3$' "$TMP/pass.txt"
grep -q '^replacement-governance-root-state: EXTERNALLY_DISTRIBUTED_TO_3_OF_3_SUPPLIED_INDEPENDENT_CHANNELS$' "$TMP/pass.txt"
grep -q '^network requests executed by verifier: none$' < <(tr '[:upper:]' '[:lower:]' < "$TMP/pass.txt")
grep -q '^classification: M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_PASS_CONTINUOUS_MONITORING_REQUIRED$' "$TMP/pass.txt"

if run_verify "$TMP/stale-out.txt" "$TMP/policy.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/base-root-policy-signature.bin" "$TMP/base-receipt1-signature.bin" "$TMP/base-receipt2-signature.bin" "$TMP/base-receipt3-signature.bin" 2026-08-25T01:09:00Z >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted stale one-shot receipts' >&2
  exit 1
fi
grep -q '^distribution-receipts-are-fresh-bounded-and-ordered: FAIL$' "$TMP/stale-out.txt"

write_receipt_set "$TMP/policy.txt" delayed 2026-08-25T01:07:00Z
sign_set "$TMP/policy.txt" delayed
if run_verify "$TMP/delayed-out.txt" "$TMP/policy.txt" delayed "$TMP/recovered-checkpoint.txt" "$TMP/delayed-root-policy-signature.bin" "$TMP/delayed-receipt1-signature.bin" "$TMP/delayed-receipt2-signature.bin" "$TMP/delayed-receipt3-signature.bin" 2026-08-25T01:07:10Z >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted a receipt beyond the publication lag bound' >&2
  exit 1
fi
grep -q '^distribution-receipts-are-fresh-bounded-and-ordered: FAIL$' "$TMP/delayed-out.txt"

: > "$TMP/missing-signature.bin"
if run_verify "$TMP/missing-out.txt" "$TMP/policy.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/base-root-policy-signature.bin" "$TMP/base-receipt1-signature.bin" "$TMP/base-receipt2-signature.bin" "$TMP/missing-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted fewer than three channel signatures' >&2
  exit 1
fi
grep -q '^all-three-independent-distribution-receipt-signatures-pass: FAIL$' "$TMP/missing-out.txt"

write_policy "$TMP/duplicate-channel-policy.txt" izzos-m7-distributor-operator-test-01 https://checkpoint-a.example.org/izzos/m7/recovered-checkpoint.txt
write_receipt_set "$TMP/duplicate-channel-policy.txt" duplicate-channel
sign_set "$TMP/duplicate-channel-policy.txt" duplicate-channel
if run_verify "$TMP/duplicate-channel-out.txt" "$TMP/duplicate-channel-policy.txt" duplicate-channel >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted a repeated operator and origin' >&2
  exit 1
fi
grep -q '^distribution-policy-has-three-distinct-pinned-https-channels: FAIL$' "$TMP/duplicate-channel-out.txt"

cp "$TMP/recovered-checkpoint.txt" "$TMP/changed-checkpoint.txt"
printf 'changed: yes\n' >> "$TMP/changed-checkpoint.txt"
if run_verify "$TMP/changed-out.txt" "$TMP/policy.txt" base "$TMP/changed-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted changed checkpoint bytes' >&2
  exit 1
fi
grep -q '^upstream-report-binds-exact-republication-checkpoint-manifest-and-root-key: FAIL$' "$TMP/changed-out.txt"
grep -q '^distribution-receipts-bind-exact-policy-channels-and-checkpoint: FAIL$' "$TMP/changed-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/policy.txt" -out "$TMP/rogue-root-signature.bin" 2>/dev/null
if run_verify "$TMP/rogue-root-out.txt" "$TMP/policy.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/rogue-root-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted a rogue root policy signature' >&2
  exit 1
fi
grep -q '^distribution-policy-replacement-root-signature-passes: FAIL$' "$TMP/rogue-root-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/base-receipt2.txt" -out "$TMP/rogue-channel-signature.bin" 2>/dev/null
if run_verify "$TMP/rogue-channel-out.txt" "$TMP/policy.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/base-root-policy-signature.bin" "$TMP/base-receipt1-signature.bin" "$TMP/rogue-channel-signature.bin" "$TMP/base-receipt3-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted a rogue channel receipt signature' >&2
  exit 1
fi
grep -q '^all-three-independent-distribution-receipt-signatures-pass: FAIL$' "$TMP/rogue-channel-out.txt"

write_policy "$TMP/unsafe-policy.txt" izzos-m7-distributor-operator-test-03 https://checkpoint-c.example.net/izzos/m7/recovered-checkpoint.txt YES
write_receipt_set "$TMP/unsafe-policy.txt" unsafe
sign_set "$TMP/unsafe-policy.txt" unsafe
if run_verify "$TMP/unsafe-out.txt" "$TMP/unsafe-policy.txt" unsafe >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted a root-signed launch claim' >&2
  exit 1
fi
grep -q '^policy-and-receipts-forbid-write-slot-wrapper-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

cp "$TMP/policy.txt" "$TMP/duplicate-field-policy.txt"
printf 'required-independent-channel-count: 3\n' >> "$TMP/duplicate-field-policy.txt"
write_receipt_set "$TMP/duplicate-field-policy.txt" duplicate-field
sign_set "$TMP/duplicate-field-policy.txt" duplicate-field
if run_verify "$TMP/duplicate-field-out.txt" "$TMP/duplicate-field-policy.txt" duplicate-field >/dev/null 2>&1; then
  echo 'ERROR: external-distribution gate accepted duplicate policy fields' >&2
  exit 1
fi
grep -q '^distribution-policy-fields-are-present-once: FAIL$' "$TMP/duplicate-field-out.txt"
grep -q '^distribution-policy-is-canonical: FAIL$' "$TMP/duplicate-field-out.txt"

echo 'PASS: M7 recovered-checkpoint external-distribution gate'
