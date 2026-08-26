#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-recovered-checkpoint-bounded-monitoring.py"
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

cat > "$TMP/distribution-policy.txt" <<EOF
external-distribution-policy-schema: IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_POLICY_V1
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
distribution-channel-1-id: izzos-m7-distribution-channel-test-01
distribution-channel-1-operator-id: izzos-m7-distributor-operator-test-01
distribution-channel-1-origin: https://checkpoint-a.example.org/izzos/m7/recovered-checkpoint.txt
distribution-channel-1-public-key-sha256: $CHANNEL1_SHA
distribution-channel-2-id: izzos-m7-distribution-channel-test-02
distribution-channel-2-operator-id: izzos-m7-distributor-operator-test-02
distribution-channel-2-origin: https://checkpoint-b.example.com/izzos/m7/recovered-checkpoint.txt
distribution-channel-2-public-key-sha256: $CHANNEL2_SHA
distribution-channel-3-id: izzos-m7-distribution-channel-test-03
distribution-channel-3-operator-id: izzos-m7-distributor-operator-test-03
distribution-channel-3-origin: https://checkpoint-c.example.net/izzos/m7/recovered-checkpoint.txt
distribution-channel-3-public-key-sha256: $CHANNEL3_SHA
EOF
POLICY_SHA="$(file_sha "$TMP/distribution-policy.txt")"

cat > "$TMP/external-report.txt" <<EOF
distribution-policy-sha256: $POLICY_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
replacement-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
replacement-governance-root-public-key-sha256: $ROOT_SHA
recovered-governance-epoch: 3
recovered-governance-sequence: 1
verification-timestamp-utc: 2026-08-25T00:09:00Z
replacement-governance-root-state: EXTERNALLY_DISTRIBUTED_TO_3_OF_3_SUPPLIED_INDEPENDENT_CHANNELS
continuous-monitoring-state: NOT_PROVEN_BY_ONE_SHOT_RECEIPTS
wrapper-execution-authorization: NO
persistent-writes: FORBIDDEN
launch-authorization: NO
classification: M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_PASS_CONTINUOUS_MONITORING_REQUIRED
EOF
REPORT_SHA="$(file_sha "$TMP/external-report.txt")"

write_mandate() {
  local output="$1"
  local operator3="${2:-izzos-m7-distributor-operator-test-03}"
  local epoch="${3:-3}"
  local launch="${4:-NO}"
  cat > "$output" <<EOF
bounded-monitoring-mandate-schema: IZZOS_M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_MANDATE_V1
monitoring-id: izzos-m7-bounded-monitoring-test-03-01
external-distribution-verification-sha256: $REPORT_SHA
external-distribution-policy-sha256: $POLICY_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: $epoch
recovered-governance-sequence: 1
active-governance-root-key-id: izzos-m7-governance-root-recovered-02
active-governance-root-public-key-sha256: $ROOT_SHA
active-governance-root-manifest-sha256: $ROOT_MANIFEST_SHA
monitoring-window-start-utc: 2026-08-25T00:10:00Z
monitoring-window-end-utc: 2026-08-25T00:55:00Z
minimum-observation-rounds: 4
maximum-observation-gap-seconds: 900
required-independent-channel-count: 3
signature-algorithm: ED25519
monitoring-channel-1-id: izzos-m7-distribution-channel-test-01
monitoring-channel-1-operator-id: izzos-m7-distributor-operator-test-01
monitoring-channel-1-origin: https://checkpoint-a.example.org/izzos/m7/recovered-checkpoint.txt
monitoring-channel-1-public-key-sha256: $CHANNEL1_SHA
monitoring-channel-2-id: izzos-m7-distribution-channel-test-02
monitoring-channel-2-operator-id: izzos-m7-distributor-operator-test-02
monitoring-channel-2-origin: https://checkpoint-b.example.com/izzos/m7/recovered-checkpoint.txt
monitoring-channel-2-public-key-sha256: $CHANNEL2_SHA
monitoring-channel-3-id: izzos-m7-distribution-channel-test-03
monitoring-channel-3-operator-id: $operator3
monitoring-channel-3-origin: https://checkpoint-c.example.net/izzos/m7/recovered-checkpoint.txt
monitoring-channel-3-public-key-sha256: $CHANNEL3_SHA
channel-independence-policy: DISTINCT_OPERATOR_ORIGIN_AND_ED25519_KEY_REQUIRED
bounded-monitoring-scope: FOUR_SYNCHRONIZED_ROUNDS_ACROSS_THREE_CHANNELS_ONLY
long-term-availability-state: NOT_PROVEN_BEYOND_BOUNDED_WINDOW
unseen-newer-checkpoint-discovery: NOT_PROVEN_OUTSIDE_MONITORED_CHANNELS
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
wrapper-execution-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

write_journal() {
  local mandate="$1" index="$2" output="$3"
  local observation2="${4:-2026-08-25T00:25:00Z}"
  local launch="${5:-NO}"
  local mandate_sha channel_id operator_id origin key_sha epoch
  mandate_sha="$(file_sha "$mandate")"
  channel_id="$(value "$mandate" "monitoring-channel-$index-id")"
  operator_id="$(value "$mandate" "monitoring-channel-$index-operator-id")"
  origin="$(value "$mandate" "monitoring-channel-$index-origin")"
  key_sha="$(value "$mandate" "monitoring-channel-$index-public-key-sha256")"
  epoch="$(value "$mandate" recovered-governance-epoch)"
  cat > "$output" <<EOF
bounded-monitoring-journal-schema: IZZOS_M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_JOURNAL_V1
monitoring-mandate-sha256: $mandate_sha
monitoring-channel-id: $channel_id
monitoring-operator-id: $operator_id
monitoring-origin: $origin
monitoring-public-key-sha256: $key_sha
external-distribution-verification-sha256: $REPORT_SHA
external-distribution-policy-sha256: $POLICY_SHA
recovered-checkpoint-sha256: $CHECKPOINT_SHA
recovered-governance-epoch: $epoch
recovered-governance-sequence: 1
observation-1-at-utc: 2026-08-25T00:10:00Z
observation-1-checkpoint-sha256: $CHECKPOINT_SHA
observation-1-availability: YES_EXACT_SHA256
observation-2-at-utc: $observation2
observation-2-checkpoint-sha256: $CHECKPOINT_SHA
observation-2-availability: YES_EXACT_SHA256
observation-3-at-utc: 2026-08-25T00:40:00Z
observation-3-checkpoint-sha256: $CHECKPOINT_SHA
observation-3-availability: YES_EXACT_SHA256
observation-4-at-utc: 2026-08-25T00:55:00Z
observation-4-checkpoint-sha256: $CHECKPOINT_SHA
observation-4-availability: YES_EXACT_SHA256
monitoring-result: ALL_REQUIRED_OBSERVATIONS_AVAILABLE
transport-policy: HTTPS_TLS_REQUIRED
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
EOF
}

write_journal_set() {
  local mandate="$1" prefix="$2" observation2="${3:-2026-08-25T00:25:00Z}" journal3_launch="${4:-NO}"
  write_journal "$mandate" 1 "$TMP/$prefix-journal1.txt" "$observation2"
  write_journal "$mandate" 2 "$TMP/$prefix-journal2.txt" "$observation2"
  write_journal "$mandate" 3 "$TMP/$prefix-journal3.txt" "$observation2" "$journal3_launch"
}

sign_set() {
  local mandate="$1" prefix="$2"
  "$OPENSSL" pkeyutl -sign -inkey "$TMP/replacement-root-private.pem" -rawin -in "$mandate" -out "$TMP/$prefix-root-signature.bin" 2>/dev/null
  for index in 1 2 3; do
    "$OPENSSL" pkeyutl -sign -inkey "$TMP/channel$index-private.pem" -rawin -in "$TMP/$prefix-journal$index.txt" -out "$TMP/$prefix-journal$index-signature.bin" 2>/dev/null
  done
}

run_verify() {
  local output="$1" mandate="${2:-$TMP/mandate.txt}" prefix="${3:-base}"
  local checkpoint="${4:-$TMP/recovered-checkpoint.txt}"
  local root_signature="${5:-$TMP/$prefix-root-signature.bin}"
  local signature1="${6:-$TMP/$prefix-journal1-signature.bin}"
  local signature2="${7:-$TMP/$prefix-journal2-signature.bin}"
  local signature3="${8:-$TMP/$prefix-journal3-signature.bin}"
  local verification="${9:-2026-08-25T00:56:00Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/external-report.txt" "$TMP/distribution-policy.txt" "$checkpoint" \
    "$TMP/replacement-root-manifest.txt" "$TMP/replacement-root-public.pem" \
    "$mandate" "$root_signature" \
    "$TMP/channel1-public.pem" "$TMP/$prefix-journal1.txt" "$signature1" \
    "$TMP/channel2-public.pem" "$TMP/$prefix-journal2.txt" "$signature2" \
    "$TMP/channel3-public.pem" "$TMP/$prefix-journal3.txt" "$signature3" \
    "$verification" "$output"
}

write_mandate "$TMP/mandate.txt"
write_journal_set "$TMP/mandate.txt" base
sign_set "$TMP/mandate.txt" base

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^bounded-monitoring-rounds-are-synchronized-fresh-and-gap-bounded: PASS$' "$TMP/pass.txt"
grep -q '^bounded-monitoring-journal-signatures-valid: 3$' "$TMP/pass.txt"
grep -q '^internal-m7-host-security-chain: COMPLETE_FOR_SUPPLIED_BOUNDED_EVIDENCE$' "$TMP/pass.txt"
grep -q '^classification: M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_PASS_INTERNAL_HOST_SECURITY_CHAIN_COMPLETE$' "$TMP/pass.txt"

write_journal_set "$TMP/mandate.txt" wide-gap 2026-08-25T00:26:00Z
sign_set "$TMP/mandate.txt" wide-gap
if run_verify "$TMP/wide-gap-out.txt" "$TMP/mandate.txt" wide-gap >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted an observation gap above 900 seconds' >&2
  exit 1
fi
grep -q '^bounded-monitoring-rounds-are-synchronized-fresh-and-gap-bounded: FAIL$' "$TMP/wide-gap-out.txt"

if run_verify "$TMP/stale-out.txt" "$TMP/mandate.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/base-root-signature.bin" "$TMP/base-journal1-signature.bin" "$TMP/base-journal2-signature.bin" "$TMP/base-journal3-signature.bin" 2026-08-25T01:01:00Z >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted a stale final observation' >&2
  exit 1
fi
grep -q '^bounded-monitoring-rounds-are-synchronized-fresh-and-gap-bounded: FAIL$' "$TMP/stale-out.txt"

: > "$TMP/missing-signature.bin"
if run_verify "$TMP/missing-out.txt" "$TMP/mandate.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/base-root-signature.bin" "$TMP/base-journal1-signature.bin" "$TMP/base-journal2-signature.bin" "$TMP/missing-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted fewer than three journal signatures' >&2
  exit 1
fi
grep -q '^all-three-bounded-monitoring-journal-signatures-pass: FAIL$' "$TMP/missing-out.txt"

write_mandate "$TMP/duplicate-channel-mandate.txt" izzos-m7-distributor-operator-test-01
write_journal_set "$TMP/duplicate-channel-mandate.txt" duplicate-channel
sign_set "$TMP/duplicate-channel-mandate.txt" duplicate-channel
if run_verify "$TMP/duplicate-channel-out.txt" "$TMP/duplicate-channel-mandate.txt" duplicate-channel >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted a repeated operator' >&2
  exit 1
fi
grep -q '^bounded-monitoring-mandate-has-three-distinct-pinned-channels: FAIL$' "$TMP/duplicate-channel-out.txt"

cp "$TMP/recovered-checkpoint.txt" "$TMP/changed-checkpoint.txt"
printf 'changed: yes\n' >> "$TMP/changed-checkpoint.txt"
if run_verify "$TMP/changed-out.txt" "$TMP/mandate.txt" base "$TMP/changed-checkpoint.txt" >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted changed checkpoint bytes' >&2
  exit 1
fi
grep -q '^upstream-report-binds-exact-policy-checkpoint-manifest-and-root-key: FAIL$' "$TMP/changed-out.txt"
grep -q '^bounded-monitoring-journals-bind-exact-mandate-channels-and-checkpoint: FAIL$' "$TMP/changed-out.txt"

"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/mandate.txt" -out "$TMP/rogue-root-signature.bin" 2>/dev/null
if run_verify "$TMP/rogue-root-out.txt" "$TMP/mandate.txt" base "$TMP/recovered-checkpoint.txt" "$TMP/rogue-root-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted a rogue root mandate signature' >&2
  exit 1
fi
grep -q '^bounded-monitoring-mandate-replacement-root-signature-passes: FAIL$' "$TMP/rogue-root-out.txt"

write_journal_set "$TMP/mandate.txt" unsafe 2026-08-25T00:25:00Z YES
sign_set "$TMP/mandate.txt" unsafe
if run_verify "$TMP/unsafe-out.txt" "$TMP/mandate.txt" unsafe >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted a channel-signed launch claim' >&2
  exit 1
fi
grep -q '^mandate-and-journals-forbid-write-slot-wrapper-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

write_mandate "$TMP/rollback-mandate.txt" izzos-m7-distributor-operator-test-03 2
write_journal_set "$TMP/rollback-mandate.txt" rollback
sign_set "$TMP/rollback-mandate.txt" rollback
if run_verify "$TMP/rollback-out.txt" "$TMP/rollback-mandate.txt" rollback >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted a lower governance epoch' >&2
  exit 1
fi
grep -q '^all-recovery-epoch-and-sequence-bindings-match: FAIL$' "$TMP/rollback-out.txt"

cp "$TMP/mandate.txt" "$TMP/duplicate-field-mandate.txt"
printf 'minimum-observation-rounds: 4\n' >> "$TMP/duplicate-field-mandate.txt"
write_journal_set "$TMP/duplicate-field-mandate.txt" duplicate-field
sign_set "$TMP/duplicate-field-mandate.txt" duplicate-field
if run_verify "$TMP/duplicate-field-out.txt" "$TMP/duplicate-field-mandate.txt" duplicate-field >/dev/null 2>&1; then
  echo 'ERROR: bounded-monitoring gate accepted duplicate mandate fields' >&2
  exit 1
fi
grep -q '^bounded-monitoring-mandate-fields-are-present-once: FAIL$' "$TMP/duplicate-field-out.txt"
grep -q '^bounded-monitoring-mandate-is-canonical: FAIL$' "$TMP/duplicate-field-out.txt"

echo 'PASS: M7 recovered-checkpoint bounded-monitoring gate'
