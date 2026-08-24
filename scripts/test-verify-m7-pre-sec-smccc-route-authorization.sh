#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-pre-sec-smccc-route-authorization.py"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

HEADER_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.h" | awk '{print $1}')"
SOURCE_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.c" | awk '{print $1}')"
TRANSPORT_SHA="$(sha256sum "$LIB/M7SmcccCallAArch64.S" | awk '{print $1}')"
EMITTER_HEADER_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.h" | awk '{print $1}')"
EMITTER_SOURCE_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.c" | awk '{print $1}')"

cat > "$TMP/requirements.txt" <<'EOF'
exact-device-build: CPH2413_15.0.0.1901(EX01)
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
launch-authorization: NO
classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND
EOF
REQUIREMENTS_SHA="$(sha256sum "$TMP/requirements.txt" | awk '{print $1}')"

cat > "$TMP/observation.txt" <<EOF
requirements-sha256: $REQUIREMENTS_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
entry-current-el: EL2
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
launch-authorization: NO
classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS
EOF
OBSERVATION_SHA="$(sha256sum "$TMP/observation.txt" | awk '{print $1}')"

cat > "$TMP/recovery.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / CPH2413 / OP5552L1
OxygenOS build: CPH2413_15.0.0.1901(EX01)
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: exact-reviewed-temporary-pre-sec-route
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: docs/recovery/CPH2413-authorized-service.md
EOF
RECOVERY_SHA="$(sha256sum "$TMP/recovery.txt" | awk '{print $1}')"

cat > "$TMP/route.txt" <<EOF
route-authorization-schema: IZZOS_M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_V1
sec-requirements-sha256: $REQUIREMENTS_SHA
qualcomm-entry-observation-sha256: $OBSERVATION_SHA
recovery-evidence-sha256: $RECOVERY_SHA
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
device-model: CPH2413
vendor-device: OP5552L1
platform: SM8475
route-kind: TEMPORARY_NON_PERSISTENT_PRE_SEC_INSTRUMENTED_PATH
route-candidate: exact-reviewed-temporary-pre-sec-route
route-validation-authority: PROJECT_OWNER_REVIEWED_BOUND_EVIDENCE
route-validation-result: EXACT_ROUTE_VALIDATED
entry-observation-authentication: INDEPENDENTLY_REVIEWED_EXACT_CAPTURE
execution-phase: PRE_SEC
caller-security-state: NONSECURE
caller-exception-level: EL2
capture-cpu: PRIMARY
collector-invocation-count: 1
smccc-call-limit: 5
smccc-service-owner: ARM_ARCHITECTURE_SERVICE_OEN_0
allowed-smccc-functions: SMCCC_VERSION,SMCCC_ARCH_FEATURES,SMCCC_ARCH_FEATURE_AVAILABILITY
output-buffer-address: 0x90000000
output-buffer-capacity: 0x1000
output-buffer-alignment: 0x1000
output-buffer-security-state: NONSECURE
output-buffer-reservation: EXACT_NONSECURE_SCRATCH_PROVEN
output-buffer-lifetime: PRE_SEC_CAPTURE_ONLY
transcript-output-policy: EMIT_V1_THEN_HOST_SERIALIZE_BOUND_CAPTURE
transcript-serialization-required: YES
vendor-or-sip-smc-action: NONE
direct-el3-register-read-action: NONE
secure-monitor-modification-action: NONE
mmio-action: NONE
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
flash-erase-format-action: NONE
recovery-route-requirement: VERIFIED_HARD_RECOVERY
collector-invocation-authorization: EXACTLY_ONCE
payload-launch-authorization: NO
EOF

run_verify() {
  local out="$1" requirements="${2:-$TMP/requirements.txt}" observation="${3:-$TMP/observation.txt}" recovery="${4:-$TMP/recovery.txt}" route="${5:-$TMP/route.txt}"
  "$PYTHON" "$VERIFY" "$requirements" "$observation" "$recovery" "$route" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^entry-observation-is-nonsecure-el2: PASS$' "$TMP/pass.txt"
grep -q '^recovery-hard-path-is-verified: PASS$' "$TMP/pass.txt"
grep -q '^collector-invocation-is-exactly-once: PASS$' "$TMP/pass.txt"
grep -q '^output-buffer-alignment-is-safe: PASS$' "$TMP/pass.txt"
grep -q '^route-forbids-vendor-or-sip-smc: PASS$' "$TMP/pass.txt"
grep -q '^collector-invocation-authorization: EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY$' "$TMP/pass.txt"
grep -q '^payload-launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS$' "$TMP/pass.txt"

run_verify "$TMP/pass-2.txt" >/dev/null
cmp "$TMP/pass.txt" "$TMP/pass-2.txt"

assert_route_blocked() {
  local name="$1" expression="$2" check="$3"
  sed "$expression" "$TMP/route.txt" > "$TMP/$name-route.txt"
  if run_verify "$TMP/$name-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/recovery.txt" "$TMP/$name-route.txt" >/dev/null 2>&1; then
    echo "ERROR: M7 pre-SEC route verifier accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$TMP/$name-out.txt"
  grep -q '^collector-invocation-authorization: NO$' "$TMP/$name-out.txt"
  grep -q '^classification: M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_BLOCKED$' "$TMP/$name-out.txt"
}

assert_route_blocked wrong-component-hash \
  "s/collector-transport-sha256: $TRANSPORT_SHA/collector-transport-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  route-collector-transport-sha256-matches
assert_route_blocked el1-caller \
  's/caller-exception-level: EL2/caller-exception-level: EL1/' \
  route-executes-at-pre-sec-nonsecure-el2
assert_route_blocked repeated-invocation \
  's/collector-invocation-count: 1/collector-invocation-count: 2/' \
  collector-invocation-is-exactly-once
assert_route_blocked excess-calls \
  's/smccc-call-limit: 5/smccc-call-limit: 6/' \
  smccc-call-limit-is-five
assert_route_blocked misaligned-buffer \
  's/output-buffer-address: 0x90000000/output-buffer-address: 0x90000001/' \
  output-buffer-alignment-is-safe
assert_route_blocked undersized-buffer \
  's/output-buffer-capacity: 0x1000/output-buffer-capacity: 0x800/' \
  output-buffer-capacity-is-bounded
assert_route_blocked vendor-smc \
  's/vendor-or-sip-smc-action: NONE/vendor-or-sip-smc-action: PERFORMED/' \
  route-forbids-vendor-or-sip-smc
assert_route_blocked persistent-write \
  's/persistent-writes: NONE/persistent-writes: REQUIRED/' \
  route-forbids-device-and-persistent-writes
assert_route_blocked payload-launch \
  's/payload-launch-authorization: NO/payload-launch-authorization: YES/' \
  route-denies-payload-launch
assert_route_blocked unreviewed-authority \
  's/route-validation-authority: PROJECT_OWNER_REVIEWED_BOUND_EVIDENCE/route-validation-authority: UNVALIDATED/' \
  route-review-authority-is-explicit

cp "$TMP/route.txt" "$TMP/duplicate-route.txt"
printf 'payload-launch-authorization: NO\n' >> "$TMP/duplicate-route.txt"
if run_verify "$TMP/duplicate-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/recovery.txt" "$TMP/duplicate-route.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 pre-SEC route verifier accepted a duplicate field" >&2
  exit 1
fi
grep -q '^route-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"

cp "$TMP/requirements.txt" "$TMP/tampered-requirements.txt"
printf X >> "$TMP/tampered-requirements.txt"
if run_verify "$TMP/tampered-requirements-out.txt" "$TMP/tampered-requirements.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 pre-SEC route verifier accepted tampered SEC requirements" >&2
  exit 1
fi
grep -q '^route-binds-exact-sec-requirements: FAIL$' "$TMP/tampered-requirements-out.txt"

sed 's/entry-current-el: EL2/entry-current-el: EL1/' "$TMP/observation.txt" > "$TMP/el1-observation.txt"
if run_verify "$TMP/el1-observation-out.txt" "$TMP/requirements.txt" "$TMP/el1-observation.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 pre-SEC route verifier accepted an EL1 entry observation" >&2
  exit 1
fi
grep -q '^entry-observation-is-nonsecure-el2: FAIL$' "$TMP/el1-observation-out.txt"

sed 's/AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED/ASSISTED_HARD_RECOVERY_DOCUMENTED/' "$TMP/recovery.txt" > "$TMP/assisted-recovery.txt"
if run_verify "$TMP/assisted-recovery-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/assisted-recovery.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 pre-SEC route verifier accepted assisted-only recovery" >&2
  exit 1
fi
grep -q '^recovery-hard-path-is-verified: FAIL$' "$TMP/assisted-recovery-out.txt"

echo "PASS: M7 exact pre-SEC SMCCC collector route authorization gate"
