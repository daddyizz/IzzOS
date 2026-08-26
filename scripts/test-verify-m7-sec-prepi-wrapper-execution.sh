#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-sec-prepi-wrapper-execution.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/requirements.txt" <<'EOF'
exact-device-build: CPH2413_15.0.0.1901(EX01)
required-wrapper-currentel-capture: YES
required-wrapper-sctlr-state-capture: YES
required-wrapper-daif-state-capture: YES
required-wrapper-timer-state-capture: YES
required-wrapper-dtb-register-preservation: YES
required-wrapper-stack-and-temporary-ram-bootstrap: YES
required-wrapper-image-coherency-normalization: YES
dsc-fdf-promotion-authorization: NO
launch-authorization: NO
classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND
EOF
REQ_SHA="$(sha256sum "$TMP/requirements.txt" | awk '{print $1}')"

cat > "$TMP/observation.txt" <<EOF
requirements-sha256: $REQ_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
entry-current-el: EL2
entry-x0: 0x80100000
entry-daif: 0x3C0
entry-sctlr: 0x1004
entry-cntfrq-el0: 0x124F800
entry-cntvoff-el2: 0x0
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS
EOF
OBS_SHA="$(sha256sum "$TMP/observation.txt" | awk '{print $1}')"

cat > "$TMP/device-promotion.txt" <<'EOF'
independent-observation-authenticity: HASH_BOUND_NOT_CRYPTOGRAPHICALLY_ATTESTED
sec-prepi-wrapper-execution: NOT_PROVEN
dsc-fdf-promotion-authorization: NO
android-container-construction-authorization: NO
launch-authorization: NO
classification: M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED
EOF
DEVICE_SHA="$(sha256sum "$TMP/device-promotion.txt" | awk '{print $1}')"

printf 'synthetic non-integrated wrapper artifact\n' > "$TMP/wrapper.bin"
WRAPPER_SHA="$(sha256sum "$TMP/wrapper.bin" | awk '{print $1}')"

cat > "$TMP/assertion.txt" <<EOF
wrapper-execution-schema: IZZOS_M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_V1
execution-source: PRE_SEC_WRAPPER_SELF_REPORTED_ASSERTION
execution-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
execution-route-authorization: NOT_INCLUDED
sec-requirements-sha256: $REQ_SHA
qualcomm-entry-observation-sha256: $OBS_SHA
device-promotion-readiness-sha256: $DEVICE_SHA
wrapper-artifact-sha256: $WRAPPER_SHA
wrapper-artifact-kind: NON_INTEGRATED_TEST_ARTIFACT
exact-device-build: CPH2413_15.0.0.1901(EX01)
capture-cpu: PRIMARY
entry-security-state: NON_SECURE
entry-current-el: EL2
before-x0: 0x80100000
before-x1: 0x0
before-x2: 0x0
before-x3: 0x0
after-x0: 0x80100000
after-x1: 0x0
after-x2: 0x0
after-x3: 0x0
before-daif: 0x3C0
after-daif: 0x3C0
before-sctlr: 0x1004
after-sctlr: 0x1004
before-cntfrq-el0: 0x124F800
after-cntfrq-el0: 0x124F800
before-cntvoff-el2: 0x0
after-cntvoff-el2: 0x0
stack-base: 0x90018000
stack-size: 0x8000
temporary-ram-base: 0x90000000
temporary-ram-size: 0x200000
prepi-entry-address: 0xA0010000
final-runtime-destination: 0xA0000000
final-runtime-destination-validation: STRUCTURAL_ONLY_MEMORY_MAP_OWNERSHIP_NOT_INCLUDED
fd-entry-form: FV_PATCHED_TO_SEC_OR_PREPI_ENTRYPOINT
image-coherency-normalization: CLEAN_TO_POC_AND_NO_STALE_ICACHE_ENTRIES
control-transfer-count: 1
prepi-returned: NO
exception-observed: NONE
mmio-action: NONE
smc-action: NONE
secure-monitor-modification-action: NONE
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
flash-erase-format-action: NONE
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
launch-authorization: NO
EOF

run_verify() {
  local out="$1" requirements="${2:-$TMP/requirements.txt}" observation="${3:-$TMP/observation.txt}" device="${4:-$TMP/device-promotion.txt}" wrapper="${5:-$TMP/wrapper.bin}" assertion="${6:-$TMP/assertion.txt}"
  "$PYTHON" "$VERIFY" "$requirements" "$observation" "$device" "$wrapper" "$assertion" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^assertion-binds-exact-wrapper-artifact: PASS$' "$TMP/pass.txt"
grep -q '^dtb-register-is-preserved: PASS$' "$TMP/pass.txt"
grep -q '^stack-is-contained-in-temporary-ram: PASS$' "$TMP/pass.txt"
grep -q '^execution-route-authorization: NOT_INCLUDED$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED$' "$TMP/pass.txt"

cp "$TMP/requirements.txt" "$TMP/tampered-requirements.txt"
printf X >> "$TMP/tampered-requirements.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/tampered-requirements.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted changed requirements bytes" >&2
  exit 1
fi
grep -q '^assertion-binds-exact-requirements: FAIL$' "$TMP/tampered-out.txt"

cp "$TMP/wrapper.bin" "$TMP/tampered-wrapper.bin"
printf X >> "$TMP/tampered-wrapper.bin"
if run_verify "$TMP/tampered-wrapper-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/tampered-wrapper.bin" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted changed artifact bytes" >&2
  exit 1
fi
grep -q '^assertion-binds-exact-wrapper-artifact: FAIL$' "$TMP/tampered-wrapper-out.txt"

cp "$TMP/assertion.txt" "$TMP/duplicate.txt"
printf 'execution-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED\n' >> "$TMP/duplicate.txt"
if run_verify "$TMP/duplicate-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/wrapper.bin" "$TMP/duplicate.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted a duplicate field" >&2
  exit 1
fi
grep -q '^assertion-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"

sed 's/after-x0: 0x80100000/after-x0: 0x80200000/' "$TMP/assertion.txt" > "$TMP/wrong-dtb.txt"
if run_verify "$TMP/wrong-dtb-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/wrapper.bin" "$TMP/wrong-dtb.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted a changed DTB register" >&2
  exit 1
fi
grep -q '^dtb-register-is-preserved: FAIL$' "$TMP/wrong-dtb-out.txt"

sed 's/after-sctlr: 0x1004/after-sctlr: 0x1005/' "$TMP/assertion.txt" > "$TMP/mmu-on.txt"
if run_verify "$TMP/mmu-on-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/wrapper.bin" "$TMP/mmu-on.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted an enabled MMU" >&2
  exit 1
fi
grep -q '^mmu-remains-off: FAIL$' "$TMP/mmu-on-out.txt"

sed 's/stack-base: 0x90018000/stack-base: 0x91000000/' "$TMP/assertion.txt" > "$TMP/stack-outside.txt"
if run_verify "$TMP/stack-outside-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/wrapper.bin" "$TMP/stack-outside.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted a stack outside temporary RAM" >&2
  exit 1
fi
grep -q '^stack-is-contained-in-temporary-ram: FAIL$' "$TMP/stack-outside-out.txt"

sed 's/mmio-action: NONE/mmio-action: WRITE/' "$TMP/assertion.txt" > "$TMP/unsafe-mmio.txt"
if run_verify "$TMP/unsafe-mmio-out.txt" "$TMP/requirements.txt" "$TMP/observation.txt" "$TMP/device-promotion.txt" "$TMP/wrapper.bin" "$TMP/unsafe-mmio.txt" >/dev/null 2>&1; then
  echo "ERROR: wrapper assertion gate accepted an MMIO action" >&2
  exit 1
fi
grep -q '^assertion-forbids-mmio-smc-and-monitor-changes: FAIL$' "$TMP/unsafe-mmio-out.txt"
grep -q '^classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_BLOCKED$' "$TMP/unsafe-mmio-out.txt"

echo "PASS: M7 SEC/PrePi wrapper execution assertion schema gate"
