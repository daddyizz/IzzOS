#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-aarch64-extension-register-inventory.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/baseline.txt" <<'EOF'
entry-current-el: EL2
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
entry-cntfrq-el0: 0x124F800
entry-cntvoff-el2: 0x0
classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS
EOF
BASELINE_SHA="$(sha256sum "$TMP/baseline.txt" | awk '{print $1}')"

cat > "$TMP/inventory.txt" <<EOF
extension-register-schema: IZZOS_M7_AARCH64_EXTENSION_REGISTERS_V1
capture-source: SAME_PRE_SEC_INSTRUMENTED_SNAPSHOT
capture-cpu: PRIMARY
baseline-observation-sha256: $BASELINE_SHA
entry-current-el: EL2
midr-el1: 0x410FD4B0
mpidr-el1: 0x80000000
id-aa64pfr0-el1: 0x0000000100001111
id-aa64pfr1-el1: 0x0000000000000000
id-aa64isar0-el1: 0x1021111110212120
id-aa64isar1-el1: 0x0000000000000000
id-aa64mmfr0-el1: 0x0000000011221122
id-aa64mmfr1-el1: 0x0000000011212122
id-aa64dfr0-el1: 0x0000000010305106
hcr-el2: 0x80000000
cptr-el2: 0x0
cnthctl-el2: 0x3
mdcr-el2: 0x0
icc-sre-el2: 0x9
zcr-el2: 0xF
smcr-el2: NOT_IMPLEMENTED
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local out="$1" baseline="${2:-$TMP/baseline.txt}" inventory="${3:-$TMP/inventory.txt}"
  "$PYTHON" "$VERIFY" "$baseline" "$inventory" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^all-required-primary-cpu-id-registers-are-present: PASS$' "$TMP/pass.txt"
grep -q '^el2-control-register-visibility-is-explicit: PASS$' "$TMP/pass.txt"
grep -q '^baseline-counter-frequency-is-valid: PASS$' "$TMP/pass.txt"
grep -q '^baseline-virtual-counter-offset-is-zero: PASS$' "$TMP/pass.txt"
grep -q '^entry-cntfrq-el0: 0x124F800$' "$TMP/pass.txt"
grep -q '^entry-cntvoff-el2: 0x0$' "$TMP/pass.txt"
grep -q '^feature-sve: PRESENT$' "$TMP/pass.txt"
grep -q '^feature-sme: ABSENT$' "$TMP/pass.txt"
grep -q '^feature-fp: PRESENT$' "$TMP/pass.txt"
grep -q '^feature-advanced-simd: PRESENT$' "$TMP/pass.txt"
grep -q '^extension-specific-bit-compliance: NOT_YET_PROVEN$' "$TMP/pass.txt"
grep -q '^sec-wrapper-implementation-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS$' "$TMP/pass.txt"

cp "$TMP/baseline.txt" "$TMP/tampered-baseline.txt"
printf X >> "$TMP/tampered-baseline.txt"
if run_verify "$TMP/tampered-baseline-out.txt" "$TMP/tampered-baseline.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension verifier accepted a tampered baseline report" >&2
  exit 1
fi
grep -q '^inventory-binds-exact-baseline-report: FAIL$' "$TMP/tampered-baseline-out.txt"

sed 's/entry-current-el: EL2/entry-current-el: EL1/' "$TMP/inventory.txt" > "$TMP/wrong-el.txt"
if run_verify "$TMP/wrong-el-out.txt" "$TMP/baseline.txt" "$TMP/wrong-el.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension verifier accepted an EL mismatch" >&2
  exit 1
fi
grep -q '^inventory-currentel-matches-baseline: FAIL$' "$TMP/wrong-el-out.txt"

sed '/^hcr-el2:/d' "$TMP/inventory.txt" > "$TMP/missing-hcr.txt"
if run_verify "$TMP/missing-hcr-out.txt" "$TMP/baseline.txt" "$TMP/missing-hcr.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension verifier accepted a missing EL2 control register" >&2
  exit 1
fi
grep -q '^el2-control-register-visibility-is-explicit: FAIL$' "$TMP/missing-hcr-out.txt"

sed 's/zcr-el2: 0xF/zcr-el2: NOT_IMPLEMENTED/' "$TMP/inventory.txt" > "$TMP/missing-sve-control.txt"
if run_verify "$TMP/missing-sve-control-out.txt" "$TMP/baseline.txt" "$TMP/missing-sve-control.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension verifier accepted missing SVE control state" >&2
  exit 1
fi
grep -q '^sve-control-register-visibility-is-explicit: FAIL$' "$TMP/missing-sve-control-out.txt"
grep -q '^classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_BLOCKED$' "$TMP/missing-sve-control-out.txt"

echo "PASS: M7 AArch64 extension-register inventory schema gate"
