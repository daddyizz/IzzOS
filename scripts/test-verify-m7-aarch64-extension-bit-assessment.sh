#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-aarch64-extension-bit-assessment.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

write_inventory() {
  local path="$1" current_el="$2" hcr="$3" cptr="$4" cnthctl="$5" icc_sre="$6"
  cat > "$path" <<EOF
entry-current-el: $current_el
hcr-el2: $hcr
cptr-el2: $cptr
cnthctl-el2: $cnthctl
icc-sre-el2: $icc_sre
entry-cntfrq-el0: 0x124F800
entry-cntvoff-el2: 0x0
zcr-el2: 0xF
smcr-el2: NOT_IMPLEMENTED
feature-aarch64-el2: PRESENT
feature-fp: PRESENT
feature-advanced-simd: PRESENT
feature-sve: PRESENT
feature-sme: ABSENT
feature-mte2-or-newer: PRESENT
feature-pointer-authentication: PRESENT
register-values-policy: RAW_INVENTORY_NOT_NORMALIZATION_AUTHORIZATION
extension-specific-bit-compliance: NOT_YET_PROVEN
cross-core-register-consistency: NOT_YET_PROVEN
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
sec-wrapper-implementation-authorization: NO
dsc-fdf-promotion-authorization: NO
mmio-initialization-authorization: NO
fastboot-boot-authorization: NO
launch-authorization: NO
classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS
EOF
}

run_verify() {
  local input="$1" output="$2"
  "$PYTHON" "$VERIFY" "$input" "$output"
}

write_inventory "$TMP/el1.txt" EL1 0x100030080000000 0x30000 0x1 0x9
run_verify "$TMP/el1.txt" "$TMP/el1-out.txt" >/dev/null
grep -q '^el1-aarch64-hcr-rw: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-physical-counter-access: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-gicv3-system-register-interface: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-fp-simd-trap-disabled: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-sve-traps-disabled: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-pointer-authentication-enabled: PASS$' "$TMP/el1-out.txt"
grep -q '^el1-mte-access-enabled: PASS$' "$TMP/el1-out.txt"
grep -q '^cross-core-zcr-smcr-consistency: NOT_PROVEN$' "$TMP/el1-out.txt"
grep -q '^architected-counter-frequency-is-programmed: PASS$' "$TMP/el1-out.txt"
grep -q '^primary-cpu-virtual-counter-offset-is-visible: PASS$' "$TMP/el1-out.txt"
grep -q '^secure-el3-prerequisite-compliance: NOT_PROVEN$' "$TMP/el1-out.txt"
grep -q '^cross-core-cntvoff-consistency: NOT_PROVEN$' "$TMP/el1-out.txt"
grep -q '^conditional-bit-compliance: EL1_ASSESSED_EL2_CONTROL_BITS_PASS$' "$TMP/el1-out.txt"
grep -q '^sec-wrapper-implementation-authorization: NO$' "$TMP/el1-out.txt"
grep -q '^launch-authorization: NO$' "$TMP/el1-out.txt"
grep -q '^classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_PASS$' "$TMP/el1-out.txt"

write_inventory "$TMP/bad-hcr.txt" EL1 0x80000000 0x30000 0x1 0x9
if run_verify "$TMP/bad-hcr.txt" "$TMP/bad-hcr-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted disabled pointer authentication/MTE" >&2
  exit 1
fi
grep -q '^el1-pointer-authentication-enabled: FAIL$' "$TMP/bad-hcr-out.txt"
grep -q '^el1-mte-access-enabled: FAIL$' "$TMP/bad-hcr-out.txt"
grep -q '^classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_BLOCKED$' "$TMP/bad-hcr-out.txt"

write_inventory "$TMP/bad-cptr.txt" EL1 0x100030080000000 0x0 0x1 0x9
if run_verify "$TMP/bad-cptr.txt" "$TMP/bad-cptr-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted an invalid SVE ZEN state" >&2
  exit 1
fi
grep -q '^el1-sve-traps-disabled: FAIL$' "$TMP/bad-cptr-out.txt"

write_inventory "$TMP/bad-timer.txt" EL1 0x100030080000000 0x30000 0x0 0x9
if run_verify "$TMP/bad-timer.txt" "$TMP/bad-timer-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted disabled EL1 physical-counter access" >&2
  exit 1
fi
grep -q '^el1-physical-counter-access: FAIL$' "$TMP/bad-timer-out.txt"

write_inventory "$TMP/bad-gic.txt" EL1 0x100030080000000 0x30000 0x1 0x1
if run_verify "$TMP/bad-gic.txt" "$TMP/bad-gic-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted a disabled GICv3 Enable bit" >&2
  exit 1
fi
grep -q '^el1-gicv3-system-register-interface: FAIL$' "$TMP/bad-gic-out.txt"

write_inventory "$TMP/el2.txt" EL2 0x80000000 0x0 0x3 0x9
run_verify "$TMP/el2.txt" "$TMP/el2-out.txt" >/dev/null
grep -q '^el1-aarch64-hcr-rw: NOT_APPLICABLE_AT_EL2_ENTRY$' "$TMP/el2-out.txt"
grep -q '^secure-el3-control-state: NOT_OBSERVABLE_IN_THIS_INVENTORY$' "$TMP/el2-out.txt"
grep -q '^conditional-bit-compliance: DEFERRED_SECURE_EL3_EVIDENCE_REQUIRED$' "$TMP/el2-out.txt"
grep -q '^classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_DEFERRED_SECURE_EL3_EVIDENCE$' "$TMP/el2-out.txt"
grep -q '^launch-authorization: NO$' "$TMP/el2-out.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/el1.txt" > "$TMP/relaxed-denial.txt"
if run_verify "$TMP/relaxed-denial.txt" "$TMP/relaxed-denial-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted a relaxed launch denial" >&2
  exit 1
fi
grep -q '^inventory-denies-launch: FAIL$' "$TMP/relaxed-denial-out.txt"

sed '/^feature-mte2-or-newer:/d' "$TMP/el1.txt" > "$TMP/missing-feature.txt"
if run_verify "$TMP/missing-feature.txt" "$TMP/missing-feature-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted an implicit feature-absence label" >&2
  exit 1
fi
grep -q '^feature-presence-labels-are-explicit: FAIL$' "$TMP/missing-feature-out.txt"

sed 's/feature-sme: ABSENT/feature-sme: PRESENT/; s/smcr-el2: NOT_IMPLEMENTED/smcr-el2: 0x0/' "$TMP/el1.txt" > "$TMP/sme-incomplete.txt"
if run_verify "$TMP/sme-incomplete.txt" "$TMP/sme-incomplete-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 extension-bit assessor accepted SME without its additional mandatory controls" >&2
  exit 1
fi
grep -q '^el1-sme-additional-controls-covered: FAIL$' "$TMP/sme-incomplete-out.txt"

echo "PASS: M7 AArch64 extension control-bit assessment"
