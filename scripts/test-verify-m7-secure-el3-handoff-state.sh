#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-secure-el3-handoff-state.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/inventory.txt" <<'EOF'
entry-current-el: EL2
feature-fp: PRESENT
feature-advanced-simd: PRESENT
feature-sve: PRESENT
feature-sme: ABSENT
feature-mte2-or-newer: PRESENT
feature-pointer-authentication: PRESENT
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS
EOF
INVENTORY_SHA="$(sha256sum "$TMP/inventory.txt" | awk '{print $1}')"

cat > "$TMP/assessment.txt" <<EOF
extension-register-inventory-report-sha256: $INVENTORY_SHA
secure-el3-control-state: NOT_OBSERVABLE_IN_THIS_INVENTORY
secure-el3-prerequisite-compliance: NOT_PROVEN
launch-authorization: NO
classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_DEFERRED_SECURE_EL3_EVIDENCE
EOF

cat > "$TMP/gic.txt" <<'EOF'
gic-compatible: arm,gic-v3
runtime-controller-ownership: NOT_YET_PROVEN
mmio-initialization-authorization: NO
launch-authorization: NO
classification: M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED
EOF

cat > "$TMP/provenance.txt" <<'EOF'
secondary-cpu-enable-interface: PSCI_VIA_SMC
coherency-mechanism-implementation: NOT_PUBLICLY_PROVEN
coherency-register-authorization: NO
launch-authorization: NO
classification: M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS
EOF

ASSESSMENT_SHA="$(sha256sum "$TMP/assessment.txt" | awk '{print $1}')"
GIC_SHA="$(sha256sum "$TMP/gic.txt" | awk '{print $1}')"
PROVENANCE_SHA="$(sha256sum "$TMP/provenance.txt" | awk '{print $1}')"

cat > "$TMP/raw.txt" <<EOF
secure-el3-state-schema: IZZOS_M7_SECURE_EL3_HANDOFF_STATE_V1
extension-register-inventory-sha256: $INVENTORY_SHA
extension-bit-assessment-sha256: $ASSESSMENT_SHA
gic-timer-report-sha256: $GIC_SHA
coherency-provenance-report-sha256: $PROVENANCE_SHA
capture-source: EXISTING_PLATFORM_FIRMWARE_EL3_HANDOFF_RECORD
capture-execution-level: EL3
capture-method: FIRMWARE_GENERATED_READ_ONLY_REGISTER_RECORD
nonsecure-el2-direct-read-claim: NONE
entry-target: NONSECURE_AARCH64_EL2
evidence-kind: SELF_REPORTED_SECURE_EL3_HANDOFF_ASSERTION
scr-el3: 0x4030501
cptr-el3: 0x100
icc-sre-el3: 0x9
icc-ctlr-el3: 0x40
zcr-el3: 0xF
smcr-el3: NOT_IMPLEMENTED
cross-cpu-scr-fiq-consistency: ASSERTED
cross-cpu-icc-ctlr-pmhe-consistency: ASSERTED
cross-cpu-zcr-len-consistency: ASSERTED
cross-cpu-smcr-len-consistency: NOT_REQUIRED_FEATURE_ABSENT
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
secure-monitor-modification-action: NONE
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local raw="$1" out="$2" inventory="${3:-$TMP/inventory.txt}"
  "$PYTHON" "$VERIFY" "$inventory" "$TMP/assessment.txt" "$TMP/gic.txt" "$TMP/provenance.txt" "$raw" "$out"
}

run_verify "$TMP/raw.txt" "$TMP/pass.txt" >/dev/null
grep -q '^raw-binds-exact-inventory: PASS$' "$TMP/pass.txt"
grep -q '^scr-hce-allows-el2-hvc: PASS$' "$TMP/pass.txt"
grep -q '^scr-rw-selects-aarch64: PASS$' "$TMP/pass.txt"
grep -q '^icc-sre-el3-enables-system-register-interface: PASS$' "$TMP/pass.txt"
grep -q '^el3-pointer-authentication-access-enabled: PASS$' "$TMP/pass.txt"
grep -q '^el3-mte-access-enabled: PASS$' "$TMP/pass.txt"
grep -q '^el3-sve-access-enabled: PASS$' "$TMP/pass.txt"
grep -q '^secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS$' "$TMP/pass.txt"

cp "$TMP/inventory.txt" "$TMP/tampered-inventory.txt"
printf X >> "$TMP/tampered-inventory.txt"
if run_verify "$TMP/raw.txt" "$TMP/tampered-inventory-out.txt" "$TMP/tampered-inventory.txt" >/dev/null 2>&1; then
  echo "ERROR: Secure EL3 verifier accepted a tampered inventory" >&2
  exit 1
fi
grep -q '^raw-binds-exact-inventory: FAIL$' "$TMP/tampered-inventory-out.txt"

assert_blocked() {
  local name="$1" expression="$2" check="$3"
  sed "$expression" "$TMP/raw.txt" > "$TMP/$name.txt"
  if run_verify "$TMP/$name.txt" "$TMP/$name-out.txt" >/dev/null 2>&1; then
    echo "ERROR: Secure EL3 verifier accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$TMP/$name-out.txt"
  grep -q '^classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_BLOCKED$' "$TMP/$name-out.txt"
}

assert_blocked el2-direct-read \
  's/nonsecure-el2-direct-read-claim: NONE/nonsecure-el2-direct-read-claim: SCR_EL3/' \
  raw-nonsecure-el2-direct-read-claim-is-exact
assert_blocked wrong-capture-el \
  's/capture-execution-level: EL3/capture-execution-level: EL2/' \
  raw-capture-execution-level-is-exact
assert_blocked hvc-disabled \
  's/scr-el3: 0x4030501/scr-el3: 0x4030401/' \
  scr-hce-allows-el2-hvc
assert_blocked aarch32-lower-el \
  's/scr-el3: 0x4030501/scr-el3: 0x4030101/' \
  scr-rw-selects-aarch64
assert_blocked pauth-trapped \
  's/scr-el3: 0x4030501/scr-el3: 0x4000501/' \
  el3-pointer-authentication-access-enabled
assert_blocked mte-trapped \
  's/scr-el3: 0x4030501/scr-el3: 0x0030501/' \
  el3-mte-access-enabled
assert_blocked sve-trapped \
  's/cptr-el3: 0x100/cptr-el3: 0x0/' \
  el3-sve-access-enabled
assert_blocked gic-sre-disabled \
  's/icc-sre-el3: 0x9/icc-sre-el3: 0x0/' \
  icc-sre-el3-enables-system-register-interface
assert_blocked inconsistent-zcr \
  's/cross-cpu-zcr-len-consistency: ASSERTED/cross-cpu-zcr-len-consistency: UNKNOWN/' \
  el3-sve-vector-length-cross-cpu-consistent
assert_blocked relaxed-launch \
  's/launch-authorization: NO/launch-authorization: YES/' \
  raw-launch-authorization-is-exact

echo "PASS: M7 Secure EL3 handoff-state assertion schema gate"
