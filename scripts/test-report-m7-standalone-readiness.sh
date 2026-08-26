#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDITOR="$ROOT/scripts/report-m7-standalone-readiness.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/evidence" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
root.mkdir(parents=True)

classifications = {
    "m7-layout-contract.txt": "M7_LAYOUT_REGION_CONTRACT_PASS",
    "m7-fd-capacity.txt": "M7_FD_CAPACITY_CONTRACT_PASS",
    "m7-selected-dtb.txt": "M7_EXACT_SELECTED_DTB_BOUND",
    "m7-gic-timer-dtb.txt": "M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED",
    "m7-aarch64-entry-contract.txt": "M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED",
    "m7-android-container-inputs.txt": "M7_ANDROID_CONTAINER_INPUTS_BOUND",
    "m7-linuxloader-placement-evidence.txt": "M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND",
    "m7-standalone-sec-entry-requirements.txt": "M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND",
    "m7-qualcomm-entry-observation.txt": "M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS",
    "m7-aarch64-extension-registers.txt": "M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS",
    "m7-aarch64-extension-bit-assessment.txt": "M7_AARCH64_EXTENSION_BIT_ASSESSMENT_PASS",
    "m7-aarch64-cross-core-registers.txt": "M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS",
    "m7-coherency-secondary-state.txt": "M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS",
    "m7-sm8475-coherency-provenance.txt": "M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS",
    "m7-secure-el3-handoff-state.txt": "M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS",
    "m7-pre-sec-smccc-route-authorization.txt": "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS",
    "m7-smccc-route-token-generation.txt": "M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS",
    "m7-smccc-capture-provisioning.txt": "M7_SMCCC_CAPTURE_PROVISIONING_PASS",
    "m7-smccc-capture-serialization.txt": "M7_SMCCC_CAPTURE_SERIALIZATION_PASS",
    "m7-smccc-el3-feature-availability.txt": "M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS",
}

def digest(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()

def write(name, lines=()):
    text = "\n".join([*lines, f"classification: {classifications[name]}"]) + "\n"
    (root / name).write_text(text, newline="\n")

for name in classifications:
    write(name)

write("m7-qualcomm-entry-observation.txt", [
    f"requirements-sha256: {digest('m7-standalone-sec-entry-requirements.txt')}",
])
write("m7-aarch64-extension-bit-assessment.txt", [
    f"extension-register-inventory-report-sha256: {digest('m7-aarch64-extension-registers.txt')}",
])
write("m7-aarch64-cross-core-registers.txt", [
    f"extension-register-inventory-report-sha256: {digest('m7-aarch64-extension-registers.txt')}",
    f"selected-dtb-binding-report-sha256: {digest('m7-selected-dtb.txt')}",
])
write("m7-coherency-secondary-state.txt", [
    f"cross-core-register-report-sha256: {digest('m7-aarch64-cross-core-registers.txt')}",
])
write("m7-sm8475-coherency-provenance.txt", [
    f"coherency-assertion-report-sha256: {digest('m7-coherency-secondary-state.txt')}",
])
write("m7-secure-el3-handoff-state.txt", [
    f"extension-register-inventory-sha256: {digest('m7-aarch64-extension-registers.txt')}",
    f"extension-bit-assessment-sha256: {digest('m7-aarch64-extension-bit-assessment.txt')}",
    f"gic-timer-report-sha256: {digest('m7-gic-timer-dtb.txt')}",
    f"coherency-provenance-report-sha256: {digest('m7-sm8475-coherency-provenance.txt')}",
])
write("m7-pre-sec-smccc-route-authorization.txt", [
    f"sec-requirements-sha256: {digest('m7-standalone-sec-entry-requirements.txt')}",
    f"qualcomm-entry-observation-sha256: {digest('m7-qualcomm-entry-observation.txt')}",
    "collector-invocation-authorization: EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY",
])
write("m7-smccc-route-token-generation.txt", [
    f"route-authorization-report-sha256: {digest('m7-pre-sec-smccc-route-authorization.txt')}",
])
write("m7-smccc-capture-provisioning.txt", [
    f"secure-el3-handoff-report-sha256: {digest('m7-secure-el3-handoff-state.txt')}",
    f"route-authorization-report-sha256: {digest('m7-pre-sec-smccc-route-authorization.txt')}",
    "current-dsc-inf-integration: FORBIDDEN_AND_ABSENT",
    "real-transport-selection: CALLER_SUPPLIED_NOT_GENERATED",
])
write("m7-smccc-capture-serialization.txt", [
    f"secure-el3-handoff-report-sha256: {digest('m7-secure-el3-handoff-state.txt')}",
    f"route-authorization-report-sha256: {digest('m7-pre-sec-smccc-route-authorization.txt')}",
    f"capture-provisioning-report-sha256: {digest('m7-smccc-capture-provisioning.txt')}",
])
write("m7-smccc-el3-feature-availability.txt", [
    f"secure-el3-handoff-report-sha256: {digest('m7-secure-el3-handoff-state.txt')}",
    f"route-authorization-report-sha256: {digest('m7-pre-sec-smccc-route-authorization.txt')}",
    f"capture-provisioning-report-sha256: {digest('m7-smccc-capture-provisioning.txt')}",
    "capture-route-binding: EXACT_SINGLE_USE_TOKEN_AND_CAPTURE_PROVISION_REPORT_MATCH",
    "capture-route-device-authorization: DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "independent-observation-authenticity: NOT_ESTABLISHED",
    "secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
])
PY

"$PYTHON" "$AUDITOR" "$TMP/evidence" "$TMP/readiness.txt" >/dev/null
grep -q '^required-report-count: 20$' "$TMP/readiness.txt"
grep -q '^smccc-gate-binds-capture-provision: PASS$' "$TMP/readiness.txt"
grep -q '^product-roadmap-milestone: M1_NON_DESTRUCTIVE_UEFI_DIAGNOSTIC_PAYLOAD$' "$TMP/readiness.txt"
grep -q '^internal-engineering-stage: M7_STANDALONE_LAYOUT_AND_ENTRY_EVIDENCE$' "$TMP/readiness.txt"
grep -q '^launch-authorization: NO$' "$TMP/readiness.txt"
grep -q '^classification: M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED$' "$TMP/readiness.txt"

cp -R "$TMP/evidence" "$TMP/missing"
rm "$TMP/missing/m7-smccc-capture-provisioning.txt"
if "$PYTHON" "$AUDITOR" "$TMP/missing" "$TMP/missing-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 readiness auditor accepted a missing required report" >&2
  exit 1
fi
grep -q '^capture-provision-report-present: FAIL$' "$TMP/missing-readiness.txt"
grep -q '^classification: M7_HOST_READINESS_INCOMPLETE$' "$TMP/missing-readiness.txt"

cp -R "$TMP/evidence" "$TMP/tampered"
printf X >> "$TMP/tampered/m7-secure-el3-handoff-state.txt"
if "$PYTHON" "$AUDITOR" "$TMP/tampered" "$TMP/tampered-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 readiness auditor accepted a changed upstream report" >&2
  exit 1
fi
grep -q '^capture-provision-binds-secure-handoff: FAIL$' "$TMP/tampered-readiness.txt"
grep -q '^smccc-gate-binds-secure-handoff: FAIL$' "$TMP/tampered-readiness.txt"

cp -R "$TMP/evidence" "$TMP/duplicate"
printf 'classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS\n' >> "$TMP/duplicate/m7-smccc-el3-feature-availability.txt"
if "$PYTHON" "$AUDITOR" "$TMP/duplicate" "$TMP/duplicate-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 readiness auditor accepted duplicate classification" >&2
  exit 1
fi
grep -q '^smccc-gate-classification-is-exact: FAIL$' "$TMP/duplicate-readiness.txt"

cp -R "$TMP/evidence" "$TMP/unsafe"
sed -i 's/dsc-fdf-promotion-authorization: NO/dsc-fdf-promotion-authorization: YES/' "$TMP/unsafe/m7-smccc-el3-feature-availability.txt"
if "$PYTHON" "$AUDITOR" "$TMP/unsafe" "$TMP/unsafe-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 readiness auditor accepted an unsupported promotion claim" >&2
  exit 1
fi
grep -q '^smccc-gate-dsc-fdf-promotion-authorization-is-safe: FAIL$' "$TMP/unsafe-readiness.txt"

echo "PASS: M7 standalone host-readiness audit"
