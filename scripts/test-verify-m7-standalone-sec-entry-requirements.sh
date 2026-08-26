#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-standalone-sec-entry-requirements.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BOOT_SHA="$(printf 'boot-m7-sec' | sha256sum | awk '{print $1}')"
DTB_SHA="$(printf 'dtb-m7-sec' | sha256sum | awk '{print $1}')"
LOADER_SHA="$(printf 'linuxloader-m7-sec' | sha256sum | awk '{print $1}')"

cat > "$TMP/entry.txt" <<EOF
actual-boot-sha256: $BOOT_SHA
stock-dtb-load-address: 0x80100000
source-linux-entry-register-contract: x0=DTB_PHYSICAL_ADDRESS,x1=0,x2=0,x3=0
source-linux-entry-security-contract: NON_SECURE
source-linux-entry-el-contract: EL2_RECOMMENDED_OR_EL1
source-linux-entry-interrupt-contract: PSTATE_DAIF_ALL_MASKED
source-linux-entry-mmu-contract: OFF
source-linux-entry-timer-contract: CNTFRQ_AND_CNTVOFF_PREINITIALIZED
observed-qualcomm-entry-el: NOT_CAPTURED
observed-qualcomm-system-register-state: NOT_CAPTURED
standalone-sec-entry-equivalence: NOT_PROVEN
launch-authorization: NO
classification: M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED
EOF

cat > "$TMP/placement.txt" <<EOF
exact-device-build: CPH2413_15.0.0.1901(EX01)
boot-sha256: $BOOT_SHA
linuxloader-sha256: $LOADER_SHA
final-physical-destination: NOT_RUNTIME_OBSERVED
fd-kernel-substitution-equivalence: NOT_PROVEN
standalone-sec-entry-equivalence: NOT_PROVEN
launch-authorization: NO
classification: M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND
EOF

cat > "$TMP/selected.txt" <<EOF
selected-dtb-sha256: $DTB_SHA
launch-authorization: NO
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF

cat > "$TMP/gic.txt" <<EOF
bound-selected-dtb-sha256: $DTB_SHA
actual-selected-dtb-sha256: $DTB_SHA
exception-level-contract: NOT_YET_PROVEN
runtime-controller-ownership: NOT_YET_PROVEN
launch-authorization: NO
classification: M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED
EOF

run_verify() {
  local out="$1" entry="${2:-$TMP/entry.txt}" placement="${3:-$TMP/placement.txt}" selected="${4:-$TMP/selected.txt}" gic="${5:-$TMP/gic.txt}"
  "$PYTHON" "$VERIFY" "$entry" "$placement" "$selected" "$gic" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^entry-and-placement-boot-hashes-match: PASS$' "$TMP/pass.txt"
grep -q '^selected-and-gic-bound-dtb-hashes-match: PASS$' "$TMP/pass.txt"
grep -q "^linuxloader-sha256: $LOADER_SHA$" "$TMP/pass.txt"
grep -q '^stock-dtb-load-address: 0x80100000$' "$TMP/pass.txt"
grep -q '^source-linux-instruction-cache-contract: MAY_BE_ON_OR_OFF_NO_STALE_IMAGE_ENTRIES$' "$TMP/pass.txt"
grep -q '^edk2-entry-wrapper-required: YES$' "$TMP/pass.txt"
grep -q '^direct-fd-as-linux-image: FORBIDDEN$' "$TMP/pass.txt"
grep -q '^dsc-fdf-promotion-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND$' "$TMP/pass.txt"

sed "s/$BOOT_SHA/0000000000000000000000000000000000000000000000000000000000000000/" "$TMP/placement.txt" > "$TMP/wrong-boot.txt"
if run_verify "$TMP/wrong-boot-out.txt" "$TMP/entry.txt" "$TMP/wrong-boot.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 SEC-entry verifier accepted mismatched boot evidence" >&2
  exit 1
fi
grep -q '^entry-and-placement-boot-hashes-match: FAIL$' "$TMP/wrong-boot-out.txt"

sed "s/$DTB_SHA/1111111111111111111111111111111111111111111111111111111111111111/" "$TMP/gic.txt" > "$TMP/wrong-dtb.txt"
if run_verify "$TMP/wrong-dtb-out.txt" "$TMP/entry.txt" "$TMP/placement.txt" "$TMP/selected.txt" "$TMP/wrong-dtb.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 SEC-entry verifier accepted mismatched DTB evidence" >&2
  exit 1
fi
grep -q '^selected-and-gic-bound-dtb-hashes-match: FAIL$' "$TMP/wrong-dtb-out.txt"

sed 's/observed-qualcomm-entry-el: NOT_CAPTURED/observed-qualcomm-entry-el: EL2_UNVERIFIED/' "$TMP/entry.txt" > "$TMP/unverified-el.txt"
if run_verify "$TMP/unverified-el-out.txt" "$TMP/unverified-el.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 SEC-entry verifier accepted an unverified EL claim" >&2
  exit 1
fi
grep -q '^qualcomm-entry-el-remains-uncaptured: FAIL$' "$TMP/unverified-el-out.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/gic.txt" > "$TMP/authorized-gic.txt"
if run_verify "$TMP/authorized-gic-out.txt" "$TMP/entry.txt" "$TMP/placement.txt" "$TMP/selected.txt" "$TMP/authorized-gic.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 SEC-entry verifier accepted a launch-authorizing prerequisite" >&2
  exit 1
fi
grep -q '^all-prerequisite-reports-deny-launch: FAIL$' "$TMP/authorized-gic-out.txt"
grep -q '^classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BLOCKED$' "$TMP/authorized-gic-out.txt"

echo "PASS: M7 standalone SEC entry requirement binding"
