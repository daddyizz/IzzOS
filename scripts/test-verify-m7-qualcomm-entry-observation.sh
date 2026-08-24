#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-qualcomm-entry-observation.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BOOT_SHA="$(printf 'boot-m7-observation' | sha256sum | awk '{print $1}')"
LOADER_SHA="$(printf 'loader-m7-observation' | sha256sum | awk '{print $1}')"
DTB_SHA="$(printf 'dtb-m7-observation' | sha256sum | awk '{print $1}')"

cat > "$TMP/requirements.txt" <<EOF
exact-device-build: CPH2413_15.0.0.1901(EX01)
boot-sha256: $BOOT_SHA
linuxloader-sha256: $LOADER_SHA
selected-dtb-sha256: $DTB_SHA
stock-dtb-load-address: 0x80100000
dsc-fdf-promotion-authorization: NO
launch-authorization: NO
classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND
EOF
REQ_SHA="$(sha256sum "$TMP/requirements.txt" | awk '{print $1}')"

cat > "$TMP/observation.txt" <<EOF
capture-schema: IZZOS_M7_QUALCOMM_ENTRY_V1
capture-source: PRE_SEC_INSTRUMENTED_SNAPSHOT
capture-cpu: PRIMARY
capture-route-evidence: NOT_INCLUDED
requirements-sha256: $REQ_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
boot-sha256: $BOOT_SHA
linuxloader-sha256: $LOADER_SHA
selected-dtb-sha256: $DTB_SHA
entry-security-state: NON_SECURE
entry-current-el: EL2
entry-sctlr-register: SCTLR_EL2
entry-x0: 0x80100000
entry-x1: 0x0
entry-x2: 0x0
entry-x3: 0x0
entry-daif: 0x3C0
entry-sctlr: 0x1004
entry-cntfrq-el0: 0x124F800
entry-cntvoff-el2: 0x0
entry-image-clean-to-poc: YES
entry-icache-stale-image-entries: NO
secondary-cpu-state: PARKED_OR_NOT_RELEASED
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local out="$1" requirements="${2:-$TMP/requirements.txt}" observation="${3:-$TMP/observation.txt}"
  "$PYTHON" "$VERIFY" "$requirements" "$observation" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^entry-currentel-is-linux-compatible: PASS$' "$TMP/pass.txt"
grep -q '^entry-sctlr-register-matches-currentel: PASS$' "$TMP/pass.txt"
grep -q '^entry-daif-masks-all-exceptions: PASS$' "$TMP/pass.txt"
grep -q '^entry-mmu-is-off: PASS$' "$TMP/pass.txt"
grep -q '^entry-sctlr-data-cache-enabled: YES$' "$TMP/pass.txt"
grep -q '^observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED$' "$TMP/pass.txt"
grep -q '^sec-wrapper-implementation-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS$' "$TMP/pass.txt"

cp "$TMP/requirements.txt" "$TMP/tampered-requirements.txt"
printf X >> "$TMP/tampered-requirements.txt"
if run_verify "$TMP/tampered-requirements-out.txt" "$TMP/tampered-requirements.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 observation verifier accepted a tampered requirements report" >&2
  exit 1
fi
grep -q '^observation-binds-exact-requirements-report: FAIL$' "$TMP/tampered-requirements-out.txt"

sed 's/entry-x0: 0x80100000/entry-x0: 0x80200000/' "$TMP/observation.txt" > "$TMP/wrong-x0.txt"
if run_verify "$TMP/wrong-x0-out.txt" "$TMP/requirements.txt" "$TMP/wrong-x0.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 observation verifier accepted the wrong DTB register" >&2
  exit 1
fi
grep -q '^entry-x0-matches-stock-dtb-address: FAIL$' "$TMP/wrong-x0-out.txt"

sed 's/entry-sctlr: 0x1004/entry-sctlr: 0x1005/' "$TMP/observation.txt" > "$TMP/mmu-on.txt"
if run_verify "$TMP/mmu-on-out.txt" "$TMP/requirements.txt" "$TMP/mmu-on.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 observation verifier accepted an enabled MMU" >&2
  exit 1
fi
grep -q '^entry-mmu-is-off: FAIL$' "$TMP/mmu-on-out.txt"

sed 's/entry-daif: 0x3C0/entry-daif: 0x80/' "$TMP/observation.txt" > "$TMP/bad-daif.txt"
if run_verify "$TMP/bad-daif-out.txt" "$TMP/requirements.txt" "$TMP/bad-daif.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 observation verifier accepted incompletely masked exceptions" >&2
  exit 1
fi
grep -q '^entry-daif-masks-all-exceptions: FAIL$' "$TMP/bad-daif-out.txt"
grep -q '^classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_BLOCKED$' "$TMP/bad-daif-out.txt"

echo "PASS: M7 Qualcomm entry observation schema gate"
