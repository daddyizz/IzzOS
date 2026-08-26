#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-runtime-destination-ownership.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/Ovaltine.fd" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(b"M7 ownership test FD".ljust(0x2000, b"\0"))
PY
FD_SHA="$(sha256sum "$TMP/Ovaltine.fd" | awk '{print $1}')"
DTB_SHA="$(printf 'selected-dtb-runtime-ownership' | sha256sum | awk '{print $1}')"

cat > "$TMP/wrapper.txt" <<'EOF'
execution-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
execution-route-authorization: NOT_INCLUDED
final-runtime-destination-ownership: NOT_INDEPENDENTLY_PROVEN
final-runtime-destination: 0xA0000000
prepi-entry-address: 0xA0001000
temporary-ram-base: 0x92000000
temporary-ram-size: 0x200000
stack-base: 0x92180000
stack-size: 0x8000
preserved-dtb-address: 0x98000000
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
launch-authorization: NO
classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED
EOF

cat > "$TMP/capacity.txt" <<EOF
fd-sha256: $FD_SHA
fd-size-bytes: 8192
fd-size-hex: 0x2000
fd-base-policy: NOT_YET_PROVEN
launch-authorization: NO
classification: M7_FD_CAPACITY_CONTRACT_PASS
EOF

cat > "$TMP/selected-dtb.txt" <<EOF
selected-dtb-sha256: $DTB_SHA
fd-base-policy: NOT_YET_PROVEN
launch-authorization: NO
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF

WRAPPER_SHA="$(sha256sum "$TMP/wrapper.txt" | awk '{print $1}')"
CAPACITY_SHA="$(sha256sum "$TMP/capacity.txt" | awk '{print $1}')"
SELECTED_REPORT_SHA="$(sha256sum "$TMP/selected-dtb.txt" | awk '{print $1}')"

cat > "$TMP/ownership.txt" <<EOF
memory-ownership-schema: IZZOS_M7_RUNTIME_DESTINATION_OWNERSHIP_V1
capture-id: CPH2413-EX01-runtime-ownership-test
capture-timestamp-utc: 2026-08-25T00:00:00Z
evidence-source: EXACT_DEVICE_RUNTIME_READ_ONLY_CAPTURE
evidence-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
wrapper-execution-report-sha256: $WRAPPER_SHA
fd-capacity-report-sha256: $CAPACITY_SHA
selected-dtb-report-sha256: $SELECTED_REPORT_SHA
selected-dtb-sha256: $DTB_SHA
fd-sha256: $FD_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
physical-memory-range-count: 1
physical-memory-range: base=0x90000000 size=0x20000000 source=RUNTIME_PHYSICAL_MEMORY
exclusion-range-count: 7
exclusion-range: base=0x90000000 size=0x01000000 kind=FIXED_RESERVED name=secure-fixed
exclusion-range: base=0x91000000 size=0x01000000 kind=DYNAMIC_RESERVED name=dynamic-pool
exclusion-range: base=0x94000000 size=0x00100000 kind=BOOTLOADER name=bootloader-relocation
exclusion-range: base=0x97000000 size=0x00400000 kind=KERNEL name=linux-kernel
exclusion-range: base=0x98000000 size=0x00100000 kind=DTB name=selected-dtb
exclusion-range: base=0x99000000 size=0x00200000 kind=VENDOR_RAMDISK name=vendor-ramdisk
exclusion-range: base=0x9C000000 size=0x00800000 kind=FRAMEBUFFER name=runtime-framebuffer
dynamic-pool-resolution: COMPLETE_FOR_EXACT_CAPTURE_INSTANT
bootloader-relocation-resolution: CAPTURED_AND_EXCLUDED
kernel-resolution: CAPTURED_AND_EXCLUDED
dtb-resolution: CAPTURED_AND_EXCLUDED
vendor-ramdisk-resolution: CAPTURED_AND_EXCLUDED
framebuffer-resolution: CAPTURED_AND_EXCLUDED
secure-reserved-resolution: EXACT_SELECTED_DTB_AND_RUNTIME_CAPTURE_RECONCILED
ownership-snapshot-lifetime: EXACT_CAPTURE_INSTANT_ONLY
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local out="$1" wrapper="${2:-$TMP/wrapper.txt}" capacity="${3:-$TMP/capacity.txt}" selected="${4:-$TMP/selected-dtb.txt}" fd="${5:-$TMP/Ovaltine.fd}" ownership="${6:-$TMP/ownership.txt}"
  "$PYTHON" "$VERIFY" "$wrapper" "$capacity" "$selected" "$fd" "$ownership" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^fd-range-is-inside-physical-memory: PASS$' "$TMP/pass.txt"
grep -q '^fd-range-does-not-overlap-exclusions: PASS$' "$TMP/pass.txt"
grep -q '^temporary-ram-does-not-overlap-exclusions: PASS$' "$TMP/pass.txt"
grep -q '^preserved-dtb-address-is-in-dtb-exclusion: PASS$' "$TMP/pass.txt"
grep -q '^final-runtime-destination-ownership: ARITHMETICALLY_CLEAR_IN_DECLARED_SNAPSHOT_ONLY$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_RUNTIME_DESTINATION_OWNERSHIP_SCHEMA_PASS_AUTHENTICITY_FRESHNESS_REQUIRED$' "$TMP/pass.txt"

cp "$TMP/Ovaltine.fd" "$TMP/tampered.fd"
printf X >> "$TMP/tampered.fd"
if run_verify "$TMP/tampered-fd-out.txt" "$TMP/wrapper.txt" "$TMP/capacity.txt" "$TMP/selected-dtb.txt" "$TMP/tampered.fd" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted changed FD bytes" >&2
  exit 1
fi
grep -q '^fd-capacity-report-binds-actual-fd: FAIL$' "$TMP/tampered-fd-out.txt"
grep -q '^ownership-binds-fd-bytes: FAIL$' "$TMP/tampered-fd-out.txt"

sed 's/final-runtime-destination: 0xA0000000/final-runtime-destination: 0x98000000/' "$TMP/wrapper.txt" > "$TMP/fd-overlap.txt"
if run_verify "$TMP/fd-overlap-out.txt" "$TMP/fd-overlap.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted an FD overlapping the DTB" >&2
  exit 1
fi
grep -q '^fd-range-does-not-overlap-exclusions: FAIL$' "$TMP/fd-overlap-out.txt"

sed 's/prepi-entry-address: 0xA0001000/prepi-entry-address: 0xA0010000/' "$TMP/wrapper.txt" > "$TMP/entry-outside.txt"
if run_verify "$TMP/entry-outside-out.txt" "$TMP/entry-outside.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted a PrePi entry outside the FD" >&2
  exit 1
fi
grep -q '^prepi-entry-is-inside-fd: FAIL$' "$TMP/entry-outside-out.txt"

sed 's/temporary-ram-base: 0x92000000/temporary-ram-base: 0xB1000000/' "$TMP/wrapper.txt" > "$TMP/temp-outside.txt"
if run_verify "$TMP/temp-outside-out.txt" "$TMP/temp-outside.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted temporary RAM outside physical memory" >&2
  exit 1
fi
grep -q '^temporary-ram-is-inside-physical-memory: FAIL$' "$TMP/temp-outside-out.txt"

sed 's/kind=DYNAMIC_RESERVED/kind=UNRESOLVED/' "$TMP/ownership.txt" > "$TMP/missing-kind.txt"
if run_verify "$TMP/missing-kind-out.txt" "$TMP/wrapper.txt" "$TMP/capacity.txt" "$TMP/selected-dtb.txt" "$TMP/Ovaltine.fd" "$TMP/missing-kind.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted an unresolved dynamic pool category" >&2
  exit 1
fi
grep -q '^required-exclusion-kinds-are-complete: FAIL$' "$TMP/missing-kind-out.txt"

cp "$TMP/ownership.txt" "$TMP/duplicate.txt"
printf 'capture-id: duplicate\n' >> "$TMP/duplicate.txt"
if run_verify "$TMP/duplicate-out.txt" "$TMP/wrapper.txt" "$TMP/capacity.txt" "$TMP/selected-dtb.txt" "$TMP/Ovaltine.fd" "$TMP/duplicate.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted a duplicate unique field" >&2
  exit 1
fi
grep -q '^ownership-unique-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"

sed 's/2026-08-25T00:00:00Z/2026-99-25T00:00:00Z/' "$TMP/ownership.txt" > "$TMP/invalid-timestamp.txt"
if run_verify "$TMP/invalid-timestamp-out.txt" "$TMP/wrapper.txt" "$TMP/capacity.txt" "$TMP/selected-dtb.txt" "$TMP/Ovaltine.fd" "$TMP/invalid-timestamp.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted an invalid UTC timestamp" >&2
  exit 1
fi
grep -q '^ownership-capture-identity-is-specific: FAIL$' "$TMP/invalid-timestamp-out.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/ownership.txt" > "$TMP/unsafe.txt"
if run_verify "$TMP/unsafe-out.txt" "$TMP/wrapper.txt" "$TMP/capacity.txt" "$TMP/selected-dtb.txt" "$TMP/Ovaltine.fd" "$TMP/unsafe.txt" >/dev/null 2>&1; then
  echo "ERROR: ownership gate accepted a launch-authorizing snapshot" >&2
  exit 1
fi
grep -q '^ownership-snapshot-denies-device-write-and-launch: FAIL$' "$TMP/unsafe-out.txt"
grep -q '^classification: M7_RUNTIME_DESTINATION_OWNERSHIP_BLOCKED$' "$TMP/unsafe-out.txt"

echo "PASS: M7 final runtime-destination ownership gate"
