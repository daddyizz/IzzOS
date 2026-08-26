#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-android-container-inputs.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/fd.bin" "$TMP/boot.img" "$TMP/vendor_boot.img" <<'PY'
import struct, sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(b"IzzOS-M7-FD".ljust(8192, b"\0"))

boot = bytearray(4096 + 0x4000)
boot[:8] = b"ANDROID!"
struct.pack_into("<II", boot, 8, 0x4000, 0)
struct.pack_into("<I", boot, 20, 1584)
struct.pack_into("<I", boot, 40, 4)
Path(sys.argv[2]).write_bytes(boot)

vendor = bytearray(4096)
vendor[:8] = b"VNDRBOOT"
struct.pack_into("<IIII", vendor, 8, 4, 4096, 0x80080000, 0x88100000)
struct.pack_into("<I", vendor, 24, 0x1000)
struct.pack_into("<I", vendor, 2096, 2128)
Path(sys.argv[3]).write_bytes(vendor)
PY

FD_SHA="$(sha256sum "$TMP/fd.bin" | awk '{print $1}')"
BOOT_SHA="$(sha256sum "$TMP/boot.img" | awk '{print $1}')"
VENDOR_SHA="$(sha256sum "$TMP/vendor_boot.img" | awk '{print $1}')"

cat > "$TMP/layout.txt" <<EOF
proven-stock-page-size: 0x1000
geometry-boot-sha256: $BOOT_SHA
geometry-vendor-boot-sha256: $VENDOR_SHA
classification: M7_LAYOUT_REGION_CONTRACT_PASS
EOF

cat > "$TMP/capacity.txt" <<EOF
fd-sha256: $FD_SHA
fd-size-bytes: 8192
launch-authorization: NO
classification: M7_FD_CAPACITY_CONTRACT_PASS
EOF

cat > "$TMP/selected.txt" <<EOF
device-build-id: CPH2413_15.0.0.1901(EX01)
selected-dtb-sha256: 1111111111111111111111111111111111111111111111111111111111111111
vendor-boot-sha256: $VENDOR_SHA
m6-vendor-boot-sha256: $VENDOR_SHA
launch-authorization: NO
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF

cat > "$TMP/entry.txt" <<EOF
m6-boot-sha256: $BOOT_SHA
actual-boot-sha256: $BOOT_SHA
launch-authorization: NO
classification: M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED
EOF

run_verify() {
  local out="$1" fd="${2:-$TMP/fd.bin}" boot="${3:-$TMP/boot.img}" vendor="${4:-$TMP/vendor_boot.img}" capacity="${5:-$TMP/capacity.txt}" entry="${6:-$TMP/entry.txt}"
  "$PYTHON" "$VERIFY" "$TMP/layout.txt" "$capacity" "$TMP/selected.txt" "$entry" "$fd" "$boot" "$vendor" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^fd-hash-is-bound-to-capacity-report: PASS$' "$TMP/pass.txt"
grep -q '^boot-hash-matches-entry-report: PASS$' "$TMP/pass.txt"
grep -q '^vendor-boot-hash-matches-selected-dtb-report: PASS$' "$TMP/pass.txt"
grep -q '^qualcomm-container-entry-semantics: NOT_YET_PROVEN$' "$TMP/pass.txt"
grep -q '^container-build-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_ANDROID_CONTAINER_INPUTS_BOUND$' "$TMP/pass.txt"

cp "$TMP/fd.bin" "$TMP/tampered-fd.bin"
printf X >> "$TMP/tampered-fd.bin"
if run_verify "$TMP/tampered-fd.txt" "$TMP/tampered-fd.bin" >/dev/null 2>&1; then
  echo "ERROR: M7 container input verifier accepted a tampered FD" >&2
  exit 1
fi
grep -q '^fd-hash-is-bound-to-capacity-report: FAIL$' "$TMP/tampered-fd.txt"

cp "$TMP/vendor_boot.img" "$TMP/tampered-vendor.img"
printf X >> "$TMP/tampered-vendor.img"
if run_verify "$TMP/tampered-vendor.txt" "$TMP/fd.bin" "$TMP/boot.img" "$TMP/tampered-vendor.img" >/dev/null 2>&1; then
  echo "ERROR: M7 container input verifier accepted the wrong vendor_boot.img" >&2
  exit 1
fi
grep -q '^vendor-boot-hash-matches-layout: FAIL$' "$TMP/tampered-vendor.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/entry.txt" > "$TMP/authorized-entry.txt"
if run_verify "$TMP/authorized-entry-out.txt" "$TMP/fd.bin" "$TMP/boot.img" "$TMP/vendor_boot.img" "$TMP/capacity.txt" "$TMP/authorized-entry.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 container input verifier accepted a launch-authorizing prerequisite" >&2
  exit 1
fi
grep -q '^all-prerequisite-reports-deny-launch: FAIL$' "$TMP/authorized-entry-out.txt"

cp "$TMP/boot.img" "$TMP/bad-header.img"
"$PYTHON" - "$TMP/bad-header.img" <<'PY'
import struct, sys
from pathlib import Path
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
struct.pack_into("<I", data, 40, 3)
path.write_bytes(data)
PY
if run_verify "$TMP/bad-header.txt" "$TMP/fd.bin" "$TMP/bad-header.img" >/dev/null 2>&1; then
  echo "ERROR: M7 container input verifier accepted a non-v4 boot header" >&2
  exit 1
fi
grep -q '^android-boot-header-is-v4: FAIL$' "$TMP/bad-header.txt"
grep -q '^classification: M7_ANDROID_CONTAINER_INPUT_BINDING_BLOCKED$' "$TMP/bad-header.txt"

echo "PASS: M7 exact Android container input binding"
