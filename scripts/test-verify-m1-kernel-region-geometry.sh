#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/verify-m1-kernel-region-geometry.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP" <<'PY'
import struct
import sys
from pathlib import Path

root = Path(sys.argv[1])
(root / "uefiplat.cfg").write_text(
    '0x80000000, 0x08000000, "Kernel", 0x0, 0x0, 0x0,\n'
    '0x88000000, 0x01000000, "NextRegion", 0x0, 0x0, 0x0,\n'
)

boot = bytearray(64)
boot[:8] = b"ANDROID!"
struct.pack_into("<II", boot, 8, 0x01000000, 0x00400000)
struct.pack_into("<I", boot, 40, 4)
(root / "boot.img").write_bytes(boot)

vendor = bytearray(0x850)
vendor[:8] = b"VNDRBOOT"
struct.pack_into("<I", vendor, 8, 4)
struct.pack_into("<I", vendor, 12, 0x1000)
struct.pack_into("<I", vendor, 24, 0x00800000)
struct.pack_into("<I", vendor, 0x84C, 0x1000)
(root / "vendor_boot.img").write_bytes(vendor)
PY

GOOD="$TMP/good.txt"
"$PYTHON" "$SCRIPT" \
  "$TMP/uefiplat.cfg" \
  "$TMP/boot.img" \
  "$TMP/vendor_boot.img" \
  "$GOOD" >/dev/null

grep -q '^kernel-payload-before-DeviceTreeLoadAddr: yes$' "$GOOD"
grep -q '^kernel-payload-before-dtb: PASS$' "$GOOD"
grep -q '^classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED$' "$GOOD"

"$PYTHON" - "$TMP/boot.img" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
struct.pack_into("<I", data, 8, 0x07800000)
path.write_bytes(data)
PY

OVERSIZED="$TMP/oversized.txt"
if "$PYTHON" "$SCRIPT" \
  "$TMP/uefiplat.cfg" \
  "$TMP/boot.img" \
  "$TMP/vendor_boot.img" \
  "$OVERSIZED" >/dev/null 2>&1; then
  echo "ERROR: M6 verifier accepted a kernel payload that overlaps DTB placement" >&2
  exit 1
fi
grep -q '^kernel-payload-before-dtb: FAIL$' "$OVERSIZED"
grep -q '^classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED$' "$OVERSIZED"

"$PYTHON" - "$TMP/vendor_boot.img" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
struct.pack_into("<I", data, 12, 0)
path.write_bytes(data)
PY

BAD_PAGE="$TMP/bad-page.txt"
if "$PYTHON" "$SCRIPT" \
  "$TMP/uefiplat.cfg" \
  "$TMP/boot.img" \
  "$TMP/vendor_boot.img" \
  "$BAD_PAGE" >/dev/null 2>&1; then
  echo "ERROR: M6 verifier accepted an invalid vendor_boot page size" >&2
  exit 1
fi
grep -q '^- vendor-page-size-is-invalid$' "$BAD_PAGE"
grep -q '^classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED$' "$BAD_PAGE"

echo "PASS: M6 exact stock kernel-region geometry verifier"
