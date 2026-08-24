#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
M6="$ROOT/scripts/verify-m1-kernel-region-geometry.py"
M7="$ROOT/scripts/check-m7-layout-contract.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

make_inputs() {
  local dir="$1"
  local extra_region="${2:-}"
  mkdir -p "$dir"
  "$PYTHON" - "$dir" "$extra_region" <<'PY'
import struct
import sys
from pathlib import Path

root = Path(sys.argv[1])
extra_region = sys.argv[2]
cfg = '0x80000000, 0x08000000, "Kernel", 0x0, 0x0, 0x0,\n'
if extra_region:
    cfg += extra_region + "\n"
cfg += '0x88000000, 0x01000000, "NextRegion", 0x0, 0x0, 0x0,\n'
(root / "uefiplat.cfg").write_text(cfg)

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
  "$PYTHON" "$M6" \
    "$dir/uefiplat.cfg" \
    "$dir/boot.img" \
    "$dir/vendor_boot.img" \
    "$dir/geometry.txt" >/dev/null
}

make_inputs "$TMP/pass"
"$PYTHON" "$M7" \
  "$TMP/pass/geometry.txt" \
  "$TMP/pass/uefiplat.cfg" \
  "$TMP/pass/layout.txt" >/dev/null
grep -q '^cfg-hash-matches-geometry: PASS$' "$TMP/pass/layout.txt"
grep -q '^kernel-region-does-not-overlap-other-cfg-regions: PASS$' "$TMP/pass/layout.txt"
grep -q '^classification: M7_LAYOUT_REGION_CONTRACT_PASS$' "$TMP/pass/layout.txt"

printf '\n# tampered after M6 evidence capture\n' >> "$TMP/pass/uefiplat.cfg"
if "$PYTHON" "$M7" \
  "$TMP/pass/geometry.txt" \
  "$TMP/pass/uefiplat.cfg" \
  "$TMP/pass/tampered-layout.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 checker accepted a cfg that no longer matches M6 evidence" >&2
  exit 1
fi
grep -q '^cfg-hash-matches-geometry: FAIL$' "$TMP/pass/tampered-layout.txt"
grep -q '^classification: M7_LAYOUT_CONTRACT_FAIL$' "$TMP/pass/tampered-layout.txt"

make_inputs "$TMP/overlap" '0x87F00000, 0x00200000, "OverlapRegion", 0x0, 0x0, 0x0,'
if "$PYTHON" "$M7" \
  "$TMP/overlap/geometry.txt" \
  "$TMP/overlap/uefiplat.cfg" \
  "$TMP/overlap/layout.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 checker accepted an overlapping configured region" >&2
  exit 1
fi
grep -q '^kernel-region-does-not-overlap-other-cfg-regions: FAIL$' "$TMP/overlap/layout.txt"
grep -q '^- OverlapRegion: 0x87F00000-0x88100000$' "$TMP/overlap/layout.txt"
grep -q '^classification: M7_LAYOUT_CONTRACT_FAIL$' "$TMP/overlap/layout.txt"

echo "PASS: M7 standalone layout region contract"
