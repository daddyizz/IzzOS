#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/verify-m7-fd-capacity.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/layout.txt" <<'EOF'
IzzOS Milestone 7 standalone layout contract
proven-kernel-region-base: 0x80000000
proven-kernel-region-size: 0x00020000
proven-kernel-region-end: 0x80020000
proven-stock-dtb-load: 0x80010000
proven-stock-ramdisk-load: 0x80018000
proven-stock-page-size: 0x1000
classification: M7_LAYOUT_REGION_CONTRACT_PASS
EOF

"$PYTHON" - "$TMP/good.fd" "$TMP/oversized.fd" <<'PY'
import sys
from pathlib import Path

good = Path(sys.argv[1])
oversized = Path(sys.argv[2])
good.write_bytes(b"IzzOS-M7-FD".ljust(0x2000, b"\0"))
oversized.write_bytes(b"IzzOS-M7-OVERSIZED".ljust(0x11000, b"\0"))
PY

"$PYTHON" "$SCRIPT" "$TMP/layout.txt" "$TMP/good.fd" "$TMP/good.txt" >/dev/null
grep -q '^fd-size-is-stock-page-aligned: PASS$' "$TMP/good.txt"
grep -q '^fd-aligned-size-fits-before-stock-dtb-bound: PASS$' "$TMP/good.txt"
grep -q '^fd-base-policy: NOT_YET_PROVEN$' "$TMP/good.txt"
grep -q '^launch-authorization: NO$' "$TMP/good.txt"
grep -q '^classification: M7_FD_CAPACITY_CONTRACT_PASS$' "$TMP/good.txt"

printf 'x' >> "$TMP/good.fd"
if "$PYTHON" "$SCRIPT" "$TMP/layout.txt" "$TMP/good.fd" "$TMP/misaligned.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 capacity verifier accepted a page-misaligned FD" >&2
  exit 1
fi
grep -q '^fd-size-is-stock-page-aligned: FAIL$' "$TMP/misaligned.txt"
grep -q '^classification: M7_FD_CAPACITY_CONTRACT_FAIL$' "$TMP/misaligned.txt"

if "$PYTHON" "$SCRIPT" "$TMP/layout.txt" "$TMP/oversized.fd" "$TMP/oversized.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 capacity verifier accepted an FD that crosses the stock DTB bound" >&2
  exit 1
fi
grep -q '^fd-aligned-size-fits-before-stock-dtb-bound: FAIL$' "$TMP/oversized.txt"
grep -q '^classification: M7_FD_CAPACITY_CONTRACT_FAIL$' "$TMP/oversized.txt"

echo "PASS: M7 standalone FD capacity contract"
