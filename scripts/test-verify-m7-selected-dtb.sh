#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-selected-dtb.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/dtb-1.dtb" <<'PY'
import struct, sys
from pathlib import Path

def pad4(value):
    return value + b"\0" * ((-len(value)) & 3)

strings = b"model\0compatible\0"
structure = struct.pack(">I", 1) + b"\0\0\0\0"
for name_offset, value in (
    (0, b"Qualcomm Technologies, Inc. Cape SoC\0"),
    (6, b"qcom,cape\0"),
):
    structure += struct.pack(">III", 3, len(value), name_offset) + pad4(value)
structure += struct.pack(">III", 2, 9, 0)
reserve = b"\0" * 16
struct_off = 40 + len(reserve)
strings_off = struct_off + len(structure)
total = strings_off + len(strings)
header = struct.pack(">10I", 0xD00DFEED, total, struct_off, strings_off, 40, 17, 16, 0, len(strings), len(structure))
Path(sys.argv[1]).write_bytes(header + reserve + structure + strings)
PY

printf 'VNDRBOOT-M7-TEST\n' > "$TMP/vendor_boot.img"
VENDOR_SHA="$(sha256sum "$TMP/vendor_boot.img" | awk '{print $1}')"
DTB_SHA="$(sha256sum "$TMP/dtb-1.dtb" | awk '{print $1}')"
DTB_SIZE="$(wc -c < "$TMP/dtb-1.dtb" | tr -d ' ')"

cat > "$TMP/layout.txt" <<EOF
geometry-vendor-boot-sha256: $VENDOR_SHA
classification: M7_LAYOUT_REGION_CONTRACT_PASS
EOF
cat > "$TMP/inspection.txt" <<'EOF'
Target match: yes
Build ID: CPH2413_15.0.0.1901(EX01)
DTB index: 1
Classification: NEED_EXACT_FASTBOOT_INSPECTION
EOF
printf 'dtb-index: 1 offset=0x0 size=%s sha256=%s\n' "$DTB_SIZE" "$DTB_SHA" > "$TMP/MANIFEST.txt"

"$PYTHON" "$VERIFY" "$TMP/layout.txt" "$TMP/inspection.txt" "$TMP/MANIFEST.txt" "$TMP/dtb-1.dtb" "$TMP/vendor_boot.img" "$TMP/pass.txt" >/dev/null
grep -q '^device-dtb-index: 1$' "$TMP/pass.txt"
grep -q '^inspection-build-id-matches-exact-stock: PASS$' "$TMP/pass.txt"
grep -q '^selected-dtb-compatible: qcom,cape$' "$TMP/pass.txt"
grep -q '^actual-vendor-boot-hash-matches-m6: PASS$' "$TMP/pass.txt"
grep -q '^classification: M7_EXACT_SELECTED_DTB_BOUND$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"

sed 's/^DTB index: 1$/DTB index: 0/' "$TMP/inspection.txt" > "$TMP/wrong-index.txt"
if "$PYTHON" "$VERIFY" "$TMP/layout.txt" "$TMP/wrong-index.txt" "$TMP/MANIFEST.txt" "$TMP/dtb-1.dtb" "$TMP/vendor_boot.img" "$TMP/wrong-index-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 selected-DTB verifier accepted a mismatched device index" >&2
  exit 1
fi
grep -q '^classification: M7_SELECTED_DTB_BINDING_FAIL$' "$TMP/wrong-index-out.txt"

printf 'changed-vendor-boot\n' > "$TMP/wrong-vendor_boot.img"
if "$PYTHON" "$VERIFY" "$TMP/layout.txt" "$TMP/inspection.txt" "$TMP/MANIFEST.txt" "$TMP/dtb-1.dtb" "$TMP/wrong-vendor_boot.img" "$TMP/wrong-vendor-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 selected-DTB verifier accepted the wrong vendor_boot image" >&2
  exit 1
fi
grep -q '^actual-vendor-boot-hash-matches-m6: FAIL$' "$TMP/wrong-vendor-out.txt"

printf 'tampered\n' >> "$TMP/dtb-1.dtb"
if "$PYTHON" "$VERIFY" "$TMP/layout.txt" "$TMP/inspection.txt" "$TMP/MANIFEST.txt" "$TMP/dtb-1.dtb" "$TMP/vendor_boot.img" "$TMP/tampered-out.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 selected-DTB verifier accepted tampered DTB bytes" >&2
  exit 1
fi
grep -q '^selected-dtb-hash-matches-manifest: FAIL$' "$TMP/tampered-out.txt"
grep -q '^classification: M7_SELECTED_DTB_BINDING_FAIL$' "$TMP/tampered-out.txt"

echo "PASS: M7 exact selected-DTB binding"
