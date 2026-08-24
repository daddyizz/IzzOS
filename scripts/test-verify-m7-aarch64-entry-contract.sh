#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-aarch64-entry-contract.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/boot.img" <<'PY'
import struct, sys
from pathlib import Path

boot = bytearray(4096 + 0x4000)
boot[:8] = b"ANDROID!"
struct.pack_into("<II", boot, 8, 0x4000, 0)
struct.pack_into("<I", boot, 20, 1584)
struct.pack_into("<I", boot, 40, 4)
offset = 4096
struct.pack_into("<II", boot, offset, 0x14000010, 0xD503201F)
struct.pack_into("<QQQ", boot, offset + 8, 0x80000, 0x3000, 0x2)
struct.pack_into("<QQQ", boot, offset + 32, 0, 0, 0)
struct.pack_into("<II", boot, offset + 56, 0x644D5241, 0)
Path(sys.argv[1]).write_bytes(boot)
PY

BOOT_SHA="$(sha256sum "$TMP/boot.img" | awk '{print $1}')"
make_layout() {
  local out="$1" hash="$2" base="${3:-0x80080000}"
  cat > "$out" <<EOF
proven-kernel-region-base: $base
proven-stock-dtb-load: 0x80100000
proven-stock-page-size: 0x1000
geometry-boot-sha256: $hash
classification: M7_LAYOUT_REGION_CONTRACT_PASS
EOF
}

make_layout "$TMP/layout.txt" "$BOOT_SHA"
"$PYTHON" "$VERIFY" "$TMP/layout.txt" "$TMP/boot.img" "$TMP/pass.txt" >/dev/null
grep -q '^actual-boot-hash-matches-m6: PASS$' "$TMP/pass.txt"
grep -q '^aarch64-image-magic-is-valid: PASS$' "$TMP/pass.txt"
grep -q '^stock-kernel-call-address-follows-2m-text-offset-rule: PASS$' "$TMP/pass.txt"
grep -q '^stock-linux-image-call-address: 0x80080000$' "$TMP/pass.txt"
grep -q '^derived-2m-aligned-base: 0x80000000$' "$TMP/pass.txt"
grep -q '^source-linux-entry-register-contract: x0=DTB_PHYSICAL_ADDRESS,x1=0,x2=0,x3=0$' "$TMP/pass.txt"
grep -q '^standalone-sec-entry-equivalence: NOT_PROVEN$' "$TMP/pass.txt"
grep -q '^classification: M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"

make_layout "$TMP/wrong-hash-layout.txt" '0000000000000000000000000000000000000000000000000000000000000000'
if "$PYTHON" "$VERIFY" "$TMP/wrong-hash-layout.txt" "$TMP/boot.img" "$TMP/wrong-hash.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 entry verifier accepted the wrong boot.img hash" >&2
  exit 1
fi
grep -q '^actual-boot-hash-matches-m6: FAIL$' "$TMP/wrong-hash.txt"

make_layout "$TMP/bad-placement-layout.txt" "$BOOT_SHA" '0x80000000'
if "$PYTHON" "$VERIFY" "$TMP/bad-placement-layout.txt" "$TMP/boot.img" "$TMP/bad-placement.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 entry verifier accepted a call address that violates text_offset placement" >&2
  exit 1
fi
grep -q '^stock-kernel-call-address-follows-2m-text-offset-rule: FAIL$' "$TMP/bad-placement.txt"

cp "$TMP/boot.img" "$TMP/bad-flags.img"
"$PYTHON" - "$TMP/bad-flags.img" <<'PY'
import struct, sys
from pathlib import Path
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
struct.pack_into("<Q", data, 4096 + 24, 0x12)
path.write_bytes(data)
PY
BAD_FLAGS_SHA="$(sha256sum "$TMP/bad-flags.img" | awk '{print $1}')"
make_layout "$TMP/bad-flags-layout.txt" "$BAD_FLAGS_SHA"
if "$PYTHON" "$VERIFY" "$TMP/bad-flags-layout.txt" "$TMP/bad-flags.img" "$TMP/bad-flags.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 entry verifier accepted reserved AArch64 flag bits" >&2
  exit 1
fi
grep -q '^aarch64-reserved-flag-bits-are-zero: FAIL$' "$TMP/bad-flags.txt"
grep -q '^classification: M7_STOCK_AARCH64_ENTRY_CONTRACT_BLOCKED$' "$TMP/bad-flags.txt"

echo "PASS: M7 exact-stock AArch64 Linux entry contract"
