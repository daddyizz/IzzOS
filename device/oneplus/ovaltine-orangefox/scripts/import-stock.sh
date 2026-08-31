#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  import-stock.sh --boot boot.img --vendor-boot vendor_boot.img \
    --dtbo dtbo.img --vbmeta vbmeta.img --unpack-tool /path/to/unpack_bootimg.py

Imports only the stock kernel, DTB and DTBO needed for a CPH2413 bring-up.
The source images must come from OxygenOS 15.0.0.1901(EX01).
EOF
}

BOOT=""
VENDOR_BOOT=""
DTBO=""
VBMETA=""
UNPACK_TOOL=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --boot) BOOT="$2"; shift 2 ;;
    --vendor-boot) VENDOR_BOOT="$2"; shift 2 ;;
    --dtbo) DTBO="$2"; shift 2 ;;
    --vbmeta) VBMETA="$2"; shift 2 ;;
    --unpack-tool) UNPACK_TOOL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for item in "$BOOT" "$VENDOR_BOOT" "$DTBO" "$VBMETA" "$UNPACK_TOOL"; do
  if [ -z "$item" ] || [ ! -f "$item" ]; then
    echo "Missing input file: $item" >&2
    exit 2
  fi
done

check_size() {
  local file="$1" expected="$2" actual
  actual="$(stat -c '%s' "$file")"
  if [ "$actual" != "$expected" ]; then
    echo "Unexpected size for $file: $actual (expected $expected)" >&2
    exit 1
  fi
}

check_size "$BOOT" 201326592
check_size "$VENDOR_BOOT" 201326592
check_size "$DTBO" 25165824
check_size "$VBMETA" 12288

check_hash() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "$(basename "$file") does not match OOS 15.0.0.1901(EX01)." >&2
    echo "actual:   $actual" >&2
    echo "expected: $expected" >&2
    exit 1
  fi
}

check_hash "$BOOT" "08bf7cce2df493945da3b3c9e5d6dd24ed9ecdc635c6349c177b61081b737fc8"
check_hash "$VENDOR_BOOT" "ef230a4e1b9957ce0093f86f9bc8728f344665e741aa0bc584cc65281652e6e0"
check_hash "$DTBO" "2f1efc6328c4a87923489f453c5acc455d3713694178cd2631d022924c106313"
check_hash "$VBMETA" "71463b21c5a8be134789bcb7498dc58a955c4d2c73468a31eee971f9d2914f5e"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

python3 "$UNPACK_TOOL" --boot_img "$BOOT" --out "$WORK_DIR/boot"
python3 "$UNPACK_TOOL" --boot_img "$VENDOR_BOOT" --out "$WORK_DIR/vendor_boot"

if [ ! -s "$WORK_DIR/boot/kernel" ]; then
  echo "unpack_bootimg did not produce the stock kernel" >&2
  exit 1
fi
if [ ! -s "$WORK_DIR/vendor_boot/dtb" ]; then
  echo "unpack_bootimg did not produce the stock DTB" >&2
  exit 1
fi

install -m 0644 "$WORK_DIR/boot/kernel" "$TREE_DIR/prebuilt/kernel"
install -m 0644 "$WORK_DIR/vendor_boot/dtb" "$TREE_DIR/prebuilt/dtbs/stock.dtb"
install -m 0644 "$DTBO" "$TREE_DIR/prebuilt/dtbo.img"

{
  sha256sum "$BOOT"
  sha256sum "$VENDOR_BOOT"
  sha256sum "$DTBO"
  sha256sum "$VBMETA"
} | sed 's#  .*/#  #' > "$TREE_DIR/prebuilt/STOCK_SHA256SUMS"

echo "Stock prebuilts imported successfully."
echo "Do not add boot.img, vendor_boot.img or vbmeta.img to git."
