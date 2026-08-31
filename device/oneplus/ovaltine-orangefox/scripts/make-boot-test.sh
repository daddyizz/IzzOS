#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  make-boot-test.sh --magiskboot /path/to/magiskboot \
    --stock-boot boot.img --recovery recovery.img --output boot-test.img

Creates a temporary-boot image by retaining the exact stock boot header/kernel
and replacing only its ramdisk with the built OrangeFox recovery ramdisk.
EOF
}

MAGISKBOOT=""
STOCK_BOOT=""
RECOVERY=""
OUTPUT=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --magiskboot) MAGISKBOOT="$2"; shift 2 ;;
    --stock-boot) STOCK_BOOT="$2"; shift 2 ;;
    --recovery) RECOVERY="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for item in "$MAGISKBOOT" "$STOCK_BOOT" "$RECOVERY"; do
  if [ -z "$item" ] || [ ! -f "$item" ]; then
    echo "Missing input file: $item" >&2
    exit 2
  fi
done
if [ -z "$OUTPUT" ]; then
  echo "Missing --output" >&2
  exit 2
fi

MAGISKBOOT="$(cd "$(dirname "$MAGISKBOOT")" && pwd)/$(basename "$MAGISKBOOT")"
STOCK_BOOT="$(cd "$(dirname "$STOCK_BOOT")" && pwd)/$(basename "$STOCK_BOOT")"
RECOVERY="$(cd "$(dirname "$RECOVERY")" && pwd)/$(basename "$RECOVERY")"
OUTPUT_DIR="$(cd "$(dirname "$OUTPUT")" && pwd)"
OUTPUT="$OUTPUT_DIR/$(basename "$OUTPUT")"

if [ "$(stat -c '%s' "$STOCK_BOOT")" != "201326592" ]; then
  echo "The stock boot image is not the expected 192 MiB partition image." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/recovery" "$WORK_DIR/boot"

(
  cd "$WORK_DIR/recovery"
  "$MAGISKBOOT" unpack -h "$RECOVERY"
  test -s ramdisk.cpio
)
install -m 0644 "$WORK_DIR/recovery/ramdisk.cpio" "$WORK_DIR/orangefox-ramdisk.cpio"

(
  cd "$WORK_DIR/boot"
  "$MAGISKBOOT" unpack -h "$STOCK_BOOT"
  test -s kernel
  install -m 0644 "$WORK_DIR/orangefox-ramdisk.cpio" ramdisk.cpio
  "$MAGISKBOOT" repack "$STOCK_BOOT" "$OUTPUT"
)

if [ ! -s "$OUTPUT" ]; then
  echo "Failed to create $OUTPUT" >&2
  exit 1
fi

echo "Temporary test image created: $OUTPUT"
sha256sum "$OUTPUT"
echo "This image is for temporary fastboot boot testing only. Do not flash it."
