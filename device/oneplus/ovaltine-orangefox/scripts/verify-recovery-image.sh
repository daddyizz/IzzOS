#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 /absolute/path/to/recovery.img [OrangeFox-source-root]" >&2
  exit 2
fi

IMAGE="$1"
SOURCE_ROOT="${2:-}"
MAX_SIZE=104857600

if [ ! -f "$IMAGE" ]; then
  echo "Missing recovery image: $IMAGE" >&2
  exit 1
fi

SIZE="$(stat -c '%s' "$IMAGE")"
if [ "$SIZE" -le 0 ] || [ "$SIZE" -gt "$MAX_SIZE" ]; then
  echo "Invalid image size: $SIZE bytes (maximum: $MAX_SIZE)" >&2
  exit 1
fi

MAGIC="$(od -An -tx1 -N8 "$IMAGE" | tr -d '[:space:]')"
if [ "$MAGIC" != "414e44524f494421" ]; then
  echo "Invalid Android boot image magic: $MAGIC" >&2
  exit 1
fi

if [ -n "$SOURCE_ROOT" ]; then
  UNPACKER="$SOURCE_ROOT/system/tools/mkbootimg/unpack_bootimg.py"
  if [ ! -f "$UNPACKER" ]; then
    echo "Missing unpack_bootimg.py under source root: $SOURCE_ROOT" >&2
    exit 1
  fi
  TEMP_DIR="$(mktemp -d)"
  trap 'find "$TEMP_DIR" -depth -delete' EXIT
  python3 "$UNPACKER" --boot_img "$IMAGE" --out "$TEMP_DIR" >/dev/null
  if ! find "$TEMP_DIR" -type f -name '*ramdisk*' -size +0c -print -quit | grep -q .; then
    echo "Image has no unpackable ramdisk" >&2
    exit 1
  fi
fi

sha256sum "$IMAGE"
echo "PASS: Android boot header and size validated ($SIZE/$MAX_SIZE bytes)"
echo "NEXT: inspect the unpacked recovery root for OrangeFox binaries on the build host."
