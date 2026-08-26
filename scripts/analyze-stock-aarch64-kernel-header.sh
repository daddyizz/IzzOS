#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <exact-stock-boot.img>" >&2
  exit 2
fi

BOOT_IMG="$1"
if [[ ! -f "$BOOT_IMG" ]]; then
  echo "ERROR: boot image not found: $BOOT_IMG" >&2
  exit 1
fi

# Android boot image header v3/v4 uses a fixed 4096-byte page for the primary
# boot header. The kernel payload starts at offset 4096. This script only reads
# the image; it does not modify the file or device.
BOOT_MAGIC="$(dd if="$BOOT_IMG" bs=1 count=8 2>/dev/null)"
if [[ "$BOOT_MAGIC" != "ANDROID!" ]]; then
  echo "ERROR: not an Android boot image (missing ANDROID! magic)" >&2
  exit 1
fi

le32_at() {
  local off="$1"
  od -An -tu4 -N4 -j"$off" "$BOOT_IMG" | tr -d ' '
}

hex_le64_at() {
  local off="$1"
  local bytes
  bytes="$(dd if="$BOOT_IMG" bs=1 skip="$off" count=8 2>/dev/null | od -An -tx1 -v | tr -d ' \n')"
  if [[ ${#bytes} -ne 16 ]]; then
    printf 'UNAVAILABLE'
    return
  fi
  printf '0x%s%s%s%s%s%s%s%s' \
    "${bytes:14:2}" "${bytes:12:2}" "${bytes:10:2}" "${bytes:8:2}" \
    "${bytes:6:2}" "${bytes:4:2}" "${bytes:2:2}" "${bytes:0:2}" | tr 'a-f' 'A-F'
}

KERNEL_SIZE="$(le32_at 8)"
RAMDISK_SIZE="$(le32_at 12)"
HEADER_VERSION="$(le32_at 40)"
KERNEL_OFF=4096

A64_MAGIC_HEX="$(dd if="$BOOT_IMG" bs=1 skip=$((KERNEL_OFF + 56)) count=4 2>/dev/null | od -An -tx1 -v | tr -d ' \n' | tr 'a-f' 'A-F')"
TEXT_OFFSET="$(hex_le64_at $((KERNEL_OFF + 8)))"
IMAGE_SIZE="$(hex_le64_at $((KERNEL_OFF + 16)))"
FLAGS="$(hex_le64_at $((KERNEL_OFF + 24)))"

printf 'IzzOS exact-stock AArch64 kernel header analysis\n'
printf '===============================================\n'
echo "Collector mode: READ_ONLY"
echo "Device writes: NONE"
echo "Boot image: $BOOT_IMG"
echo "Android boot header version: $HEADER_VERSION"
echo "Android kernel payload size: $KERNEL_SIZE"
echo "Android ramdisk payload size: $RAMDISK_SIZE"
echo "Kernel payload file offset: $KERNEL_OFF"
echo "AArch64 Image magic bytes: ${A64_MAGIC_HEX:-UNAVAILABLE}"
echo "AArch64 text_offset: $TEXT_OFFSET"
echo "AArch64 image_size: $IMAGE_SIZE"
echo "AArch64 flags: $FLAGS"

if [[ "$HEADER_VERSION" != "4" ]]; then
  echo "classification: STOCK_KERNEL_HEADER_UNEXPECTED_BOOT_VERSION"
  echo "decision: expected exact stock boot header v4; do not use this result for firmware-placement analysis."
  exit 1
fi

if [[ "$A64_MAGIC_HEX" != "41524D64" ]]; then
  echo "classification: STOCK_KERNEL_AARCH64_HEADER_UNCONFIRMED"
  echo "decision: AArch64 Image magic ARMd was not found at the expected exact stock kernel header location; do not infer load geometry."
  exit 1
fi

echo "classification: STOCK_KERNEL_AARCH64_HEADER_CONFIRMED"
echo "decision: exact stock AArch64 Image header geometry is confirmed. text_offset/image_size constrain kernel placement analysis, but they do not by themselves reveal the Qualcomm bootloader-selected physical base and do not authorize an FD address or device launch."
