#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/extract-vendor-boot-dtb-set.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
IMG="$TMP/vendor_boot.img"
OUT="$TMP/out"

# Build a tiny synthetic vendor_boot v4 image with two concatenated FDT blobs.
# Only fields consumed by the extractor are populated.
dd if=/dev/zero of="$IMG" bs=1 count=$((4096 + 4096 + 128)) status=none
printf 'VNDRBOOT' | dd of="$IMG" bs=1 seek=0 conv=notrunc status=none
# version=4, page_size=4096, kernel_addr=0x8000, ramdisk_addr=0x1000000,
# ramdisk_size=1, header_size=2128, dtb_size=80, dtb_addr=0x1f00000
printf '\x04\x00\x00\x00' | dd of="$IMG" bs=1 seek=8 conv=notrunc status=none
printf '\x00\x10\x00\x00' | dd of="$IMG" bs=1 seek=12 conv=notrunc status=none
printf '\x00\x80\x00\x00' | dd of="$IMG" bs=1 seek=16 conv=notrunc status=none
printf '\x00\x00\x00\x01' | dd of="$IMG" bs=1 seek=20 conv=notrunc status=none
printf '\x01\x00\x00\x00' | dd of="$IMG" bs=1 seek=24 conv=notrunc status=none
printf '\x50\x08\x00\x00' | dd of="$IMG" bs=1 seek=2096 conv=notrunc status=none
printf '\x50\x00\x00\x00' | dd of="$IMG" bs=1 seek=2100 conv=notrunc status=none
printf '\x00\x00\xF0\x01\x00\x00\x00\x00' | dd of="$IMG" bs=1 seek=2104 conv=notrunc status=none

# DTB payload begins at align(2128,4096)+align(1,4096)=8192.
# Two minimal synthetic FDT-like blobs, each totalsize=40 bytes.
for off in 8192 8232; do
  printf '\xD0\x0D\xFE\xED\x00\x00\x00\x28' | dd of="$IMG" bs=1 seek="$off" conv=notrunc status=none
done

out="$(bash "$SCRIPT" "$IMG" "$OUT")"
grep -q '^DTB blob count: 2$' <<<"$out"
grep -q '^classification: VENDOR_BOOT_MULTI_DTB_SET_EXTRACTED$' <<<"$out"
grep -q '^dtb-index: 0 ' <<<"$out"
grep -q '^dtb-index: 1 ' <<<"$out"
test -f "$OUT/dtb-0.dtb"
test -f "$OUT/dtb-1.dtb"

echo "PASS: vendor_boot multi-DTB count survives extraction loop"
