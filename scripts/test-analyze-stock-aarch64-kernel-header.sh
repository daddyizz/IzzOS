#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/analyze-stock-aarch64-kernel-header.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
IMG="$TMP/boot.img"

# Build a minimal synthetic Android boot header v4 + AArch64 Image header.
dd if=/dev/zero of="$IMG" bs=1 count=8192 status=none
printf 'ANDROID!' | dd of="$IMG" bs=1 seek=0 conv=notrunc status=none
# kernel_size = 4096, ramdisk_size = 0, header_version = 4
printf '\x00\x10\x00\x00' | dd of="$IMG" bs=1 seek=8 conv=notrunc status=none
printf '\x00\x00\x00\x00' | dd of="$IMG" bs=1 seek=12 conv=notrunc status=none
printf '\x04\x00\x00\x00' | dd of="$IMG" bs=1 seek=40 conv=notrunc status=none
# AArch64 text_offset=0x80000, image_size=0x02000000, flags=0
printf '\x00\x00\x08\x00\x00\x00\x00\x00' | dd of="$IMG" bs=1 seek=$((4096+8)) conv=notrunc status=none
printf '\x00\x00\x00\x02\x00\x00\x00\x00' | dd of="$IMG" bs=1 seek=$((4096+16)) conv=notrunc status=none
printf 'ARMd' | dd of="$IMG" bs=1 seek=$((4096+56)) conv=notrunc status=none

OUT="$(bash "$SCRIPT" "$IMG")"
grep -q '^Android boot header version: 4$' <<<"$OUT"
grep -q '^AArch64 Image magic bytes: 41524D64$' <<<"$OUT"
grep -q '^AArch64 text_offset: 0x0000000000080000$' <<<"$OUT"
grep -q '^AArch64 image_size: 0x0000000002000000$' <<<"$OUT"
grep -q '^classification: STOCK_KERNEL_AARCH64_HEADER_CONFIRMED$' <<<"$OUT"

echo "PASS: exact-stock AArch64 kernel header analyzer"
