#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

fail=0
require_text() {
  local file="$1" pattern="$2"
  if ! grep -Eq "$pattern" "$file"; then
    echo "FAIL: $file is missing pattern: $pattern" >&2
    fail=1
  fi
}

require_text "$TREE_DIR/BoardConfig.mk" 'BOARD_BOOT_HEADER_VERSION := 4'
require_text "$TREE_DIR/BoardConfig.mk" 'BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE := 201326592'
require_text "$TREE_DIR/BoardConfig.mk" 'BOARD_DTBOIMG_PARTITION_SIZE := 25165824'
require_text "$TREE_DIR/BoardConfig.mk" 'BOARD_EXCLUDE_KERNEL_FROM_RECOVERY_IMAGE := true'
require_text "$TREE_DIR/board-info.txt" 'OP5552L1'
require_text "$TREE_DIR/twrp_ovaltine.mk" 'PRODUCT_MODEL := CPH2413'
require_text "$TREE_DIR/recovery/root/system/etc/recovery.fstab" '/dev/block/bootdevice/by-name/userdata'
require_text "$TREE_DIR/scripts/make-boot-test.sh" 'Do not flash it'

if grep -RInE '(^|[[:space:]])(fastboot flash|dd if=)' "$TREE_DIR" --exclude-dir=.git; then
  echo "FAIL: an unsafe flashing command is embedded in the tree" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "Tree validation passed."
