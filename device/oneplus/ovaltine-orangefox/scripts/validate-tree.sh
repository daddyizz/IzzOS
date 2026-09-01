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
require_text "$TREE_DIR/BoardConfig.mk" '^[[:space:]]+product \\'
require_text "$TREE_DIR/BoardConfig.mk" '^[[:space:]]+system \\'
require_text "$TREE_DIR/BoardConfig.mk" '^[[:space:]]+system_ext \\'
require_text "$TREE_DIR/BoardConfig.mk" 'TWRP_INCLUDE_LOGCAT := true'
require_text "$TREE_DIR/BoardConfig.mk" 'TARGET_SYSTEM_PROP \+= \$\(DEVICE_PATH\)/system.prop'
require_text "$TREE_DIR/board-info.txt" 'OP5552L1'
require_text "$TREE_DIR/twrp_ovaltine.mk" 'PRODUCT_MODEL := CPH2413'
require_text "$TREE_DIR/AndroidProducts.mk" 'twrp_ovaltine-ap2a-eng'
require_text "$TREE_DIR/recovery/root/system/etc/recovery.fstab" '/dev/block/bootdevice/by-name/userdata'
require_text "$TREE_DIR/recovery/root/system/etc/recovery.fstab" 'oplusreserve2 /mnt/vendor/oplusreserve'
require_text "$TREE_DIR/recovery/root/system/etc/recovery.fstab" 'by-name/persist /mnt/vendor/persist'
require_text "$TREE_DIR/recovery/root/init.recovery.qcom.rc" 'import /init.recovery.qcom_decrypt.rc'
require_text "$TREE_DIR/scripts/make-boot-test.sh" 'Do not flash it'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" 'clang-r510928'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" 'DROP_REPO_CACHE:-0'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" '/27/public/api/android.txt'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" '/30/public/android.jar'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" '!/tools/\*/'
require_text "$TREE_DIR/scripts/bootstrap-constrained.sh" 'Refusing non-empty directory'
require_text "$TREE_DIR/patches/constrained/soong-path-no-socket.patch" 'SetupLitePath'
require_text "$TREE_DIR/patches/constrained/host-prebuilts.patch" 'build-tools-lld-windows'

for executable in \
  "$TREE_DIR/scripts/bootstrap-constrained.sh" \
  "$TREE_DIR/scripts/build-orangefox.sh" \
  "$TREE_DIR/scripts/validate-tree.sh"; do
  if [ ! -x "$executable" ]; then
    echo "FAIL: script is not executable: $executable" >&2
    fail=1
  fi
done

stale_clang='clang-r487747''c'
if grep -RIn "$stale_clang" \
  "$TREE_DIR/scripts" "$TREE_DIR/manifests" "$TREE_DIR/patches"; then
  echo "FAIL: stale pre-QPR3 Clang revision found" >&2
  fail=1
fi

if grep -Eq 'oplusreserve2[[:space:]]+/cache' "$TREE_DIR/recovery/root/system/etc/recovery.fstab"; then
  echo "FAIL: oplusreserve2 must never be exposed as wipeable /cache" >&2
  fail=1
fi

if grep -RInE '(^|[[:space:]])(fastboot flash|dd if=)' "$TREE_DIR" --exclude-dir=.git; then
  echo "FAIL: an unsafe flashing command is embedded in the tree" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "Tree validation passed."
