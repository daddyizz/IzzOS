#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

FDEVICE="ovaltine"

fox_get_target_device() {
  if echo "${BASH_SOURCE[0]}" | grep -q "/${FDEVICE}/"; then
    FOX_BUILD_DEVICE="${FDEVICE}"
  fi
}

if [ -z "${FOX_BUILD_DEVICE}" ]; then
  fox_get_target_device
fi

if [ "${FOX_BUILD_DEVICE}" = "${FDEVICE}" ]; then
  export LC_ALL=C
  export ALLOW_MISSING_DEPENDENCIES=true
  export FOX_BUILD_DEVICE="${FDEVICE}"
  export FOX_BUILD_TYPE=Alpha
  export FOX_ENABLE_APP_MANAGER=1
  export FOX_USE_BASH_SHELL=1
  export FOX_ASH_IS_BASH=1
  export FOX_USE_TAR_BINARY=1
  export FOX_USE_XZ_UTILS=1
  export FOX_USE_LZ4_BINARY=1
  export FOX_USE_ZSTD_BINARY=1
  export FOX_USE_BUSYBOX_BINARY=1
  export FOX_USE_DATE_BINARY=1
  export FOX_RECOVERY_SYSTEM_PARTITION=/dev/block/mapper/system
  export FOX_RECOVERY_VENDOR_PARTITION=/dev/block/mapper/vendor
  export FOX_SETTINGS_ROOT_DIRECTORY=/data/recovery
  export FOX_MISCELLANEOUS_ROOT_DIRECTORY=/sdcard
fi
