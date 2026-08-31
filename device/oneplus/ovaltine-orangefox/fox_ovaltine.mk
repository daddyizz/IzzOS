# SPDX-License-Identifier: GPL-3.0-or-later

OF_ENABLE_LPTOOLS := 1
OF_ENABLE_ALL_PARTITION_TOOLS := 1
OF_PATCH_AVB20 := 1
OF_KEEP_DM_VERITY := 1
OF_USE_DMCTL := 1
OF_USE_LZMA_COMPRESSION := 1
OF_DONT_PATCH_ENCRYPTED_DEVICE := 1
OF_NO_TREBLE_COMPATIBILITY_CHECK := 1
OF_QUICK_BACKUP_LIST := /boot;/dtbo;/recovery;/vendor_boot;/data;

OF_SCREEN_H := 2412
OF_STATUS_H := 103
OF_STATUS_INDENT_LEFT := 48
OF_STATUS_INDENT_RIGHT := 48
OF_HIDE_NOTCH := 1
OF_CLOCK_POS := 1
OF_OPTIONS_LIST_NUM := 9

# Keep the first release conservative. OTA-survival and automatic system
# patching stay disabled until boot, touch, storage and FBE are verified.
OF_DISABLE_MIUI_OTA_BY_DEFAULT := 1
OF_SPLASH_MAX_SIZE := 130
