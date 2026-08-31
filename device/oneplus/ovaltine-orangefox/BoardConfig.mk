# SPDX-License-Identifier: Apache-2.0

DEVICE_PATH := device/oneplus/ovaltine

# Architecture
TARGET_ARCH := arm64
TARGET_ARCH_VARIANT := armv8-2a-dotprod
TARGET_CPU_ABI := arm64-v8a
TARGET_CPU_ABI2 :=
TARGET_CPU_VARIANT := generic
TARGET_CPU_VARIANT_RUNTIME := kryo300
TARGET_SUPPORTS_64_BIT_APPS := true
TARGET_IS_64_BIT := true

# Bootloader / platform
TARGET_BOOTLOADER_BOARD_NAME := taro
TARGET_BOARD_PLATFORM := taro
TARGET_NO_BOOTLOADER := true
TARGET_USES_UEFI := true

# A/B layout
AB_OTA_UPDATER := true
AB_OTA_PARTITIONS += \
    xbl_ramdump \
    abl \
    aop \
    aop_config \
    bluetooth \
    boot \
    cpucp \
    devcfg \
    dsp \
    dtbo \
    engineering_cdt \
    featenabler \
    hyp \
    imagefv \
    keymaster \
    modem \
    oplus_sec \
    oplusstanvbk \
    qupfw \
    recovery \
    shrm \
    splash \
    tz \
    uefi \
    uefisecapp \
    vbmeta \
    vbmeta_system \
    vbmeta_vendor \
    vendor_boot \
    xbl \
    xbl_config \
    vendor \
    vendor_dlkm \
    odm \
    odm_dlkm \
    my_product \
    my_engineering \
    my_stock \
    my_company \
    my_carrier \
    my_region \
    my_bigball \
    my_heytap \
    my_preload \
    my_manifest

# Kernel and boot image (stock prebuilts imported by scripts/import-stock.sh)
BOARD_BOOT_HEADER_VERSION := 4
BOARD_KERNEL_BASE := 0x00000000
BOARD_KERNEL_PAGESIZE := 4096
BOARD_KERNEL_IMAGE_NAME := Image
BOARD_KERNEL_CMDLINE := video=vfb:640x400,bpp=32,memsize=3072000
BOARD_BOOTCONFIG := androidboot.hardware=qcom androidboot.memcg=1 androidboot.usbcontroller=a600000.dwc3
BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)
BOARD_RAMDISK_USE_LZ4 := true
TARGET_PREBUILT_KERNEL := $(DEVICE_PATH)/prebuilt/kernel
BOARD_PREBUILT_DTBIMAGE_DIR := $(DEVICE_PATH)/prebuilt/dtbs
BOARD_PREBUILT_DTBOIMAGE := $(DEVICE_PATH)/prebuilt/dtbo.img
BOARD_INCLUDE_DTB_IN_BOOTIMG := true

# Exact CPH2413 / OP5552L1 stock partition sizes
BOARD_FLASH_BLOCK_SIZE := 262144
BOARD_BOOTIMAGE_PARTITION_SIZE := 201326592
BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE := 201326592
BOARD_DTBOIMG_PARTITION_SIZE := 25165824
BOARD_RECOVERYIMAGE_PARTITION_SIZE := 104857600
BOARD_SUPER_PARTITION_SIZE := 11274289152
BOARD_ONEPLUS_DYNAMIC_PARTITIONS_SIZE := 5637144572
BOARD_SUPER_PARTITION_GROUPS := oneplus_dynamic_partitions
BOARD_ONEPLUS_DYNAMIC_PARTITIONS_PARTITION_LIST := \
    odm odm_dlkm product system system_ext vendor vendor_dlkm \
    my_product my_engineering my_stock my_company my_carrier my_region \
    my_bigball my_heytap my_preload my_manifest

TARGET_COPY_OUT_ODM := odm
TARGET_COPY_OUT_ODM_DLKM := odm_dlkm
TARGET_COPY_OUT_PRODUCT := product
TARGET_COPY_OUT_SYSTEM_EXT := system_ext
TARGET_COPY_OUT_VENDOR := vendor
TARGET_COPY_OUT_VENDOR_DLKM := vendor_dlkm

BOARD_ODMIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_ODM_DLKMIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_SYSTEM_EXTIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_VENDOR_DLKMIMAGE_FILE_SYSTEM_TYPE := ext4

# Filesystems / metadata
TARGET_USERIMAGES_USE_EXT4 := true
TARGET_USERIMAGES_USE_F2FS := true
BOARD_USES_METADATA_PARTITION := true

# Recovery is a dedicated ramdisk partition on ovaltine. The running kernel and
# first-stage vendor ramdisk continue to come from the matching stock slot.
BOARD_EXCLUDE_KERNEL_FROM_RECOVERY_IMAGE := true
TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery/root/system/etc/recovery.fstab
TARGET_RECOVERY_PIXEL_FORMAT := RGBX_8888
TARGET_RECOVERY_UI_MARGIN_HEIGHT := 103
TARGET_BOARD_INFO_FILE := $(DEVICE_PATH)/board-info.txt

# Recovery features
TW_THEME := portrait_hdpi
TW_FRAMERATE := 120
TW_NO_SCREEN_BLANK := true
TW_EXTRA_LANGUAGES := true
TW_INCLUDE_NTFS_3G := true
TW_INCLUDE_RESETPROP := true
TW_INCLUDE_LIBRESETPROP := true
TW_INCLUDE_LPTOOLS := true
TW_INCLUDE_LOGCAT := true
TARGET_USES_LOGD := true
TARGET_USES_MKE2FS := true
TW_EXCLUDE_APEX := true
TW_EXCLUDE_DEFAULT_USB_INIT := true
RECOVERY_SDCARD_ON_DATA := true
TW_BRIGHTNESS_PATH := /sys/class/backlight/panel0-backlight/brightness
TW_MAX_BRIGHTNESS := 4095
TW_DEFAULT_BRIGHTNESS := 200
TW_NO_HAPTICS := true

# Android 15 FBE bring-up. Decryption must be validated on-device before this
# tree is considered stable.
TW_INCLUDE_CRYPTO := true
TW_INCLUDE_CRYPTO_FBE := true
TW_INCLUDE_FBE_METADATA_DECRYPT := true
TW_USE_FSCRYPT_POLICY := 2
BOARD_USES_QCOM_FBE_DECRYPTION := true

# Build-system compatibility for recovery-only trees
ALLOW_MISSING_DEPENDENCIES := true
BUILD_BROKEN_DUP_RULES := true
BUILD_BROKEN_ELF_PREBUILT_PRODUCT_COPY_FILES := true
BUILD_BROKEN_MISSING_REQUIRED_MODULES := true

# AVB: generate test-signed artifacts only. Never flash a generated vbmeta.
BOARD_AVB_ENABLE := true
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3

PLATFORM_SECURITY_PATCH := 2026-06-01
BOOT_SECURITY_PATCH := $(PLATFORM_SECURITY_PATCH)
VENDOR_SECURITY_PATCH := $(PLATFORM_SECURITY_PATCH)
