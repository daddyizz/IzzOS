# SPDX-License-Identifier: Apache-2.0

PRODUCT_RELEASE_NAME := ovaltine
DEVICE_PATH := device/oneplus/ovaltine

$(call inherit-product, $(SRC_TARGET_DIR)/product/base.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, vendor/twrp/config/common.mk)
$(call inherit-product, $(DEVICE_PATH)/device.mk)
$(call inherit-product-if-exists, $(DEVICE_PATH)/fox_ovaltine.mk)

PRODUCT_DEVICE := ovaltine
PRODUCT_NAME := twrp_ovaltine
PRODUCT_BRAND := OnePlus
PRODUCT_MODEL := CPH2413
PRODUCT_MANUFACTURER := OnePlus
