# OnePlus 10T / Ovaltine Boot Image Format Notes

Status: **source-backed preparation; exact stock firmware still must be verified**

This document records boot-image properties derived from the current public OnePlus 10T (`ovaltine`) Lineage device configuration. These values are useful for pre-M2 packaging research, but they are **not** a substitute for inspecting the exact stock firmware image from the physical test device.

## Source-backed properties

The `ovaltine` device BoardConfig includes `device/oneplus/sm8450-common/BoardConfigCommon.mk` without overriding the common boot header, page size, boot-image or vendor-boot settings.

Current common configuration states:

- architecture: ARM64
- A/B OTA layout enabled
- A/B set includes `boot`, `dtbo`, `recovery`, `vbmeta`, `vendor_boot` and related partitions
- Android boot header version: **4**
- kernel page size: **4096 bytes**
- kernel image name: `Image`
- Generic Kernel Image (GKI): enabled
- boot image includes DTB: enabled
- separate DTBO image: required
- vendor boot image: present
- ramdisk compression: LZ4
- boot image partition size: **201326592 bytes** (192 MiB)
- vendor_boot partition size: **201326592 bytes** (192 MiB)
- dtbo partition size: **25165824 bytes** (24 MiB)
- recovery partition size: **104857600 bytes** (100 MiB)
- flash block size: **262144 bytes**
- AVB: enabled

The device-specific `ovaltine/BoardConfig.mk` inherits those settings and adds only device-specific kernel config, dynamic-partition sizing, product reserve sizing, vendor properties and recovery UI margin. It does not override the boot-header version or page size.

## Important naming note

The public Lineage common tree is named `sm8450-common` and reports the Android board platform as `taro`. That source-tree naming must not be interpreted as the physical SoC identity of the OnePlus 10T. The physical OnePlus 10T target remains Snapdragon 8+ Gen 1 / **SM8475** (`cape` in the OnePlus-published Qualcomm device-tree source).

## What is safe to assume for host-side preparation

Before exact firmware inspection, IzzOS may use these values only as **expected metadata**:

- expect boot header v4;
- expect 4 KiB kernel page size;
- expect GKI-style boot + vendor_boot split;
- expect a distinct DTBO partition;
- expect AVB-protected boot-chain components;
- expect A/B slot semantics.

These expectations are useful for validating an extracted stock image. They must not directly authorize a launch command or partition write.

## What remains device-gated

Before any route-specific packaging or temporary launch attempt, verify against the exact stock firmware used by the physical phone:

1. extracted `boot.img` header version;
2. extracted `vendor_boot.img` header version and fragment layout;
3. exact DTB/DTBO placement;
4. exact kernel/ramdisk compression and sizes;
5. exact AVB footer/descriptor state;
6. exact active slot and matching stock image set;
7. whether classic fastboot accepts a non-persistent temporary boot operation on that firmware.

Any mismatch between stock metadata and the source-backed expectations above is a **hard stop** for automatic packaging.

## M2 packaging rule

`OvaltineDiag.efi` must never be wrapped using assumptions copied from an older Snapdragon device. A route-specific package may be produced only from a validated template derived from the exact stock image format and only after the M2 recovery gate is satisfied.
