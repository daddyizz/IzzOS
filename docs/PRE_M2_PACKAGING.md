# Pre-M2 Temporary Launch Packaging Contract

Status: **host-side preparation only / no device route selected**

This document defines what an IzzOS temporary launch package must guarantee before M2 can begin on the exact OnePlus 10T 5G test device.

## Purpose

`OvaltineDiag.efi` is a verified ARM64 UEFI application, but it is not by itself an Android boot image and must not be flashed directly to any phone partition.

The packaging layer is deliberately route-neutral until exact-device inspection proves which temporary launch mechanism exists on the target firmware.

## Required inputs before route-specific packaging

- exact OnePlus 10T product/model and OxygenOS build;
- current A/B slot;
- bootloader lock state;
- classic bootloader fastboot versus fastbootd state;
- exact stock boot/vendor_boot format for that firmware;
- stock boot-critical image backups or reproducible extraction source;
- documented recovery path back to stock boot;
- explicit evidence that the chosen launch route is temporary and does not require a persistent partition write.

## Packaging invariants

Any future M2 package must:

1. embed or chain-load the already verified `OvaltineDiag.efi` payload;
2. preserve the payload SHA256 in package metadata;
3. identify the exact stock firmware/build it was derived from;
4. never reuse boot-header offsets or addresses copied from an older Snapdragon target;
5. contain no partition flashing command;
6. contain no slot-changing command;
7. contain no bootloader unlock command;
8. fail closed when the detected device/firmware does not match its manifest;
9. provide a dry-run/inspection mode before any launch operation;
10. leave stock boot intact after a reboot.

## Route-neutral package layout

A future generated package should use a structure similar to:

```text
out/m2-launch/<firmware-id>/
  manifest.txt
  payload/
    OvaltineDiag.efi
    SHA256SUMS
  derived/
    <route-specific temporary image or chain-load files>
  logs/
    packaging-report.txt
```

`derived/` must remain empty until exact-device inspection selects and validates a route.

## Manifest minimum fields

- IzzOS source revision
- EDK2 revision
- `OvaltineDiag.efi` SHA256
- target model/product
- target OxygenOS build
- expected slot topology
- expected bootloader mode
- selected launch route
- persistent writes: `FORBIDDEN`
- route validation evidence reference

## Route decision states

- `BLOCKED_TARGET_MISMATCH`
- `BLOCKED_BOOTLOADER_LOCKED`
- `BLOCKED_FASTBOOTD_ONLY`
- `INSUFFICIENT_DEVICE_DATA`
- `CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED`
- `CHAINLOAD_CANDIDATE_UNVERIFIED`
- `TEMPORARY_ROUTE_VALIDATED`

Only `TEMPORARY_ROUTE_VALIDATED` may advance to an actual M2 launch package.

## Rollback acceptance gate

Before first launch, IzzOS must be able to answer all of these with evidence:

- How does the phone return to stock boot after a failed diagnostic launch?
- Which stock images/build are required for recovery?
- Does the launch touch slot metadata?
- Does it write boot, vendor_boot, init_boot, dtbo, vbmeta, abl, xbl, or any other persistent partition?
- Is emergency recovery for the exact variant understood well enough to stop if the temporary route behaves unexpectedly?

If any answer is unknown, the launch stays blocked.

## M2 entry condition

M2 begins only after exact-device inspection plus route research produces `TEMPORARY_ROUTE_VALIDATED`. Until then, this document is a packaging contract, not a launch instruction.
