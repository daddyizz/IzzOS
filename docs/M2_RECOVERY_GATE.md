# M2 Recovery Gate — OnePlus 10T 5G

Status: **required before first temporary launch**

This gate exists to stop M2 from advancing merely because a temporary launch command appears technically available. A launch is acceptable only when recovery and rollback are understood for the exact device/firmware.

## Required evidence

Before first M2 execution, record:

- exact OnePlus 10T variant/product;
- exact OxygenOS build;
- current A/B slot and slot count;
- bootloader lock state;
- classic fastboot versus fastbootd state;
- exact stock `boot`, `vendor_boot`, `init_boot`, `dtbo`, and `vbmeta` expectations for that firmware where applicable;
- source/location from which exact stock boot-critical images can be restored;
- documented method to return to normal stock boot if the temporary diagnostic fails;
- whether emergency download/recovery access for the exact variant is known, and whether OEM/Qualcomm authorization constraints exist;
- confirmation that the selected M2 route performs no persistent write and no slot change.

## Stop conditions

M2 launch remains blocked if any of these are true:

- device identity or firmware is ambiguous;
- only fastbootd is available and no validated temporary chain-load route exists;
- the route requires `flash`, `erase`, `format`, `set_active`, unlock, or a boot-critical partition write;
- required stock recovery images are unavailable or do not match the exact firmware;
- the recovery method depends on an unverified EDL/firehose assumption;
- the proposed package was derived from a different OnePlus 10T firmware or another Snapdragon device;
- slot behavior is unknown;
- the route cannot guarantee return to stock boot after reboot.

## Evidence record template

```text
Device model/product:
OxygenOS build:
Current slot:
Slot count:
Bootloader unlocked:
Fastboot mode:
Bootloader version:
Stock image source:
Stock boot image verified:
Stock vendor_boot verified:
Stock init_boot verified/NA:
Stock dtbo verified:
Stock vbmeta verified:
Emergency recovery status:
Temporary route candidate:
Persistent write required: NO
Slot change required: NO
Recovery procedure reference:
Decision: BLOCKED / TEMPORARY_ROUTE_VALIDATED
```

## Acceptance rule

`TEMPORARY_ROUTE_VALIDATED` may be recorded only when the exact-device capability report, package manifest and recovery evidence agree. Unlocked bootloader state alone is never sufficient.

## Relationship to milestones

- M1 may complete only after the read-only diagnostic is executed and runtime GOP/memory-map data is captured.
- M2 temporary boot development may be prepared host-side before this gate is satisfied.
- The first actual M2 launch is forbidden until this gate is satisfied.
