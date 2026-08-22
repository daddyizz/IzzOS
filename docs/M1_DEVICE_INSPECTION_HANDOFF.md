# M1 Exact-Device Inspection Handoff

Status: **prepared; do not execute until the project explicitly reaches the physical-device inspection gate**

Target: OnePlus 10T 5G (`ovaltine`) / Qualcomm SM8475.

This handoff is intentionally read-only. It collects only the minimum device/build/boot-mode evidence required to choose the next safe temporary-route investigation. It does not flash, boot a payload, erase, format, unlock, change slots, or write partitions.

## Preconditions

Before running the inspection:

- use the exact OnePlus 10T 5G intended for IzzOS bring-up;
- keep the phone on its current OxygenOS build;
- do not update/downgrade firmware between inspection and stock-image acquisition without repeating the inspection;
- enable USB debugging only if needed for ADB inspection;
- ensure only one target Android/fastboot device is connected to avoid ambiguous identity;
- do not run broad `fastboot getvar all`.

## Stage A — Android/ADB read-only capture

From the IzzOS repository:

```bash
git switch izzos-woa-foundation
git pull
bash scripts/inspect-ovaltine-device.sh | tee ovaltine-inspection-adb.txt
bash scripts/analyze-ovaltine-inspection.sh ovaltine-inspection-adb.txt
```

Expected outcome at this stage is normally `NEED_EXACT_FASTBOOT_INSPECTION` unless fastboot evidence is already present in the capture.

## Stage B — classic bootloader/fastboot read-only capture

Only after the user intentionally reboots the phone into the normal bootloader/fastboot screen using the phone's normal reboot method or OEM UI flow, run the same inspector again:

```bash
bash scripts/inspect-ovaltine-device.sh | tee ovaltine-inspection-fastboot.txt
bash scripts/analyze-ovaltine-inspection.sh ovaltine-inspection-fastboot.txt
```

The inspector is restricted to safe capability/identity queries. Do not add flash, erase, format, unlock, boot, `set_active`, or broad `getvar all` commands.

## Evidence required before route work

The combined captures must establish, or explicitly fail to establish:

- exact model/product identifier;
- exact OxygenOS build ID;
- codename/target consistency with `ovaltine`;
- current slot where exposed;
- slot count where exposed;
- bootloader unlocked/secure state where exposed;
- whether the observed fastboot environment is classic fastboot or userspace fastbootd;
- whether more exact-device inspection is still required.

## Accepted analyzer classifications

`CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED` means only that the environment may be suitable for further temporary-route research. It does **not** mean `fastboot boot` is supported or safe for this exact firmware.

The following remain hard stops for route-specific packaging:

- `TARGET_MISMATCH_BLOCKED`
- `FASTBOOTD_DETECTED_BLOCKED`
- `LOCKED_BOOTLOADER_BLOCKED`
- `BOOTLOADER_STATE_UNKNOWN_BLOCKED`
- `NEED_EXACT_FASTBOOT_INSPECTION`
- `INSUFFICIENT_DATA`

## Privacy

Before sharing or committing inspection output, keep model/product/build/slot/boot-mode fields but redact any raw serial, IMEI/MEID, MAC address, account name, or personally identifying local path. The provided inspector is designed to avoid printing raw serials.

## What happens after a valid capture

After exact-device evidence is available, the project will decide whether it is time to acquire matching stock images from the exact official OnePlus firmware package. Do not extract `boot.img`, `vendor_boot.img`, `dtbo.img`, `vbmeta.img`, or other stock images before that request unless there is another recovery reason to do so.

No physical device launch is authorized by this handoff document.
