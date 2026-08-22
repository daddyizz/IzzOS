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

## Preferred one-command collector

From the IzzOS repository:

```bash
git switch izzos-woa-foundation
git pull
bash scripts/collect-m1-device-inspection.sh
```

Default evidence output:

```text
out/m1-device-inspection/
  ovaltine-inspection.txt
  ovaltine-inspection-analysis.txt
  INSPECTION_SUMMARY.txt
  SHA256SUMS
```

The collector runs only the existing privacy-safe inspector and offline analyzer. It does not reboot the phone or execute any boot/flash/unlock/slot-changing command.

## Stage A — Android/ADB capture

With the phone booted normally into OxygenOS and USB debugging authorized, run the collector once.

The expected classification is normally:

```text
NEED_EXACT_FASTBOOT_INSPECTION
```

This is not an error. It means Android-side identity/build evidence was captured but classic bootloader-fastboot evidence is still missing.

Keep this first output directory as evidence. If desired, provide a custom directory:

```bash
bash scripts/collect-m1-device-inspection.sh out/m1-device-inspection-adb
```

## Stage B — classic bootloader/fastboot capture

Only after intentionally entering the phone's normal bootloader/fastboot screen using the device's normal reboot method or OEM UI flow, run the collector again into a second directory:

```bash
bash scripts/collect-m1-device-inspection.sh out/m1-device-inspection-fastboot
```

The collector queries only:

- product;
- current slot;
- slot count;
- unlocked state;
- secure state;
- userspace-fastboot state;
- bootloader version.

It intentionally does not use broad `fastboot getvar all`.

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

Every collector bundle includes SHA256 checksums so evidence can be preserved unchanged for later route/recovery decisions.

## Accepted analyzer classifications

`CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED` means only that the environment may be suitable for further temporary-route research. It does **not** mean temporary boot is supported or safe for this exact firmware.

The following remain hard stops for route-specific packaging:

- `TARGET_MISMATCH_BLOCKED`
- `FASTBOOTD_DETECTED_BLOCKED`
- `LOCKED_BOOTLOADER_BLOCKED`
- `BOOTLOADER_STATE_UNKNOWN_BLOCKED`
- `NEED_EXACT_FASTBOOT_INSPECTION`
- `INSUFFICIENT_DATA`

## Privacy

Before sharing or committing inspection output, keep model/product/build/slot/boot-mode fields but redact any raw serial, IMEI/MEID, MAC address, account name, or personally identifying local path. The provided inspector is designed to avoid printing raw serials.

## What to send back for analysis

When the physical inspection gate is reached, the useful handoff is the two evidence directories (or at minimum these files from each capture):

- `ovaltine-inspection.txt`
- `ovaltine-inspection-analysis.txt`
- `INSPECTION_SUMMARY.txt`
- `SHA256SUMS`

Do not manually edit the evidence files after capture; if redaction is needed for public sharing, preserve the original privately and make a separate redacted copy.

## What happens after a valid capture

After exact-device evidence is available, the project will decide whether it is time to acquire matching stock images from the exact official OnePlus firmware package. Do not extract `boot.img`, `vendor_boot.img`, `dtbo.img`, `vbmeta.img`, or other stock images before that request unless there is another recovery reason to do so.

No physical device launch is authorized by this handoff document.
