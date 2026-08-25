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

## Stage A — Android/ADB capture

From the IzzOS repository:

```bash
git switch izzos-woa-foundation
git pull
bash scripts/collect-m1-device-inspection.sh out/m1-device-inspection-adb
```

With the phone booted normally into OxygenOS and USB debugging authorized, the expected classification is normally:

```text
NEED_EXACT_FASTBOOT_INSPECTION
```

This is not an error. It means Android-side identity/build evidence was captured but classic bootloader-fastboot evidence is still missing.

## Stage B — classic bootloader/fastboot capture

Only after intentionally entering the phone's normal bootloader/fastboot screen using the device's normal reboot method or OEM UI flow, run:

```bash
bash scripts/collect-m1-device-inspection.sh out/m1-device-inspection-fastboot
```

The collector queries only product, current slot, slot count, unlocked state, secure state, userspace-fastboot state and bootloader version. It intentionally does not use broad `fastboot getvar all`.

## Stage C — merge both captures into canonical evidence

After both capture directories exist, run:

```bash
bash scripts/merge-m1-device-inspections.sh \
  out/m1-device-inspection-adb \
  out/m1-device-inspection-fastboot \
  out/m1-exact-device-evidence
```

Expected successful output file:

```text
out/m1-exact-device-evidence/
  M1_EXACT_DEVICE_EVIDENCE.txt
  SHA256SUMS
```

The merger checks the fields that can safely be compared across the two phases. It requires both captures to positively match `ovaltine`, requires an exact Android-side build ID, blocks contradictory build IDs when fastboot exposes one, and blocks contradictory slot observations after normalizing `_a`/`a` and `_b`/`b` forms.

Expected successful classification:

```text
Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
```

This classification means the supplied capture pair is internally consistent on the target/build/slot fields available to us. It does **not** prove physical identity by a hidden serial number and it does not authorize launch or packaging.

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

Every collector bundle and the merged canonical evidence include SHA256 checksums so evidence can be preserved unchanged for later route/recovery decisions.

## Accepted analyzer classifications

`CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED` means only that the environment may be suitable for further temporary-route research. It does **not** mean temporary boot is supported or safe for this exact firmware.

The following remain hard stops for route-specific packaging:

- `DEVICE_TOOLCHAIN_REQUIRED`
- `DEVICE_CONNECTION_REQUIRED`
- `ADB_AUTHORIZATION_REQUIRED`
- `DEVICE_SELECTION_AMBIGUOUS_BLOCKED`
- `TARGET_MISMATCH_BLOCKED`
- `FASTBOOTD_DETECTED_BLOCKED`
- `LOCKED_BOOTLOADER_BLOCKED`
- `BOOTLOADER_STATE_UNKNOWN_BLOCKED`
- `NEED_EXACT_FASTBOOT_INSPECTION`
- `INSUFFICIENT_DATA`
- `M1_EXACT_DEVICE_EVIDENCE_BLOCKED`

The first four classifications are attendance states rather than device failures. They distinguish a missing host tool, disconnected phone, unapproved USB-debugging fingerprint and ambiguous multi-device connection. `NEED_EXACT_FASTBOOT_INSPECTION` means Android identity is available but a person at the phone must still enter classic bootloader-fastboot before the same read-only collector is rerun. None of these states authorizes `adb reboot`, `fastboot boot`, flashing, unlocking or slot changes.

## Privacy

Before sharing or committing inspection output, keep model/product/build/slot/boot-mode fields but redact any raw serial, IMEI/MEID, MAC address, account name, or personally identifying local path. The provided inspector is designed to avoid printing raw serials.

## What to send back for analysis

When the physical inspection gate is reached, the preferred handoff is:

- `out/m1-device-inspection-adb/`
- `out/m1-device-inspection-fastboot/`
- `out/m1-exact-device-evidence/M1_EXACT_DEVICE_EVIDENCE.txt`
- `out/m1-exact-device-evidence/SHA256SUMS`

Do not manually edit the evidence files after capture; if redaction is needed for public sharing, preserve the original privately and make a separate redacted copy.

## What happens after a valid capture

After exact-device evidence is available, the project will decide whether it is time to acquire matching stock images from the exact official OnePlus firmware package. Do not extract `boot.img`, `vendor_boot.img`, `dtbo.img`, `vbmeta.img`, or other stock images before that request unless there is another recovery reason to do so.

No physical device launch is authorized by this handoff document.
