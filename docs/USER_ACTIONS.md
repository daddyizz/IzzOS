# IzzOS — User Actions Required Later

This checklist records tasks that require the physical OnePlus 10T 5G and/or a PC. Development should continue without blocking on these items whenever possible.

## Pending — when boss is at a PC

- [ ] Connect the OnePlus 10T 5G to the PC with USB debugging enabled.
- [ ] Pull the latest `izzos-woa-foundation` branch.
- [ ] Run the privacy-safe read-only inspector and save its output:

  ```bash
  bash scripts/inspect-ovaltine-device.sh | tee ovaltine-inspection.txt
  ```

- [ ] Analyze the captured output locally:

  ```bash
  bash scripts/analyze-ovaltine-inspection.sh ovaltine-inspection.txt
  ```

- [ ] Keep the analyzer result together with the inspection text for IzzOS bring-up review.
- [ ] When instructed later, reboot to bootloader/fastboot and run the same inspector again to capture bootloader capability data, then rerun the analyzer.

The inspector intentionally does not print raw ADB or Fastboot serial numbers. If multiple devices are connected, identity/bootloader queries are skipped rather than choosing one ambiguously.

## Analyzer classifications

The analyzer is deliberately conservative. Its main outcomes are:

- `CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED` — exact device appears to be in classic fastboot and reports unlocked, but temporary boot support is still not assumed.
- `FASTBOOTD_DETECTED_BLOCKED` — userspace fastboot was detected; classic bootloader-fastboot capability is still required.
- `LOCKED_BOOTLOADER_BLOCKED` — do not prepare unsigned temporary boot payloads.
- `TARGET_MISMATCH_BLOCKED` — stop launch preparation until the exact OnePlus 10T / `ovaltine` target is confirmed.
- `NEED_EXACT_FASTBOOT_INSPECTION` — Android-side data is useful but bootloader-side capability is still missing.
- `BOOTLOADER_STATE_UNKNOWN_BLOCKED` — required bootloader state could not be resolved.

A `CANDIDATE` classification is not permission to execute `fastboot boot`; it only identifies the next route worth validating against the exact firmware.

## Important

These steps are read-only. Do not run `fastboot flash`, `fastboot erase`, `fastboot format`, `fastboot set_active`, bootloader unlock commands, or any partition-changing command unless a later IzzOS milestone explicitly documents and approves that step.

## Why this is needed

The output will confirm the exact device/firmware/slot/bootloader capabilities and determine whether a non-destructive temporary boot route such as `fastboot boot` is actually available on this exact OnePlus 10T firmware.

## Current project state

M1 host-build tooling is complete and CI-verified. M1 remains active until the verified `OvaltineDiag.efi` is safely executed on the exact target and runtime GOP/UEFI memory-map data is captured.
