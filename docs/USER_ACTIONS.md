# IzzOS — User Actions Required Later

This checklist records tasks that require the physical OnePlus 10T 5G and/or a PC. Development should continue without blocking on these items whenever possible.

## Pending — when boss is at a PC

- [ ] Connect the OnePlus 10T 5G to the PC with USB debugging enabled.
- [ ] Pull the latest `izzos-woa-foundation` branch.
- [ ] Run the read-only inspector:

  ```bash
  bash scripts/inspect-ovaltine-device.sh
  ```

- [ ] Save the output for IzzOS bring-up review.
- [ ] When instructed later, reboot to bootloader/fastboot and run the same inspector again to capture bootloader capability data.

## Important

These steps are read-only. Do not run `fastboot flash`, `fastboot erase`, `fastboot format`, `fastboot set_active`, bootloader unlock commands, or any partition-changing command unless a later IzzOS milestone explicitly documents and approves that step.

## Why this is needed

The output will confirm the exact device/firmware/slot/bootloader capabilities and determine whether a non-destructive temporary boot route such as `fastboot boot` is actually available on this exact OnePlus 10T firmware.

## Current project state

M1 remains active. Host-side build/CI, firmware research, UEFI code, and documentation can continue before this physical-device inspection is performed.
