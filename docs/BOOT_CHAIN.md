# IzzOS Boot Chain — OnePlus 10T 5G

Target: OnePlus 10T 5G (`ovaltine`) / Qualcomm SM8475.

## Intended development path

`Boot ROM -> Qualcomm/OEM signed stages -> ABL/Fastboot path -> IzzOS EDK2 payload -> EFI environment -> Windows Boot Manager -> Windows ARM64`

The stock Qualcomm boot stages remain signed and are not replaced during early bring-up. IzzOS should initially be packaged as a bootable payload that can be loaded through an unlocked boot path, following the same broad strategy used by Qualcomm phone EDK2 projects: make the custom UEFI payload acceptable to the existing boot chain as a kernel-style boot image.

## Phase A — non-destructive payload

The first hardware milestone is not Windows installation. It is a temporary EDK2 payload that:

1. is accepted by the unlocked bootloader;
2. enters AArch64 UEFI code;
3. prints a visible IzzOS bring-up marker through framebuffer and/or a debug channel;
4. enumerates a minimal memory map without writing to UFS;
5. can exit/reboot without modifying Android partitions.

## Phase B — EFI hardware services

After stable entry into UEFI:

- identify framebuffer hand-off from the OEM boot chain;
- build the SM8475 memory-region map;
- initialize timers and required interrupts;
- expose UFS safely as read-only first;
- validate USB where feasible;
- provide EFI Simple File System access to a controlled test volume.

## Phase C — Windows hand-off

Only after storage and memory-map validation:

- add ACPI tables for the minimum boot-critical hardware;
- launch Windows Boot Manager / Windows PE ARM64;
- collect boot diagnostics;
- add drivers incrementally.

## Safety gates

No repartitioning, formatting or permanent UEFI flash is part of the M0/M1 bring-up phase.

Before any destructive operation on the physical phone, require:

- verified bootloader unlock;
- backup of critical partitions and identifiers;
- tested stock restore path;
- confirmed device variant;
- repeatable temporary UEFI boot;
- documented rollback procedure.

## Known engineering risks

- SM8475 does not currently have a mature public Windows-phone EDK2 target that can simply be reused.
- Device-tree descriptions are useful references but Windows requires ACPI-facing descriptions and suitable drivers.
- GPU acceleration is a separate milestone from basic display output.
- USB, charging, thermals, cellular and camera may require substantial device-specific work even after Windows boots.
