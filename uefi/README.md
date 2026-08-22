# IzzOS UEFI Bring-up

This directory is the staging area for the OnePlus 10T 5G (`ovaltine`) EDK2 port.

## Upstream strategy

The project will study and selectively adapt concepts from `edk2-porting/edk2-msm`, but will not pretend that an SDM845 or older Qualcomm platform definition is compatible with SM8475.

The first platform implementation must derive its own:

- physical memory map;
- reserved-memory exclusions;
- framebuffer information;
- timer/GIC setup assumptions;
- UFS/USB requirements;
- ACPI tables;
- Windows-facing device resource descriptions.

## Source-of-truth hierarchy

1. OnePlus SM8475 kernel source.
2. OnePlus SM8475 kernel modules/device-tree source.
3. `ovaltine` community device configuration for cross-checking partitions and device-specific details.
4. Existing Qualcomm EDK2 projects for architecture and boot-image techniques only.

## First payload definition

The initial payload is intentionally small. A successful M1 build should only need to:

- enter UEFI reliably;
- preserve the OEM-provided framebuffer when possible;
- show an IzzOS diagnostic screen or shell;
- provide a trustworthy memory map;
- avoid writes to internal storage;
- reboot cleanly.

Windows Boot Manager integration is explicitly deferred until the M1 payload is repeatable.

## Planned tree

```text
uefi/
  Platform/IzzOS/OvaltinePkg/
    Ovaltine.dsc
    Ovaltine.fdf
    Include/
    Library/
    AcpiTables/
  Silicon/Qualcomm/SM8475/
    Include/
    Library/
```

These package directories will be introduced as hardware constants are verified. Placeholder MMIO addresses must not be committed as if they were validated values.

## Build policy

- AArch64 only.
- Debug-first builds during bring-up.
- Warnings treated seriously.
- No destructive device operation embedded in build scripts.
- Build output must identify git revision and target device.
- Release images are not produced until temporary boot has been validated on real hardware.
