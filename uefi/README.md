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

## Current diagnostic scaffold

`Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag/` contains the first read-only UEFI diagnostic application.

Its current responsibilities are deliberately limited to standard UEFI protocols:

- print target and safety state to the firmware console;
- locate `EFI_GRAPHICS_OUTPUT_PROTOCOL` and report the runtime framebuffer base, size, resolution and pixel format when GOP is already provided by the boot firmware;
- call `GetMemoryMap()` and print the firmware-provided memory descriptors;
- wait for a key and return cleanly to the calling firmware environment.

The application intentionally does **not**:

- call `ExitBootServices()`;
- access `EFI_BLOCK_IO_PROTOCOL` or `EFI_DISK_IO_PROTOCOL`;
- write files or partitions;
- program UFS/ICE/HWKM registers;
- hard-code a framebuffer address;
- enable clocks, regulators or interconnects using guessed MMIO values.

`OvaltineDiag.dsc` is a minimal AArch64 DSC intended only to compile this diagnostic application inside a normal EDK2 workspace. It is **not** yet an Ovaltine firmware image and does not claim to contain SM8475 hardware initialization.

## Reproducible host build

The host build is pinned to EDK2 revision:

`d98a39d4ceeb7204b33fc330fdfee8cdb5ddbb43`

The pinned upstream revision is intentional: EDK2 toolchain definitions change over time, and current upstream uses the `GCC` toolchain tag rather than the removed legacy `GCC5` tag.

On an Ubuntu/Debian-like development host with an AArch64 GNU cross compiler installed:

```bash
bash scripts/build-ovaltine-diag.sh
```

The script:

1. fetches/checks out the pinned EDK2 revision;
2. initializes EDK2 submodules;
3. copies the IzzOS platform package into the EDK2 workspace;
4. builds BaseTools;
5. configures `GCC_AARCH64_PREFIX=aarch64-linux-gnu-` by default;
6. compiles the DEBUG AARCH64 diagnostic application;
7. copies `OvaltineDiag.efi` and `BUILD_INFO.txt` into `out/ovaltine-diag/`.

GitHub Actions runs the same build through `.github/workflows/uefi-ovaltine-diag.yml` and uploads the resulting EFI file as the `OvaltineDiag-AARCH64` artifact when successful.

A successful host build proves only that the diagnostic EFI application compiles. It does **not** prove that the OnePlus 10T boot chain can launch it, nor does it authorize flashing the phone.

## Planned tree

```text
uefi/
  Platform/IzzOS/OvaltinePkg/
    OvaltineDiag.dsc
    Applications/
      OvaltineDiag/
        OvaltineDiag.inf
        OvaltineDiag.c
    Ovaltine.dsc          # future full platform DSC
    Ovaltine.fdf          # future full firmware image definition
    Include/
    Library/
    AcpiTables/
  Silicon/Qualcomm/SM8475/
    Include/
    Library/
```

Full package directories will be introduced only as hardware constants are verified. Placeholder MMIO addresses must not be committed as if they were validated values.

## Build policy

- AArch64 only.
- Debug-first builds during bring-up.
- Pin external build inputs until deliberately upgraded.
- Warnings treated seriously.
- No destructive device operation embedded in build scripts.
- Build output identifies IzzOS and EDK2 revisions.
- Release images are not produced until temporary boot has been validated on real hardware.
