# IzzOS

**Full Windows. Pocket Size.**

IzzOS is an experimental Windows-on-ARM platform project focused on bringing a real Windows ARM64 environment to the OnePlus 10T 5G (`ovaltine`, Snapdragon 8+ Gen 1 / SM8475).

The project is not an Android launcher and is not an Android ROM. The current direction is a real Windows ARM64 boot path using EDK2/UEFI, platform bring-up, ACPI/device support, drivers, tooling, recovery-aware install flows, and Windows-side optimization.

## Core Principle

> **Minimum OS overhead. Maximum Windows compatibility.**

IzzOS aims to keep Windows as lightweight as safely possible without breaking compatibility with normal Windows ARM64 software, x64 translation, heavy desktop applications, and eventually DirectX gaming.

## Reference Device

- **Device:** OnePlus 10T 5G
- **Codename:** `ovaltine`
- **SoC:** Qualcomm Snapdragon 8+ Gen 1 / SM8475
- **GPU:** Adreno 730
- **Storage:** UFS 3.1

## What IzzOS Includes

IzzOS is the platform and integration layer around a legally user-sourced Windows ARM64 installation. The repository may contain:

- EDK2 / UEFI platform code
- ACPI tables and platform description work
- device bring-up code
- boot diagnostics
- hardware resource manifests
- Windows driver integration work
- install / recovery tooling
- performance and compatibility profiles

Microsoft Windows images, product keys, or other proprietary Microsoft files are **not redistributed** by this project.

## Current Milestone

### M1 — Non-Destructive UEFI Diagnostic Payload

Current work is focused on building the first AARCH64 UEFI diagnostic application for the OnePlus 10T platform.

The diagnostic payload is designed to:

- run without writing to UFS storage
- inspect the active UEFI memory map
- detect GOP / framebuffer information supplied by firmware
- avoid guessed MMIO addresses
- avoid destructive partition or bootloader changes

The first successful on-device goal is a temporary diagnostic launch that proves UEFI execution and captures real runtime platform information.

## Milestone Roadmap

1. **M0 — Hardware & Platform Map**
2. **M1 — Non-Destructive UEFI Diagnostic Payload** ← current
3. **M2 — Temporary UEFI Boot on OnePlus 10T**
4. **M3 — Stable Display + Debug Output**
5. **M4 — UFS Read Access in EFI**
6. **M5 — Windows PE ARM64 Boot**
7. **M6 — Windows ARM64 Full Boot**
8. **M7 — Core Device Drivers**
9. **M8 — GPU Acceleration / Adreno 730**
10. **M9 — Windows Compatibility Validation**
11. **M10 — Performance & Thermal Tuning**
12. **M11 — IzzOS Lightweight Windows Profile**
13. **M12 — AAA Gaming Validation**
14. **M13 — Phone/Desktop Experience**
15. **M14 — Installer / Recovery / Update System**
16. **M15 — Release Candidate**
17. **M16 — IzzOS 1.0 Final**

M8 is a separable GPU track and may be paused after M7 while M9A validates non-GPU Windows compatibility. GPU-dependent M9B, hardware-accelerated workloads, M12 gaming validation and the corresponding final-release claims remain blocked until M8 is resumed and passes.

## Safety Rules

Until the relevant platform stages are validated:

- destructive flashing is forbidden
- UFS writes are forbidden
- guessed MMIO / PCD values are forbidden
- framebuffer addresses from older Qualcomm targets must not be copied blindly
- exact-device runtime validation is required before turning discovered resources into active firmware constants

## Gaming Goal

The long-term target is to support full Windows desktop software and, where driver compatibility allows it, demanding DirectX games.

The biggest technical dependency is Windows GPU acceleration for the Adreno 730. Until a workable Windows graphics path exists, AAA gaming remains a later milestone rather than a current capability.

## Monetization Direction

The IzzOS firmware, UEFI core, and desktop core will remain ad-free.

If monetization is added later, it should live in optional Windows-side companion applications such as:

- IzzOS Control Center
- Driver & Update Manager
- Game Compatibility Hub
- Themes / Store

The core OS experience should stay lightweight and free from desktop, lock-screen, firmware, or gaming-session ads.

## Status

**Project stage:** Early platform bring-up  
**Current milestone:** M1 — Non-Destructive UEFI Diagnostic Payload  
**Internal engineering checkpoint:** M12 signed temporary-route attestation gate implemented; product M1 awaits exact stock acceptance, genuine route evidence and governed independent-attester trust<br>
**Reference target:** OnePlus 10T 5G / `ovaltine` / SM8475

This project is experimental. Do not flash or repartition a device based on incomplete bring-up work.

## Legacy Prototype

The repository history contains an earlier Android desktop-launcher prototype. That prototype is no longer the main IzzOS direction and will be retained only as archived historical work.
