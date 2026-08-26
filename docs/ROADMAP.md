# IzzOS Windows-on-ARM Roadmap

## Phase 0 — Platform foundation

- Lock reference device to OnePlus 10T 5G (`ovaltine`).
- Record exact commercial variant before any flashing work.
- Collect official SM8475 kernel and device-tree sources.
- Map boot chain, A/B partitions, super/dynamic partitions and recovery path.
- Preserve stock boot/ABL/recovery artifacts for rollback.

Exit condition: documented recovery path and verified source map.

## Phase 1 — First UEFI boot

- Create an EDK2 platform package for `ovaltine`/SM8475.
- Implement early UART/logging where practical.
- Bring up basic framebuffer/display output.
- Implement enough storage access to locate EFI payloads.
- Prefer temporary/test boot paths before writing persistent firmware.

Exit condition: device reaches an IzzOS/EDK2 UEFI screen or shell without Android running.

## Phase 2 — Windows PE / installer boot

- Define ACPI tables required by Windows ARM64.
- Expose CPU, timers, interrupt controller and storage correctly.
- Boot Windows PE ARM64.
- Validate USB input and basic filesystem access.

Exit condition: Windows PE reaches a usable UI.

## Phase 3 — Core device enablement

Priority order:

1. UFS/storage
2. USB
3. touchscreen
4. battery telemetry and charging
5. display/GPU acceleration
6. Wi-Fi
7. Bluetooth
8. audio
9. sensors
10. cellular/modem, if realistically supportable

Exit condition: Windows is usable as a portable PC for normal desktop workloads.

## Phase 4 — Performance and compatibility

- Validate Windows ARM64 x64/x86 emulation.
- Tune power plans for phone thermals.
- Reduce safe background overhead without deleting compatibility-critical Windows components.
- Measure idle RAM, idle CPU, boot time and storage footprint.
- Add an IzzOS Performance Mode for sustained CPU/GPU workloads.

Exit condition: repeatable performance profile suitable for heavy desktop software.

## Phase 5 — Gaming

- Validate Adreno GPU driver path and DirectX feature level.
- Test representative ARM64, x64 DX11 and DX12 applications.
- Document anti-cheat and driver limitations rather than bypassing them.
- Benchmark thermals, sustained clocks, battery drain and external-display performance.

Exit condition: evidence-based compatibility matrix for modern PC games, including AAA titles where technically possible.

## Phase 6 — Companion experience and monetization

- Keep the firmware, UEFI, boot path and Windows desktop core completely ad-free.
- Do not add advertising code to EDK2, boot services, the lock screen, desktop shell, Start menu, or gaming path.
- Build optional IzzOS companion software only after the Windows platform is stable enough for daily use.
- Candidate companion components include IzzOS Control Center, Driver & Update Manager, Game Compatibility Hub, themes/wallpapers, and setup helpers.
- If monetization is added, use an ad or sponsor system that officially supports the chosen Windows/web companion technology rather than forcing mobile-only SDKs into the OS.
- Offer an optional Premium/ad-free tier only at the companion layer; core OS functionality must not depend on ads.
- Measure companion CPU, memory, network and startup overhead and keep it disabled from critical boot/performance paths.

Exit condition: monetization is optional, policy-compatible, measurable, and has no material impact on boot, gaming or core Windows performance.

## Project principle

**Minimum OS overhead, maximum Windows compatibility.**

IzzOS will not chase a tiny install size by removing components that commonly break drivers, servicing, application installers, emulation or gaming dependencies.

Monetization must never compromise this principle: the IzzOS boot stack and core Windows experience remain ad-free.
