# IzzOS

**Full Windows. Pocket Size.**

IzzOS is an experimental Windows-on-ARM project targeting the **OnePlus 10T 5G (`ovaltine`)**. The project goal is to boot a real Windows ARM64 environment on the phone, while keeping OS overhead as low as practical without breaking compatibility with demanding desktop software and games.

## Mission

- Replace Android as the primary runtime on the target device.
- Boot real Windows ARM64 through a device-specific UEFI/EDK2 path.
- Preserve maximum Windows application compatibility.
- Optimize background services, startup behavior, storage usage and power profiles instead of aggressively stripping core Windows components.
- Work toward usable GPU acceleration, DirectX support, x64/x86 emulation, external-display use, keyboard/mouse support and high-performance workloads.

## Reference device

- Device: OnePlus 10T 5G
- Codename: `ovaltine`
- SoC family: Qualcomm SM8475 / Snapdragon 8+ Gen 1
- GPU: Adreno 730
- Primary objective: native Windows ARM64 boot and device enablement

## Current project stage

**Phase 0 — Platform research and WOA foundation**

The old Android desktop-launcher prototype is deprecated. It remains in Git history only as the original concept proof and is no longer the development direction.

Current work is focused on:

1. mapping the OnePlus 10T boot chain and partitions;
2. studying available SM8475 kernel/device-tree sources;
3. establishing the EDK2/UEFI port structure;
4. defining ACPI and Windows driver requirements;
5. reaching a safe first UEFI boot before any destructive repartitioning or Windows deployment.

See `docs/ROADMAP.md`, `docs/DEVICE_OVALTINE.md`, and `docs/ARCHITECTURE.md`.

## Safety rule

No flashing, repartitioning, bootloader replacement, or destructive device changes should be performed until a tested recovery path and exact device variant are documented.
