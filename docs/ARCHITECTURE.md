# IzzOS Architecture

## Goal

IzzOS is not an Android launcher and not an Android ROM. The target architecture is a real Windows ARM64 runtime on the OnePlus 10T 5G.

## Layers

### 1. Qualcomm/OEM boot chain

Retain the minimum OEM boot components required to initialize the Snapdragon platform and reach the IzzOS payload safely.

### 2. IzzOS UEFI / EDK2 platform layer

Responsibilities:

- initialize the platform sufficiently for an EFI environment;
- provide framebuffer/display output;
- expose storage and required EFI protocols;
- load Windows Boot Manager or diagnostic EFI payloads;
- provide logs for bring-up and recovery.

### 3. ACPI hardware description

Windows-facing tables describe enabled SoC/device resources, interrupts, clocks, buses and power relationships. Device-tree information from Android/Linux sources is used as engineering reference, not passed directly to Windows.

### 4. Windows ARM64 driver layer

Device-specific drivers make storage, display/GPU, touch, networking, audio, power and other hardware usable. This is expected to be the longest phase of the project.

### 5. Windows ARM64 runtime

Use a normal, serviceable Windows ARM64 base where possible. Lightweight behavior should come from safe configuration and optional-component choices rather than indiscriminate component deletion.

### 6. IzzOS optimization profile

Planned features:

- low-overhead startup profile;
- phone-aware power plans;
- performance mode for sustained workloads;
- external-monitor profile;
- keyboard/mouse defaults;
- touch-friendly scaling defaults;
- telemetry for idle RAM, CPU, thermals and battery drain.

## Non-goals

- Android UI pretending to be Windows.
- Reimplementing the Windows kernel from scratch.
- Claiming universal Android-phone support.
- Sacrificing application/driver compatibility just to minimize disk footprint.

## Development order

`OEM boot chain -> EDK2/UEFI -> framebuffer/storage -> ACPI -> Windows PE -> core drivers -> GPU -> optimization -> gaming validation`
