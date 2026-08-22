# M1 Runtime Capture Contract

Status: **prepared for first on-device diagnostic execution**

This document defines the minimum runtime evidence required to close M1 after `OvaltineDiag.efi` is safely executed on the exact OnePlus 10T 5G.

## Required capture

The runtime record must contain:

- the IzzOS diagnostic title/target banner;
- the read-only/storage-write-disabled banner;
- GOP availability status;
- if GOP exists: mode, max mode, resolution, pixels-per-scanline, pixel format, framebuffer base and framebuffer size;
- UEFI memory-map descriptor count, descriptor size and descriptor version;
- every printed memory descriptor line;
- final `[RESULT] memory-map dump completed` or the exact failure status;
- a note describing how the phone returned to stock boot after the temporary run.

## Preferred capture methods

Use the least invasive method available for the validated route:

1. text capture from an existing firmware/UEFI console if the route exposes one;
2. serial/debug console only if already available without device modification;
3. clear photographs/video of the diagnostic screen when no text export exists.

Do not add storage writes to the diagnostic merely to save a log during M1.

## Completeness checks

After converting the capture to plain text, run:

```bash
bash scripts/analyze-ovaltine-diag.sh ovaltine-diag-output.txt
```

Expected success classification:

```text
classification: DIAGNOSTIC_CAPTURE_COMPLETE
```

A complete classification alone is not enough if `memory-map-integrity: MISMATCH` is reported. Descriptor-count mismatch must be investigated before using the map as an engineering source.

## GOP interpretation

GOP data is runtime firmware hand-off evidence. It may be used to inform later framebuffer/GOP work only after the exact capture is associated with:

- device variant;
- OxygenOS build;
- bootloader state;
- launch route;
- IzzOS source revision / payload SHA256.

A runtime framebuffer address from one firmware build must not be promoted to a universal hard-coded constant.

## Memory-map interpretation

The captured UEFI memory map is evidence about the environment that executed the diagnostic. It must be cross-checked against source-verified SM8475/Cape reserved-memory information before any region is treated as reusable platform configuration.

Dynamic descriptors must not automatically become fixed PCD/MMIO constants.

## Privacy / redaction

Before committing any runtime log or screenshot to a public repository, remove or crop:

- USB/ADB/Fastboot serial numbers;
- IMEI/MEID;
- MAC addresses;
- account names;
- local file paths containing personal names;
- any OEM identifier not needed for platform engineering.

Keep model/product, OxygenOS build, slot state and bootloader mode because those are required engineering context.

## M1 closure criteria

M1 may be marked complete only when all are true:

1. the exact device inspection is recorded;
2. a temporary non-persistent launch route is validated;
3. `OvaltineDiag.efi` executes on the phone;
4. GOP state is captured (available or unavailable is both valid evidence);
5. the UEFI memory map is captured without integrity mismatch, or any mismatch is understood and resolved;
6. the device returns to stock boot without partition/slot changes;
7. the runtime record is linked to the exact payload SHA256.

Only then should the project advance formally to M2 temporary UEFI boot bring-up.
