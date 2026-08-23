# M1 standalone firmware bring-up

## Why this stage exists

`M1-DIAG-R3` / `OvaltineDiag.efi` is an AArch64 UEFI **application**. It requires an existing UEFI firmware environment and therefore cannot be treated as a standalone Qualcomm boot payload or passed directly to `fastboot boot`.

The next engineering target is a minimal standalone Ovaltine firmware image that can provide the UEFI environment in which the diagnostic code can run.

## Required progression

1. Preserve the existing read-only diagnostic application as reusable M1 logic.
2. Establish source-backed SM8475 platform entry and memory-layout evidence.
3. Add `Ovaltine.dsc` and `Ovaltine.fdf` only after the FD placement assumptions are explicit and reviewable.
4. Produce a standalone `.fd`/firmware artifact in CI.
5. Independently inspect its architecture, size, sections/FV structure, entry assumptions and hashes.
6. Only then design the exact-device Android boot container for temporary launch.
7. Device launch remains separately gated.

## Mandatory evidence before an FD can become a launch candidate

- exact target binding: OnePlus 10T 5G / CPH2413 / `ovaltine` / SM8475;
- exact OxygenOS firmware binding;
- verified DDR base/usable range for the boot environment;
- verified reserved-memory exclusions;
- a non-overlapping firmware load/FD range;
- verified entry/exception-level assumptions;
- verified timer/GIC requirements, or a deliberately narrower execution design that does not claim unsupported initialization;
- no guessed framebuffer address;
- no UFS/storage write path;
- no AVB bypass or vbmeta modification;
- persistent writes and slot changes remain forbidden.

## Current state

The project has source-backed platform observations for Cape/SM8475 and exact-device stock/recovery evidence, but the standalone firmware memory-placement evidence is not yet complete.

Therefore the current classification is:

`M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED`

This is an engineering gate, not a device failure.

## Safety invariant

A host build passing is never sufficient by itself to authorize `fastboot boot`. Packaging and device-launch authorization remain separate gates.
