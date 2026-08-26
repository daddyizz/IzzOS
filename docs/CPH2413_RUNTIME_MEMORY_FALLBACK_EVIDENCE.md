# CPH2413 runtime memory fallback evidence

Target: OnePlus 10T 5G / CPH2413 / OP5552L1 / SM8475
Build: `CPH2413_15.0.0.1901(EX01)`
Observed slot: `_a`
Collector mode: read-only Android userspace

## Direct DT status

The runtime device-tree hierarchy is visible under `/proc/device-tree` -> `/sys/firmware/devicetree/base`, but raw `reg` properties are not readable by the unprivileged adb shell on this production OxygenOS build. `/proc/iomem` and the raw `/sys/firmware/fdt` path are also unavailable to that shell context.

Therefore raw DT bytes are **not** accepted as evidence from this capture. A previous collector revision incorrectly hex-encoded the remote `cat: ... Permission denied` diagnostic; commit `481c626c4403f8e60d053416a627cac06ecf7e20` hardens the collector against that false positive.

## Kernel-exposed fallback evidence

Observed kernel page size:

- 4096 bytes (`0x1000`)

Observed `/proc/zoneinfo` for Node 0 Normal zone:

- `start_pfn = 524288` (`0x80000` pages)
- `spanned = 11534336` (`0xB00000` pages)
- `present = 4132608` pages
- `managed = 3895894` pages

Derived physical start address:

`0x80000 * 0x1000 = 0x80000000`

The `spanned` value covers a physical-address span of `0xB00000000` bytes, ending at exclusive address `0xB80000000` when added to the observed zone start. This **must not** be interpreted as one contiguous RAM bank. `present` is much smaller than `spanned`, proving that the zone contains substantial holes/reserved areas or otherwise non-present PFNs.

Observed `/proc/meminfo`:

- `MemTotal = 15583576 kB`
- `CmaTotal = 516096 kB`

The present-page count is broadly consistent with a 16 GB-class physical device after firmware/kernel reservations, but total capacity does not identify a safe standalone firmware load range.

## Engineering conclusion

Classification: `M1_RUNTIME_MEMORY_FALLBACK_EVIDENCE_CAPTURED`

Evidence supports `0x80000000` as the beginning of the kernel Normal-zone physical span on this exact running device/build. It does **not** yet establish a contiguous usable DDR range for EDK2 FD placement.

Before `Ovaltine.dsc` / `Ovaltine.fdf` can be promoted to a launch-oriented layout, the project must reconcile this runtime evidence with the exact SM8475/Cape reserved-memory map and avoid all secure, modem/DSP, hypervisor, bootloader, framebuffer, DTB and other carve-outs. No guessed gap may be treated as safe RAM.

Device launch remains unauthorized. Persistent writes and slot changes remain forbidden.
