# M1 pre-Linux placement boundary

This note separates Android/Linux runtime allocation evidence from the pre-Linux temporary-boot environment used by M1 firmware experiments.

## Key distinction

Dynamic reserved-memory pools such as CMA/shared-dma-pool nodes are Linux runtime consumers. They are useful to understand the stock OS memory map, but they do not by themselves prove that the same physical range is occupied before Linux starts.

Therefore these signals must NOT be treated as direct pre-boot exclusion evidence:

- `CmaTotal` / `CmaFree`
- runtime shared-dma-pool allocation pressure
- post-boot Linux page allocator ownership
- Android userspace memory usage

They remain relevant only as secondary evidence about the stock operating system.

## Pre-Linux evidence that DOES matter

Before selecting an FD/load range or launch wrapper, the project must resolve:

1. bootloader-selected load/relocation behavior for the Android boot container;
2. the AArch64 entry contract used by the temporary route;
3. bootloader/firmware-owned carveouts that remain live before ExitBootServices or equivalent handoff;
4. whether the bootloader can place/execute the payload above 4 GiB on this exact CPH2413 firmware;
5. DTB handoff address and any firmware-side relocation requirements;
6. exact image-size/alignment requirements for the standalone firmware container.

## Current high-memory evidence

Strongly supported:

- gross high-memory bank: `0x800000000-0xB80000000`
- derived memory block size: 128 MiB
- `memory256..memory367` directory presence: 112/112
- no selected-DTB FDT memreserve overlap with the gross high-memory bank

Still unresolved:

- bootloader high-memory placement/relocation policy
- byte-level pre-boot ownership
- exact FD base
- temporary Android boot-image wrapper and entry path

## Gate

Classification: `M1_PRELINUX_BOOTLOADER_PLACEMENT_EVIDENCE_REQUIRED`

No high-memory candidate is SAFE merely because Linux runtime pools are absent or irrelevant at pre-boot time. Do not create a launch-oriented `Ovaltine.dsc`/`Ovaltine.fdf` load base and do not issue a device launch command until bootloader placement/entry evidence is independently resolved.
