# M1 High-Memory Placement Strategy

Status: INVESTIGATION ONLY

Exact target evidence currently establishes:

- Runtime Linux Normal zone starts at physical `0x80000000`.
- `spanned=11534336` 4-KiB pages implies an address span ending at `0xB80000000`, but this span contains large holes and must **not** be treated as contiguous DRAM.
- `present=4132608` pages (~15.76 GiB) proves substantial RAM exists somewhere inside that span, including above 4 GiB, but does not prove any particular high-memory interval is safe.
- Exact selected DTB is vendor_boot `dtb-1`, model `Qualcomm Technologies, Inc. Cape SoC`, compatible `qcom,cape`.
- Exact DTB contains 15 dynamic reserved-memory pools. Twelve may allocate below 4 GiB; three are constrained to >=4 GiB.
- Runtime CMA reports 504 MiB total and 0 free, but Android does not expose the CMA physical base to an unprivileged shell.

## Consequence

No sub-4-GiB mathematical gap may be promoted merely because it is absent from fixed `reserved-memory` ranges. All such gaps are under dynamic allocation pressure.

Likewise, no >=4-GiB range may be promoted merely because low-memory CMA pressure is avoided. Three exact-DTB dynamic pools explicitly allocate at/above 4 GiB, and the runtime physical map remains sparse.

## Required gate before any FD placement

A high-memory candidate may advance from `INVESTIGATE_ONLY` only after all of the following are demonstrated from exact-device evidence:

1. The candidate lies inside a physically present RAM interval, not just within the Linux zone span.
2. It does not overlap fixed reserved-memory ranges.
3. It does not overlap any dynamic pool's alloc-ranges after considering size/alignment.
4. It does not overlap kernel, DTB, vendor ramdisk, framebuffer, bootloader relocation, ramdump, secure VM, or hypervisor consumers.
5. The chosen firmware image and working memory fit with explicit alignment/headroom.
6. A host-side verifier can reproduce the decision from recorded evidence.

Until these are met, `Ovaltine.dsc` / `Ovaltine.fdf` launch-oriented placement remains blocked.

Device writes: NONE
Launch authorization: NO
