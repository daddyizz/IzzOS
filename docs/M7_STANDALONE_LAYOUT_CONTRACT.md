# M7 Standalone Firmware Layout Contract

Status: **host-side region contract implemented; launch remains blocked**

This document uses the internal M1 engineering sequence. Internal Milestone 7 is not the product-roadmap milestone named “M7 — Core Device Drivers.” It is the standalone-firmware layout step inside the overall M1 UEFI bring-up.

## M6 handoff

Internal Milestone 6 is complete only when `scripts/verify-m1-kernel-region-geometry.py` classifies the exact stock evidence as:

```text
M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED
```

The verifier binds its result to the exact `uefiplat.cfg`, `boot.img`, and `vendor_boot.img` hashes. It also requires Android boot header v4, vendor boot header v4, a valid page size, in-region DTB/ramdisk placement, and a kernel payload that ends before the derived DTB load address.

Invalid or overlapping geometry is classified:

```text
M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED
```

## M7 region contract

Run:

```bash
python3 scripts/check-m7-layout-contract.py \
  out/m1-kernel-region-geometry.txt \
  out/uefiplat.cfg \
  out/m7-layout-contract.txt
```

The M7 checker independently verifies:

- the exact `uefiplat.cfg` hash still matches the M6 evidence;
- the named `Kernel` region is unique and matches the M6 base/size;
- the derived DTB and ramdisk placements remain inside that region and ordered correctly;
- M6 proved that the stock kernel payload ends before the DTB;
- no other named `uefiplat.cfg` region overlaps the bounded Kernel region.

A successful result is:

```text
M7_LAYOUT_REGION_CONTRACT_PASS
```

This result authorizes only host-side construction and validation work. It does not authorize a device launch.

## Still required before standalone DSC/FDF promotion

The following remain separate evidence gates:

- actual FD size and alignment from a concrete SEC/PEI/DXE composition;
- FD base derived from that concrete image, not an arbitrary window;
- AArch64 entry and exception-level contract;
- GIC/timer/platform-init requirements;
- exact temporary Android boot-container behavior;
- recovery and exact-device route authorization.

Storage writes, slot changes, flashing, and guessed MMIO initialization remain forbidden.
