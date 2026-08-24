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

## Actual FD capacity check

After a real standalone FD artifact exists, validate its actual bytes rather than a configured estimate:

```bash
python3 scripts/verify-m7-fd-capacity.py \
  out/m7-layout-contract.txt \
  out/ovaltine-standalone/Ovaltine.fd \
  out/m7-fd-capacity.txt
```

The verifier hashes the FD, checks that its real size is aligned to the exact stock page size recorded by M6, and ensures its aligned size does not cross the exact stock DTB load bound. A successful result is:

```text
M7_FD_CAPACITY_CONTRACT_PASS
```

This is a capacity result only. It deliberately does not choose the FD base or claim that the bootloader will enter the artifact.

## Exact selected-DTB binding

Before deriving GIC, timer, or other platform facts from a DTB, bind one extracted blob to all three sources of evidence:

```bash
python3 scripts/verify-m7-selected-dtb.py \
  out/m7-layout-contract.txt \
  out/m1-device-inspection/ovaltine-inspection-analysis.txt \
  out/vendor-boot-dtb-set/MANIFEST.txt \
  out/vendor-boot-dtb-set/dtb-1.dtb \
  output/vendor_boot.img \
  out/m7-selected-dtb.txt
```

The verifier requires a passing M7 layout contract, the exact `vendor_boot` hash carried from M6, a numeric device-reported DTB index, a matching extraction-manifest entry, matching DTB bytes, and the expected Cape identity. A successful result is:

```text
M7_EXACT_SELECTED_DTB_BOUND
```

This binds the DTB input for later platform analysis. It does not prove that static DTB MMIO values are sufficient for standalone initialization.

## Still required before standalone DSC/FDF promotion

The following remain separate evidence gates:

- actual FD size and alignment from a concrete SEC/PEI/DXE composition;
- FD base and Android container behavior derived from exact boot-chain evidence, not an arbitrary window;
- AArch64 entry and exception-level contract;
- GIC/timer/platform-init requirements derived from an `M7_EXACT_SELECTED_DTB_BOUND` artifact;
- exact temporary Android boot-container behavior;
- recovery and exact-device route authorization.

Storage writes, slot changes, flashing, and guessed MMIO initialization remain forbidden.
