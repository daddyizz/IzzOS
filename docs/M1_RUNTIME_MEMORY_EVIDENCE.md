# M1 runtime memory evidence for standalone firmware

## Why runtime evidence is required

The OnePlus/Qualcomm Cape source tree does not contain a fixed physical DRAM range that is safe to copy into IzzOS. In `cape.dtsi`, the root memory node is deliberately declared with a zero placeholder (`reg = <0 0 0 0>`). The boot chain is therefore expected to provide or patch the actual DRAM topology at runtime.

By contrast, `cape-reserved-memory.dtsi` contains many explicit secure/firmware/DSP/modem carve-outs beginning at physical address `0x80000000` and extending through multiple reserved regions. Those source-backed carve-outs are exclusions, not proof that any gap is automatically safe for an IzzOS firmware image.

## Collection policy

`scripts/collect-m1-runtime-memory-evidence.sh` reads only Android-exposed runtime information:

- exact build/product binding;
- runtime device-tree `/memory/reg`;
- every accessible direct child of `/reserved-memory`, including raw `reg`, `no-map`, and `reusable` state;
- optional `chosen/linux,usable-memory-range`;
- `/proc/iomem` and a small `/proc/meminfo` summary as cross-checks.

The collector does not use root, write the device, change slots, invoke fastboot, or launch a payload. Device serial numbers are intentionally omitted.

## Interpretation rules

1. Device-tree cells are big-endian. Raw hex must be decoded using the runtime tree's `#address-cells` and `#size-cells` semantics before arithmetic.
2. Physical DRAM topology, Linux-usable RAM, reserved-memory, CMA/reusable pools, and a safe firmware load range are different concepts.
3. A gap between static reserved nodes is not automatically safe. Bootloader allocations, DTB, framebuffer, kernel/initramfs placement, dynamic reserved pools, and firmware handoff structures must also be considered.
4. `/proc/iomem` may be restricted or address-redacted on production Android. Missing data there does not override valid runtime DT evidence.
5. Capturing a non-zero `/memory/reg` advances evidence collection only. It does not authorize creating a launch-oriented FD address, Android boot container, or `fastboot boot` command.

## Source-backed observations locked before runtime capture

- Cape root compatible: `qcom,cape`.
- Cape MSM ID: `<530 0x10000>`.
- Source `memory` node is a zero placeholder and therefore is not a usable fixed DDR definition.
- Cape has an explicit `/reserved-memory` tree with many `no-map` carve-outs, including hypervisor, XBL logs/ramdump, AOP, SMEM, DSP/modem, secure heaps, Trust UI, QTEE and trusted-app regions.

## Current gate

Until exact-device runtime output has been captured and independently analyzed:

`M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED`

No `Ovaltine.dsc` / `Ovaltine.fdf` launch placement and no device launch are authorized by this document.
