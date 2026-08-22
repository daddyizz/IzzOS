# SM8475 / Cape Reserved Memory Map

Status: **source-verified, device runtime validation pending**

This document records memory regions taken directly from the OnePlus-published SM8475 device-tree source used by the OnePlus 10T 5G branch. These addresses are engineering inputs for IzzOS bring-up; they are **not** yet permission to flash or write device storage.

## Platform identity

The OnePlus SM8475 device-tree branch contains `qcom/cape.dtsi`, which declares:

- model: `Qualcomm Technologies, Inc. Cape`
- compatible: `qcom,cape`
- Qualcomm MSM ID: `530 0x10000`
- embedded UFS alias: `ufshc1 = &ufshc_mem`
- UART stdout path: `/soc/qcom,qup_uart@99c000:115200n8`
- SRAM region: `0x17D09400`, size `0x400`

`cape.dtsi` includes `cape-reserved-memory.dtsi`; therefore Cape is the platform-level DTS source used for the SM8475 branch and is not an inferred codename.

## Verified fixed reserved regions

| Region | Base | Size | Notes |
|---|---:|---:|---|
| hyp | `0x80000000` | `0x00600000` | no-map |
| xbl_dtlog | `0x80600000` | `0x00040000` | no-map |
| xbl_ramdump | `0x80640000` | `0x001C0000` | no-map |
| aop_image | `0x80800000` | `0x00060000` | no-map |
| aop_cmd_db | `0x80860000` | `0x00020000` | Qualcomm command DB |
| aop_config | `0x80880000` | `0x00020000` | no-map |
| tme_crash_dump | `0x808A0000` | `0x00040000` | no-map |
| tme_log | `0x808E0000` | `0x00004000` | no-map |
| uefi_log | `0x808E4000` | `0x00010000` | OEM UEFI log region; preserve |
| smem | `0x80900000` | `0x00200000` | Qualcomm shared memory |
| cpucp_fw | `0x80B00000` | `0x00100000` | no-map |
| cdsp_secure_heap | `0x80C00000` | `0x04600000` | no-map |
| video | `0x85700000` | `0x00700000` | no-map |
| adsp | `0x85E00000` | `0x02100000` | no-map |
| slpi | `0x88000000` | `0x01900000` | no-map |
| cdsp | `0x89900000` | `0x02000000` | no-map |
| ipa_fw | `0x8B900000` | `0x00010000` | no-map |
| ipa_gsi | `0x8B910000` | `0x0000A000` | no-map |
| gpu_microcode | `0x8B91A000` | `0x00002000` | GPU microcode reserved region |
| spss | `0x8BA00000` | `0x00180000` | no-map |
| spu_tz_shared | `0x8BB80000` | `0x00060000` | secure shared memory |
| spu_modem_shared | `0x8BBE0000` | `0x00020000` | secure shared memory |
| mpss | `0x8BC00000` | `0x13200000` | modem subsystem |
| cvp | `0x9EE00000` | `0x00700000` | no-map |
| camera | `0x9F500000` | `0x00800000` | no-map |
| xbl_sc | `0xA6E00000` | `0x00040000` | no-map |
| global_sync | `0xA6F00000` | `0x00100000` | no-map |
| qheebsp | `0xE0000000` | `0x00600000` | no-map |
| cpusys_vm | `0xE0600000` | `0x00400000` | no-map |
| hyp_reserved | `0xE0A00000` | `0x00100000` | no-map |
| trust_ui_vm | `0xE0B00000` | `0x04AF3000` | no-map |
| trust_ui_vm_qrtr | `0xE55F3000` | `0x00009000` | no-map |
| trust_ui_vm_vblk0_ring | `0xE55FC000` | `0x00004000` | Gunyah label `0x11` |
| trust_ui_vm_swiotlb | `0xE5600000` | `0x00100000` | Gunyah label `0x12` |
| tz_stat | `0xE8800000` | `0x00100000` | no-map |
| tags | `0xE8900000` | `0x01200000` | no-map |
| qtee | `0xE9B00000` | `0x00500000` | no-map |
| trusted_apps | `0xEA000000` | `0x03900000` | no-map |
| trusted_apps_ext | `0xED900000` | `0x03B00000` | no-map |

There are also dynamically allocated shared-DMA regions such as `sp_mem`; these do not have a fixed base in the source and must not be represented as fixed EDK2 memory descriptors without runtime evidence.

## Framebuffer status

**UNKNOWN / not yet source-verified.**

`cape-reserved-memory.dtsi` does not declare a fixed `splash_mem` or framebuffer region. Searches for `cont-splash` in the OnePlus SM8475 device-tree repository also did not identify a Cape-specific static splash allocation. Older Qualcomm platforms in the same source tree do contain splash declarations, which makes reusing their addresses especially unsafe.

For IzzOS, framebuffer information must therefore come from one of these verified paths before it is encoded into EDK2:

1. bootloader-provided framebuffer hand-off data;
2. a runtime DT/DTBO dump from the exact OnePlus 10T 5G firmware;
3. OEM UEFI display protocol / GOP state inspection;
4. a device-side boot log or memory-map dump that can be independently cross-checked.

## EDK2 bring-up rules derived from this map

- Treat every `no-map` region above as reserved until proven otherwise.
- Do not allocate IzzOS firmware, stacks, page tables or framebuffer buffers across these regions.
- Preserve the OEM `uefi_log` region at `0x808E4000..0x808F3FFF` during early experiments.
- Do not convert dynamically allocated DT pools into hard-coded EDK2 PCDs.
- Do not invent the total DDR range from `cape.dtsi`: its top-level `memory` node deliberately has `reg = <0 0 0 0>` and actual RAM topology is supplied later in the boot flow.
- No storage writes are permitted in the M0/M1 payload.

## Source of truth

OnePlus OSS repository:

`OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475`

Branch:

`oneplus/sm8475_s_12.1_oneplus_10t_5g`

Files:

- `kernel_platform/qcom/proprietary/devicetree/qcom/cape.dtsi`
- `kernel_platform/qcom/proprietary/devicetree/qcom/cape-reserved-memory.dtsi`

Runtime validation on the exact target phone remains mandatory before any address is used for a destructive operation.