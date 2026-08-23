#!/usr/bin/env python3
"""Model source-backed SM8475/Cape reserved-memory gaps for M1 research.

This is deliberately conservative: it only contains fixed carve-outs explicitly
observed in the OnePlus/Qualcomm Cape device-tree source used by the project.
It does NOT select or authorize a firmware load address.
"""

from dataclasses import dataclass

DRAM_SPAN_BASE = 0x80000000

@dataclass(frozen=True)
class Region:
    name: str
    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size

# Fixed source-backed regions from cape-reserved-memory.dtsi. Dynamic CMA/shared
# pools without a fixed reg are intentionally omitted from this fixed map.
REGIONS = [
    Region("hyp_mem", 0x80000000, 0x00600000),
    Region("xbl_dtlog_mem", 0x80600000, 0x00040000),
    Region("xbl_ramdump_mem", 0x80640000, 0x001C0000),
    Region("aop_image_mem", 0x80800000, 0x00060000),
    Region("aop_cmd_db_mem", 0x80860000, 0x00020000),
    Region("aop_config_mem", 0x80880000, 0x00020000),
    Region("tme_crash_dump_mem", 0x808A0000, 0x00040000),
    Region("tme_log_mem", 0x808E0000, 0x00004000),
    Region("uefi_log_mem", 0x808E4000, 0x00010000),
    Region("smem_mem", 0x80900000, 0x00200000),
    Region("cpucp_fw_mem", 0x80B00000, 0x00100000),
    Region("cdsp_secure_heap_mem", 0x80C00000, 0x04600000),
    Region("video_mem", 0x85700000, 0x00700000),
    Region("adsp_mem", 0x85E00000, 0x02100000),
    Region("slpi_mem", 0x88000000, 0x01900000),
    Region("cdsp_mem", 0x89900000, 0x02000000),
    Region("ipa_fw_mem", 0x8B900000, 0x00010000),
    Region("ipa_gsi_mem", 0x8B910000, 0x0000A000),
    Region("gpu_microcode_mem", 0x8B91A000, 0x00002000),
    Region("spss_region_mem", 0x8BA00000, 0x00180000),
    Region("spu_tz_shared_mem", 0x8BB80000, 0x00060000),
    Region("spu_modem_shared_mem", 0x8BBE0000, 0x00020000),
    Region("mpss_mem", 0x8BC00000, 0x13200000),
    Region("cvp_mem", 0x9EE00000, 0x00700000),
    Region("camera_mem", 0x9F500000, 0x00800000),
    Region("xbl_sc_mem", 0xA6E00000, 0x00040000),
    Region("global_sync_mem", 0xA6F00000, 0x00100000),
    Region("qheebsp_reserved_mem", 0xE0000000, 0x00600000),
    Region("cpusys_vm_mem", 0xE0600000, 0x00400000),
    Region("hyp_reserved_mem", 0xE0A00000, 0x00100000),
    Region("trust_ui_vm_mem", 0xE0B00000, 0x04AF3000),
    Region("trust_ui_vm_qrtr", 0xE55F3000, 0x00009000),
    Region("trust_ui_vm_vblk0_ring", 0xE55FC000, 0x00004000),
    Region("trust_ui_vm_swiotlb", 0xE5600000, 0x00100000),
    Region("tz_stat_mem", 0xE8800000, 0x00100000),
    Region("tags_mem", 0xE8900000, 0x01200000),
    Region("qtee_mem", 0xE9B00000, 0x00500000),
    Region("trusted_apps_mem", 0xEA000000, 0x03900000),
    Region("trusted_apps_ext_mem", 0xED900000, 0x03B00000),
]


def merged(regions):
    ordered = sorted(regions, key=lambda r: (r.base, r.end))
    out = []
    for r in ordered:
        if not out or r.base > out[-1][1]:
            out.append([r.base, r.end, [r.name]])
        else:
            out[-1][1] = max(out[-1][1], r.end)
            out[-1][2].append(r.name)
    return out


def fmt(n):
    return f"0x{n:08X}"


def main():
    blocks = merged(REGIONS)
    print("IzzOS SM8475 fixed reserved-memory model")
    print("classification: SOURCE_BACKED_FIXED_CARVEOUT_MODEL_ONLY")
    print(f"runtime DRAM span base evidence: {fmt(DRAM_SPAN_BASE)}")
    print("dynamic/firmware-patched regions: NOT FULLY MODELED")
    print("candidate gaps below 4 GiB:")
    cursor = DRAM_SPAN_BASE
    limit = 0x100000000
    for start, end, names in blocks:
        if end <= DRAM_SPAN_BASE or start >= limit:
            continue
        start = max(start, DRAM_SPAN_BASE)
        end = min(end, limit)
        if start > cursor:
            print(f"  {fmt(cursor)}-{fmt(start)} size=0x{start-cursor:X} status=UNVALIDATED_GAP")
        print(f"  reserved {fmt(start)}-{fmt(end)} size=0x{end-start:X} names={','.join(names)}")
        cursor = max(cursor, end)
    if cursor < limit:
        print(f"  {fmt(cursor)}-0x100000000 size=0x{limit-cursor:X} status=UNVALIDATED_GAP")
    print("decision: fixed source carve-outs can exclude known ranges, but gaps are not safe FD ranges until runtime/dynamic allocations, bootloader placement, DTB, framebuffer, kernel loading behavior and exact-device entry assumptions are independently reconciled.")


if __name__ == "__main__":
    main()
