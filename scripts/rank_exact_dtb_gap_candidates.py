#!/usr/bin/env python3
import sys

# Evidence-backed large gaps from exact selected DTB fixed carveouts.
gaps = [
    (0x80D00000, 0x85700000),
    (0x9FD00000, 0xA6E00000),
    (0xA7000000, 0xE0600000),
    (0xE5700000, 0xE8800000),
    (0xEA000000, 0x100000000),
]

# Dynamic pools with alloc-ranges below 4GiB. These are potential runtime
# consumers of any sub-4GiB mathematical gap. Sizes are from exact dtb-1.
dynamic_low4g = [
    ('adsp_heap_region', 0x00C00000, 0x00400000),
    ('audio_cma_region', 0x01C00000, 0x00400000),
    ('cdsp_eva_region', 0x00400000, 0x00400000),
    ('cnss_wlan_region', 0x02000000, 0x00400000),
    ('linux,cma', 0x02000000, 0x00400000),
    ('non_secure_display_region', 0x0A400000, 0x00400000),
    ('qseecom_region', 0x04800000, 0x00400000),
    ('qseecom_ta_region', 0x01000000, 0x00400000),
    ('ramoops_region', 0x00200000, 0),
    ('sdsp_region', 0x00800000, 0x00400000),
    ('sp_region', 0x01000000, 0x00400000),
    ('user_contig_region', 0x01000000, 0x00400000),
]

# Pools constrained >=4GiB do not directly pressure sub-4GiB candidates.
dynamic_high = [
    ('demura_heap_region', 0x02800000),
    ('mem_dump_region', 0x03000000),
    ('va_md_mem_region', 0x01000000),
]

kernel_image_size = 0x02BC0000  # exact stock AArch64 Image header, 43.75 MiB
minimum_fd_window = 0x02000000  # current conservative engineering floor, not authorization

def mib(x):
    return x / (1024*1024)

def main():
    print('IzzOS exact-DTB candidate gap ranking')
    print('classification: DYNAMIC_PRESSURE_AWARE_RANKING_ONLY')
    print(f'exact-stock-kernel-image-size: 0x{kernel_image_size:X} ({mib(kernel_image_size):.2f} MiB)')
    print(f'dynamic-sub4g-pool-count: {len(dynamic_low4g)}')
    total=sum(s for _,s,_ in dynamic_low4g)
    print(f'dynamic-sub4g-total-requested-size: 0x{total:X} ({mib(total):.2f} MiB)')
    print('dynamic-sub4g-note: allocation placement is runtime-dependent; totals do not mean one contiguous block.')
    print(f'dynamic->=4g-pool-count: {len(dynamic_high)}')
    print()
    ranked=[]
    for start,end in gaps:
        size=end-start
        risks=[]
        if end <= 0x100000000:
            risks.append('SUB4G_DYNAMIC_ALLOC_PRESSURE')
        if size < kernel_image_size:
            risks.append('SMALLER_THAN_EXACT_STOCK_KERNEL_IMAGE')
        if size < minimum_fd_window:
            risks.append('BELOW_CONSERVATIVE_FD_WINDOW_FLOOR')
        # Prefer higher ranges only weakly: this is not a safety proof.
        score = size
        if start >= 0xE0000000:
            risks.append('NEAR_SECURE_HIGH_RESERVED_CLUSTER')
            score -= 0x08000000
        if start < 0x90000000:
            risks.append('LOW_DRAM_FIRMWARE_DSP_PROXIMITY')
            score -= 0x04000000
        if start <= 0xA7000000 < end:
            risks.append('VERY_LARGE_RUNTIME_ALLOCATION_TARGET_SURFACE')
            score -= 0x10000000
        status='REJECT_SIZE' if size < minimum_fd_window else 'INVESTIGATE_ONLY'
        ranked.append((score,start,end,size,status,risks))
    ranked.sort(reverse=True)
    print('ranked candidates:')
    for rank,(_,start,end,size,status,risks) in enumerate(ranked,1):
        print(f'{rank}. 0x{start:08X}-0x{end:08X} size=0x{size:X} ({mib(size):.2f} MiB) status={status}')
        print('   risk-flags: ' + (','.join(risks) if risks else 'NONE'))
    print()
    print('decision: this ranking only prioritizes further evidence collection. No candidate is classified SAFE. Dynamic CMA/shared-dma-pool placement, bootloader relocation, framebuffer, actual kernel/DTB placement and firmware entry constraints remain unresolved. No FD address or device launch is authorized.')

if __name__=='__main__': main()
