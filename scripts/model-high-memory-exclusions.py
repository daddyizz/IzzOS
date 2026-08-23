#!/usr/bin/env python3
# Read-only host-side model: rank high-memory 64 MiB investigation windows.
# It intentionally does NOT classify any window as SAFE.

BANK_START = 0x800000000
BANK_END = 0xB80000000
WINDOW = 0x4000000      # 64 MiB
ALIGN = 0x200000        # 2 MiB
BLOCK = 0x8000000       # 128 MiB

# Dynamic >=4GiB pools from exact dtb-1. Placement is runtime-dependent.
POOLS = [
    ("demura_heap_region", 0x2800000, 0x400000),
    ("mem_dump_region", 0x3000000, 0x400000),
    ("va_md_mem_region", 0x1000000, 0x1),
]

# Four previously selected representative windows.
CANDIDATES = [
    ("lower-interior", 0x840000000),
    ("mid-low-interior", 0x900000000),
    ("mid-high-interior", 0xA00000000),
    ("upper-interior", 0xB00000000),
]

def aligned(v, a):
    return v % a == 0

def block_index(addr):
    return addr // BLOCK

print("IzzOS high-memory exclusion model")
print("classification: HIGH_MEMORY_SHORTLIST_ONLY")
print(f"gross-bank: 0x{BANK_START:X}-0x{BANK_END:X}")
print(f"window-size: 0x{WINDOW:X} (64 MiB)")
print(f"alignment: 0x{ALIGN:X} (2 MiB)")
print("fdt-memreserve-overlap: none detected")
print("high-memory-block-presence: memory256-memory367 present")
print("per-block state/zone metadata: restricted")
print("dynamic >=4GiB pools:")
for name,size,al in POOLS:
    print(f"  {name}: size=0x{size:X} align=0x{al:X} placement=RUNTIME_DEPENDENT")
print()

rows=[]
for label,start in CANDIDATES:
    end=start+WINDOW
    flags=[]
    if not (BANK_START <= start < end <= BANK_END): flags.append("OUTSIDE_GROSS_BANK")
    if not aligned(start, ALIGN): flags.append("MISALIGNED")
    # Candidate is deliberately centered/placed inside block coverage rather than bank edge.
    bi0=block_index(start); bi1=block_index(end-1)
    boundary_penalty = 1 if (start % BLOCK == 0 or end % BLOCK == 0) else 0
    if boundary_penalty: flags.append("TOUCHES_128M_BLOCK_BOUNDARY")
    flags += ["DYNAMIC_HIGHMEM_POOL_PLACEMENT_UNKNOWN","BLOCK_PRESENCE_NOT_BYTE_SAFE","RUNTIME_LINUX_OWNERSHIP_UNRESOLVED"]
    # Prefer windows farther from gross-bank edges; this is only heuristic research priority.
    edge_distance=min(start-BANK_START, BANK_END-end)
    score=edge_distance//BLOCK - boundary_penalty
    rows.append((score,label,start,end,flags,bi0,bi1))

rows.sort(reverse=True)
print("ranked shortlist:")
for rank,(score,label,start,end,flags,bi0,bi1) in enumerate(rows,1):
    print(f"{rank}. {label}: 0x{start:X}-0x{end:X} status=INVESTIGATE_ONLY")
    print(f"   covered-memory-blocks: memory{bi0}-memory{bi1}")
    print(f"   heuristic-edge-score: {score}")
    print("   risk-flags: "+",".join(flags))

print()
print("decision: shortlist ranking is heuristic research prioritization only. No window is SAFE or launch-authorized. Exact runtime ownership/allocation and bootloader/firmware placement evidence are still required before any Ovaltine.dsc/Ovaltine.fdf FD base or fastboot boot decision.")
