#!/usr/bin/env python3

HIGH_BASE = 0x800000000
HIGH_END = 0xB80000000
ALIGN = 0x200000  # 2 MiB
FD_BUDGET = 0x04000000  # 64 MiB investigation window only

# Exact selected-DTB dynamic pools whose alloc-ranges force allocation at >=4 GiB.
# Placement remains runtime-dependent; these are pressure terms, not fixed exclusions.
HIGH_POOLS = [
    ("demura_heap_region", 0x02800000),
    ("mem_dump_region", 0x03000000),
    ("va_md_mem_region", 0x01000000),
]

print("IzzOS high-memory FD candidate ranking")
print("classification: HIGH_MEMORY_INVESTIGATION_ONLY")
print(f"gross-high-memory-bank: 0x{HIGH_BASE:X}-0x{HIGH_END:X} size=0x{HIGH_END-HIGH_BASE:X}")
print("source: cross-evidence 128 MiB sysfs memory-block geometry")
print(f"candidate-window-size: 0x{FD_BUDGET:X} ({FD_BUDGET/1024/1024:.0f} MiB)")
print(f"alignment: 0x{ALIGN:X} (2 MiB)")
print()

print("dynamic >=4GiB allocation pressure:")
total = 0
for n,s in HIGH_POOLS:
    total += s
    print(f"  {n}: 0x{s:X} ({s/1024/1024:.0f} MiB) placement=RUNTIME_DEPENDENT")
print(f"  total-requested: 0x{total:X} ({total/1024/1024:.0f} MiB)")
print()

# Rank only representative slices. Avoid bank edges because those are more likely
# to coincide with firmware bookkeeping, block boundaries, or allocator packing.
# These are NOT load addresses; they are investigation windows.
windows = [
    (0x840000000, "lower-interior"),
    (0x900000000, "mid-low-interior"),
    (0xA00000000, "mid-high-interior"),
    (0xB00000000, "upper-interior"),
]

print("representative candidate windows:")
for base,label in windows:
    end = base + FD_BUDGET
    if base < HIGH_BASE or end > HIGH_END or base % ALIGN:
        status = "REJECT_GEOMETRY"
    else:
        status = "INVESTIGATE_ONLY"
    flags = ["HIGH_MEMORY_DYNAMIC_POOL_PRESSURE", "BLOCK_PRESENCE_NOT_BYTE_SAFE"]
    if base - HIGH_BASE < 0x40000000:
        flags.append("NEAR_LOW_EDGE_OF_HIGH_BANK")
    if HIGH_END - end < 0x40000000:
        flags.append("NEAR_HIGH_EDGE_OF_HIGH_BANK")
    print(f"  {label}: 0x{base:X}-0x{end:X} status={status}")
    print("    risk-flags: " + ",".join(flags))

print()
print("decision: high-memory bank existence is strongly cross-evidence supported, but dynamic >=4GiB pools have runtime-selected placement and sysfs memory-block presence does not prove every byte is allocatable. These windows are research targets only; no FD address, Ovaltine.dsc/Ovaltine.fdf load base, or device launch is authorized.")
