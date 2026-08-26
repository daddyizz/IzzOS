#!/usr/bin/env python3
"""Derive CPH2413 physical-memory block geometry from observed sysfs indices.
Read-only host-side evidence calculator; does not touch the device.
"""

PAGE_SIZE = 4096
START_PFN = 524288
SPANNED_PAGES = 11534336
OBSERVED_GROUPS = [(16, 31), (256, 367)]
EXPECTED_START = START_PFN * PAGE_SIZE
EXPECTED_SPAN_BYTES = SPANNED_PAGES * PAGE_SIZE
EXPECTED_END = EXPECTED_START + EXPECTED_SPAN_BYTES

# Candidate Linux memory-block sizes. 128 MiB is common on arm64 but is not
# assumed: it must satisfy all independent constraints below.
CANDIDATES = [32, 64, 128, 256, 512, 1024]

print("IzzOS physical-memory block geometry derivation")
print("classification: CROSS_EVIDENCE_BLOCK_GEOMETRY_DERIVATION")
print(f"kernel-page-size: {PAGE_SIZE}")
print(f"zone-start-pfn: {START_PFN}")
print(f"zone-start-physical: 0x{EXPECTED_START:X}")
print(f"zone-spanned-pages: {SPANNED_PAGES}")
print(f"zone-spanned-bytes: 0x{EXPECTED_SPAN_BYTES:X} ({EXPECTED_SPAN_BYTES / 2**30:.2f} GiB)")
print(f"zone-span-end-exclusive: 0x{EXPECTED_END:X}")
print("observed-sysfs-index-groups: memory16-memory31, memory256-memory367")
print()

valid = []
for mib in CANDIDATES:
    bs = mib * 1024 * 1024
    first = OBSERVED_GROUPS[0][0] * bs
    last_excl = (OBSERVED_GROUPS[-1][1] + 1) * bs
    matches_start = first == EXPECTED_START
    matches_end = last_excl == EXPECTED_END
    print(f"candidate-block-size: {mib} MiB")
    print(f"  memory16-base: 0x{first:X} {'MATCH' if matches_start else 'NO_MATCH'}")
    print(f"  memory368-boundary: 0x{last_excl:X} {'MATCH' if matches_end else 'NO_MATCH'}")
    if matches_start and matches_end:
        valid.append(bs)
        print("  result: CROSS_EVIDENCE_MATCH")
    else:
        print("  result: REJECT")

print()
if len(valid) != 1:
    print("classification: MEMORY_BLOCK_GEOMETRY_UNRESOLVED")
    print("decision: no unique block size satisfies both runtime zone geometry and observed sysfs indices; keep high-memory placement blocked.")
    raise SystemExit(1)

bs = valid[0]
print(f"derived-block-size: 0x{bs:X} ({bs // 2**20} MiB)")
print("derived gross present-block banks:")
gross = 0
for lo, hi in OBSERVED_GROUPS:
    start = lo * bs
    end = (hi + 1) * bs
    size = end - start
    gross += size
    print(f"  memory{lo}-memory{hi}: 0x{start:X}-0x{end:X} size=0x{size:X} ({size / 2**30:.2f} GiB) status=BLOCK_PRESENCE_ONLY")
print(f"gross-block-covered-size: 0x{gross:X} ({gross / 2**30:.2f} GiB)")
print("derived sparse hole between banks:")
hole_start = (OBSERVED_GROUPS[0][1] + 1) * bs
hole_end = OBSERVED_GROUPS[1][0] * bs
print(f"  0x{hole_start:X}-0x{hole_end:X} size=0x{hole_end-hole_start:X} ({(hole_end-hole_start)/2**30:.2f} GiB)")
print("classification: MEMORY_BLOCK_GEOMETRY_CROSS_EVIDENCE_CONSISTENT")
print("decision: 128 MiB memory-block geometry uniquely reconciles runtime zone start/span with observed sysfs block indices. This establishes gross physical bank coverage, not that every byte inside a listed block is allocatable or FD-safe. Reserved memory, runtime allocations, firmware ownership and launch constraints still apply; no device launch is authorized.")
