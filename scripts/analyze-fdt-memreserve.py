#!/usr/bin/env python3
import struct, sys, os

DTB = sys.argv[1] if len(sys.argv) > 1 else 'out/vendor-boot-dtb-set/dtb-1.dtb'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'out/fdt-memreserve-analysis.txt'

b = open(DTB,'rb').read()
if len(b) < 40 or b[:4] != b'\xd0\x0d\xfe\xed':
    raise SystemExit('ERROR: invalid FDT')

off_mem_rsvmap = struct.unpack_from('>I', b, 16)[0]
entries=[]
p=off_mem_rsvmap
while p+16 <= len(b):
    addr,size = struct.unpack_from('>QQ', b, p)
    p += 16
    if addr == 0 and size == 0:
        break
    entries.append((addr,size))

HIGH_START=0x800000000
HIGH_END=0xB80000000

def overlap(a0,a1,b0,b1):
    return max(a0,b0) < min(a1,b1)

lines=[
'IzzOS exact-DTB FDT memreserve analysis',
f'dtb: {DTB}',
f'off_mem_rsvmap: 0x{off_mem_rsvmap:X}',
f'memreserve-entry-count: {len(entries)}',
'memreserve-entries:'
]
high=[]
for i,(a,s) in enumerate(entries):
    e=a+s
    tag='HIGH_MEMORY_OVERLAP' if s and overlap(a,e,HIGH_START,HIGH_END) else 'NO_HIGH_MEMORY_OVERLAP'
    if tag=='HIGH_MEMORY_OVERLAP': high.append((a,e))
    lines.append(f'{i}: 0x{a:X}-0x{e:X} size=0x{s:X} status={tag}')
lines += [
'',
f'high-memory-bank: 0x{HIGH_START:X}-0x{HIGH_END:X}',
f'high-memory-overlap-count: {len(high)}',
'classification: FDT_MEMRESERVE_HIGH_MEMORY_OVERLAP_PRESENT' if high else 'classification: FDT_MEMRESERVE_NO_HIGH_MEMORY_OVERLAP',
'decision: the FDT reservation map was inspected independently of /reserved-memory nodes. Absence of overlap removes only this reservation source; it does not prove a firmware-safe load window because Linux/runtime allocations and firmware ownership remain unresolved. No device launch is authorized.'
]
text='\n'.join(lines)+'\n'
os.makedirs(os.path.dirname(OUT) or '.', exist_ok=True)
open(OUT,'w',encoding='utf-8').write(text)
print(text,end='')
