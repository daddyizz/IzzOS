#!/usr/bin/env python3
import sys, struct, hashlib
from pathlib import Path

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <LinuxLoader.efi> <output.txt>", file=sys.stderr)
    raise SystemExit(2)

src = Path(sys.argv[1])
out = Path(sys.argv[2])
b = src.read_bytes()

# Exact RVAs observed in the CPH2413 stock LinuxLoader dynamic-placement fallback path:
#   ADRP/LDR w11 -> RVA 0x74CD8
#   ADRP/LDR w8  -> RVA 0x74CDC
# The PE's .text section has raw offset == RVA for this image, but resolve through
# the section table rather than assuming that property.

def u16(o): return struct.unpack_from('<H', b, o)[0]
def u32(o): return struct.unpack_from('<I', b, o)[0]
def u64(o): return struct.unpack_from('<Q', b, o)[0]

if b[:2] != b'MZ':
    raise SystemExit('not an MZ image')
pe = u32(0x3c)
if b[pe:pe+4] != b'PE\0\0':
    raise SystemExit('PE signature missing')
num_sections = u16(pe + 6)
opt_size = u16(pe + 20)
sec_off = pe + 24 + opt_size
sections = []
for i in range(num_sections):
    o = sec_off + i*40
    name = b[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
    vsize, va, raw_size, raw_off = struct.unpack_from('<IIII', b, o+8)
    sections.append((name, va, max(vsize, raw_size), raw_off, raw_size))

def rva_to_off(rva):
    for name, va, span, raw_off, raw_size in sections:
        if va <= rva < va + span:
            delta = rva - va
            if delta >= raw_size:
                return None, name
            return raw_off + delta, name
    return None, None

rvas = {
    'pcd-word-a-rva': 0x74CD8,
    'pcd-word-b-rva': 0x74CDC,
}
lines = []
lines.append('IzzOS exact LinuxLoader fallback PCD constant analysis')
lines.append('Collector mode: READ_ONLY_HOST_SIDE')
lines.append('Device writes: NONE')
lines.append(f'input: {src.as_posix()}')
lines.append(f'byte-size: {len(b)}')
lines.append(f'sha256: {hashlib.sha256(b).hexdigest()}')
lines.append('')
vals = {}
for label, rva in rvas.items():
    off, sec = rva_to_off(rva)
    if off is None or off+4 > len(b):
        lines.append(f'{label}: UNRESOLVED')
        continue
    val = u32(off)
    vals[label] = val
    lines.append(f'{label}: rva=0x{rva:X} file-off=0x{off:X} section={sec} value=0x{val:08X} ({val})')

lines.append('')
lines.append('source-backed interpretation boundary:')
lines.append('public Qualcomm BootLinux.c fallback uses PcdGet32(KernelLoadAddress) and PcdGet32(RamdiskEndAddress) for 64-bit kernels.')
lines.append('the two exact target constants above are the values loaded by the stock fallback code path immediately before KernelLoadAddr/KernelEndAddr are formed.')
lines.append('they are fallback PCD evidence only; successful QueryBootParams(KernelBaseAddr, KernelSize) would supersede them at runtime.')

if len(vals) == 2:
    a = vals['pcd-word-a-rva']
    c = vals['pcd-word-b-rva']
    lines.append('')
    lines.append(f'fallback-word-a: 0x{a:X}')
    lines.append(f'fallback-word-b: 0x{c:X}')
    lines.append('classification: LINUXLOADER_EXACT_FALLBACK_PCD_WORDS_EXTRACTED')
else:
    lines.append('classification: LINUXLOADER_FALLBACK_PCD_EXTRACTION_INCOMPLETE')

lines.append('decision: exact fallback constants were extracted host-side only. Do not treat them as proven runtime KernelBaseAddr/KernelSize values and do not authorize an FD base, fastboot boot, flashing, or slot change from this evidence alone.')
text='\n'.join(lines)+'\n'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(text, encoding='utf-8')
print(text, end='')
