#!/usr/bin/env python3
import sys, struct, hashlib

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <LinuxLoader.efi> <output.txt>")
    raise SystemExit(2)

inp, outp = sys.argv[1], sys.argv[2]
data = open(inp,'rb').read()

# Exact write sites observed in CPH2413_15.0.0.1901(EX01)
# We intentionally report raw 32-bit instruction words and a backward window.
# This is host-side evidence only; no execution/patching.
sites = {
    'SIZE_TERM_A(+0x78)': [0x22824, 0x22AB4],
    'SIZE_TERM_B(+0x94)': [0x2284C, 0x22AC4],
    'SIZE_TERM_C(+0x98)': [0x22790, 0x227B4, 0x22A20, 0x22A44],
}

# Minimal decoders for common AArch64 forms used nearby.
def u32(off):
    if off < 0 or off+4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

def reg(n): return f"x{n}" if n < 31 else "sp"
def wreg(n): return f"w{n}" if n < 31 else "wsp"

def decode(off, ins):
    # ADD (immediate), 32/64
    if (ins & 0x7F000000) in (0x11000000, 0x91000000):
        sf=(ins>>31)&1; sh=(ins>>22)&1; imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rd=ins&31
        imm=imm12 << (12 if sh else 0)
        return f"ADD {'x' if sf else 'w'}{rd}, {'x' if sf else 'w'}{rn}, #0x{imm:X}"
    # SUB (immediate)
    if (ins & 0x7F000000) in (0x51000000, 0xD1000000):
        sf=(ins>>31)&1; sh=(ins>>22)&1; imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rd=ins&31
        imm=imm12 << (12 if sh else 0)
        return f"SUB {'x' if sf else 'w'}{rd}, {'x' if sf else 'w'}{rn}, #0x{imm:X}"
    # LDR unsigned immediate 32-bit
    if (ins & 0xFFC00000) == 0xB9400000:
        imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rt=ins&31
        return f"LDR w{rt}, [{reg(rn)}, #0x{imm12*4:X}]"
    # LDR unsigned immediate 64-bit
    if (ins & 0xFFC00000) == 0xF9400000:
        imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rt=ins&31
        return f"LDR x{rt}, [{reg(rn)}, #0x{imm12*8:X}]"
    # STR unsigned immediate 32-bit
    if (ins & 0xFFC00000) == 0xB9000000:
        imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rt=ins&31
        return f"STR w{rt}, [{reg(rn)}, #0x{imm12*4:X}]"
    # STR unsigned immediate 64-bit
    if (ins & 0xFFC00000) == 0xF9000000:
        imm12=(ins>>10)&0xFFF; rn=(ins>>5)&31; rt=ins&31
        return f"STR x{rt}, [{reg(rn)}, #0x{imm12*8:X}]"
    # MOV alias ORR shifted register (common)
    if (ins & 0xFFE0FFE0) == 0x2A0003E0:
        rm=(ins>>16)&31; rd=ins&31
        return f"MOV w{rd}, w{rm}"
    if (ins & 0xFFE0FFE0) == 0xAA0003E0:
        rm=(ins>>16)&31; rd=ins&31
        return f"MOV x{rd}, x{rm}"
    # B / BL
    if (ins & 0xFC000000) in (0x14000000,0x94000000):
        imm26=ins & 0x03FFFFFF
        if imm26 & 0x02000000: imm26 -= 0x04000000
        target=off + (imm26<<2)
        return f"{'BL' if (ins & 0xFC000000)==0x94000000 else 'B'} 0x{target:X}"
    return f"0x{ins:08X}"

lines=[]
lines += [
    'IzzOS exact LinuxLoader size-term provenance trace',
    'Collector mode: READ_ONLY_HOST_SIDE',
    'Device writes: NONE',
    f'input: {inp}',
    f'byte-size: {len(data)}',
    f'sha256: {hashlib.sha256(data).hexdigest()}',
    '',
    'source baseline:',
    'public Qualcomm BootLinux.c older branch computes RamdiskLoadAddr from RamdiskSize + VendorRamdiskSize, rounded to PageSize, plus one PageSize.',
    'exact 2026 target binary uses three 32-bit size terms at +0x78/+0x94/+0x98, so the third term remains exact-build-specific until provenance is established.',
    ''
]

for name, offs in sites.items():
    lines.append(f'field: {name}')
    for site in offs:
        lines.append(f'write-site: 0x{site:08X}')
        start=max(0, site-0x50)
        end=min(len(data), site+0x10)
        for off in range(start, end, 4):
            ins=u32(off)
            mark='>>' if off==site else '  '
            lines.append(f'{mark} 0x{off:08X}: {decode(off,ins)}')
        lines.append('')

lines += [
    'interpretation-rule:',
    'do not assign semantic names to +0x78/+0x94/+0x98 from position alone; use the producer chain immediately preceding each STR plus public-source agreement.',
    'classification: LINUXLOADER_SIZE_TERM_PROVENANCE_WINDOWS_ENUMERATED',
    'decision: exact producer neighborhoods were enumerated host-side. No firmware load base, fastboot boot, flashing, or slot change is authorized.'
]

open(outp,'w',newline='\n').write('\n'.join(lines)+'\n')
print('\n'.join(lines))
