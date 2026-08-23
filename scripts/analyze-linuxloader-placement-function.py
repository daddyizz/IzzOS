#!/usr/bin/env python3
import struct,sys,hashlib

inp=sys.argv[1] if len(sys.argv)>1 else 'out/linuxloader/LinuxLoader.efi'
outp=sys.argv[2] if len(sys.argv)>2 else 'out/linuxloader-placement-function.txt'
b=open(inp,'rb').read()

def u32(o): return struct.unpack_from('<I',b,o)[0]
def sx(v,bits): return v-(1<<bits) if v&(1<<(bits-1)) else v

def decode(pc,w):
    # targeted AArch64 decoder for this function
    if (w & 0x7c000000)==0x14000000:
        imm=sx(w&0x03ffffff,26)<<2; return f'B 0x{pc+imm:X}'
    if (w & 0xfc000000)==0x94000000:
        imm=sx(w&0x03ffffff,26)<<2; return f'BL 0x{pc+imm:X}'
    if (w & 0xff000010)==0x54000000:
        imm=sx((w>>5)&0x7ffff,19)<<2; cond=w&0xf; return f'B.cond({cond}) 0x{pc+imm:X}'
    if (w & 0x9f000000)==0x90000000:
        rd=w&31; immlo=(w>>29)&3; immhi=(w>>5)&0x7ffff; imm=sx((immhi<<2)|immlo,21)<<12
        return f'ADRP x{rd}, 0x{((pc & ~0xfff)+imm):X}'
    # ADD/SUB immediate 64-bit
    if (w & 0x7f000000) in (0x11000000,0x51000000):
        sf=(w>>31)&1; op=(w>>30)&1; sh=(w>>22)&1; imm=(w>>10)&0xfff; rn=(w>>5)&31; rd=w&31
        if sh: imm <<= 12
        name='SUB' if op else 'ADD'; reg='x' if sf else 'w'
        return f'{name} {reg}{rd}, {reg}{rn}, #0x{imm:X}'
    # LDR unsigned immediate 64/32
    if (w & 0xffc00000)==0xf9400000:
        imm=((w>>10)&0xfff)*8; rn=(w>>5)&31; rt=w&31; return f'LDR x{rt}, [x{rn}, #0x{imm:X}]'
    if (w & 0xffc00000)==0xb9400000:
        imm=((w>>10)&0xfff)*4; rn=(w>>5)&31; rt=w&31; return f'LDR w{rt}, [x{rn}, #0x{imm:X}]'
    if (w & 0xffc00000)==0xf9000000:
        imm=((w>>10)&0xfff)*8; rn=(w>>5)&31; rt=w&31; return f'STR x{rt}, [x{rn}, #0x{imm:X}]'
    # ADD shifted register
    if (w & 0xff200000)==0x8b000000:
        rm=(w>>16)&31; rn=(w>>5)&31; rd=w&31; return f'ADD x{rd}, x{rn}, x{rm}'
    if (w & 0xff200000)==0xcb000000:
        rm=(w>>16)&31; rn=(w>>5)&31; rd=w&31; return f'SUB x{rd}, x{rn}, x{rm}'
    if (w & 0x7f200000)==0x0b000000:
        rm=(w>>16)&31; rn=(w>>5)&31; rd=w&31; return f'ADD w{rd}, w{rn}, w{rm}'
    if w==0xd65f03c0: return 'RET'
    return f'0x{w:08X}'

start=0x22f80; end=0x2312c
lines=['IzzOS LinuxLoader dynamic placement function analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}',f'analysis-range: 0x{start:X}-0x{end:X}','']
lines.append('decoded-instructions:')
for pc in range(start,end,4):
    w=u32(pc); lines.append(f'0x{pc:08X}: {decode(pc,w)}')
lines += ['', 'field-access-summary (base register x9 around dynamic-offset core):',
          'struct+0x6C : 32-bit field loaded at 0x23028 / 0x23054',
          'struct+0x78 : 32-bit field loaded at 0x23014',
          'struct+0x94 : 32-bit field loaded at 0x23018',
          'struct+0x98 : 32-bit field loaded at 0x23020',
          'guard/alignment constant: +0x200000 observed at 0x23058',
          '',
          'derived arithmetic skeleton:',
          'tmp32 = field_0x78 + field_0x94 + field_0x98',
          'tmp32 = field_0x6C + tmp32',
          'candidate = qword_from_context - tmp32',
          'candidate_guard = candidate - (field_0x6C + 0x200000)',
          'subsequent comparison branches to the "Not Enough space left to load kernel image" path on failure.',
          '',
          'classification: LINUXLOADER_DYNAMIC_PLACEMENT_FUNCTION_ISOLATED',
          'decision: exact arithmetic and field offsets used by the stock LinuxLoader dynamic placement routine were isolated. Field semantic names and final physical destination are not yet proven; no FD base, fastboot boot, flashing, or slot change is authorized.']
text='\n'.join(lines)+'\n'; open(outp,'w',encoding='utf-8').write(text); print(text,end='')
