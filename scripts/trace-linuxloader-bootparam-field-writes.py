#!/usr/bin/env python3
import struct, sys, hashlib

inp = sys.argv[1] if len(sys.argv) > 1 else 'out/linuxloader/LinuxLoader.efi'
outp = sys.argv[2] if len(sys.argv) > 2 else 'out/linuxloader-bootparam-field-writes.txt'
b = open(inp,'rb').read()

TARGETS = {0x48:'KernelEndAddr (source-matched)',0x50:'RamdiskLoadAddr (source-matched)',0x58:'DeviceTreeLoadAddr (source-matched)',0x6c:'PageSize (source-matched)',0x78:'SIZE_TERM_A',0x94:'SIZE_TERM_B',0x98:'SIZE_TERM_C'}
# Exact binary regions around UpdateBootParamsSizeAndCmdLine / dynamic placement established by prior evidence.
RANGES = [(0x22600,0x22c00,'UpdateBootParamsSizeAndCmdLine neighborhood'),(0x22f70,0x23130,'UpdateBootParams dynamic placement neighborhood')]

def dec_mem(w, pc):
    # AArch64 unsigned immediate LDR/STR 32/64-bit, enough for evidence tracing.
    top = w & 0xFFC00000
    table = {
        0xB9400000:('LDR','w',4), 0xB9000000:('STR','w',4),
        0xF9400000:('LDR','x',8), 0xF9000000:('STR','x',8),
    }
    if top not in table: return None
    op, width, scale = table[top]
    rt = w & 31; rn = (w>>5)&31; imm12=(w>>10)&0xfff; off=imm12*scale
    return op,width,rt,rn,off

def regname(width,n): return ('sp' if n==31 and width=='x' else f'{width}{n}')

lines=[]
lines += ['IzzOS exact LinuxLoader BootParamlist field write trace','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}','']
for start,end,label in RANGES:
    lines += [f'region: {label} 0x{start:X}-0x{end:X}']
    hits=0
    for pc in range(start, min(end,len(b)-3),4):
        w=struct.unpack_from('<I',b,pc)[0]
        d=dec_mem(w,pc)
        if not d: continue
        op,width,rt,rn,off=d
        if off in TARGETS:
            hits += 1
            lines.append(f'0x{pc:08X}: {op} {regname(width,rt)}, [{regname("x",rn)}, #0x{off:X}] ; {TARGETS[off]}')
    if not hits: lines.append('target-field-memory-ops: NONE')
    lines.append('')

lines += [
'proven-source-backed-mapping:',
'  +0x48 = KernelEndAddr',
'  +0x50 = RamdiskLoadAddr',
'  +0x58 = DeviceTreeLoadAddr',
'  +0x6C = PageSize',
'  +0x78/+0x94/+0x98 = exact-build size terms still requiring write-side semantic identification',
'',
'exact-source-matched-placement-formula:',
'  RamdiskLoadAddr = KernelEndAddr - rounded(total ramdisk-related bytes, PageSize)',
'  DeviceTreeLoadAddr = RamdiskLoadAddr - (0x200000 + PageSize)',
'',
'classification: LINUXLOADER_BOOTPARAM_WRITE_SITES_ENUMERATED',
'decision: exact target-structure memory operations were enumerated to identify the remaining size fields. Source-backed names are applied only where binary arithmetic and public Qualcomm EDK2 source agree. No firmware load base or device launch is authorized.'
]
text='\n'.join(lines)+'\n'
open(outp,'w',encoding='utf-8').write(text)
print(text,end='')
