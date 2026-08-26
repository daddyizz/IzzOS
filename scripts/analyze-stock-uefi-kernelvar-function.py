#!/usr/bin/env python3
import sys, struct, hashlib
from pathlib import Path

TARGET_PE_BASE=0x395594
TARGET_RVAS=[0x11C6C,0x1242C,0x1246C,0x12494]

def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def s32(v): return v-0x100000000 if v & 0x80000000 else v

def decode_branch(pc,ins):
    if (ins & 0x7C000000)==0x14000000:
        imm=s32((ins & 0x03FFFFFF)<<6)>>4
        return f'B/BL 0x{pc+imm:X}'
    return ''

def main():
    if len(sys.argv)<4:
        print('usage: analyze-stock-uefi-kernelvar-function.py <decompressed.bin> <out-pe> <report>'); return 2
    inp=Path(sys.argv[1]); outpe=Path(sys.argv[2]); report=Path(sys.argv[3])
    data=inp.read_bytes(); outpe.parent.mkdir(parents=True,exist_ok=True); report.parent.mkdir(parents=True,exist_ok=True)
    # Parse PE at exact proven base to get size from SizeOfImage/raw sections.
    base=TARGET_PE_BASE
    if data[base:base+2]!=b'MZ':
        raise SystemExit('ERROR: expected MZ at proven PE base')
    peoff=struct.unpack_from('<I',data,base+0x3c)[0]
    pe=base+peoff
    if data[pe:pe+4]!=b'PE\0\0': raise SystemExit('ERROR: PE signature missing')
    nsec=struct.unpack_from('<H',data,pe+6)[0]; optsz=struct.unpack_from('<H',data,pe+20)[0]
    opt=pe+24; size_img=struct.unpack_from('<I',data,opt+56)[0]; size_hdr=struct.unpack_from('<I',data,opt+60)[0]
    sec=opt+optsz; maxraw=size_hdr
    sections=[]
    for i in range(nsec):
        o=sec+i*40; name=data[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
        vsize,va,rawsz,raw=struct.unpack_from('<IIII',data,o+8)
        sections.append((name,va,vsize,raw,rawsz)); maxraw=max(maxraw,raw+rawsz)
    blob=data[base:base+maxraw]; outpe.write_bytes(blob)
    lines=['IzzOS exact stock UEFI kernel-variable producer function analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'input-sha256: {hashlib.sha256(data).hexdigest()}',f'pe-base: 0x{base:X}',f'pe-byte-size: 0x{len(blob):X}',f'pe-sha256: {hashlib.sha256(blob).hexdigest()}',f'pe-size-of-image: 0x{size_img:X}',f'pe-section-count: {nsec}','sections:']
    for s in sections: lines.append(f'{s[0]} va=0x{s[1]:X} vsize=0x{s[2]:X} raw=0x{s[3]:X}+0x{s[4]:X}')
    for rva in TARGET_RVAS:
        fo=base+rva
        lines.append(f'code-window-around-rva-0x{rva:X}:')
        start=max(base,fo-0x60); end=min(base+len(blob),fo+0xA0)
        p=start & ~3
        while p+4<=end:
            ins=u32(data,p); pc=p-base
            mark='>> ' if abs(pc-rva)<=4 else ''
            extra=decode_branch(pc,ins)
            lines.append(f'{mark}0x{pc:08X}: {ins:08X} {extra}'.rstrip())
            p+=4
    # Nearby literal/string clues inside this PE.
    for needle in [b'KernelBaseAddr',b'KernelSize',b'PropagateKernelSocInfo',b'Kernel not preloaded',b'Get Kernel info from UEFI Plat cfg']:
        pos=0; hits=[]
        while True:
            h=blob.find(needle,pos)
            if h<0: break
            hits.append(h); pos=h+1
        lines.append(f'string-{needle.decode(errors="ignore")}-hits: '+('NONE' if not hits else ' '.join(f'0x{x:X}' for x in hits)))
    lines += ['classification: STOCK_UEFI_KERNELVAR_PRODUCER_PE_ISOLATED','decision: exact UEFI PE code neighborhoods around the proven kernel-variable references were isolated host-side. This identifies the producer path for further data-flow analysis only; no runtime values, FD base, fastboot boot, flashing, or slot changes are authorized.']
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8'); print('\n'.join(lines)); return 0
if __name__=='__main__': raise SystemExit(main())
