#!/usr/bin/env python3
import hashlib, struct, sys

TARGETS=[b'calculating dynamic offsets',b'Not Enough space left to load kernel image',b'Failed to get size of kernel region',b'UpdateBootParamsSizeAndCmdLine']

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

def parse_pe(b):
    if b[:2]!=b'MZ': raise SystemExit('not MZ')
    pe=u32(b,0x3c)
    if b[pe:pe+4]!=b'PE\0\0': raise SystemExit('no PE')
    nsec=u16(b,pe+6); opt=pe+24; magic=u16(b,opt)
    if magic!=0x20b: raise SystemExit('not PE32+')
    sh=opt+u16(b,pe+20)
    secs=[]
    for i in range(nsec):
        o=sh+i*40
        name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
        vsize=u32(b,o+8); va=u32(b,o+12); rawsz=u32(b,o+16); raw=u32(b,o+20)
        secs.append((name,va,vsize,raw,rawsz))
    return secs

def off_to_rva(off,secs):
    for name,va,vsize,raw,rawsz in secs:
        if raw <= off < raw+rawsz: return va+(off-raw),name
    return None,None

def arm64_decode(insn,pc):
    # Minimal useful decoder: BL/B, ADRP, ADD immediate, LDR literal.
    if insn & 0xFC000000 == 0x94000000:
        imm=insn & 0x03ffffff
        if imm & 0x02000000: imm-=0x04000000
        return f'BL 0x{pc + (imm<<2):X}'
    if insn & 0x7C000000 == 0x14000000:
        imm=insn & 0x03ffffff
        if imm & 0x02000000: imm-=0x04000000
        return f'B 0x{pc + (imm<<2):X}'
    if insn & 0x9F000000 == 0x90000000:
        rd=insn&31; immlo=(insn>>29)&3; immhi=(insn>>5)&0x7ffff
        imm=(immhi<<2)|immlo
        if imm & (1<<20): imm-=1<<21
        target=(pc & ~0xfff) + (imm<<12)
        return f'ADRP x{rd}, 0x{target:X}'
    if insn & 0x7F000000 in (0x11000000,0x91000000):
        rd=insn&31; rn=(insn>>5)&31; imm12=(insn>>10)&0xfff; sh=(insn>>22)&1
        imm=imm12<<(12 if sh else 0)
        return f'ADD x{rd}, x{rn}, #0x{imm:X}'
    if insn & 0x3B000000 == 0x18000000:
        rt=insn&31; imm19=(insn>>5)&0x7ffff
        if imm19 & 0x40000: imm19-=0x80000
        return f'LDR-literal x{rt}, 0x{pc + (imm19<<2):X}'
    return ''

def main():
    inp=sys.argv[1] if len(sys.argv)>1 else 'out/linuxloader/LinuxLoader.efi'
    outp=sys.argv[2] if len(sys.argv)>2 else 'out/linuxloader-dynamic-offset-region.txt'
    b=open(inp,'rb').read(); secs=parse_pe(b)
    lines=['IzzOS LinuxLoader dynamic-offset code neighborhood','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}','']
    for t in TARGETS:
        start=0; found=False
        while True:
            off=b.find(t,start)
            if off<0: break
            found=True; rva,sec=off_to_rva(off,secs)
            lines += [f'target: {t.decode()}',f'string-file-off: 0x{off:X}',f'string-rva: 0x{rva:X}' if rva is not None else 'string-rva: UNKNOWN',f'section: {sec or "UNKNOWN"}']
            # Scan whole .text for ADRP+ADD pairs resolving to same 4K page+offset.
            refs=[]
            text=next((s for s in secs if s[0]=='.text'),None)
            if text and rva is not None:
                _,tva,tvs,traw,traws=text
                for fo in range(traw,traw+traws-8,4):
                    pc=tva+(fo-traw)
                    a=u32(b,fo); d1=arm64_decode(a,pc)
                    if not d1.startswith('ADRP '): continue
                    rd=int(d1.split('x',1)[1].split(',',1)[0]); page=int(d1.rsplit('0x',1)[1],16)
                    a2=u32(b,fo+4); d2=arm64_decode(a2,pc+4)
                    if d2.startswith(f'ADD x{rd}, x{rd}, #0x'):
                        imm=int(d2.rsplit('0x',1)[1],16); addr=page+imm
                        if addr==rva:
                            refs.append((fo,pc,d1,d2))
            lines.append(f'adrp-add-ref-count: {len(refs)}')
            for j,(fo,pc,d1,d2) in enumerate(refs[:8]):
                lines += [f'ref-{j}: file-off=0x{fo:X} rva=0x{pc:X}',f'  {d1}',f'  {d2}','  code-window:']
                lo=max(0,fo-0x40); hi=min(len(b),fo+0x80)
                for q in range(lo - (lo%4),hi,4):
                    qrva,_=off_to_rva(q,secs)
                    if qrva is None: continue
                    ins=u32(b,q); dec=arm64_decode(ins,qrva)
                    marker='>>' if q in (fo,fo+4) else '  '
                    lines.append(f'  {marker} 0x{qrva:08X}: {ins:08X} {dec}')
            lines.append('')
            start=off+1
        if not found: lines += [f'target: {t.decode()}','string-hits: NONE','']
    lines += ['classification: LINUXLOADER_DYNAMIC_OFFSET_CODE_REFS_ENUMERATED','decision: exact ARM64 ADRP+ADD references and nearby branch instructions were enumerated host-side. This is reverse-engineering evidence only; no Android kernel destination, FD base, fastboot boot, flashing, or slot change is authorized.']
    text='\n'.join(lines)+'\n'; open(outp,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
