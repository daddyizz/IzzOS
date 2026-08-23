#!/usr/bin/env python3
import sys, struct, hashlib
from pathlib import Path


def u32(b,o): return struct.unpack_from('<I', b, o)[0]
def u64(b,o): return struct.unpack_from('<Q', b, o)[0]

def parse_pe_at(data, base):
    if base < 0 or base + 0x40 > len(data) or data[base:base+2] != b'MZ':
        return None
    e = u32(data, base+0x3c)
    ph = base + e
    if ph + 0x108 > len(data) or data[ph:ph+4] != b'PE\0\0':
        return None
    machine = struct.unpack_from('<H',data,ph+4)[0]
    nsec = struct.unpack_from('<H',data,ph+6)[0]
    optsz = struct.unpack_from('<H',data,ph+20)[0]
    opt = ph+24
    magic = struct.unpack_from('<H',data,opt)[0]
    if magic not in (0x20b,0x10b): return None
    entry = u32(data,opt+16)
    image_base = u64(data,opt+24) if magic==0x20b else u32(data,opt+28)
    size_image = u32(data,opt+56)
    secp = opt+optsz
    secs=[]
    for i in range(nsec):
        s=secp+i*40
        if s+40>len(data): break
        name=data[s:s+8].split(b'\0',1)[0].decode('ascii','replace')
        vsize=u32(data,s+8); va=u32(data,s+12); rawsz=u32(data,s+16); raw=u32(data,s+20); chars=u32(data,s+36)
        secs.append((name,va,vsize,raw,rawsz,chars))
    return {'base':base,'machine':machine,'entry':entry,'image_base':image_base,'size_image':size_image,'sections':secs}

def find_pes(data):
    out=[]; p=0
    while True:
        p=data.find(b'MZ',p)
        if p<0: break
        pe=parse_pe_at(data,p)
        if pe: out.append(pe)
        p+=2
    return out

def fileoff_to_rva(pe, off):
    rel=off-pe['base']
    for name,va,vsize,raw,rawsz,chars in pe['sections']:
        span=max(vsize,rawsz)
        if raw <= rel < raw+span:
            return va+(rel-raw), name
    return None,None

def pe_contains(pe, off):
    rva,sec=fileoff_to_rva(pe,off)
    return rva is not None

def signext(v,bits):
    if v & (1<<(bits-1)): v -= 1<<bits
    return v

def decode_adrp(word, pc):
    if (word & 0x9F000000) != 0x90000000: return None
    rd=word & 31
    immlo=(word>>29)&3; immhi=(word>>5)&0x7ffff
    imm=signext((immhi<<2)|immlo,21)<<12
    return rd, (pc & ~0xfff)+imm

def decode_add_imm(word):
    if (word & 0x7F000000) != 0x11000000: return None
    sf=(word>>31)&1; op=(word>>30)&1; S=(word>>29)&1
    if op or S: return None
    shift=(word>>22)&3
    if shift not in (0,1): return None
    imm12=(word>>10)&0xfff
    if shift==1: imm12 <<= 12
    rn=(word>>5)&31; rd=word&31
    return rd,rn,imm12,sf

def find_adrp_add_refs(data, pe, target_rva):
    refs=[]
    for name,va,vsize,raw,rawsz,chars in pe['sections']:
        if not (chars & 0x20000000) and name not in ('.text','text'): continue
        start=pe['base']+raw; end=min(len(data),start+rawsz)
        for o in range(start, end-8, 4):
            w1=u32(data,o); a=decode_adrp(w1, va+(o-start))
            if not a: continue
            rd,page=a
            for delta in (4,8,12):
                if o+delta+4>end: continue
                w2=u32(data,o+delta); ad=decode_add_imm(w2)
                if not ad: continue
                rd2,rn,imm,sf=ad
                if rn==rd and rd2==rd and page+imm==target_rva:
                    refs.append((o,va+(o-start),o+delta,rd))
    return refs

def ascii_window(data,off,r=120):
    a=max(0,off-r); z=min(len(data),off+r)
    return ''.join(chr(c) if 32<=c<127 else '.' for c in data[a:z])

def main():
    if len(sys.argv)<3:
        print('usage: trace-stock-uefi-kernelvar-code-refs.py <guided-0-decompressed.bin> <report>'); return 2
    inp=Path(sys.argv[1]); rep=Path(sys.argv[2]); rep.parent.mkdir(parents=True,exist_ok=True)
    data=inp.read_bytes(); pes=find_pes(data)
    lines=['IzzOS exact stock UEFI kernel-variable code-reference trace','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(data)}',f'sha256: {hashlib.sha256(data).hexdigest()}',f'validated-pe-count: {len(pes)}']
    targets=[
        ('PropagateKernelSocInfo', b'PropagateKernelSocInfo'),
        ('KernelBaseAddr-utf16','KernelBaseAddr'.encode('utf-16le')),
        ('KernelSize-utf16','KernelSize'.encode('utf-16le')),
        ('KernelSize-ascii',b'KernelSize'),
        ('Kernel-not-preloaded',b'Kernel not preloaded'),
        ('Failed-Get-Kernel-info',b'Failed to Get Kernel info from UEFI Plat cfg'),
    ]
    for label,needle in targets:
        lines.append(f'\ntarget: {label}')
        pos=0; hits=[]
        while True:
            h=data.find(needle,pos)
            if h<0: break
            hits.append(h); pos=h+1
        lines.append(f'hit-count: {len(hits)}')
        for hi,h in enumerate(hits[:16]):
            lines.append(f'hit-{hi}-file-off: 0x{h:X}')
            containers=[pe for pe in pes if pe_contains(pe,h)]
            if not containers:
                lines.append('containing-pe: NONE')
                lines.append('nearby: '+ascii_window(data,h))
                continue
            pe=min(containers,key=lambda x: x['size_image'] or 0xffffffff)
            rva,sec=fileoff_to_rva(pe,h)
            lines += [f'containing-pe-base: 0x{pe["base"]:X}',f'pe-machine: 0x{pe["machine"]:04X}',f'pe-entry-rva: 0x{pe["entry"]:X}',f'pe-image-base: 0x{pe["image_base"]:X}',f'target-rva: 0x{rva:X}',f'target-section: {sec}']
            refs=find_adrp_add_refs(data,pe,rva)
            lines.append(f'adrp-add-ref-count: {len(refs)}')
            for ri,(fo,crva,ao,reg) in enumerate(refs[:16]):
                lines.append(f'ref-{ri}: file-off=0x{fo:X} code-rva=0x{crva:X} reg=x{reg}')
            # enumerate exact fallback-load constant only inside the same PE
            val=struct.pack('<Q',0x80080000); pp=pe['base']; vend=min(len(data),pe['base']+max(pe['size_image'],0x1000))
            occ=[]
            while True:
                q=data.find(val,pp,vend)
                if q<0: break
                occ.append(q); pp=q+1
            lines.append('same-pe-u64-0x80080000-offsets: '+('NONE' if not occ else ' '.join(f'0x{x:X}' for x in occ[:16])))
            lines.append('nearby: '+ascii_window(data,h))
    lines += ['','classification: STOCK_UEFI_KERNELVAR_CODE_REFS_TRACED','decision: exact PE containment and ARM64 ADRP+ADD references to kernel platform strings were traced host-side. These references identify producer/consumer code paths but do not alone prove final runtime KernelBaseAddr/KernelSize values or authorize an FD base or device launch.']
    rep.write_text('\n'.join(lines)+'\n',encoding='utf-8'); print('\n'.join(lines)); return 0
if __name__=='__main__': raise SystemExit(main())
