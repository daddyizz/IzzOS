#!/usr/bin/env python3
import hashlib, os, struct, sys, uuid


def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u24(b,o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16)
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
def guid_le(raw): return str(uuid.UUID(bytes_le=raw))
def align4(n): return (n+3)&~3

def valid_pe_at(b, mz):
    if mz+0x40 > len(b) or b[mz:mz+2] != b'MZ': return None
    e=u32(b,mz+0x3c); pe=mz+e
    if pe+0x108 > len(b) or b[pe:pe+4] != b'PE\0\0': return None
    mach=u16(b,pe+4); nsec=u16(b,pe+6); opt=u16(b,pe+20)
    om=pe+24
    magic=u16(b,om)
    if magic not in (0x10b,0x20b): return None
    entry=u32(b,om+16)
    if magic==0x20b:
        image_base=u64(b,om+24); size_image=u32(b,om+56)
    else:
        image_base=u32(b,om+28); size_image=u32(b,om+56)
    return dict(mz=mz,pe=pe,machine=mach,nsec=nsec,opt=opt,magic=magic,entry=entry,image_base=image_base,size_image=size_image)

def main():
    p=sys.argv[1] if len(sys.argv)>1 else './output/abl.img'
    outp=sys.argv[2] if len(sys.argv)>2 else 'out/stock-abl-guided-analysis.txt'
    b=open(p,'rb').read(); sha=hashlib.sha256(b).hexdigest()
    fvh=b.find(b'_FVH')
    if fvh<0: raise SystemExit('ERROR: no _FVH signature')
    fv=fvh-0x28; fvlen=u64(b,fv+0x20); hdr=u16(b,fv+0x30)
    ffs=fv+hdr
    fsz=u24(b,ffs+20); sec=ffs+24
    ssz=u24(b,sec); st=b[sec+3]
    lines=['IzzOS exact stock ABL GUID-defined section analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'ABL image: {p}',f'byte-size: {len(b)}',f'sha256: {sha}',f'fv-start: 0x{fv:X}',f'fv-length: 0x{fvlen:X}',f'ffs-offset: 0x{ffs:X}',f'ffs-size: 0x{fsz:X}',f'outer-section-offset: 0x{sec:X}',f'outer-section-size: 0x{ssz:X}',f'outer-section-type: 0x{st:02X}']
    if st != 0x02:
        lines += ['classification: STOCK_ABL_GUIDED_SECTION_NOT_FOUND','decision: expected GUID-defined section type 0x02 was not present. No launch is authorized.']
    else:
        body=sec+4
        g=guid_le(b[body:body+16]); data_off=u16(b,body+16); attrs=u16(b,body+18); payload=sec+data_off; pend=sec+ssz
        lines += [f'section-definition-guid: {g}',f'guided-data-offset: 0x{data_off:X}',f'guided-attributes: 0x{attrs:04X}',f'guided-payload-offset: 0x{payload:X}',f'guided-payload-size: 0x{max(0,pend-payload):X}']
        # Scan only inside guided payload for signatures and validate PE candidates.
        pes=[]; pos=payload
        while True:
            m=b.find(b'MZ',pos,pend)
            if m<0: break
            v=valid_pe_at(b,m)
            if v: pes.append(v)
            pos=m+2
        lines.append(f'guided-valid-pe-count: {len(pes)}')
        for i,v in enumerate(pes):
            lines += [f'pe-index: {i}',f'  mz-offset: 0x{v["mz"]:X}',f'  pe-offset: 0x{v["pe"]:X}',f'  machine: 0x{v["machine"]:04X}',f'  sections: {v["nsec"]}',f'  optional-magic: 0x{v["magic"]:04X}',f'  entry-rva: 0x{v["entry"]:X}',f'  image-base: 0x{v["image_base"]:X}',f'  size-of-image: 0x{v["size_image"]:X}']
        # Also report nested section-like records from payload start if present.
        q=payload; nested=[]
        while q+4<=pend:
            n=u24(b,q); t=b[q+3]
            if n in (0,0xffffff) or n<4 or q+n>pend: break
            nested.append((q,n,t)); q=align4(q+n)
            if len(nested)>64: break
        lines.append(f'nested-section-count-from-guided-payload-start: {len(nested)}')
        for i,(o,n,t) in enumerate(nested): lines.append(f'nested-{i}: offset=0x{o:X} size=0x{n:X} type=0x{t:02X}')
        lines += ['classification: STOCK_ABL_GUIDED_PAYLOAD_ENUMERATED','decision: GUID-defined ABL payload boundaries and any directly embedded valid PE images were enumerated host-side. Encapsulation may still require GUID-specific processing/decompression; no Android kernel relocation behavior, FD base, fastboot boot, flashing, or slot change is authorized.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(outp) or '.',exist_ok=True); open(outp,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
