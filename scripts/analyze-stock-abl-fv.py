#!/usr/bin/env python3
import hashlib, os, struct, sys, uuid

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u24(b,o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16)
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
def align(n,a): return (n + a - 1) & ~(a-1)
def guid_le(b): return str(uuid.UUID(bytes_le=b))

def main():
    path=sys.argv[1] if len(sys.argv)>1 else './output/abl.img'
    outp=sys.argv[2] if len(sys.argv)>2 else 'out/stock-abl-fv-analysis.txt'
    b=open(path,'rb').read()
    lines=[]
    lines += ['IzzOS exact stock ABL FV/FFS analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'ABL image: {path}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}']
    sig=b.find(b'_FVH')
    if sig<0:
        lines += ['classification: STOCK_ABL_FV_NOT_FOUND','decision: no firmware volume header signature found; keep bootloader relocation behavior unresolved.']
    else:
        fv=sig-0x28
        fvlen=u64(b,fv+0x20)
        hdrlen=u16(b,fv+0x30)
        lines += [f'fv-start: 0x{fv:X}',f'fv-length: 0x{fvlen:X}',f'fv-header-length: 0x{hdrlen:X}']
        p=align(fv+hdrlen,8); end=min(len(b),fv+fvlen); fidx=0; pe_like=0; te_like=0
        while p+24<=end:
            if b[p:p+24]==b'\xff'*24:
                p=align(p+8,8); continue
            name=b[p:p+16]
            ftype=b[p+18]; attrs=b[p+19]; fsize=u24(b,p+20); state=b[p+23]
            if fsize in (0,0xffffff) or p+fsize>end: break
            lines += [f'ffs-index: {fidx}',f'ffs-offset: 0x{p:X}',f'ffs-size: 0x{fsize:X}',f'ffs-guid: {guid_le(name)}',f'ffs-type: 0x{ftype:02X}',f'ffs-attributes: 0x{attrs:02X}',f'ffs-state: 0x{state:02X}']
            sp=p+24; fend=p+fsize; sidx=0
            while sp+4<=fend:
                if b[sp:sp+4]==b'\xff'*4: break
                ssize=u24(b,sp); stype=b[sp+3]
                if ssize in (0,0xffffff) or sp+ssize>fend: break
                payload=sp+4
                kind='OTHER'
                if stype==0x10:
                    kind='PE32'; pe_like+=1
                elif stype==0x12:
                    kind='TE'; te_like+=1
                elif stype==0x15:
                    kind='UI'
                elif stype==0x19:
                    kind='RAW'
                lines += [f'  section-{sidx}: offset=0x{sp:X} size=0x{ssize:X} type=0x{stype:02X} kind={kind}']
                if stype==0x15:
                    raw=b[payload:sp+ssize]
                    try:
                        txt=raw.decode('utf-16le','ignore').split('\x00',1)[0]
                    except Exception:
                        txt=''
                    if txt: lines += [f'    ui-name: {txt}']
                if stype==0x10 and payload+0x40 < len(b):
                    mz='yes' if b[payload:payload+2]==b'MZ' else 'no'
                    lines += [f'    pe32-mz-at-section-payload: {mz}']
                    if mz=='yes':
                        peoff=u32(b,payload+0x3c)
                        if payload+peoff+24<=len(b) and b[payload+peoff:payload+peoff+4]==b'PE\0\0':
                            machine=u16(b,payload+peoff+4); opt=payload+peoff+24; magic=u16(b,opt); entry=u32(b,opt+16)
                            image_base=u64(b,opt+24) if magic==0x20b else u32(b,opt+28)
                            size_img=u32(b,opt+56)
                            lines += [f'    pe-machine: 0x{machine:04X}',f'    pe-opt-magic: 0x{magic:04X}',f'    pe-entry-rva: 0x{entry:X}',f'    pe-image-base: 0x{image_base:X}',f'    pe-size-of-image: 0x{size_img:X}']
                if stype==0x12 and payload+40<=len(b):
                    sig2=u16(b,payload); machine=u16(b,payload+2); stripped=u16(b,payload+6); entry=u32(b,payload+8); base=u64(b,payload+16)
                    lines += [f'    te-signature: 0x{sig2:04X}',f'    te-machine: 0x{machine:04X}',f'    te-stripped-size: 0x{stripped:X}',f'    te-entry-point: 0x{entry:X}',f'    te-image-base: 0x{base:X}']
                sp=align(sp+ssize,4); sidx+=1
            lines.append(''); p=align(p+fsize,8); fidx+=1
        lines += [f'ffs-file-count: {fidx}',f'pe32-section-count: {pe_like}',f'te-section-count: {te_like}','classification: STOCK_ABL_FV_FFS_COMPONENTS_ENUMERATED','decision: exact ABL firmware-volume files and executable sections were enumerated host-side. Link-time image bases are not by themselves proof of Android kernel relocation or a safe FD base; no launch, flash, or slot change is authorized.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(outp) or '.',exist_ok=True); open(outp,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
