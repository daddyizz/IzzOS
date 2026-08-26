#!/usr/bin/env python3
import os, sys, struct, hashlib, uuid

def u24(b,o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16)
def align(v,a): return (v+a-1)&~(a-1)
def guid_le(raw): return str(uuid.UUID(bytes_le=raw))

def find_fv(b):
    hits=[]; p=0
    while True:
        i=b.find(b'_FVH',p)
        if i<0: break
        start=i-0x28
        if start>=0 and start+0x38<=len(b):
            ln=struct.unpack_from('<Q',b,start+0x20)[0]
            hdr=struct.unpack_from('<H',b,start+0x30)[0]
            if ln and start+ln<=len(b) and hdr>=0x38: hits.append((start,ln,hdr))
        p=i+1
    return hits

def main():
    inp=sys.argv[1] if len(sys.argv)>1 else 'out/stock-abl-lzma/decompressed.bin'
    outp=sys.argv[2] if len(sys.argv)>2 else 'out/stock-abl-inner-fv-analysis.txt'
    b=open(inp,'rb').read(); lines=[]
    lines += ['IzzOS decompressed stock ABL inner FV analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}']
    fvs=find_fv(b); lines.append(f'inner-fv-count: {len(fvs)}')
    total_ffs=total_pe=total_te=total_ui=0
    for fi,(fs,fl,fh) in enumerate(fvs):
        lines += ['',f'fv-index: {fi}',f'fv-start: 0x{fs:X}',f'fv-length: 0x{fl:X}',f'fv-header-length: 0x{fh:X}']
        p=align(fs+fh,8); end=fs+fl; idx=0
        while p+24<=end:
            h=b[p:p+24]
            if h==b'\xff'*24: break
            sz=u24(b,p+20); typ=b[p+18]; attr=b[p+19]; state=b[p+23]
            if sz<24 or p+sz>end: break
            guid=guid_le(b[p:p+16]); total_ffs+=1
            lines += [f'ffs-index: {idx}',f'ffs-offset: 0x{p:X}',f'ffs-size: 0x{sz:X}',f'ffs-guid: {guid}',f'ffs-type: 0x{typ:02X}',f'ffs-attributes: 0x{attr:02X}',f'ffs-state: 0x{state:02X}']
            sp=p+24; fend=p+sz; si=0
            while sp+4<=fend:
                ssz=u24(b,sp); st=b[sp+3]
                if ssz<4 or sp+ssz>fend: break
                kind={0x10:'PE32',0x12:'TE',0x15:'UI',0x14:'VERSION',0x19:'RAW',0x01:'COMPRESSION',0x02:'GUID_DEFINED'}.get(st,'OTHER')
                lines.append(f'  section-{si}: offset=0x{sp:X} size=0x{ssz:X} type=0x{st:02X} kind={kind}')
                payload=sp+4
                if st==0x15:
                    try:
                        raw=b[payload:sp+ssz]; name=raw.decode('utf-16le','ignore').split('\x00',1)[0]; lines.append(f'    ui-name: {name}'); total_ui+=1
                    except: pass
                elif st==0x10:
                    total_pe+=1
                    if b[payload:payload+2]==b'MZ' and payload+0x40<=len(b):
                        pe=payload+struct.unpack_from('<I',b,payload+0x3c)[0]
                        if b[pe:pe+4]==b'PE\0\0':
                            mach=struct.unpack_from('<H',b,pe+4)[0]; opt=pe+24; magic=struct.unpack_from('<H',b,opt)[0]; ep=struct.unpack_from('<I',b,opt+16)[0]
                            base=struct.unpack_from('<Q',b,opt+24)[0] if magic==0x20b else struct.unpack_from('<I',b,opt+28)[0]
                            lines += [f'    pe-machine: 0x{mach:04X}',f'    pe-entry-rva: 0x{ep:X}',f'    pe-image-base: 0x{base:X}']
                elif st==0x12:
                    total_te+=1
                    if b[payload:payload+2]==b'VZ' and payload+40<=len(b):
                        mach=struct.unpack_from('<H',b,payload+2)[0]; ep=struct.unpack_from('<I',b,payload+8)[0]; base=struct.unpack_from('<Q',b,payload+16)[0]
                        lines += [f'    te-machine: 0x{mach:04X}',f'    te-entry-rva: 0x{ep:X}',f'    te-image-base: 0x{base:X}']
                sp=align(sp+ssz,4); si+=1
            p=align(p+sz,8); idx+=1
    lines += ['',f'ffs-file-count: {total_ffs}',f'ui-section-count: {total_ui}',f'pe32-section-count: {total_pe}',f'te-section-count: {total_te}','classification: STOCK_ABL_INNER_FV_COMPONENTS_ENUMERATED','decision: decompressed inner FV files and executable sections were enumerated host-side. Link-time addresses are evidence only and do not authorize a firmware load base, fastboot boot, flashing, or slot changes.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(outp) or '.',exist_ok=True); open(outp,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
