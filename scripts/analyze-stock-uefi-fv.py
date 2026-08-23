#!/usr/bin/env python3
import sys, struct, hashlib
from pathlib import Path

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <uefi.img> <report.txt>")
    raise SystemExit(2)

inp = Path(sys.argv[1]); out = Path(sys.argv[2])
data = inp.read_bytes()
lines=[]
lines.append('IzzOS exact stock UEFI FV/FFS structural analysis')
lines.append('Collector mode: READ_ONLY_HOST_SIDE')
lines.append('Device writes: NONE')
lines.append(f'input: {inp}')
lines.append(f'byte-size: {len(data)}')
lines.append(f'sha256: {hashlib.sha256(data).hexdigest()}')

# Locate firmware volumes by _FVH signature. Signature is at FV base + 0x28.
fv_bases=[]
pos=0
while True:
    i=data.find(b'_FVH',pos)
    if i<0: break
    base=i-0x28
    if base>=0 and base+0x38<=len(data):
        fvlen=struct.unpack_from('<Q',data,base+0x20)[0]
        hdrlen=struct.unpack_from('<H',data,base+0x30)[0]
        if 0x38 <= hdrlen <= 0x1000 and 0 < fvlen <= len(data)-base:
            fv_bases.append((base,fvlen,hdrlen))
    pos=i+4
lines.append(f'validated-fv-count: {len(fv_bases)}')

for fi,(base,fvlen,hdrlen) in enumerate(fv_bases):
    lines.append(f'fv-index: {fi}')
    lines.append(f'fv-start: 0x{base:X}')
    lines.append(f'fv-length: 0x{fvlen:X}')
    lines.append(f'fv-header-length: 0x{hdrlen:X}')
    off=(base+hdrlen+7)&~7
    end=base+fvlen
    fcount=0
    while off+24<=end:
        hdr=data[off:off+24]
        if hdr == b'\xff'*24 or hdr == b'\x00'*24:
            off+=8; continue
        guid=hdr[:16]
        ftype=hdr[18]; attrs=hdr[19]
        size=hdr[20] | (hdr[21]<<8) | (hdr[22]<<16)
        state=hdr[23]
        if size in (0,0xFFFFFF) or off+size>end:
            off+=8; continue
        def guidstr(g):
            d1,d2,d3=struct.unpack_from('<IHH',g,0); tail=g[8:]
            return f'{d1:08x}-{d2:04x}-{d3:04x}-{tail[:2].hex()}-{tail[2:].hex()}'
        lines.append(f'ffs-index: {fcount} offset=0x{off:X} size=0x{size:X} guid={guidstr(guid)} type=0x{ftype:02X} attrs=0x{attrs:02X} state=0x{state:02X}')
        soff=off+24
        send=off+size
        secidx=0
        while soff+4<=send:
            ssize=data[soff] | (data[soff+1]<<8) | (data[soff+2]<<16)
            stype=data[soff+3]
            if ssize in (0,0xFFFFFF) or soff+ssize>send: break
            kind={0x10:'PE32',0x12:'TE',0x15:'UI',0x02:'GUID_DEFINED',0x01:'COMPRESSION'}.get(stype,'OTHER')
            line=f'  section-{secidx}: offset=0x{soff:X} size=0x{ssize:X} type=0x{stype:02X} kind={kind}'
            if stype==0x15 and ssize>4:
                raw=data[soff+4:soff+ssize]
                try:
                    name=raw.decode('utf-16le','ignore').split('\x00')[0]
                    if name: line += f' ui-name={name}'
                except Exception: pass
            elif stype==0x10 and ssize>0x100:
                blob=data[soff+4:soff+ssize]
                if blob[:2]==b'MZ' and len(blob)>=0x40:
                    peoff=struct.unpack_from('<I',blob,0x3c)[0]
                    if peoff+6<len(blob) and blob[peoff:peoff+4]==b'PE\0\0':
                        mach=struct.unpack_from('<H',blob,peoff+4)[0]
                        line += f' pe-machine=0x{mach:04X}'
            lines.append(line)
            soff=(soff+ssize+3)&~3; secidx+=1
        fcount+=1
        off=(off+size+7)&~7
    lines.append(f'fv-{fi}-ffs-count: {fcount}')

for target in (b'KernelBaseAddr', b'KernelSize', 'KernelBaseAddr'.encode('utf-16le'), 'KernelSize'.encode('utf-16le')):
    hits=[]; p=0
    while True:
        i=data.find(target,p)
        if i<0: break
        hits.append(i); p=i+1
    label='utf16' if b'\x00' in target else 'ascii'
    lines.append(f'{label}-{target[:10].hex()}-hits: ' + (' '.join(f'0x{x:X}' for x in hits) if hits else 'NONE'))

lines.append('classification: STOCK_UEFI_FV_FFS_STRUCTURE_ENUMERATED')
lines.append('decision: exact stock UEFI firmware-volume and FFS/section structure was enumerated host-side. This identifies candidate modules for deeper producer analysis only; no runtime KernelBaseAddr/KernelSize value, FD base, fastboot boot, flashing, or slot change is authorized.')
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('\n'.join(lines))
