#!/usr/bin/env python3
import sys, struct, hashlib, lzma
from pathlib import Path

LZMA_GUID_LE = bytes.fromhex('98584eee143959429d6edc7bd79403cf')

def u24(b,o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16)
def align(x,a): return (x+a-1)&~(a-1)
def guid_str_le(g):
    d1,d2,d3=struct.unpack_from('<IHH',g,0)
    return f'{d1:08x}-{d2:04x}-{d3:04x}-{g[8]:02x}{g[9]:02x}-'+''.join(f'{x:02x}' for x in g[10:])

def find_fvs(data):
    out=[]; pos=0
    while True:
        s=data.find(b'_FVH',pos)
        if s<0: break
        start=s-0x28
        if start>=0 and start+0x38<=len(data):
            ln=struct.unpack_from('<Q',data,start+0x20)[0]
            hdr=struct.unpack_from('<H',data,start+0x30)[0]
            if 0x48<=hdr<=0x1000 and ln>=hdr and start+ln<=len(data): out.append((start,ln,hdr))
        pos=s+4
    return out

def parse_inner_fv(data, lines, label):
    fvs=find_fvs(data)
    lines.append(f'{label}-inner-fv-count: {len(fvs)}')
    names=[]
    for fi,(fs,fl,fh) in enumerate(fvs):
        lines += [f'{label}-fv-{fi}-start: 0x{fs:X}',f'{label}-fv-{fi}-length: 0x{fl:X}']
        p=align(fs+fh,8); end=fs+fl; idx=0
        while p+24<=end:
            size=u24(data,p+20)
            if size in (0,0xffffff) or p+size>end:
                # Padding or an unsupported extended FFS header; advance conservatively.
                p=align(p+8,8); continue
            guid=guid_str_le(data[p:p+16]); typ=data[p+18]
            lines.append(f'{label}-ffs-{idx}: off=0x{p:X} size=0x{size:X} guid={guid} type=0x{typ:02X}')
            sp=p+24; se=p+size
            while sp+4<=se:
                ss=u24(data,sp); st=data[sp+3]
                if ss<4 or sp+ss>se: break
                if st==0x15:
                    raw=data[sp+4:sp+ss]
                    try: nm=raw.decode('utf-16le','ignore').rstrip('\x00')
                    except Exception: nm=''
                    if nm:
                        names.append(nm); lines.append(f'  ui-name: {nm}')
                elif st in (0x10,0x12):
                    lines.append(f'  executable-section: type=0x{st:02X} off=0x{sp:X} size=0x{ss:X}')
                sp=align(sp+ss,4)
            p=align(p+size,8); idx+=1
    return names

def discover_guided_sections(data, lines):
    guided=[]
    seen=set()

    # Primary path: walk outer FV/FFS section tables.
    for fs,fl,fh in find_fvs(data):
        p=align(fs+fh,8); end=fs+fl
        while p+24<=end:
            sz=u24(data,p+20)
            if sz in (0,0xffffff) or p+sz>end:
                p=align(p+8,8); continue
            sp=p+24; se=p+sz
            while sp+4<=se:
                ss=u24(data,sp); st=data[sp+3]
                if ss<4 or sp+ss>se: break
                if st==0x02 and ss>=0x1c:
                    g=data[sp+4:sp+20]; doff=struct.unpack_from('<H',data,sp+20)[0]; attrs=struct.unpack_from('<H',data,sp+22)[0]
                    key=(sp,ss)
                    if key not in seen:
                        guided.append((sp,ss,g,doff,attrs,'FV_WALK')); seen.add(key)
                sp=align(sp+ss,4)
            p=align(p+sz,8)

    # Robust fallback: exact UEFI image already proved GUID_DEFINED sections exist.
    # Locate the EDK2 LZMA GUID directly; in a GUID-defined section the GUID begins
    # immediately after the 4-byte common section header.
    pos=0
    direct_hits=0
    while True:
        goff=data.find(LZMA_GUID_LE,pos)
        if goff<0: break
        direct_hits+=1
        sp=goff-4
        if sp>=0 and sp+24<=len(data) and data[sp+3]==0x02:
            ss=u24(data,sp)
            if ss>=0x1c and sp+ss<=len(data):
                doff=struct.unpack_from('<H',data,sp+20)[0]
                attrs=struct.unpack_from('<H',data,sp+22)[0]
                if 0x18<=doff<ss:
                    key=(sp,ss)
                    if key not in seen:
                        guided.append((sp,ss,LZMA_GUID_LE,doff,attrs,'DIRECT_LZMA_GUID_SCAN')); seen.add(key)
        pos=goff+1
    lines.append(f'direct-lzma-guid-hit-count: {direct_hits}')
    guided.sort(key=lambda x:x[0])
    return guided

def main():
    if len(sys.argv)<4:
        print('usage: decompress-analyze-stock-uefi-guided.py <uefi.img> <outdir> <report>'); return 2
    inp=Path(sys.argv[1]); outdir=Path(sys.argv[2]); report=Path(sys.argv[3]); outdir.mkdir(parents=True,exist_ok=True); report.parent.mkdir(parents=True,exist_ok=True)
    data=inp.read_bytes(); lines=['IzzOS exact stock UEFI GUID-defined decompression analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(data)}',f'sha256: {hashlib.sha256(data).hexdigest()}']

    guided=discover_guided_sections(data,lines)
    lines.append(f'guided-section-count: {len(guided)}')
    allnames=[]
    for i,(sp,ss,g,doff,attrs,method) in enumerate(guided):
        gs=guid_str_le(g); po=sp+doff; payload=data[po:sp+ss]
        lines += [f'guided-{i}-discovery: {method}',f'guided-{i}-section-offset: 0x{sp:X}',f'guided-{i}-section-size: 0x{ss:X}',f'guided-{i}-guid: {gs}',f'guided-{i}-data-offset: 0x{doff:X}',f'guided-{i}-attributes: 0x{attrs:04X}',f'guided-{i}-payload-size: 0x{len(payload):X}']
        dec=None; fmt='NONE'; last_error=''
        if g==LZMA_GUID_LE:
            for f,name in ((lzma.FORMAT_ALONE,'FORMAT_ALONE'),(lzma.FORMAT_AUTO,'FORMAT_AUTO')):
                try: dec=lzma.decompress(payload,format=f); fmt=name; break
                except Exception as e: last_error=str(e)
        if dec is None:
            lines.append(f'guided-{i}-decompression-status: UNSUPPORTED_OR_FAILED')
            if last_error: lines.append(f'guided-{i}-decompression-error: {last_error}')
            continue
        op=outdir/f'guided-{i}-decompressed.bin'; op.write_bytes(dec)
        lines += [f'guided-{i}-decompression-status: PASS',f'guided-{i}-lzma-format: {fmt}',f'guided-{i}-decompressed-size: 0x{len(dec):X}',f'guided-{i}-decompressed-sha256: {hashlib.sha256(dec).hexdigest()}',f'guided-{i}-output: {op}']
        allnames += parse_inner_fv(dec,lines,f'guided-{i}')
        for needle in ('KernelBaseAddr','KernelSize'):
            a=dec.find(needle.encode()); w=dec.find(needle.encode('utf-16le'))
            lines.append(f'guided-{i}-{needle}-ascii-hit: '+('NONE' if a<0 else f'0x{a:X}'))
            lines.append(f'guided-{i}-{needle}-utf16-hit: '+('NONE' if w<0 else f'0x{w:X}'))
    lines.append('candidate-ui-names:')
    for n in allnames:
        low=n.lower()
        if any(k in low for k in ('mem','ram','dxe','variable','platform','boot','config','uefi')): lines.append(n)
    if guided:
        classification='STOCK_UEFI_GUIDED_PAYLOADS_DISCOVERED_AND_ANALYZED'
    else:
        classification='STOCK_UEFI_GUIDED_DISCOVERY_FAILED_INCONSISTENT_WITH_PRIOR_FV_EVIDENCE'
    lines += [f'classification: {classification}','decision: compressed stock UEFI payloads and inner module names were analyzed host-side only. Presence of a module or variable string does not by itself prove runtime KernelBaseAddr/KernelSize values or authorize any FD base, fastboot boot, flashing, or slot change.']
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8'); print('\n'.join(lines)); return 0
if __name__=='__main__': raise SystemExit(main())
