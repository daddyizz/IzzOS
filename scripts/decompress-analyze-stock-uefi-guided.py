#!/usr/bin/env python3
import sys, struct, hashlib, lzma, gzip, zlib
from pathlib import Path

LZMA_GUID_LE = bytes.fromhex('98584eee143959429d6edc7bd79403cf')
GZIP_QC_GUID_LE = bytes.fromhex('e91f301d79be534391c2d23bc959ae0c')
KNOWN_STOCK_GUIDED_OFFSETS = (0x4B0E0, 0x1A1748)

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
            if data[p:p+16]==b'\xff'*16:
                p=align(p+8,8); continue
            size=u24(data,p+20)
            if size in (0,0xffffff) or p+size>end: break
            guid=guid_str_le(data[p:p+16]); typ=data[p+18]
            lines.append(f'{label}-ffs-{idx}: off=0x{p:X} size=0x{size:X} guid={guid} type=0x{typ:02X}')
            sp=p+24; se=p+size
            while sp+4<=se:
                ss=u24(data,sp); st=data[sp+3]
                if ss<4 or sp+ss>se: break
                if st==0x15:
                    raw=data[sp+4:sp+ss]
                    try: nm=raw.decode('utf-16le','ignore').rstrip('\x00')
                    except: nm=''
                    if nm:
                        names.append(nm); lines.append(f'  ui-name: {nm}')
                elif st in (0x10,0x12):
                    lines.append(f'  executable-section: type=0x{st:02X} off=0x{sp:X} size=0x{ss:X}')
                sp=align(sp+ss,4)
            p=align(p+size,8); idx+=1
    return names

def decompress_guided(g, payload):
    if g==LZMA_GUID_LE:
        for f,name in ((lzma.FORMAT_ALONE,'LZMA_FORMAT_ALONE'),(lzma.FORMAT_AUTO,'LZMA_FORMAT_AUTO')):
            try: return lzma.decompress(payload,format=f), name
            except Exception: pass
        return None,'LZMA_FAILED'
    if g==GZIP_QC_GUID_LE:
        attempts=[(payload,'GZIP_DIRECT')]
        gz=payload.find(b'\x1f\x8b\x08')
        if gz>0: attempts.append((payload[gz:],f'GZIP_MAGIC_AT_0x{gz:X}'))
        for blob,name in attempts:
            try: return gzip.decompress(blob), name
            except Exception: pass
            try: return zlib.decompress(blob,16+zlib.MAX_WBITS), name+'_ZLIB'
            except Exception: pass
        return None,'GZIP_QC_FAILED'
    return None,'UNSUPPORTED_GUID'

def decode_guided_header(data, sp, discovery):
    if sp+0x18>len(data): return None
    ss=u24(data,sp); st=data[sp+3]
    if st!=0x02 or ss<0x1c or sp+ss>len(data): return None
    g=data[sp+4:sp+20]
    doff=struct.unpack_from('<H',data,sp+20)[0]
    attrs=struct.unpack_from('<H',data,sp+22)[0]
    if doff<0x18 or doff>=ss: return None
    return (sp,ss,g,doff,attrs,discovery)

def main():
    if len(sys.argv)<4:
        print('usage: decompress-analyze-stock-uefi-guided.py <uefi.img> <outdir> <report>'); return 2
    inp=Path(sys.argv[1]); outdir=Path(sys.argv[2]); report=Path(sys.argv[3])
    outdir.mkdir(parents=True,exist_ok=True); report.parent.mkdir(parents=True,exist_ok=True)
    data=inp.read_bytes()
    lines=['IzzOS exact stock UEFI GUID-defined decompression analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(data)}',f'sha256: {hashlib.sha256(data).hexdigest()}']
    guided=[]; seen=set()
    for fs,fl,fh in find_fvs(data):
        p=align(fs+fh,8); end=fs+fl
        while p+24<=end:
            if data[p:p+16]==b'\xff'*16:
                p=align(p+8,8); continue
            sz=u24(data,p+20)
            if sz in (0,0xffffff) or p+sz>end: break
            sp=p+24; se=p+sz
            while sp+4<=se:
                ss=u24(data,sp); st=data[sp+3]
                if ss<4 or sp+ss>se: break
                if st==0x02:
                    ent=decode_guided_header(data,sp,'FV_WALK')
                    if ent and sp not in seen:
                        guided.append(ent); seen.add(sp)
                sp=align(sp+ss,4)
            p=align(p+sz,8)
    # Exact-stock fallback: prior independent FV parser established these two section offsets.
    fallback_added=0
    for sp in KNOWN_STOCK_GUIDED_OFFSETS:
        if sp not in seen:
            ent=decode_guided_header(data,sp,'EXACT_STOCK_OFFSET_FALLBACK')
            if ent:
                guided.append(ent); seen.add(sp); fallback_added+=1
    raw_hits=[]
    for guid in (LZMA_GUID_LE,GZIP_QC_GUID_LE):
        pos=0
        while True:
            h=data.find(guid,pos)
            if h<0: break
            raw_hits.append((h,guid)); pos=h+1
    lines.append(f'direct-known-compression-guid-hit-count: {len(raw_hits)}')
    lines.append(f'exact-stock-offset-fallback-added: {fallback_added}')
    lines.append(f'guided-section-count: {len(guided)}')
    allnames=[]
    for i,(sp,ss,g,doff,attrs,discovery) in enumerate(sorted(guided)):
        gs=guid_str_le(g); po=sp+doff; payload=data[po:sp+ss]
        lines += [f'guided-{i}-discovery: {discovery}',f'guided-{i}-section-offset: 0x{sp:X}',f'guided-{i}-section-size: 0x{ss:X}',f'guided-{i}-guid: {gs}',f'guided-{i}-data-offset: 0x{doff:X}',f'guided-{i}-attributes: 0x{attrs:04X}',f'guided-{i}-payload-size: 0x{len(payload):X}']
        dec,fmt=decompress_guided(g,payload)
        if dec is None:
            lines.append(f'guided-{i}-decompression-status: UNSUPPORTED_OR_FAILED')
            lines.append(f'guided-{i}-decoder-result: {fmt}')
            continue
        op=outdir/f'guided-{i}-decompressed.bin'; op.write_bytes(dec)
        lines += [f'guided-{i}-decompression-status: PASS',f'guided-{i}-compression-format: {fmt}',f'guided-{i}-decompressed-size: 0x{len(dec):X}',f'guided-{i}-decompressed-sha256: {hashlib.sha256(dec).hexdigest()}',f'guided-{i}-output: {op}']
        allnames += parse_inner_fv(dec,lines,f'guided-{i}')
        for needle in ('KernelBaseAddr','KernelSize'):
            a=dec.find(needle.encode()); w=dec.find(needle.encode('utf-16le'))
            lines.append(f'guided-{i}-{needle}-ascii-hit: '+('NONE' if a<0 else f'0x{a:X}'))
            lines.append(f'guided-{i}-{needle}-utf16-hit: '+('NONE' if w<0 else f'0x{w:X}'))
    lines.append('candidate-ui-names:')
    for n in allnames:
        low=n.lower()
        if any(k in low for k in ('mem','ram','dxe','variable','platform','boot','config','uefi')): lines.append(n)
    lines += ['classification: STOCK_UEFI_GUIDED_PAYLOADS_DISCOVERED_AND_ANALYZED','decision: stock UEFI guided payloads were decoded and enumerated host-side only. Module names or variable strings do not by themselves prove runtime KernelBaseAddr/KernelSize values or authorize any FD base, fastboot boot, flashing, or slot change.']
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8'); print('\n'.join(lines)); return 0
if __name__=='__main__': raise SystemExit(main())
