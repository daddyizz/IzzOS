#!/usr/bin/env python3
import hashlib, lzma, os, struct, sys, uuid

LZMA_GUID='ee4e5898-3914-4259-9d6e-dc7bd79403cf'

def u24(b,o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16)
def guid_le(raw): return str(uuid.UUID(bytes_le=raw))

def main():
    src=sys.argv[1] if len(sys.argv)>1 else './output/abl.img'
    outdir=sys.argv[2] if len(sys.argv)>2 else 'out/stock-abl-lzma'
    report=sys.argv[3] if len(sys.argv)>3 else 'out/stock-abl-lzma-analysis.txt'
    b=open(src,'rb').read()
    # Exact offsets established by prior parser; re-derive defensively from FV/FFS headers.
    fv=0x1000
    if b[fv+0x28:fv+0x2c] != b'_FVH': raise SystemExit('ERROR: FVH not found at expected exact-stock offset')
    hdrlen=struct.unpack_from('<H',b,fv+0x30)[0]
    ffs=fv+hdrlen
    sec=ffs+24
    ssize=u24(b,sec)
    stype=b[sec+3]
    if stype != 0x02: raise SystemExit(f'ERROR: expected GUID-defined section type 0x02, got 0x{stype:02X}')
    guid=guid_le(b[sec+4:sec+20])
    data_off=struct.unpack_from('<H',b,sec+20)[0]
    attrs=struct.unpack_from('<H',b,sec+22)[0]
    payload_start=sec+data_off
    payload_end=sec+ssize
    payload=b[payload_start:payload_end]
    os.makedirs(outdir,exist_ok=True)
    rawp=os.path.join(outdir,'guided-payload.lzma')
    open(rawp,'wb').write(payload)
    status='FAILED'; dec=b''; err=''
    for fmt,name in ((lzma.FORMAT_ALONE,'FORMAT_ALONE'),(lzma.FORMAT_AUTO,'FORMAT_AUTO')):
        try:
            dec=lzma.decompress(payload,format=fmt); status='PASS'; used=name; break
        except Exception as e: err=repr(e)
    if status!='PASS':
        used='NONE'
    outp=os.path.join(outdir,'decompressed.bin')
    if dec: open(outp,'wb').write(dec)
    lines=[
      'IzzOS exact stock ABL LZMA guided-section decompression',
      'Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',
      f'ABL image: {src}',f'ABL sha256: {hashlib.sha256(b).hexdigest()}',
      f'section-definition-guid: {guid}',f'expected-lzma-guid: {LZMA_GUID}',
      f'guided-data-offset: 0x{data_off:X}',f'guided-attributes: 0x{attrs:04X}',
      f'guided-payload-offset: 0x{payload_start:X}',f'guided-payload-size: 0x{len(payload):X}',
      f'guided-payload-sha256: {hashlib.sha256(payload).hexdigest()}',
      f'lzma-decompression-status: {status}',f'lzma-python-format-used: {used}'
    ]
    if dec:
      lines += [f'decompressed-size: 0x{len(dec):X} ({len(dec)} bytes)',f'decompressed-sha256: {hashlib.sha256(dec).hexdigest()}',f'decompressed-FVH-count: {dec.count(b"_FVH")}',f'decompressed-MZ-count: {dec.count(b"MZ")}',f'decompressed-PE-signature-count: {dec.count(b"PE\\x00\\x00")}',f'output: {outp}', 'classification: STOCK_ABL_LZMA_GUIDED_PAYLOAD_DECOMPRESSED', 'decision: the exact stock ABL guided payload was decompressed host-side. Internal FV/FFS/executable analysis is still required before drawing any conclusion about Android kernel relocation or firmware placement; no launch, flash, or slot change is authorized.']
    else:
      lines += [f'error: {err}','classification: STOCK_ABL_LZMA_DECOMPRESSION_UNRESOLVED','decision: do not infer internal executable layout until the guided payload is successfully decompressed. No device launch is authorized.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(report) or '.',exist_ok=True); open(report,'w',encoding='utf-8').write(text); print(text,end='')

if __name__=='__main__': main()
