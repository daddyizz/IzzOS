#!/usr/bin/env python3
import sys, hashlib, re
from pathlib import Path

# Exact stock CPH2413 UEFI FV evidence from analyze-stock-uefi-fv.py:
# FFS uefiplat.cfg at 0x49000, RAW section at 0x49038 size 0x208A.
RAW_SECTION_OFF = 0x49038
RAW_SECTION_SIZE = 0x208A

def u24(b, o):
    return b[o] | (b[o+1] << 8) | (b[o+2] << 16)

def printable_ascii_runs(data, minlen=4):
    out=[]
    for m in re.finditer(rb'[\x20-\x7e\t\r\n]{%d,}' % minlen, data):
        s=m.group().decode('ascii','replace')
        out.append((m.start(), s))
    return out

def utf16_runs(data, minchars=4):
    out=[]
    # tolerant scan for printable UTF-16LE runs
    i=0
    while i+2 <= len(data):
        start=i; chars=[]
        while i+2 <= len(data):
            lo,hi=data[i],data[i+1]
            if hi==0 and (lo==9 or lo==10 or lo==13 or 0x20<=lo<=0x7e):
                chars.append(chr(lo)); i+=2
            else:
                break
        if len(chars)>=minchars:
            out.append((start,''.join(chars)))
        i=max(i+2,start+2)
    return out

def main():
    if len(sys.argv) < 4:
        print('usage: extract-analyze-uefiplat-cfg.py <uefi.img> <output-cfg> <report>')
        return 2
    inp=Path(sys.argv[1]); outcfg=Path(sys.argv[2]); report=Path(sys.argv[3])
    data=inp.read_bytes()
    if len(data) < RAW_SECTION_OFF + 4:
        raise SystemExit('ERROR: input too small for exact stock uefiplat.cfg RAW section')
    ss=u24(data, RAW_SECTION_OFF); st=data[RAW_SECTION_OFF+3]
    if ss != RAW_SECTION_SIZE or st != 0x19:
        raise SystemExit(f'ERROR: exact stock RAW section mismatch: size=0x{ss:X} type=0x{st:02X}')
    payload=data[RAW_SECTION_OFF+4:RAW_SECTION_OFF+ss]
    outcfg.parent.mkdir(parents=True,exist_ok=True); report.parent.mkdir(parents=True,exist_ok=True)
    outcfg.write_bytes(payload)
    lines=[
        'IzzOS exact stock uefiplat.cfg extraction / key-value analysis',
        'Collector mode: READ_ONLY_HOST_SIDE',
        'Device writes: NONE',
        f'input: {inp}',
        f'input-sha256: {hashlib.sha256(data).hexdigest()}',
        f'raw-section-offset: 0x{RAW_SECTION_OFF:X}',
        f'raw-section-size: 0x{ss:X}',
        f'raw-section-type: 0x{st:02X}',
        f'payload-size: 0x{len(payload):X}',
        f'payload-sha256: {hashlib.sha256(payload).hexdigest()}',
        f'output: {outcfg}',
    ]
    targets=['KernelBaseAddr','KernelSize','Shared_IMEM_Base','BootDeviceBaseAddr','MemBase','MemSize','KernelLoadAddress','RamdiskEndAddress','BaseMemory','MemoryMap','RAM','DDR']
    text_ascii=payload.decode('latin1','ignore')
    text_utf16=payload.decode('utf-16le','ignore') if len(payload)%2==0 else ''
    lines.append('target-hits:')
    for t in targets:
        ah=[]; p=0
        while True:
            p=payload.find(t.encode(),p)
            if p<0: break
            ah.append(p); p+=1
        wh=[]; p=0; w=t.encode('utf-16le')
        while True:
            p=payload.find(w,p)
            if p<0: break
            wh.append(p); p+=2
        lines.append(f'{t}: ascii={",".join(f"0x{x:X}" for x in ah) or "NONE"} utf16={",".join(f"0x{x:X}" for x in wh) or "NONE"}')
        for x in ah[:8]:
            lo=max(0,x-96); hi=min(len(payload),x+192)
            near=''.join(chr(c) if 32<=c<127 else '.' for c in payload[lo:hi])
            lines.append(f'  ascii-context@0x{x:X}: {near}')
        for x in wh[:8]:
            lo=max(0,x-128); hi=min(len(payload),x+256)
            near=payload[lo:hi].decode('utf-16le','ignore').replace('\x00','.')
            lines.append(f'  utf16-context@0x{x:X}: {near}')
    lines.append('printable-ascii-runs:')
    for off,s in printable_ascii_runs(payload):
        if any(k.lower() in s.lower() for k in ('kernel','mem','ram','ddr','boot','base','size','region')):
            lines.append(f'0x{off:X}: {s[:600]}')
    lines.append('printable-utf16-runs:')
    for off,s in utf16_runs(payload):
        if any(k.lower() in s.lower() for k in ('kernel','mem','ram','ddr','boot','base','size','region')):
            lines.append(f'0x{off:X}: {s[:600]}')
    lines += [
        'classification: STOCK_UEFIPLAT_CFG_EXTRACTED_AND_CONTEXT_SCANNED',
        'decision: exact stock uefiplat.cfg payload was extracted and searched host-side. Static configuration values, if present, are platform evidence only until reconciled with the exact UEFI producer path and runtime behavior; no FD base or device launch is authorized.'
    ]
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n'.join(lines))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
