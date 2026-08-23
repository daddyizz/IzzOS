#!/usr/bin/env python3
import sys, hashlib
from pathlib import Path

def find_all(data, needle):
    out=[]; p=0
    while True:
        i=data.find(needle,p)
        if i<0: break
        out.append(i); p=i+1
    return out

def ascii_window(data, off, radius=160):
    s=max(0,off-radius); e=min(len(data),off+radius)
    chunk=data[s:e]
    return ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)

def hex_window(data, off, radius=64):
    s=max(0,off-radius); e=min(len(data),off+radius)
    return f'0x{s:X}-0x{e:X}: '+data[s:e].hex()

def main():
    if len(sys.argv)<3:
        print('usage: analyze-stock-uefi-kernelvar-context.py <guided-0-decompressed.bin> <report>')
        return 2
    inp=Path(sys.argv[1]); report=Path(sys.argv[2]); report.parent.mkdir(parents=True,exist_ok=True)
    data=inp.read_bytes()
    lines=['IzzOS exact stock UEFI KernelBaseAddr/KernelSize context analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(data)}',f'sha256: {hashlib.sha256(data).hexdigest()}']
    for name in ('KernelBaseAddr','KernelSize'):
        lines.append(f'target: {name}')
        ah=find_all(data,name.encode())
        wh=find_all(data,name.encode('utf-16le'))
        lines.append(f'ascii-hit-count: {len(ah)}')
        for i,o in enumerate(ah):
            lines.append(f'ascii-hit-{i}: 0x{o:X}')
            lines.append('ascii-nearby: '+ascii_window(data,o))
            lines.append('hex-nearby: '+hex_window(data,o))
        lines.append(f'utf16-hit-count: {len(wh)}')
        for i,o in enumerate(wh):
            lines.append(f'utf16-hit-{i}: 0x{o:X}')
            lines.append('ascii-nearby: '+ascii_window(data,o))
            lines.append('hex-nearby: '+hex_window(data,o))
    # broader strings likely to reveal producer module / memory map logic
    for name in ('MemRegion','MemoryMap','RAM','RamPartition','SystemMemory','BaseMemory','KernelLoadAddress','RamdiskEndAddress','uefiplat.cfg'):
        a=find_all(data,name.encode()); w=find_all(data,name.encode('utf-16le'))
        if a or w:
            lines.append(f'context-target: {name} ascii={len(a)} utf16={len(w)}')
            for o in (a+w)[:8]: lines.append(f'  hit=0x{o:X} nearby='+ascii_window(data,o,96))
    lines += ['classification: STOCK_UEFI_KERNEL_VARIABLE_CONTEXT_CAPTURED','decision: exact decompressed UEFI bytes containing KernelBaseAddr/KernelSize were context-scanned host-side. String context can identify producer configuration or module provenance, but values are not yet runtime-confirmed and no FD base or device launch is authorized.']
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n'.join(lines))
    return 0
if __name__=='__main__': raise SystemExit(main())
