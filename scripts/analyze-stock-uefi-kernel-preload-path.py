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

def ascii_window(data, off, r=0x180):
    a=max(0,off-r); b=min(len(data),off+r)
    chunk=data[a:b]
    return ''.join(chr(x) if 32<=x<127 else '.' for x in chunk)

def main():
    if len(sys.argv)<3:
        print('usage: analyze-stock-uefi-kernel-preload-path.py <guided-0-decompressed.bin> <report>'); return 2
    inp=Path(sys.argv[1]); report=Path(sys.argv[2]); report.parent.mkdir(parents=True,exist_ok=True)
    data=inp.read_bytes()
    lines=['IzzOS exact stock UEFI kernel preload-path evidence','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(data)}',f'sha256: {hashlib.sha256(data).hexdigest()}']
    targets=[
        b'Kernel not preloaded',
        b'(KernelAddress >= Region.MemBase)',
        b'Locate EFI_RAMPARTITION_Protocol failed',
        b'RAM Partition',
        b'Preload',
        b'KernelAddress',
        b'Region.MemBase',
        b'Region.MemSize',
    ]
    for t in targets:
        hits=find_all(data,t)
        lines.append(f'target: {t.decode("ascii","ignore")}')
        lines.append(f'hit-count: {len(hits)}')
        for n,h in enumerate(hits[:16]):
            lines.append(f'hit-{n}: 0x{h:X}')
            lines.append(f'nearby: {ascii_window(data,h)}')
    # scan common exact-memory values as little-endian integers
    vals=[0x80000000,0x80600000,0x80080000,0x85600000]
    for v in vals:
        b=v.to_bytes(8,'little')
        hits=find_all(data,b)
        lines.append(f'u64-value-0x{v:X}-hit-count: {len(hits)}')
        if hits: lines.append('u64-offsets: '+' '.join(f'0x{x:X}' for x in hits[:32]))
        b4=(v & 0xffffffff).to_bytes(4,'little')
        hits4=find_all(data,b4)
        lines.append(f'u32-value-0x{v & 0xffffffff:X}-hit-count: {len(hits4)}')
        if hits4: lines.append('u32-offsets: '+' '.join(f'0x{x:X}' for x in hits4[:32]))
    lines += [
        'classification: STOCK_UEFI_KERNEL_PRELOAD_PATH_CONTEXT_ENUMERATED',
        'decision: exact stock UEFI preload-path strings and related memory constants were enumerated host-side. This can identify the runtime producer path but does not by itself prove the final KernelBaseAddr/KernelSize values or authorize any FD base or device launch.'
    ]
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n'.join(lines)); return 0
if __name__=='__main__': raise SystemExit(main())
