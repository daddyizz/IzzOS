#!/usr/bin/env python3
import os, struct, sys

FDT_BEGIN_NODE=1; FDT_END_NODE=2; FDT_PROP=3; FDT_NOP=4; FDT_END=9

def u32(b,o): return struct.unpack_from('>I',b,o)[0]
def align4(n): return (n+3)&~3
def cstr(b,o):
    e=b.find(b'\0',o)
    if e<0: e=len(b)
    return b[o:e].decode('utf-8','replace')

def parse(path):
    b=open(path,'rb').read()
    if len(b)<40 or b[:4]!=b'\xd0\x0d\xfe\xed': raise ValueError('invalid FDT')
    os_=u32(b,8); ostr=u32(b,12); ss=u32(b,36); p=os_; end=os_+ss; stack=[]
    model=''; compat=''; memory=[]; reserved=[]
    while p+4<=end:
        tok=u32(b,p); p+=4
        if tok==FDT_BEGIN_NODE:
            name=cstr(b,p); p=align4(p+len(name.encode())+1); stack.append(name)
        elif tok==FDT_END_NODE:
            if stack: stack.pop()
        elif tok==FDT_PROP:
            ln=u32(b,p); no=u32(b,p+4); p+=8; name=cstr(b,ostr+no); v=b[p:p+ln]; p=align4(p+ln)
            parts=[x for x in stack if x]; pathstr='/'+'/'.join(parts)
            if pathstr=='/' and name=='model': model=v.rstrip(b'\0').decode('utf-8','replace')
            if pathstr=='/' and name=='compatible': compat=','.join(x.decode('utf-8','replace') for x in v.split(b'\0') if x)
            if parts and parts[-1].startswith('memory') and name=='reg' and ln%16==0:
                for i in range(0,ln,16): memory.append((int.from_bytes(v[i:i+8],'big'),int.from_bytes(v[i+8:i+16],'big')))
            if len(parts)==2 and parts[0]=='reserved-memory' and name=='reg' and ln%16==0:
                for i in range(0,ln,16): reserved.append((parts[1],int.from_bytes(v[i:i+8],'big'),int.from_bytes(v[i+8:i+16],'big')))
        elif tok==FDT_NOP: pass
        elif tok==FDT_END: break
        else: raise ValueError(f'unknown token {tok}')
    return model,compat,memory,reserved

def fmt(x): return f'0x{x:08X}' if x<=0xffffffff else f'0x{x:X}'

def main():
    path=sys.argv[1] if len(sys.argv)>1 else 'out/vendor-boot-dtb-set/dtb-1.dtb'
    model,compat,memory,reserved=parse(path)
    print('IzzOS exact selected-DTB reserved-memory model')
    print(f'dtb: {path}')
    print(f'model: {model or "UNAVAILABLE"}')
    print(f'compatible: {compat or "UNAVAILABLE"}')
    print('selection-evidence: device ro.boot.dtb_idx=1 + vendor_boot DTB index 1')
    print('classification: EXACT_DTB_FIXED_CARVEOUT_MODEL_ONLY')
    if memory:
        for base,size in memory: print(f'static-memory-reg: base={fmt(base)} size=0x{size:X}')
    print('runtime-memory-note: static memory reg is firmware-patched on this platform; runtime zoneinfo independently establishes DRAM span base 0x80000000')
    usable=[]
    for name,base,size in reserved:
        if size==0:
            print(f'zero-size-reserved-entry: {name} base={fmt(base)} status=NON_BLOCKING_STATIC_ENTRY')
            continue
        usable.append((base,base+size,name))
    usable.sort()
    merged=[]
    for start,end,name in usable:
        if not merged or start>merged[-1][1]: merged.append([start,end,[name]])
        else:
            merged[-1][1]=max(merged[-1][1],end); merged[-1][2].append(name)
    base=0x80000000; limit=0x100000000; cursor=base
    print('exact fixed reserved ranges and mathematical gaps below 4 GiB:')
    for start,end,names in merged:
        if end<=base or start>=limit: continue
        start=max(start,base); end=min(end,limit)
        if start>cursor:
            size=start-cursor
            print(f'  gap {fmt(cursor)}-{fmt(start)} size=0x{size:X} status=UNVALIDATED_GAP')
        print(f'  reserved {fmt(start)}-{fmt(end)} size=0x{end-start:X} names={",".join(names)}')
        cursor=max(cursor,end)
    if cursor<limit: print(f'  gap {fmt(cursor)}-0x100000000 size=0x{limit-cursor:X} status=UNVALIDATED_GAP')
    print('large-gap candidates (>=32 MiB; size-only filter, NOT safety approval):')
    cursor=base
    for start,end,names in merged:
        if end<=base or start>=limit: continue
        start=max(start,base); end=min(end,limit)
        if start>cursor and start-cursor>=0x02000000: print(f'  {fmt(cursor)}-{fmt(start)} size=0x{start-cursor:X} status=SIZE_CANDIDATE_ONLY')
        cursor=max(cursor,end)
    if cursor<limit and limit-cursor>=0x02000000: print(f'  {fmt(cursor)}-0x100000000 size=0x{limit-cursor:X} status=SIZE_CANDIDATE_ONLY')
    print('decision: exact DTB fixed carveouts supersede the earlier generic source model. Gaps remain unvalidated because dynamic allocations, bootloader relocation, framebuffer, kernel/DTB placement and firmware entry constraints are not yet fully reconciled. No FD address or device launch is authorized.')
if __name__=='__main__': main()
