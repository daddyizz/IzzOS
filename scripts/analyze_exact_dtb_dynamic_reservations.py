#!/usr/bin/env python3
import os, struct, sys

BEGIN, END_NODE, PROP, NOP, END = 1,2,3,4,9

def u32(b,o=0): return struct.unpack_from('>I', b, o)[0]
def a4(n): return (n+3)&~3

def cstr(b,o):
    e=b.find(b'\0',o)
    if e<0: e=len(b)
    return b[o:e].decode('utf-8','replace')

def slist(v): return ','.join(x.decode('utf-8','replace') for x in v.split(b'\0') if x)
def cells(v): return [u32(v,i) for i in range(0,len(v)-3,4)]
def hx(v): return v.hex() if v else 'UNAVAILABLE'

def parse(path):
    b=open(path,'rb').read()
    if len(b)<40 or b[:4]!=b'\xd0\x0d\xfe\xed': raise SystemExit('ERROR: invalid FDT')
    os_=u32(b,8); ostr=u32(b,12); ss=u32(b,36)
    p=os_; lim=os_+ss; stack=[]; props={}; flags=set()
    while p+4<=lim:
        t=u32(b,p); p+=4
        if t==BEGIN:
            n=cstr(b,p); p=a4(p+len(n.encode())+1); stack.append(n)
        elif t==END_NODE:
            if stack: stack.pop()
        elif t==PROP:
            ln=u32(b,p); no=u32(b,p+4); p+=8; name=cstr(b,ostr+no); v=b[p:p+ln]; p=a4(p+ln)
            parts=[x for x in stack if x]; key='/'+'/'.join(parts)
            props.setdefault(key,{})[name]=v
            if ln==0: flags.add((key,name))
        elif t==NOP: pass
        elif t==END: break
        else: raise SystemExit(f'ERROR: unknown FDT token {t} at {p-4}')
    return props, flags

def main():
    dtb=sys.argv[1] if len(sys.argv)>1 else 'out/vendor-boot-dtb-set/dtb-1.dtb'
    out=sys.argv[2] if len(sys.argv)>2 else 'out/exact-dtb-dynamic-reservations.txt'
    p, flags=parse(dtb)
    root=p.get('/',{}); rm=p.get('/reserved-memory',{})
    ac=u32(rm.get('#address-cells',b'\0\0\0\2')) if len(rm.get('#address-cells',b''))==4 else 2
    sc=u32(rm.get('#size-cells',b'\0\0\0\2')) if len(rm.get('#size-cells',b''))==4 else 2
    lines=['IzzOS exact DTB dynamic reserved-memory analysis',f'dtb: {dtb}',f'model: {slist(root.get("model",b"")) or "UNAVAILABLE"}',f'compatible: {slist(root.get("compatible",b"")) or "UNAVAILABLE"}',f'reserved-address-cells: {ac}',f'reserved-size-cells: {sc}','']
    children=sorted(k for k in p if k.startswith('/reserved-memory/') and k.count('/')==2)
    dyn=0; fixed=0
    for k in children:
        q=p[k]; name=k.split('/')[-1]; reg=q.get('reg'); size=q.get('size'); alloc=q.get('alloc-ranges'); align=q.get('alignment'); comp=slist(q.get('compatible',b''))
        kind='FIXED_REG' if reg else ('DYNAMIC_SIZE' if size else 'NO_REG_NO_SIZE')
        if reg: fixed+=1
        elif size: dyn+=1
        lines += [f'node: {name}',f'  kind: {kind}',f'  compatible: {comp or "UNAVAILABLE"}',f'  reg-raw-hex: {hx(reg)}',f'  size-raw-hex: {hx(size)}',f'  alignment-raw-hex: {hx(align)}',f'  alloc-ranges-raw-hex: {hx(alloc)}',f'  no-map: {"yes" if (k,"no-map") in flags else "no"}',f'  reusable: {"yes" if (k,"reusable") in flags else "no"}','']
    lines += [f'fixed-reg-child-count: {fixed}',f'dynamic-size-child-count: {dyn}','classification: EXACT_DTB_DYNAMIC_RESERVATIONS_ENUMERATED','decision: all selected-DTB reserved-memory children were enumerated, including dynamic size/alignment/alloc-ranges constraints. Dynamic nodes without fixed reg must be treated as potential runtime consumers of mathematical gaps. This output does not authorize an FD address or device launch.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(out) or '.',exist_ok=True); open(out,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
