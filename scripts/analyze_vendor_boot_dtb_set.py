#!/usr/bin/env python3
import glob, hashlib, os, struct, sys

FDT_BEGIN_NODE=1; FDT_END_NODE=2; FDT_PROP=3; FDT_NOP=4; FDT_END=9

def u32(b,o): return struct.unpack_from('>I',b,o)[0]
def align4(n): return (n+3)&~3

def cstr(b,o):
    e=b.find(b'\0',o)
    if e<0: e=len(b)
    return b[o:e].decode('utf-8','replace')

def slist(v):
    return ','.join(x.decode('utf-8','replace') for x in v.split(b'\0') if x)

def analyze(path):
    b=open(path,'rb').read()
    if len(b)<40 or b[:4]!=b'\xd0\x0d\xfe\xed': raise ValueError('invalid FDT')
    total=u32(b,4); os_=u32(b,8); ostr=u32(b,12); ss=u32(b,36); sstr=u32(b,32)
    out={'total':total,'os':os_,'ostr':ostr,'ss':ss,'sstr':sstr,'model':'','compatible':'','rac':'','rsc':'','memory':[], 'chosen':False,'usable':'','rrac':'','rrsc':'','reserved':[]}
    p=os_; end=os_+ss; stack=[]
    while p+4<=end:
        tok=u32(b,p); p+=4
        if tok==FDT_BEGIN_NODE:
            name=cstr(b,p); p=align4(p+len(name.encode('utf-8'))+1); stack.append(name)
        elif tok==FDT_END_NODE:
            if stack: stack.pop()
        elif tok==FDT_PROP:
            ln=u32(b,p); no=u32(b,p+4); p+=8; name=cstr(b,ostr+no); v=b[p:p+ln]; p=align4(p+ln)
            parts=[x for x in stack if x]; pathstr='/'+'/'.join(parts)
            if pathstr=='/':
                if name=='model': out['model']=slist(v)
                elif name=='compatible': out['compatible']=slist(v)
                elif name=='#address-cells' and ln==4: out['rac']=u32(v,0)
                elif name=='#size-cells' and ln==4: out['rsc']=u32(v,0)
            if parts and parts[-1].startswith('memory') and name=='reg': out['memory'].append(v.hex())
            if pathstr=='/chosen':
                out['chosen']=True
                if name=='linux,usable-memory-range': out['usable']=v.hex()
            if pathstr=='/reserved-memory':
                if name=='#address-cells' and ln==4: out['rrac']=u32(v,0)
                elif name=='#size-cells' and ln==4: out['rrsc']=u32(v,0)
            if len(parts)==2 and parts[0]=='reserved-memory' and name=='reg': out['reserved'].append((parts[1],v.hex()))
        elif tok==FDT_NOP: pass
        elif tok==FDT_END: break
        else: raise ValueError(f'unknown FDT token {tok} at {p-4}')
    return out, hashlib.sha256(b).hexdigest()

def main():
    d=sys.argv[1] if len(sys.argv)>1 else 'out/vendor-boot-dtb-set'; outp=sys.argv[2] if len(sys.argv)>2 else 'out/vendor-boot-dtb-analysis.txt'
    fs=sorted(glob.glob(os.path.join(d,'dtb-*.dtb')))
    if not fs: raise SystemExit('ERROR: no dtb-*.dtb files found')
    lines=['IzzOS vendor_boot DTB structural analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE','Parser: PYTHON_FDT_PROPERTY_WALKER','DTB count: '+str(len(fs)),'']
    for f in fs:
        a,sha=analyze(f); idx=os.path.basename(f)[4:-4]
        lines += [f'dtb-index: {idx}',f'sha256: {sha}','fdt-magic: d00dfeed',f"fdt-total-size: {a['total']}",f"fdt-struct-offset: {a['os']}",f"fdt-struct-size: {a['ss']}",f"fdt-strings-offset: {a['ostr']}",f"fdt-strings-size: {a['sstr']}",f"model: {a['model'] or 'UNAVAILABLE'}",f"compatible: {a['compatible'] or 'UNAVAILABLE'}",f"root-address-cells: {a['rac'] if a['rac']!='' else 'UNAVAILABLE'}",f"root-size-cells: {a['rsc'] if a['rsc']!='' else 'UNAVAILABLE'}",f"memory-reg-raw-hex: {'|'.join(a['memory']) if a['memory'] else 'UNAVAILABLE'}",f"reserved-memory-address-cells: {a['rrac'] if a['rrac']!='' else 'UNAVAILABLE'}",f"reserved-memory-size-cells: {a['rrsc'] if a['rrsc']!='' else 'UNAVAILABLE'}",f"reserved-memory-child-count: {len(a['reserved'])}",f"chosen-present: {'yes' if a['chosen'] else 'no'}",f"chosen-usable-memory-range-raw-hex: {a['usable'] or 'UNAVAILABLE'}",'reserved-memory-reg-entries:']
        lines += [f'  {n} reg={r}' for n,r in a['reserved']] or ['  UNAVAILABLE']; lines.append('')
    lines += ['classification: VENDOR_BOOT_DTB_SET_PROPERTY_WALKED_FAST','decision: exact DTB properties were parsed host-side. Static DTB memory values may still be firmware-patched at runtime; no FD address or device launch is authorized.']
    text='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(outp) or '.',exist_ok=True); open(outp,'w',encoding='utf-8').write(text); print(text,end='')
if __name__=='__main__': main()
