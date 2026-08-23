#!/usr/bin/env python3
import os, re, struct, sys, hashlib

inp=sys.argv[1] if len(sys.argv)>1 else 'out/linuxloader/LinuxLoader.efi'
outp=sys.argv[2] if len(sys.argv)>2 else 'out/linuxloader-string-refs.txt'
b=open(inp,'rb').read()

# PE helpers
pe=struct.unpack_from('<I',b,0x3c)[0]
coff=pe+4
machine, nsec, _,_,_, optsz,_=struct.unpack_from('<HHIIIHH', b, coff)
opt=coff+20
entry=struct.unpack_from('<I',b,opt+16)[0]
imagebase=struct.unpack_from('<Q',b,opt+24)[0]
sects=[]
sh=opt+optsz
for i in range(nsec):
    o=sh+i*40
    name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
    vsize, va, rawsz, raw=struct.unpack_from('<IIII',b,o+8)
    sects.append((name,va,vsize,raw,rawsz))

def off_to_rva(off):
    for n,va,vs,raw,rs in sects:
        if raw <= off < raw+rs:
            return va + (off-raw), n
    return None, None

def rva_to_off(rva):
    for n,va,vs,raw,rs in sects:
        span=max(vs,rs)
        if va <= rva < va+span:
            return raw + (rva-va)
    return None

keys=[b'ANDROID!',b'VNDRBOOT',b'vendor_boot',b'vbmeta',b'fastboot',b'kernel',b'ramdisk',b'dtb',b'LoadImage',b'LinuxLoader']
lines=['IzzOS LinuxLoader string/RVA reference analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {inp}',f'byte-size: {len(b)}',f'sha256: {hashlib.sha256(b).hexdigest()}',f'machine: 0x{machine:04X}',f'entry-rva: 0x{entry:X}',f'image-base: 0x{imagebase:X}','']

# Find direct little-endian 64-bit/32-bit occurrences of target RVAs in image.
for key in keys:
    start=0; hits=[]
    while True:
        p=b.find(key,start)
        if p<0: break
        rva, sec=off_to_rva(p)
        hits.append((p,rva,sec))
        start=p+1
    lines.append(f'target: {key.decode("ascii","replace")}')
    if not hits:
        lines.append('  string-hits: NONE')
        continue
    for idx,(off,rva,sec) in enumerate(hits):
        lines.append(f'  hit-{idx}: file-off=0x{off:X} rva={"0x%X"%rva if rva is not None else "UNMAPPED"} section={sec or "UNMAPPED"}')
        if rva is None: continue
        refs=[]
        pat32=struct.pack('<I',rva & 0xffffffff)
        pat64=struct.pack('<Q',rva)
        for pat,kind in ((pat32,'LE32_RVA_LITERAL'),(pat64,'LE64_RVA_LITERAL')):
            s=0
            while True:
                q=b.find(pat,s)
                if q<0: break
                qrva,qsec=off_to_rva(q)
                if q != off:
                    refs.append((q,qrva,qsec,kind))
                s=q+1
        # Nearby AArch64 ADRP/ADD style references require disassembly; report code windows around any literal refs.
        if refs:
            for j,(q,qrva,qsec,kind) in enumerate(refs[:16]):
                lines.append(f'    ref-{j}: file-off=0x{q:X} rva={"0x%X"%qrva if qrva is not None else "UNMAPPED"} section={qsec or "UNMAPPED"} kind={kind}')
        else:
            lines.append('    direct-rva-literal-refs: NONE')
        lo=max(0,off-64); hi=min(len(b),off+len(key)+64)
        snippet=b[lo:hi]
        printable=''.join(chr(x) if 32<=x<127 else '.' for x in snippet)
        lines.append(f'    nearby-ascii-window: {printable}')
    lines.append('')

lines += ['classification: LINUXLOADER_STRING_RVA_MAP_ENUMERATED','decision: string locations and direct RVA literal references were enumerated host-side. Absence of direct literals does not exclude ADRP/ADD or computed references; code-level disassembly is still required before inferring Android kernel destination or any launch address.']
os.makedirs(os.path.dirname(outp) or '.', exist_ok=True)
open(outp,'w',encoding='utf-8').write('\n'.join(lines)+'\n')
print('\n'.join(lines))
