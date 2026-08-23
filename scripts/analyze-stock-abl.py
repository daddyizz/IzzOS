#!/usr/bin/env python3
import hashlib, os, re, struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else './output/abl.img'
outp = sys.argv[2] if len(sys.argv) > 2 else 'out/stock-abl-analysis.txt'
if not os.path.exists(path):
    raise SystemExit(f'ERROR: missing {path}')
b = open(path,'rb').read()
sha = hashlib.sha256(b).hexdigest()
md5 = hashlib.md5(b).hexdigest()

def find_all(sig):
    out=[]; p=0
    while True:
        p=b.find(sig,p)
        if p<0: return out
        out.append(p); p+=1

def ascii_strings(minlen=5):
    return [m.group().decode('ascii','replace') for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen,b)]

strings = ascii_strings()
needles = ['LinuxLoader','fastboot','vendor_boot','boot.img','ANDROID!','VNDRBOOT','kernel_addr','ramdisk_addr','dtb_addr','BootLinux','LoadImage','AVB','vbmeta']
hits=[]
for s in strings:
    ls=s.lower()
    if any(n.lower() in ls for n in needles):
        hits.append(s)

lines=[]
lines += ['IzzOS exact stock ABL structural analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'ABL image: {path}',f'byte-size: {len(b)}',f'md5: {md5}',f'sha256: {sha}']
lines += [f'elf-magic-at-0: {"yes" if b[:4]==bytes.fromhex("7f454c46") else "no"}',f'pe-mz-signature-count: {len(find_all(b"MZ"))}',f'firmware-volume-signature-count: {len(find_all(b"_FVH"))}',f'android-boot-magic-count: {len(find_all(b"ANDROID!"))}',f'vendor-boot-magic-count: {len(find_all(b"VNDRBOOT"))}']
lines += ['selected ASCII policy clues:']
if hits:
    for s in hits[:120]: lines.append('  '+s)
else:
    lines.append('  NONE_FOUND')

# Conservative classification only.
if b[:4] == bytes.fromhex('7f454c46'):
    cls='STOCK_ABL_ELF_CONTAINER_CONFIRMED'
elif find_all(b'_FVH'):
    cls='STOCK_ABL_FIRMWARE_VOLUME_CONTENT_CONFIRMED'
else:
    cls='STOCK_ABL_FORMAT_PARTIALLY_IDENTIFIED'
lines += [f'classification: {cls}','decision: exact stock ABL bytes were inspected host-side only. String/signature evidence may locate boot-policy components but does not yet prove kernel relocation behavior or authorize any firmware load address, fastboot boot, flashing, or slot change.']
text='\n'.join(lines)+'\n'
os.makedirs(os.path.dirname(outp) or '.',exist_ok=True)
open(outp,'w',encoding='utf-8').write(text)
print(text,end='')
