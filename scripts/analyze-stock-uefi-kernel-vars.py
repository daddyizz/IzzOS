#!/usr/bin/env python3
import sys, hashlib, re, struct
from pathlib import Path

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <uefi.img> <output.txt>", file=sys.stderr)
    sys.exit(2)

inp = Path(sys.argv[1])
outp = Path(sys.argv[2])
data = inp.read_bytes()
lines = []
add = lines.append
add("IzzOS exact stock UEFI KernelBaseAddr/KernelSize evidence")
add("Collector mode: READ_ONLY_HOST_SIDE")
add("Device writes: NONE")
add(f"input: {inp.as_posix()}")
add(f"byte-size: {len(data)}")
add(f"sha256: {hashlib.sha256(data).hexdigest()}")

# Search ASCII and UTF-16LE occurrences of the runtime-variable names and nearby printable context.
for name in ("KernelBaseAddr", "KernelSize"):
    add("")
    add(f"target: {name}")
    hits = []
    for kind, needle in (("ASCII", name.encode()), ("UTF16LE", name.encode('utf-16le'))):
        start = 0
        while True:
            off = data.find(needle, start)
            if off < 0: break
            hits.append((off, kind))
            start = off + 1
    if not hits:
        add("hits: NONE")
        continue
    add(f"hit-count: {len(hits)}")
    for i,(off,kind) in enumerate(hits):
        lo=max(0,off-96); hi=min(len(data),off+192)
        raw=data[lo:hi]
        ascii_ctx=''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        add(f"hit-{i}: off=0x{off:X} encoding={kind}")
        add(f"nearby-ascii: {ascii_ctx}")

# Generic firmware signatures / likely executable density.
add("")
add(f"FVH-signature-count: {data.count(b'_FVH')}")
add(f"MZ-count: {data.count(b'MZ')}")
add(f"PE-signature-count: {data.count(b'PE\\x00\\x00')}")

# Search exact fallback constants in little-endian form too, to see whether UEFI side carries matching layout hints.
for label,val in (("KernelLoadAddress-fallback",0x00080000),("RamdiskEndAddress-fallback",0x05600000)):
    needle=struct.pack('<I',val)
    poss=[]; start=0
    while True:
        off=data.find(needle,start)
        if off<0: break
        poss.append(off); start=off+1
    add(f"{label}-u32-occurrences: {len(poss)}")
    if poss:
        add("  offsets: " + " ".join(f"0x{x:X}" for x in poss[:32]))

if any(data.find(n) >= 0 or data.find(n.decode().encode('utf-16le')) >= 0 for n in (b'KernelBaseAddr', b'KernelSize')):
    cls="STOCK_UEFI_KERNEL_VARIABLE_NAMES_PRESENT"
else:
    cls="STOCK_UEFI_KERNEL_VARIABLE_NAMES_NOT_FOUND_RAW"
add(f"classification: {cls}")
add("decision: exact stock UEFI bytes were searched host-side for KernelBaseAddr/KernelSize producers and related constants. Raw-name presence can identify promising firmware components but does not by itself prove the runtime values. No firmware load base, fastboot boot, flashing, or slot change is authorized.")

outp.parent.mkdir(parents=True,exist_ok=True)
outp.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('\n'.join(lines))
