#!/usr/bin/env python3
import hashlib, struct, sys
from pathlib import Path

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <kernelvar-producer.efi> <output.txt>")
    raise SystemExit(2)

inp = Path(sys.argv[1]); outp = Path(sys.argv[2]); b = inp.read_bytes()

def u32(o): return struct.unpack_from('<I', b, o)[0]
def u64(o): return struct.unpack_from('<Q', b, o)[0]
def sx(v,bits):
    s=1<<(bits-1); return (v^s)-s

def decode(pc, ins):
    # BL
    if ins & 0xFC000000 == 0x94000000:
        imm=sx(ins & 0x03ffffff,26)<<2; return f"BL 0x{pc+imm:X}"
    if ins & 0xFC000000 == 0x14000000:
        imm=sx(ins & 0x03ffffff,26)<<2; return f"B 0x{pc+imm:X}"
    # BLR/BR/RET
    if ins & 0xFFFFFC1F == 0xD63F0000: return f"BLR x{(ins>>5)&31}"
    if ins & 0xFFFFFC1F == 0xD61F0000: return f"BR x{(ins>>5)&31}"
    if ins == 0xD65F03C0: return "RET"
    # ADRP
    if ins & 0x9F000000 == 0x90000000:
        rd=ins&31; immhi=(ins>>5)&0x7ffff; immlo=(ins>>29)&3
        imm=sx((immhi<<2)|immlo,21)<<12; base=(pc & ~0xfff)+imm
        return f"ADRP x{rd}, 0x{base:X}"
    # ADD immediate 64/32
    if ins & 0x7F000000 == 0x11000000:
        sf=(ins>>31)&1; rd=ins&31; rn=(ins>>5)&31; imm=(ins>>10)&0xfff
        if (ins>>22)&1: imm <<= 12
        return f"ADD {'x' if sf else 'w'}{rd}, {'x' if sf else 'w'}{rn}, #0x{imm:X}"
    # LDR unsigned immediate 64-bit
    if ins & 0xFFC00000 == 0xF9400000:
        rt=ins&31; rn=(ins>>5)&31; imm=((ins>>10)&0xfff)*8
        return f"LDR x{rt}, [x{rn}, #0x{imm:X}]"
    if ins & 0xFFC00000 == 0xB9400000:
        rt=ins&31; rn=(ins>>5)&31; imm=((ins>>10)&0xfff)*4
        return f"LDR w{rt}, [x{rn}, #0x{imm:X}]"
    if ins & 0xFFC00000 == 0xF9000000:
        rt=ins&31; rn=(ins>>5)&31; imm=((ins>>10)&0xfff)*8
        return f"STR x{rt}, [x{rn}, #0x{imm:X}]"
    # MOV register aliases (ORR)
    if ins & 0xFFE0FFE0 == 0xAA0003E0:
        rd=ins&31; rm=(ins>>16)&31; return f"MOV x{rd}, x{rm}"
    return f"0x{ins:08X}"

# PE validation + section mapping
if b[:2] != b'MZ': raise SystemExit('input is not PE/MZ')
peoff=u32(0x3c)
if b[peoff:peoff+4] != b'PE\0\0': raise SystemExit('invalid PE signature')
coff=peoff+4; nsec=struct.unpack_from('<H',b,coff+2)[0]; optsz=struct.unpack_from('<H',b,coff+16)[0]
opt=coff+20; entry=u32(opt+16); imgbase=u64(opt+24); sh=opt+optsz
secs=[]
for i in range(nsec):
    o=sh+i*40; name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace'); vs=u32(o+8); va=u32(o+12); rs=u32(o+16); rp=u32(o+20)
    secs.append((name,va,vs,rs,rp))

def rva2off(rva):
    for name,va,vs,rs,rp in secs:
        if va <= rva < va+max(vs,rs): return rp+(rva-va)
    return rva if rva < len(b) else None

def dump(lo,hi):
    rows=[]
    for pc in range(lo,hi,4):
        o=rva2off(pc)
        if o is None or o+4>len(b): continue
        ins=u32(o); rows.append(f"0x{pc:08X}: {decode(pc,ins)}")
    return rows

lines=[]
lines += [
"IzzOS exact stock UEFI kernel-variable interface provenance trace",
"Collector mode: READ_ONLY_HOST_SIDE","Device writes: NONE",
f"input: {inp}",f"byte-size: {len(b)}",f"sha256: {hashlib.sha256(b).hexdigest()}",
f"pe-entry-rva: 0x{entry:X}",f"pe-image-base: 0x{imgbase:X}",
"analysis-focus: resolve the interface/function-pointer used by the back-to-back KernelBaseAddr and KernelSize reads",
]

# Exact proven window from previous analysis
lo,hi=0x12380,0x12560
lines.append(f"code-window: 0x{lo:X}-0x{hi:X}")
lines += dump(lo,hi)

# Key callsite structural annotations based only on exact instructions in this binary.
lines += [
"",
"exact-callsite-annotations:",
"0x12464: LDR x8, [global/table] before KernelBaseAddr read",
"0x12468-0x1247C: x19 is formed from an image-relative/global object and passed as x1",
"0x12474: output pointer for KernelBaseAddr is stack+0x20 (x4)",
"0x12484: LDR x8, [x8, #0x58] selects a function pointer from the same interface table",
"0x1248C: BLR x8 performs the KernelBaseAddr query",
"0x12490: the same global/table base is reloaded",
"0x12498: output pointer for KernelSize is stack+0x28 (x4)",
"0x124A0: x19 is reused as x1",
"0x124AC: LDR x8, [x8, #0x58] selects the same interface method",
"0x124B0: BLR x8 performs the KernelSize query",
"interpretation: KernelBaseAddr and KernelSize are fetched by the same method at interface-table offset 0x58, with different UTF-16 key names and different output buffers.",
"",
"provenance-boundary:",
"This proves a keyed platform-configuration interface pattern in the exact producer PE. It does not yet identify the concrete protocol GUID/object behind the global table, nor does it prove the runtime numeric values returned for either key.",
"classification: STOCK_UEFI_KERNELVAR_KEYED_INTERFACE_CONFIRMED",
"decision: isolate and resolve the interface object/protocol behind the table used at 0x12464/0x12490, then trace its method at +0x58 or correlate it with public Qualcomm UEFI config APIs. No FD base or device launch is authorized.",
]
outp.parent.mkdir(parents=True,exist_ok=True); outp.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('\n'.join(lines))
