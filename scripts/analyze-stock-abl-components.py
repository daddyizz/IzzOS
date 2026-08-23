#!/usr/bin/env python3
import hashlib, os, struct, sys


def u16(b,o): return struct.unpack_from('<H', b, o)[0]
def u32(b,o): return struct.unpack_from('<I', b, o)[0]
def u64(b,o): return struct.unpack_from('<Q', b, o)[0]


def pe_info(b, off):
    out = {'offset':off}
    if off+0x40 > len(b) or b[off:off+2] != b'MZ':
        return out
    peoff = off + u32(b, off+0x3c)
    if peoff+0x18 > len(b) or b[peoff:peoff+4] != b'PE\0\0':
        return out
    machine = u16(b, peoff+4)
    nsec = u16(b, peoff+6)
    optsz = u16(b, peoff+20)
    opt = peoff+24
    magic = u16(b,opt) if opt+2<=len(b) else 0
    entry = u32(b,opt+16) if opt+20<=len(b) else 0
    image_base = 0
    size_image = 0
    if magic == 0x20B and opt+64 <= len(b):
        image_base = u64(b,opt+24)
        size_image = u32(b,opt+56)
    elif magic == 0x10B and opt+60 <= len(b):
        image_base = u32(b,opt+28)
        size_image = u32(b,opt+56)
    out.update(machine=machine, sections=nsec, optional_magic=magic, entry_rva=entry, image_base=image_base, size_image=size_image, pe_header_offset=peoff-off, optional_size=optsz)
    return out


def main():
    path = sys.argv[1] if len(sys.argv)>1 else './output/abl.img'
    outp = sys.argv[2] if len(sys.argv)>2 else 'out/stock-abl-components.txt'
    b = open(path,'rb').read()
    mz=[]; pos=0
    while True:
        i=b.find(b'MZ',pos)
        if i<0: break
        info=pe_info(b,i)
        if 'machine' in info: mz.append(info)
        pos=i+2
    fv=[]; pos=0
    while True:
        i=b.find(b'_FVH',pos)
        if i<0: break
        # UEFI FV signature is at header offset 0x28, so probable FV start is sig-0x28
        start=i-0x28 if i>=0x28 else None
        length=None
        if start is not None and start+0x28 <= len(b):
            try: length=u64(b,start+0x20)
            except Exception: pass
        fv.append((i,start,length))
        pos=i+4
    lines=[
        'IzzOS exact stock ABL embedded component analysis',
        'Collector mode: READ_ONLY_HOST_SIDE',
        'Device writes: NONE',
        f'ABL image: {path}',
        f'byte-size: {len(b)}',
        f'sha256: {hashlib.sha256(b).hexdigest()}',
        f'validated-pe-count: {len(mz)}',
        f'firmware-volume-signature-count: {len(fv)}',
        ''
    ]
    for idx,x in enumerate(mz):
        lines += [
            f'pe-index: {idx}',
            f'file-offset: 0x{x["offset"]:X}',
            f'pe-header-offset-from-mz: 0x{x["pe_header_offset"]:X}',
            f'machine: 0x{x["machine"]:04X}',
            f'section-count: {x["sections"]}',
            f'optional-header-magic: 0x{x["optional_magic"]:04X}',
            f'entry-rva: 0x{x["entry_rva"]:X}',
            f'image-base: 0x{x["image_base"]:X}',
            f'size-of-image: 0x{x["size_image"]:X}',
            'classification: PE32_PLUS_AARCH64' if x['machine']==0xAA64 and x['optional_magic']==0x20B else 'classification: PE_OTHER',
            ''
        ]
    for idx,(sig,start,length) in enumerate(fv):
        lines += [
            f'fv-index: {idx}',
            f'_FVH-signature-offset: 0x{sig:X}',
            f'probable-fv-start: {"0x%X"%start if start is not None else "UNAVAILABLE"}',
            f'fv-length-field: {"0x%X"%length if isinstance(length,int) else "UNAVAILABLE"}',
            ''
        ]
    # ELF program header summary if ELF64 LE
    if b[:4]==b'\x7fELF' and len(b)>=64 and b[4]==2 and b[5]==1:
        phoff=u64(b,32); phentsz=u16(b,54); phnum=u16(b,56)
        lines += [f'elf-program-header-offset: 0x{phoff:X}',f'elf-program-header-entry-size: {phentsz}',f'elf-program-header-count: {phnum}','elf-load-segments:']
        for i in range(phnum):
            o=phoff+i*phentsz
            if o+56>len(b): break
            p_type=u32(b,o); flags=u32(b,o+4); p_off=u64(b,o+8); vaddr=u64(b,o+16); paddr=u64(b,o+24); filesz=u64(b,o+32); memsz=u64(b,o+40); align=u64(b,o+48)
            if p_type==1:
                lines.append(f'  ph{i}: off=0x{p_off:X} vaddr=0x{vaddr:X} paddr=0x{paddr:X} filesz=0x{filesz:X} memsz=0x{memsz:X} flags=0x{flags:X} align=0x{align:X}')
        lines.append('')
    lines += [
        'classification: STOCK_ABL_COMPONENT_BOUNDARIES_ENUMERATED',
        'decision: embedded PE/FV and ELF load-segment metadata were enumerated from exact stock ABL host-side. This can identify internal firmware components and link-time addresses, but it still does not prove Android kernel relocation behavior or authorize any firmware load address, fastboot boot, flashing, or slot change.'
    ]
    text='\n'.join(lines)+'\n'
    os.makedirs(os.path.dirname(outp) or '.',exist_ok=True)
    open(outp,'w',encoding='utf-8').write(text)
    print(text,end='')

if __name__=='__main__': main()
