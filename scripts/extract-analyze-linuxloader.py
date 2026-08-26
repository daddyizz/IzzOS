#!/usr/bin/env python3
import hashlib, os, struct, sys, re

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

def main():
    src=sys.argv[1] if len(sys.argv)>1 else 'out/stock-abl-lzma/decompressed.bin'
    outdir=sys.argv[2] if len(sys.argv)>2 else 'out/linuxloader'
    report=sys.argv[3] if len(sys.argv)>3 else 'out/linuxloader-analysis.txt'
    b=open(src,'rb').read()
    # Exact structure established by prior parser: inner FV @ 0x8, LinuxLoader FFS @ 0x80,
    # UI section @ 0x98, PE32 section @ 0xB4 with section header size 4.
    sec=0xB4
    size=b[sec] | (b[sec+1]<<8) | (b[sec+2]<<16)
    typ=b[sec+3]
    if typ != 0x10 or size < 8:
        raise SystemExit(f'ERROR: expected PE32 section at 0x{sec:X}, got type=0x{typ:02X} size=0x{size:X}')
    pe=b[sec+4:sec+size]
    os.makedirs(outdir,exist_ok=True)
    pepath=os.path.join(outdir,'LinuxLoader.efi')
    open(pepath,'wb').write(pe)

    lines=['IzzOS exact stock LinuxLoader PE analysis','Collector mode: READ_ONLY_HOST_SIDE','Device writes: NONE',f'input: {src}',f'pe32-section-offset: 0x{sec:X}',f'pe32-section-size: 0x{size:X}',f'output: {pepath}',f'byte-size: {len(pe)}',f'sha256: {hashlib.sha256(pe).hexdigest()}']
    if pe[:2] != b'MZ':
        lines += ['mz-signature: no','classification: LINUXLOADER_PE_EXTRACTION_UNEXPECTED_FORMAT']
    else:
        e_lfanew=u32(pe,0x3c)
        sig=pe[e_lfanew:e_lfanew+4]
        lines += ['mz-signature: yes',f'pe-header-offset: 0x{e_lfanew:X}',f'pe-signature: {sig.hex()}']
        if sig != b'PE\0\0':
            lines += ['classification: LINUXLOADER_PE_HEADER_INVALID']
        else:
            coff=e_lfanew+4; machine=u16(pe,coff); nsec=u16(pe,coff+2); optsz=u16(pe,coff+16)
            opt=coff+20; magic=u16(pe,opt); entry=u32(pe,opt+16); imagebase=u64(pe,opt+24) if magic==0x20b else u32(pe,opt+28)
            sectalign=u32(pe,opt+32); filealign=u32(pe,opt+36); sizeofimage=u32(pe,opt+56); sizeofheaders=u32(pe,opt+60)
            numdirs=u32(pe,opt+108) if magic==0x20b else u32(pe,opt+92)
            dd=opt+(112 if magic==0x20b else 96)
            reloc_rva=reloc_size=0
            if numdirs>5 and dd+6*8 <= len(pe): reloc_rva,reloc_size=struct.unpack_from('<II',pe,dd+5*8)
            lines += [f'machine: 0x{machine:04X}',f'optional-header-magic: 0x{magic:04X}',f'section-count: {nsec}',f'entry-rva: 0x{entry:X}',f'image-base: 0x{imagebase:X}',f'section-alignment: 0x{sectalign:X}',f'file-alignment: 0x{filealign:X}',f'size-of-image: 0x{sizeofimage:X}',f'size-of-headers: 0x{sizeofheaders:X}',f'base-relocation-directory-rva: 0x{reloc_rva:X}',f'base-relocation-directory-size: 0x{reloc_size:X}','sections:']
            sh=opt+optsz
            for i in range(nsec):
                o=sh+i*40
                if o+40>len(pe): break
                name=pe[o:o+8].rstrip(b'\0').decode('ascii','replace'); vs=u32(pe,o+8); va=u32(pe,o+12); rawsz=u32(pe,o+16); rawptr=u32(pe,o+20); ch=u32(pe,o+36)
                lines.append(f'  {i}: name={name} va=0x{va:X} vsize=0x{vs:X} raw=0x{rawptr:X}+0x{rawsz:X} characteristics=0x{ch:08X}')
            text=pe.decode('latin1','ignore')
            clues=[]
            pats=['ANDROID!','VNDRBOOT','vendor_boot','vbmeta','fastboot','kernel','ramdisk','dtb','bootimg','LoadImage','StartImage','ExitBootServices','LinuxLoader','GetMemoryMap','AllocatePages','AllocatePool']
            low=text.lower()
            for p in pats:
                if p.lower() in low: clues.append(p)
            lines += ['selected-string-clues: '+(', '.join(clues) if clues else 'NONE_FOUND')]
            if machine==0xAA64 and magic==0x20B:
                if reloc_size:
                    lines += ['classification: LINUXLOADER_PE32PLUS_ARM64_RELOCATABLE_CONFIRMED']
                else:
                    lines += ['classification: LINUXLOADER_PE32PLUS_ARM64_NO_BASE_RELOC_DIRECTORY']
            else:
                lines += ['classification: LINUXLOADER_PE_FORMAT_UNEXPECTED']
    lines += ['decision: exact LinuxLoader PE metadata was extracted host-side. PE relocatability describes the loader image itself, not by itself the Android kernel physical destination or an FD-safe base. No fastboot boot, flashing, or slot change is authorized.']
    txt='\n'.join(lines)+'\n'; os.makedirs(os.path.dirname(report) or '.',exist_ok=True); open(report,'w',encoding='utf-8').write(txt); print(txt,end='')
if __name__=='__main__': main()
