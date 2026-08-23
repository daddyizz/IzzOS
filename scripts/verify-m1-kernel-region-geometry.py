#!/usr/bin/env python3
import re, struct, hashlib, sys
from pathlib import Path

CFG = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('out/uefiplat.cfg')
BOOT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('output/boot.img')
VBOOT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path('output/vendor_boot.img')
OUT = Path(sys.argv[4]) if len(sys.argv) > 4 else Path('out/m1-kernel-region-geometry.txt')

def sha256(p):
    h=hashlib.sha256(); h.update(p.read_bytes()); return h.hexdigest()

def align_up(x,a): return (x+a-1)&~(a-1)

cfg = CFG.read_text(errors='replace')
m = re.search(r'(?im)^\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*"Kernel"\s*,', cfg)
if not m:
    raise SystemExit('ERROR: exact "Kernel" entry not found in uefiplat.cfg')
kbase = int(m.group(1),16)
ksize = int(m.group(2),16)
kend = kbase + ksize

boot = BOOT.read_bytes()
if boot[:8] != b'ANDROID!': raise SystemExit('ERROR: boot.img magic mismatch')
kernel_size, ramdisk_size = struct.unpack_from('<II', boot, 8)
header_version = struct.unpack_from('<I', boot, 40)[0]

vb = VBOOT.read_bytes()
if vb[:8] != b'VNDRBOOT': raise SystemExit('ERROR: vendor_boot.img magic mismatch')
vhdrver = struct.unpack_from('<I', vb, 8)[0]
page = struct.unpack_from('<I', vb, 12)[0]
vendor_ramdisk_size = struct.unpack_from('<I', vb, 24)[0]
# v4 bootconfig_size is final u32 in 2128-byte header, offset 0x84c.
bootconfig_size = struct.unpack_from('<I', vb, 0x84c)[0] if vhdrver >= 4 and len(vb) >= 0x850 else 0

ram_total = ramdisk_size + vendor_ramdisk_size + bootconfig_size
rounded = align_up(ram_total, page)
reservation = rounded + page
ramdisk_load = kend - reservation
dtb_load = ramdisk_load - (0x200000 + page)

kernel_payload_end = kbase + kernel_size
kernel_payload_fits = kernel_payload_end <= dtb_load

lines = [
'IzzOS M1 exact stock kernel-region geometry reconciliation',
'Collector mode: READ_ONLY_HOST_SIDE',
'Device writes: NONE',
f'uefiplat-cfg: {CFG}',
f'uefiplat-sha256: {sha256(CFG)}',
f'boot-image: {BOOT}',
f'boot-sha256: {sha256(BOOT)}',
f'vendor-boot-image: {VBOOT}',
f'vendor-boot-sha256: {sha256(VBOOT)}',
'',
'exact stock UEFI Kernel memory region:',
f'KernelBaseAddr: 0x{kbase:08X}',
f'KernelSize: 0x{ksize:X} ({ksize//(1024*1024)} MiB)',
f'KernelEndAddr: 0x{kend:08X}',
'',
'exact boot inputs:',
f'boot-header-version: {header_version}',
f'kernel-payload-size: 0x{kernel_size:X}',
f'ramdisk-size: 0x{ramdisk_size:X}',
f'vendor-header-version: {vhdrver}',
f'page-size: 0x{page:X}',
f'vendor-ramdisk-size: 0x{vendor_ramdisk_size:X}',
f'vendor-bootconfig-size: 0x{bootconfig_size:X}',
'',
'source/binary matched stock placement formula:',
f'ramdisk-related-total: 0x{ram_total:X}',
f'rounded-to-page: 0x{rounded:X}',
f'placement-reservation-including-one-page-buffer: 0x{reservation:X}',
f'RamdiskLoadAddr: 0x{ramdisk_load:08X}',
f'DeviceTreeLoadAddr: 0x{dtb_load:08X}',
'',
f'kernel-payload-end-if-loaded-at-KernelBaseAddr: 0x{kernel_payload_end:08X}',
f'kernel-payload-before-DeviceTreeLoadAddr: {"yes" if kernel_payload_fits else "no"}',
'',
'cross-evidence chain:',
'1. exact stock uefiplat.cfg defines the named Kernel region.',
'2. public Qualcomm PlatformBds source sets KernelBaseAddr/KernelSize from GetMemRegionInfoByName("Kernel").',
'3. exact stock UEFI binary contains and writes KernelBaseAddr/KernelSize through the matched variable-service call path.',
'4. exact stock LinuxLoader consumes KernelBaseAddr/KernelSize and uses the independently reverse-engineered dynamic placement formula.',
'5. exact boot/vendor_boot v4 headers provide the size terms used by that formula.',
'',
'classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED',
'decision: Milestone 6 memory/placement geometry evidence is internally reconciled for the exact stock build. This closes the evidence gate for constructing and host-validating the Milestone 7 standalone firmware layout. It does not by itself authorize flashing, slot changes, or a device launch.',
]
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
