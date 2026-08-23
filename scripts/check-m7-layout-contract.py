#!/usr/bin/env python3
import re
import sys
from pathlib import Path

GEOM = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('out/m1-kernel-region-geometry.txt')
CFG = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('out/uefiplat.cfg')
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path('out/m7-layout-contract.txt')

if not GEOM.is_file():
    raise SystemExit(f'ERROR: geometry evidence not found: {GEOM}')
if not CFG.is_file():
    raise SystemExit(f'ERROR: uefiplat.cfg not found: {CFG}')

geom = GEOM.read_text(errors='replace')
cfg = CFG.read_text(errors='replace')

if 'classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED' not in geom:
    raise SystemExit('ERROR: Milestone 6 geometry classification is not reconciled')


def grab(label):
    m = re.search(rf'(?m)^{re.escape(label)}:\s*(0x[0-9A-Fa-f]+)', geom)
    if not m:
        raise SystemExit(f'ERROR: missing {label} in geometry evidence')
    return int(m.group(1), 16)

kbase = grab('KernelBaseAddr')
ksize = grab('KernelSize')
kend = grab('KernelEndAddr')
ramdisk = grab('RamdiskLoadAddr')
dtb = grab('DeviceTreeLoadAddr')

km = re.search(r'(?im)^\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*"Kernel"\s*,', cfg)
if not km:
    raise SystemExit('ERROR: Kernel region not found in uefiplat.cfg')
cfg_base = int(km.group(1), 16)
cfg_size = int(km.group(2), 16)

next_region = None
for m in re.finditer(r'(?im)^\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*"([^"]+)"\s*,', cfg):
    base = int(m.group(1), 16)
    if base >= kbase + ksize and (next_region is None or base < next_region[0]):
        next_region = (base, int(m.group(2), 16), m.group(3))

checks = []
checks.append(('kernel-base-matches-cfg', kbase == cfg_base))
checks.append(('kernel-size-matches-cfg', ksize == cfg_size))
checks.append(('kernel-end-consistent', kend == kbase + ksize))
checks.append(('dtb-inside-kernel-region', kbase <= dtb < kend))
checks.append(('ramdisk-inside-kernel-region', kbase <= ramdisk < kend))
checks.append(('dtb-before-ramdisk', dtb < ramdisk))
checks.append(('ramdisk-before-kernel-end', ramdisk < kend))
if next_region is not None:
    checks.append(('kernel-region-does-not-overlap-next-cfg-region', kend <= next_region[0]))

failed = [name for name, ok in checks if not ok]

lines = [
    'IzzOS Milestone 7 standalone layout contract',
    'Collector mode: READ_ONLY_HOST_SIDE',
    'Device writes: NONE',
    'Launch commands executed: NO',
    '',
    f'geometry-evidence: {GEOM}',
    f'uefiplat-cfg: {CFG}',
    '',
    f'proven-kernel-region-base: 0x{kbase:08X}',
    f'proven-kernel-region-size: 0x{ksize:X}',
    f'proven-kernel-region-end: 0x{kend:08X}',
    f'proven-stock-dtb-load: 0x{dtb:08X}',
    f'proven-stock-ramdisk-load: 0x{ramdisk:08X}',
]
if next_region is not None:
    lines += [
        f'next-configured-region-base: 0x{next_region[0]:08X}',
        f'next-configured-region-size: 0x{next_region[1]:X}',
        f'next-configured-region-name: {next_region[2]}',
    ]

lines += ['', 'checks:']
for name, ok in checks:
    lines.append(f'{name}: {"PASS" if ok else "FAIL"}')

lines += [
    '',
    'fd-size-policy: NOT_YET_SELECTED',
    'fd-base-policy: must remain within the proven Kernel region and must be justified by the actual standalone SEC/PEI/DXE image layout, not by an arbitrary fixed window.',
    'entry-policy: NOT_YET_PROVEN',
    'gic-timer-policy: NOT_YET_PROVEN',
    'storage-writes: FORBIDDEN',
    'slot-changes: FORBIDDEN',
]

if failed:
    lines += [
        'classification: M7_LAYOUT_CONTRACT_FAIL',
        'decision: do not create launch-oriented Ovaltine.dsc/Ovaltine.fdf; reconcile failed geometry checks first.',
    ]
else:
    lines += [
        'classification: M7_LAYOUT_REGION_CONTRACT_PASS',
        'decision: exact stock Kernel-region geometry is suitable as the bounded address contract for constructing host-only standalone DSC/FDF sources. FD size, entry, SEC/PEI/DXE composition and platform-init assumptions remain separately unproven; no device launch is authorized.',
    ]

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text('\n'.join(lines) + '\n')
print('\n'.join(lines))
if failed:
    raise SystemExit(1)
