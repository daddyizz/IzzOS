#!/usr/bin/env python3
import hashlib
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


def grab_hash(label):
    m = re.search(rf'(?m)^{re.escape(label)}:\s*([0-9A-Fa-f]{{64}})\s*$', geom)
    return m.group(1).lower() if m else None


def sha256(path):
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()

kbase = grab('KernelBaseAddr')
ksize = grab('KernelSize')
kend = grab('KernelEndAddr')
ramdisk = grab('RamdiskLoadAddr')
dtb = grab('DeviceTreeLoadAddr')
page_size = grab('page-size')

region_matches = list(
    re.finditer(
        r'(?im)^\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*"([^"]+)"\s*,',
        cfg,
    )
)
regions = [
    (int(match.group(1), 16), int(match.group(2), 16), match.group(3))
    for match in region_matches
]
kernel_regions = [region for region in regions if region[2] == 'Kernel']
if not kernel_regions:
    raise SystemExit('ERROR: Kernel region not found in uefiplat.cfg')
cfg_base, cfg_size, _ = kernel_regions[0]

next_region = None
overlapping_regions = []
invalid_regions = []
skipped_kernel = False
for base, size, name in regions:
    if name == 'Kernel' and not skipped_kernel:
        skipped_kernel = True
        continue
    if size <= 0 or base + size > (1 << 64):
        invalid_regions.append((base, size, name))
        continue
    if base < kend and base + size > kbase:
        overlapping_regions.append((base, size, name))
    if base >= kend and (next_region is None or base < next_region[0]):
        next_region = (base, size, name)

cfg_hash_from_geometry = grab_hash('uefiplat-sha256')
boot_hash_from_geometry = grab_hash('boot-sha256')
vendor_boot_hash_from_geometry = grab_hash('vendor-boot-sha256')
kernel_fit_match = re.search(
    r'(?mi)^kernel-payload-before-DeviceTreeLoadAddr:\s*(yes|no)\s*$', geom
)
kernel_fit = kernel_fit_match.group(1).lower() if kernel_fit_match else None

checks = []
checks.append(('geometry-has-exact-stock-input-hashes', bool(boot_hash_from_geometry and vendor_boot_hash_from_geometry)))
checks.append(('cfg-hash-matches-geometry', cfg_hash_from_geometry == sha256(CFG)))
checks.append(('kernel-entry-is-unique', len(kernel_regions) == 1))
checks.append(('configured-regions-have-valid-geometry', not invalid_regions))
checks.append(('kernel-base-matches-cfg', kbase == cfg_base))
checks.append(('kernel-size-matches-cfg', ksize == cfg_size))
checks.append(('kernel-end-consistent', kend == kbase + ksize))
checks.append(('m6-stock-page-size-is-valid', 4096 <= page_size <= 65536 and not page_size & (page_size - 1)))
checks.append(('dtb-inside-kernel-region', kbase <= dtb < kend))
checks.append(('ramdisk-inside-kernel-region', kbase <= ramdisk < kend))
checks.append(('dtb-before-ramdisk', dtb < ramdisk))
checks.append(('ramdisk-before-kernel-end', ramdisk < kend))
checks.append(('m6-kernel-payload-fit-is-proven', kernel_fit == 'yes'))
checks.append(('kernel-region-does-not-overlap-other-cfg-regions', not overlapping_regions))

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
    f'proven-stock-page-size: 0x{page_size:X}',
    f'geometry-cfg-sha256: {cfg_hash_from_geometry or "MISSING"}',
    f'actual-cfg-sha256: {sha256(CFG)}',
]
if next_region is not None:
    lines += [
        f'next-configured-region-base: 0x{next_region[0]:08X}',
        f'next-configured-region-size: 0x{next_region[1]:X}',
        f'next-configured-region-name: {next_region[2]}',
    ]

if overlapping_regions:
    lines += ['', 'overlapping-configured-regions:']
    for base, size, name in overlapping_regions:
        lines.append(f'- {name}: 0x{base:08X}-0x{base + size:08X}')
else:
    lines.append('overlapping-configured-regions: NONE')

if invalid_regions:
    lines += ['', 'invalid-configured-regions:']
    for base, size, name in invalid_regions:
        lines.append(f'- {name}: base=0x{base:X} size=0x{size:X}')

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
