#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

CFG = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/uefiplat.cfg")
BOOT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output/boot.img")
VBOOT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("output/vendor_boot.img")
OUT = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m1-kernel-region-geometry.txt")


def sha256(path):
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (CFG, BOOT, VBOOT):
    if not required.is_file():
        raise SystemExit(f"ERROR: required input not found: {required}")

cfg = CFG.read_text(errors="replace")
kernel_entries = re.findall(
    r'(?im)^\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*"Kernel"\s*,',
    cfg,
)
if len(kernel_entries) != 1:
    raise SystemExit(
        f'ERROR: expected exactly one "Kernel" entry in uefiplat.cfg; found {len(kernel_entries)}'
    )

kbase = int(kernel_entries[0][0], 16)
ksize = int(kernel_entries[0][1], 16)
kend = kbase + ksize

boot = BOOT.read_bytes()
if len(boot) < 44:
    raise SystemExit("ERROR: boot.img is too short for an Android boot v4 header")
if boot[:8] != b"ANDROID!":
    raise SystemExit("ERROR: boot.img magic mismatch")
kernel_size, ramdisk_size = struct.unpack_from("<II", boot, 8)
header_version = struct.unpack_from("<I", boot, 40)[0]

vb = VBOOT.read_bytes()
if len(vb) < 0x850:
    raise SystemExit("ERROR: vendor_boot.img is too short for a vendor boot v4 header")
if vb[:8] != b"VNDRBOOT":
    raise SystemExit("ERROR: vendor_boot.img magic mismatch")
vhdrver = struct.unpack_from("<I", vb, 8)[0]
page = struct.unpack_from("<I", vb, 12)[0]
vendor_ramdisk_size = struct.unpack_from("<I", vb, 24)[0]
# v4 bootconfig_size is the final u32 in the 2128-byte header, offset 0x84c.
bootconfig_size = struct.unpack_from("<I", vb, 0x84C)[0]

errors = []
if ksize <= 0 or kend <= kbase or kend > (1 << 64):
    errors.append("invalid-kernel-region")
if header_version != 4:
    errors.append("boot-header-version-is-not-v4")
if vhdrver != 4:
    errors.append("vendor-boot-header-version-is-not-v4")
if kernel_size <= 0:
    errors.append("kernel-payload-size-is-zero")
if page < 4096 or page > 65536 or page & (page - 1):
    errors.append("vendor-page-size-is-invalid")

base_lines = [
    "IzzOS M1 exact stock kernel-region geometry reconciliation",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    f"uefiplat-cfg: {CFG}",
    f"uefiplat-sha256: {sha256(CFG)}",
    f"boot-image: {BOOT}",
    f"boot-sha256: {sha256(BOOT)}",
    f"vendor-boot-image: {VBOOT}",
    f"vendor-boot-sha256: {sha256(VBOOT)}",
    "",
    "exact stock UEFI Kernel memory region:",
    f"KernelBaseAddr: 0x{kbase:08X}",
    f"KernelSize: 0x{ksize:X} ({ksize // (1024 * 1024)} MiB)",
    f"KernelEndAddr: 0x{kend:08X}",
    "",
    "exact boot inputs:",
    f"boot-header-version: {header_version}",
    f"kernel-payload-size: 0x{kernel_size:X}",
    f"ramdisk-size: 0x{ramdisk_size:X}",
    f"vendor-header-version: {vhdrver}",
    f"page-size: 0x{page:X}",
    f"vendor-ramdisk-size: 0x{vendor_ramdisk_size:X}",
    f"vendor-bootconfig-size: 0x{bootconfig_size:X}",
]

if errors:
    emit(
        base_lines
        + [
            "",
            "failed-checks:",
            *[f"- {error}" for error in errors],
            "",
            "classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED",
            "decision: Milestone 6 geometry inputs are invalid or incompatible with the exact v4 placement model; do not construct a Milestone 7 layout.",
        ],
        1,
    )

ram_total = ramdisk_size + vendor_ramdisk_size + bootconfig_size
rounded = align_up(ram_total, page)
reservation = rounded + page
ramdisk_load = kend - reservation
dtb_load = ramdisk_load - (0x200000 + page)
kernel_payload_end = kbase + kernel_size

checks = [
    ("ramdisk-reservation-fits-kernel-region", reservation < ksize),
    ("dtb-load-inside-kernel-region", kbase <= dtb_load < kend),
    ("ramdisk-load-inside-kernel-region", kbase <= ramdisk_load < kend),
    ("dtb-before-ramdisk", dtb_load < ramdisk_load),
    ("kernel-payload-before-dtb", kernel_payload_end <= dtb_load),
]
failed = [name for name, passed in checks if not passed]

lines = base_lines + [
    "",
    "source/binary matched stock placement formula:",
    f"ramdisk-related-total: 0x{ram_total:X}",
    f"rounded-to-page: 0x{rounded:X}",
    f"placement-reservation-including-one-page-buffer: 0x{reservation:X}",
    f"RamdiskLoadAddr: 0x{ramdisk_load:08X}",
    f"DeviceTreeLoadAddr: 0x{dtb_load:08X}",
    "",
    f"kernel-payload-end-if-loaded-at-KernelBaseAddr: 0x{kernel_payload_end:08X}",
    f'kernel-payload-before-DeviceTreeLoadAddr: {"yes" if not failed else "no"}',
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
]

if failed:
    emit(
        lines
        + [
            "",
            "classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED",
            "decision: Milestone 6 placement arithmetic overlaps or escapes the exact stock Kernel region; do not construct a Milestone 7 layout.",
        ],
        1,
    )

lines += [
    "",
    "cross-evidence chain:",
    '1. exact stock uefiplat.cfg defines the named Kernel region.',
    '2. public Qualcomm PlatformBds source sets KernelBaseAddr/KernelSize from GetMemRegionInfoByName("Kernel").',
    "3. exact stock UEFI binary contains and writes KernelBaseAddr/KernelSize through the matched variable-service call path.",
    "4. exact stock LinuxLoader consumes KernelBaseAddr/KernelSize and uses the independently reverse-engineered dynamic placement formula.",
    "5. exact boot/vendor_boot v4 headers provide the size terms used by that formula.",
    "",
    "classification: M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED",
    "decision: Milestone 6 memory/placement geometry evidence is internally reconciled for the exact stock build. This closes the evidence gate for constructing and host-validating the Milestone 7 standalone firmware layout. It does not by itself authorize flashing, slot changes, or a device launch.",
]
emit(lines)
