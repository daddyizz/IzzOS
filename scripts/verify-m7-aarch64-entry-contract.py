#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

LAYOUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-layout-contract.txt")
BOOT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output/boot.img")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-aarch64-entry-contract.txt")

ANDROID_V4_PAGE = 4096
ANDROID_V4_HEADER_SIZE = 1584
AARCH64_HEADER_SIZE = 64
AARCH64_MAGIC = 0x644D5241
PLACEMENT_ALIGNMENT = 2 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def hex_field(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (LAYOUT, BOOT):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 entry input not found: {required}")

layout = LAYOUT.read_text(errors="replace")
boot = BOOT.read_bytes()
actual_boot_hash = sha256(BOOT)
expected_boot_hash = field(layout, "geometry-boot-sha256")
kernel_base = hex_field(layout, "proven-kernel-region-base")
dtb_load = hex_field(layout, "proven-stock-dtb-load")
stock_page = hex_field(layout, "proven-stock-page-size")

header_available = len(boot) >= ANDROID_V4_PAGE + AARCH64_HEADER_SIZE
android_magic = boot[:8] if len(boot) >= 8 else b""
kernel_size = u32(boot, 8) if len(boot) >= 12 else 0
ramdisk_size = u32(boot, 12) if len(boot) >= 16 else 0
header_size = u32(boot, 20) if len(boot) >= 24 else 0
android_reserved = boot[24:40] if len(boot) >= 40 else b""
header_version = u32(boot, 40) if len(boot) >= 44 else 0

if header_available:
    offset = ANDROID_V4_PAGE
    code0 = u32(boot, offset)
    code1 = u32(boot, offset + 4)
    text_offset = u64(boot, offset + 8)
    image_size = u64(boot, offset + 16)
    flags = u64(boot, offset + 24)
    res2 = u64(boot, offset + 32)
    res3 = u64(boot, offset + 40)
    res4 = u64(boot, offset + 48)
    image_magic = u32(boot, offset + 56)
    res5 = u32(boot, offset + 60)
else:
    code0 = code1 = text_offset = image_size = flags = res2 = res3 = res4 = image_magic = res5 = 0

kernel_payload_end = ANDROID_V4_PAGE + kernel_size
aligned_base = kernel_base - text_offset if kernel_base is not None and kernel_base >= text_offset else -1
image_end = kernel_base + image_size if kernel_base is not None else 0
page_flag = (flags >> 1) & 0x3
page_flag_names = {0: "UNSPECIFIED", 1: "4K", 2: "16K", 3: "64K"}
placement_flag = (flags >> 3) & 0x1

checks = [
    ("m7-layout-region-contract-pass", field(layout, "classification") == "M7_LAYOUT_REGION_CONTRACT_PASS"),
    ("boot-hash-is-carried-from-m6", bool(expected_boot_hash and re.fullmatch(r"[0-9A-Fa-f]{64}", expected_boot_hash))),
    ("actual-boot-hash-matches-m6", expected_boot_hash is not None and actual_boot_hash == expected_boot_hash.lower()),
    ("android-boot-magic-is-valid", android_magic == b"ANDROID!"),
    ("android-boot-header-is-v4", header_version == 4 and header_size == ANDROID_V4_HEADER_SIZE),
    ("android-boot-reserved-fields-are-zero", android_reserved == b"\0" * 16),
    ("kernel-payload-contains-aarch64-header", header_available and kernel_size >= AARCH64_HEADER_SIZE and kernel_payload_end <= len(boot)),
    ("aarch64-image-magic-is-valid", image_magic == AARCH64_MAGIC),
    ("aarch64-native-entry-code-is-present", code0 != 0 or code1 != 0),
    ("aarch64-reserved-header-fields-are-zero", res2 == 0 and res3 == 0 and res4 == 0),
    ("aarch64-reserved-flag-bits-are-zero", flags >> 4 == 0),
    ("aarch64-image-is-little-endian", flags & 0x1 == 0),
    ("aarch64-text-offset-is-within-2m-window", 0 <= text_offset < PLACEMENT_ALIGNMENT),
    ("aarch64-image-size-is-concrete-and-fits-payload", 0 < image_size <= kernel_size),
    ("stock-kernel-call-address-follows-2m-text-offset-rule", aligned_base >= 0 and aligned_base % PLACEMENT_ALIGNMENT == 0),
    ("stock-kernel-image-ends-before-dtb", kernel_base is not None and dtb_load is not None and image_end <= dtb_load),
    ("stock-page-size-is-valid", stock_page in (4096, 16384, 65536)),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 exact-stock AArch64 Linux entry contract",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "Launch commands executed: NO",
    "",
    f"layout-contract: {LAYOUT}",
    f"boot-image: {BOOT}",
    f"m6-boot-sha256: {expected_boot_hash or 'MISSING'}",
    f"actual-boot-sha256: {actual_boot_hash}",
    f"android-header-version: {header_version}",
    f"android-header-size: {header_size}",
    f"android-kernel-payload-offset: 0x{ANDROID_V4_PAGE:X}",
    f"android-kernel-payload-size: 0x{kernel_size:X}",
    f"android-ramdisk-payload-size: 0x{ramdisk_size:X}",
    "",
    f"aarch64-code0: 0x{code0:08X}",
    f"aarch64-code1: 0x{code1:08X}",
    f"aarch64-text-offset: 0x{text_offset:X}",
    f"aarch64-image-size: 0x{image_size:X}",
    f"aarch64-flags: 0x{flags:X}",
    f"aarch64-kernel-endianness: {'BIG' if flags & 1 else 'LITTLE'}",
    f"aarch64-kernel-page-size-flag: {page_flag_names[page_flag]}",
    f"aarch64-physical-placement-flag: {placement_flag}",
    f"aarch64-pe-coff-offset-res5: 0x{res5:X}",
    "",
    f"stock-linux-image-call-address: 0x{kernel_base:X}" if kernel_base is not None else "stock-linux-image-call-address: UNAVAILABLE",
    f"derived-2m-aligned-base: 0x{aligned_base:X}" if aligned_base >= 0 else "derived-2m-aligned-base: UNAVAILABLE",
    f"stock-linux-image-end: 0x{image_end:X}" if kernel_base is not None else "stock-linux-image-end: UNAVAILABLE",
    f"stock-dtb-load-address: 0x{dtb_load:X}" if dtb_load is not None else "stock-dtb-load-address: UNAVAILABLE",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "source-linux-entry-register-contract: x0=DTB_PHYSICAL_ADDRESS,x1=0,x2=0,x3=0",
    "source-linux-entry-security-contract: NON_SECURE",
    "source-linux-entry-el-contract: EL2_RECOMMENDED_OR_EL1",
    "source-linux-entry-interrupt-contract: PSTATE_DAIF_ALL_MASKED",
    "source-linux-entry-mmu-contract: OFF",
    "source-linux-entry-timer-contract: CNTFRQ_AND_CNTVOFF_PREINITIALIZED",
    "observed-qualcomm-entry-el: NOT_CAPTURED",
    "observed-qualcomm-system-register-state: NOT_CAPTURED",
    "standalone-sec-entry-equivalence: NOT_PROVEN",
    "android-container-substitution: FORBIDDEN",
    "storage-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_STOCK_AARCH64_ENTRY_CONTRACT_BLOCKED",
            "decision: the exact boot image does not satisfy the bounded Android v4 and AArch64 Linux Image entry checks. Do not infer a standalone SEC entry or authorize launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED",
        "decision: the exact stock Linux Image call address, header geometry and source-defined AArch64 handoff requirements are enumerated. The actual Qualcomm exception level/system-register state and a standalone EDK2 SEC entry remain unobserved, non-equivalent and unauthorized.",
    ]
)
