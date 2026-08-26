#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

LAYOUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-layout-contract.txt")
CAPACITY = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-fd-capacity.txt")
SELECTED_DTB = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-selected-dtb.txt")
ENTRY = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-aarch64-entry-contract.txt")
FD = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/ovaltine-standalone/Ovaltine.fd")
BOOT = Path(sys.argv[6]) if len(sys.argv) > 6 else Path("output/boot.img")
VENDOR_BOOT = Path(sys.argv[7]) if len(sys.argv) > 7 else Path("output/vendor_boot.img")
OUT = Path(sys.argv[8]) if len(sys.argv) > 8 else Path("out/m7-android-container-inputs.txt")

TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
ANDROID_V4_HEADER_SIZE = 1584
VENDOR_V4_HEADER_SIZE = 2128


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def valid_hash(value):
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{64}", value))


def hex_field(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def int_field(text, label):
    value = field(text, label)
    return int(value) if value and value.isdigit() else None


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (LAYOUT, CAPACITY, SELECTED_DTB, ENTRY, FD, BOOT, VENDOR_BOOT):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 container input not found: {required}")

layout = LAYOUT.read_text(errors="replace")
capacity = CAPACITY.read_text(errors="replace")
selected_dtb = SELECTED_DTB.read_text(errors="replace")
entry = ENTRY.read_text(errors="replace")
boot = BOOT.read_bytes()
vendor_boot = VENDOR_BOOT.read_bytes()

fd_hash = sha256(FD)
boot_hash = sha256(BOOT)
vendor_boot_hash = sha256(VENDOR_BOOT)
layout_boot_hash = field(layout, "geometry-boot-sha256")
layout_vendor_hash = field(layout, "geometry-vendor-boot-sha256")
capacity_fd_hash = field(capacity, "fd-sha256")
capacity_fd_size = int_field(capacity, "fd-size-bytes")
selected_vendor_hash = field(selected_dtb, "vendor-boot-sha256")
selected_m6_vendor_hash = field(selected_dtb, "m6-vendor-boot-sha256")
selected_dtb_hash = field(selected_dtb, "selected-dtb-sha256")
entry_boot_hash = field(entry, "actual-boot-sha256")
entry_m6_boot_hash = field(entry, "m6-boot-sha256")
stock_page = hex_field(layout, "proven-stock-page-size")

boot_header_available = len(boot) >= ANDROID_V4_HEADER_SIZE
boot_kernel_size = u32(boot, 8) if len(boot) >= 12 else 0
boot_ramdisk_size = u32(boot, 12) if len(boot) >= 16 else 0
boot_header_size = u32(boot, 20) if len(boot) >= 24 else 0
boot_header_version = u32(boot, 40) if len(boot) >= 44 else 0

vendor_header_available = len(vendor_boot) >= VENDOR_V4_HEADER_SIZE
vendor_header_version = u32(vendor_boot, 8) if len(vendor_boot) >= 12 else 0
vendor_page_size = u32(vendor_boot, 12) if len(vendor_boot) >= 16 else 0
vendor_kernel_address = u32(vendor_boot, 16) if len(vendor_boot) >= 20 else 0
vendor_ramdisk_address = u32(vendor_boot, 20) if len(vendor_boot) >= 24 else 0
vendor_ramdisk_size = u32(vendor_boot, 24) if len(vendor_boot) >= 28 else 0
vendor_header_size = u32(vendor_boot, 2096) if len(vendor_boot) >= 2100 else 0

checks = [
    ("m7-layout-region-contract-pass", field(layout, "classification") == "M7_LAYOUT_REGION_CONTRACT_PASS"),
    ("m7-fd-capacity-contract-pass", field(capacity, "classification") == "M7_FD_CAPACITY_CONTRACT_PASS"),
    ("m7-selected-dtb-binding-pass", field(selected_dtb, "classification") == "M7_EXACT_SELECTED_DTB_BOUND"),
    ("m7-aarch64-entry-contract-pass", field(entry, "classification") == "M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED"),
    ("all-prerequisite-reports-deny-launch", all(field(report, "launch-authorization") == "NO" for report in (capacity, selected_dtb, entry))),
    ("selected-dtb-targets-exact-device-build", field(selected_dtb, "device-build-id") == TARGET_BUILD),
    ("selected-dtb-hash-is-carried", valid_hash(selected_dtb_hash)),
    ("layout-boot-hash-is-valid", valid_hash(layout_boot_hash)),
    ("layout-vendor-boot-hash-is-valid", valid_hash(layout_vendor_hash)),
    ("fd-hash-is-bound-to-capacity-report", valid_hash(capacity_fd_hash) and capacity_fd_hash.lower() == fd_hash),
    ("fd-size-is-bound-to-capacity-report", capacity_fd_size == FD.stat().st_size),
    ("fd-is-nonempty-and-stock-page-aligned", bool(stock_page and FD.stat().st_size > 0 and FD.stat().st_size % stock_page == 0)),
    ("boot-hash-matches-layout", valid_hash(layout_boot_hash) and layout_boot_hash.lower() == boot_hash),
    ("boot-hash-matches-entry-report", valid_hash(entry_boot_hash) and entry_boot_hash.lower() == boot_hash),
    ("entry-report-carries-layout-boot-hash", valid_hash(entry_m6_boot_hash) and valid_hash(layout_boot_hash) and entry_m6_boot_hash.lower() == layout_boot_hash.lower()),
    ("vendor-boot-hash-matches-layout", valid_hash(layout_vendor_hash) and layout_vendor_hash.lower() == vendor_boot_hash),
    ("vendor-boot-hash-matches-selected-dtb-report", valid_hash(selected_vendor_hash) and selected_vendor_hash.lower() == vendor_boot_hash),
    ("selected-dtb-report-carries-layout-vendor-hash", valid_hash(selected_m6_vendor_hash) and valid_hash(layout_vendor_hash) and selected_m6_vendor_hash.lower() == layout_vendor_hash.lower()),
    ("android-boot-magic-is-valid", boot[:8] == b"ANDROID!"),
    ("android-boot-header-is-v4", boot_header_available and boot_header_version == 4 and boot_header_size == ANDROID_V4_HEADER_SIZE),
    ("android-boot-kernel-payload-is-present", boot_kernel_size > 0),
    ("vendor-boot-magic-is-valid", vendor_boot[:8] == b"VNDRBOOT"),
    ("vendor-boot-header-is-v4", vendor_header_available and vendor_header_version == 4 and vendor_header_size == VENDOR_V4_HEADER_SIZE),
    ("vendor-boot-page-size-matches-layout", stock_page in (4096, 16384, 65536) and vendor_page_size == stock_page),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 exact Android container input binding",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "Container construction executed: NO",
    "Launch commands executed: NO",
    "",
    f"exact-device-build: {TARGET_BUILD}",
    f"layout-contract: {LAYOUT}",
    f"fd-capacity-report: {CAPACITY}",
    f"selected-dtb-report: {SELECTED_DTB}",
    f"aarch64-entry-report: {ENTRY}",
    "",
    f"fd-artifact: {FD}",
    f"fd-sha256: {fd_hash}",
    f"fd-size-bytes: {FD.stat().st_size}",
    f"boot-image: {BOOT}",
    f"boot-sha256: {boot_hash}",
    f"vendor-boot-image: {VENDOR_BOOT}",
    f"vendor-boot-sha256: {vendor_boot_hash}",
    f"selected-dtb-sha256: {selected_dtb_hash or 'MISSING'}",
    f"layout-boot-sha256: {layout_boot_hash or 'MISSING'}",
    f"entry-report-boot-sha256: {entry_boot_hash or 'MISSING'}",
    f"layout-vendor-boot-sha256: {layout_vendor_hash or 'MISSING'}",
    f"selected-report-vendor-boot-sha256: {selected_vendor_hash or 'MISSING'}",
    "",
    f"android-header-version: {boot_header_version}",
    f"android-header-size: {boot_header_size}",
    f"android-kernel-size: {boot_kernel_size}",
    f"android-ramdisk-size: {boot_ramdisk_size}",
    f"vendor-header-version: {vendor_header_version}",
    f"vendor-header-size: {vendor_header_size}",
    f"vendor-page-size: {vendor_page_size}",
    f"vendor-kernel-address-evidence: 0x{vendor_kernel_address:X}",
    f"vendor-ramdisk-address-evidence: 0x{vendor_ramdisk_address:X}",
    f"vendor-ramdisk-size: {vendor_ramdisk_size}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "container-build-authorization: NO",
    "kernel-replacement-authorization: NO",
    "vendor-boot-modification-authorization: NO",
    "avb-bypass-authorization: NO",
    "fastboot-boot-authorization: NO",
    "qualcomm-container-entry-semantics: NOT_YET_PROVEN",
    "fd-base-policy: NOT_YET_PROVEN",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_ANDROID_CONTAINER_INPUT_BINDING_BLOCKED",
            "decision: one or more exact input bytes, prerequisite reports, header geometries, or denial policies do not form a consistent M7 evidence chain. Do not construct, repack, substitute, or launch an Android container.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_ANDROID_CONTAINER_INPUTS_BOUND",
        "decision: the exact FD, boot.img, vendor_boot.img, selected-DTB binding, layout, capacity, and stock Linux entry reports form one hash-bound input set. This remains an input-only result: Qualcomm replacement/relocation semantics, an FD base, and a launch route are unproven, so construction, repacking, substitution, and launch remain unauthorized.",
    ]
)
