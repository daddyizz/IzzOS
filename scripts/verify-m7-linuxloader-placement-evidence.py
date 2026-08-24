#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

INPUTS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-android-container-inputs.txt")
LINUXLOADER = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/linuxloader/LinuxLoader.efi")
PLACEMENT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/linuxloader-placement-function.txt")
BOOTPARAM = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/linuxloader-bootparam-field-writes.txt")
PROVENANCE = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/linuxloader-size-term-provenance.txt")
V4_SEMANTICS = Path(sys.argv[6]) if len(sys.argv) > 6 else Path("out/linuxloader-v4-size-term-semantics.txt")
BOOT = Path(sys.argv[7]) if len(sys.argv) > 7 else Path("output/boot.img")
VENDOR_BOOT = Path(sys.argv[8]) if len(sys.argv) > 8 else Path("output/vendor_boot.img")
OUT = Path(sys.argv[9]) if len(sys.argv) > 9 else Path("out/m7-linuxloader-placement-evidence.txt")

TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
AARCH64_MACHINE = 0xAA64
PE32_PLUS_MAGIC = 0x20B


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


def carried_hash(report, label, actual):
    value = field(report, label)
    return valid_hash(value) and value.lower() == actual


def pe_identity(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return 0, 0, False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 26 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return 0, 0, False
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    optional_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    return machine, optional_magic, True


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (INPUTS, LINUXLOADER, PLACEMENT, BOOTPARAM, PROVENANCE, V4_SEMANTICS, BOOT, VENDOR_BOOT):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 LinuxLoader evidence input not found: {required}")

inputs = INPUTS.read_text(errors="replace")
placement = PLACEMENT.read_text(errors="replace")
bootparam = BOOTPARAM.read_text(errors="replace")
provenance = PROVENANCE.read_text(errors="replace")
v4_semantics = V4_SEMANTICS.read_text(errors="replace")
loader_bytes = LINUXLOADER.read_bytes()

loader_hash = sha256(LINUXLOADER)
boot_hash = sha256(BOOT)
vendor_hash = sha256(VENDOR_BOOT)
machine, optional_magic, pe_valid = pe_identity(loader_bytes)

placement_formula = "tmp32 = field_0x78 + field_0x94 + field_0x98"
placement_guard = "candidate_guard = candidate - (field_0x6C + 0x200000)"
ramdisk_formula = "RamdiskLoadAddr = KernelEndAddr - rounded(total ramdisk-related bytes, PageSize)"
dtb_formula = "DeviceTreeLoadAddr = RamdiskLoadAddr - (0x200000 + PageSize)"
semantic_formula = "RamdiskLoadAddr = KernelEndAddr - (ROUND_UP(RamdiskSize + VendorRamdiskSize + VendorBootConfigSize, PageSize) + PageSize)"

checks = [
    ("m7-container-input-binding-pass", field(inputs, "classification") == "M7_ANDROID_CONTAINER_INPUTS_BOUND"),
    ("container-input-report-denies-build", field(inputs, "container-build-authorization") == "NO"),
    ("container-input-report-denies-kernel-replacement", field(inputs, "kernel-replacement-authorization") == "NO"),
    ("container-input-report-denies-launch", field(inputs, "launch-authorization") == "NO"),
    ("container-input-report-targets-exact-build", field(inputs, "exact-device-build") == TARGET_BUILD),
    ("linuxloader-is-aarch64-pe32-plus", pe_valid and machine == AARCH64_MACHINE and optional_magic == PE32_PLUS_MAGIC),
    ("placement-analysis-classification-pass", field(placement, "classification") == "LINUXLOADER_DYNAMIC_PLACEMENT_FUNCTION_ISOLATED"),
    ("bootparam-analysis-classification-pass", field(bootparam, "classification") == "LINUXLOADER_BOOTPARAM_WRITE_SITES_ENUMERATED"),
    ("size-provenance-classification-pass", field(provenance, "classification") == "LINUXLOADER_SIZE_TERM_PROVENANCE_WINDOWS_ENUMERATED"),
    ("v4-size-semantics-classification-pass", field(v4_semantics, "classification") == "LINUXLOADER_V4_SIZE_TERM_SEMANTICS_CROSS_EVIDENCE_CONSISTENT"),
    ("placement-analysis-matches-exact-linuxloader", carried_hash(placement, "sha256", loader_hash)),
    ("bootparam-analysis-matches-exact-linuxloader", carried_hash(bootparam, "sha256", loader_hash)),
    ("size-provenance-matches-exact-linuxloader", carried_hash(provenance, "sha256", loader_hash)),
    ("container-input-boot-hash-matches-actual", carried_hash(inputs, "boot-sha256", boot_hash)),
    ("v4-semantics-boot-hash-matches-actual", carried_hash(v4_semantics, "boot-sha256", boot_hash)),
    ("container-input-vendor-hash-matches-actual", carried_hash(inputs, "vendor-boot-sha256", vendor_hash)),
    ("v4-semantics-vendor-hash-matches-actual", carried_hash(v4_semantics, "vendor-boot-sha256", vendor_hash)),
    ("dynamic-size-sum-is-explicit", placement_formula in placement),
    ("dynamic-guard-is-explicit", placement_guard in placement),
    ("source-matched-ramdisk-formula-is-explicit", ramdisk_formula in bootparam),
    ("source-matched-dtb-formula-is-explicit", dtb_formula in bootparam),
    ("v4-size-term-formula-is-explicit", semantic_formula in v4_semantics),
    ("page-size-field-is-source-mapped", "+0x6C = PageSize" in bootparam and "struct+0x6C = PageSize" in v4_semantics),
    ("v4-size-terms-are-source-mapped", all(term in v4_semantics for term in ("struct+0x78 = RamdiskSize", "struct+0x94 = VendorRamdiskSize", "struct+0x98 = VendorBootConfigSize"))),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 exact LinuxLoader placement evidence binding",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "Container construction executed: NO",
    "Launch commands executed: NO",
    "",
    f"exact-device-build: {TARGET_BUILD}",
    f"container-input-report: {INPUTS}",
    f"linuxloader-image: {LINUXLOADER}",
    f"linuxloader-sha256: {loader_hash}",
    f"linuxloader-pe-machine: 0x{machine:04X}",
    f"linuxloader-optional-header-magic: 0x{optional_magic:03X}",
    f"boot-sha256: {boot_hash}",
    f"vendor-boot-sha256: {vendor_hash}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "stock-linux-kernel-placement-arithmetic: BOUND_TO_EXACT_LINUXLOADER",
    "final-physical-destination: NOT_RUNTIME_OBSERVED",
    "fd-kernel-substitution-equivalence: NOT_PROVEN",
    "standalone-sec-entry-equivalence: NOT_PROVEN",
    "fd-base-policy: NOT_YET_PROVEN",
    "container-build-authorization: NO",
    "kernel-replacement-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_LINUXLOADER_PLACEMENT_EVIDENCE_BLOCKED",
            "decision: the exact LinuxLoader binary, placement reports, v4 size semantics, or M7 input hashes do not form one consistent evidence chain. Do not infer an FD base, substitute a kernel, construct a container, or launch the device.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND",
        "decision: the stock Linux kernel placement arithmetic and v4 size-term meanings are bound to one exact AArch64 LinuxLoader and the exact M7 boot/vendor input set. The final runtime destination and equivalence of replacing the Linux kernel with a standalone FD remain unobserved and unproven; no FD base, container build, or launch is authorized.",
    ]
)
