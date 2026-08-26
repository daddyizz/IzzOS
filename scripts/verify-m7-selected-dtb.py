#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

LAYOUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-layout-contract.txt")
INSPECTION = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m1-device-inspection/ovaltine-inspection-analysis.txt")
MANIFEST = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/vendor-boot-dtb-set/MANIFEST.txt")
DTB = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/vendor-boot-dtb-set/dtb-1.dtb")
VENDOR_BOOT = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("output/vendor_boot.img")
OUT = Path(sys.argv[6]) if len(sys.argv) > 6 else Path("out/m7-selected-dtb.txt")

BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def align4(value):
    return (value + 3) & ~3


def cstring(data, offset, limit):
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ValueError("unterminated FDT string")
    return data[offset:end].decode("utf-8", "replace"), end + 1


def string_list(value):
    return [part.decode("utf-8", "replace") for part in value.split(b"\0") if part]


def root_identity(path):
    data = path.read_bytes()
    if len(data) < 40 or data[:4] != b"\xd0\x0d\xfe\xed":
        raise ValueError("invalid FDT magic or truncated header")
    total, struct_off, strings_off, _, version, last_compatible, _, strings_size, struct_size = struct.unpack_from(
        ">9I", data, 4
    )
    if total > len(data) or total < 40 or version < 17 or last_compatible > 17:
        raise ValueError("invalid FDT header geometry or version")
    struct_end = struct_off + struct_size
    strings_end = strings_off + strings_size
    if struct_off < 40 or struct_end > total or strings_off < 40 or strings_end > total:
        raise ValueError("FDT blocks escape totalsize")

    cursor = struct_off
    depth = 0
    model = []
    compatible = []
    while cursor + 4 <= struct_end:
        token = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4
        if token == BEGIN_NODE:
            _, cursor = cstring(data, cursor, struct_end)
            cursor = align4(cursor)
            depth += 1
        elif token == END_NODE:
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced FDT node")
        elif token == PROP:
            if cursor + 8 > struct_end:
                raise ValueError("truncated FDT property header")
            length, name_offset = struct.unpack_from(">II", data, cursor)
            cursor += 8
            if cursor + length > struct_end or name_offset >= strings_size:
                raise ValueError("FDT property escapes its block")
            name, _ = cstring(data, strings_off + name_offset, strings_end)
            value = data[cursor : cursor + length]
            cursor = align4(cursor + length)
            if depth == 1 and name == "model":
                model = string_list(value)
            elif depth == 1 and name == "compatible":
                compatible = string_list(value)
        elif token == NOP:
            continue
        elif token == END:
            break
        else:
            raise ValueError(f"unknown FDT token {token}")
    return model, compatible, total


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (LAYOUT, INSPECTION, MANIFEST, DTB, VENDOR_BOOT):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 input not found: {required}")

layout = LAYOUT.read_text(errors="replace")
inspection = INSPECTION.read_text(errors="replace")
manifest = MANIFEST.read_text(errors="replace")
expected_vendor_hash = field(layout, "geometry-vendor-boot-sha256")
dtb_index_text = field(inspection, "DTB index")
device_build = field(inspection, "Build ID")
dtb_index = int(dtb_index_text) if dtb_index_text and dtb_index_text.isdigit() else -1
manifest_match = re.search(
    rf"(?m)^dtb-index:\s*{dtb_index}\s+offset=(0x[0-9A-Fa-f]+)\s+size=([0-9]+)\s+sha256=([0-9A-Fa-f]{{64}})\s*$",
    manifest,
) if dtb_index >= 0 else None

actual_dtb_hash = sha256(DTB)
actual_vendor_hash = sha256(VENDOR_BOOT)
try:
    models, compatibles, fdt_total = root_identity(DTB)
    fdt_error = None
except ValueError as error:
    models, compatibles, fdt_total = [], [], 0
    fdt_error = str(error)

manifest_size = int(manifest_match.group(2)) if manifest_match else -1
manifest_hash = manifest_match.group(3).lower() if manifest_match else None
checks = [
    ("m7-layout-region-contract-pass", field(layout, "classification") == "M7_LAYOUT_REGION_CONTRACT_PASS"),
    ("inspection-target-match", field(inspection, "Target match") == "yes"),
    ("inspection-build-id-matches-exact-stock", device_build == TARGET_BUILD),
    ("device-dtb-index-is-numeric", dtb_index >= 0),
    ("selected-dtb-filename-matches-device-index", DTB.name == f"dtb-{dtb_index}.dtb"),
    ("selected-dtb-has-one-manifest-entry", manifest_match is not None),
    ("selected-dtb-size-matches-manifest", manifest_size == DTB.stat().st_size),
    ("selected-dtb-hash-matches-manifest", manifest_hash == actual_dtb_hash),
    ("vendor-boot-hash-is-carried-from-m6", bool(expected_vendor_hash and re.fullmatch(r"[0-9a-fA-F]{64}", expected_vendor_hash))),
    ("actual-vendor-boot-hash-matches-m6", expected_vendor_hash is not None and actual_vendor_hash == expected_vendor_hash.lower()),
    ("selected-dtb-is-structurally-valid", fdt_error is None and fdt_total == DTB.stat().st_size),
    ("selected-dtb-compatible-is-cape", "qcom,cape" in compatibles),
    ("selected-dtb-model-is-present", bool(models)),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 exact selected-DTB binding",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "Launch commands executed: NO",
    "",
    f"device-build-id: {device_build or 'UNKNOWN'}",
    f"device-dtb-index: {dtb_index_text or 'UNKNOWN'}",
    f"selected-dtb: {DTB}",
    f"selected-dtb-sha256: {actual_dtb_hash}",
    f"selected-dtb-size: {DTB.stat().st_size}",
    f"selected-dtb-model: {','.join(models) if models else 'UNAVAILABLE'}",
    f"selected-dtb-compatible: {','.join(compatibles) if compatibles else 'UNAVAILABLE'}",
    f"fdt-parse-error: {fdt_error or 'NONE'}",
    f"vendor-boot-sha256: {actual_vendor_hash}",
    f"m6-vendor-boot-sha256: {expected_vendor_hash or 'MISSING'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "static-dtb-mmio-policy: EVIDENCE_ONLY_NOT_INIT_AUTHORIZATION",
    "gic-timer-policy: NOT_YET_PROVEN",
    "fd-base-policy: NOT_YET_PROVEN",
    "storage-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_SELECTED_DTB_BINDING_FAIL",
            "decision: the selected DTB is not fully bound to the exact device-reported index, extraction manifest, and M6 vendor_boot hash; do not derive platform initialization data from it.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_EXACT_SELECTED_DTB_BOUND",
        "decision: the selected Cape DTB bytes are bound to the device-reported index, extraction manifest, and exact M6 vendor_boot image. This authorizes read-only platform-property analysis only; it does not authorize MMIO initialization, FD placement, packaging, or launch.",
    ]
)
