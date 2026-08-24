#!/usr/bin/env python3
import hashlib
import re
import sys
from datetime import datetime
from pathlib import Path


if len(sys.argv) != 7:
    raise SystemExit(
        "Usage: verify-m7-runtime-destination-ownership.py "
        "<wrapper-execution-report.txt> <fd-capacity-report.txt> "
        "<selected-dtb-report.txt> <fd-artifact> "
        "<runtime-ownership-snapshot.txt> <output.txt>"
    )

WRAPPER = Path(sys.argv[1])
FD_CAPACITY = Path(sys.argv[2])
SELECTED_DTB = Path(sys.argv[3])
FD = Path(sys.argv[4])
OWNERSHIP = Path(sys.argv[5])
OUT = Path(sys.argv[6])

SCHEMA = "IZZOS_M7_RUNTIME_DESTINATION_OWNERSHIP_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
UINT64_LIMIT = 1 << 64
REQUIRED_EXCLUSION_KINDS = {
    "FIXED_RESERVED",
    "DYNAMIC_RESERVED",
    "BOOTLOADER",
    "KERNEL",
    "DTB",
    "VENDOR_RAMDISK",
    "FRAMEBUFFER",
}
TOKEN = r"[A-Za-z0-9_.-]+"
PHYSICAL_RE = re.compile(
    rf"base=(0x[0-9A-Fa-f]+) size=(0x[0-9A-Fa-f]+) source=({TOKEN})"
)
EXCLUSION_RE = re.compile(
    rf"base=(0x[0-9A-Fa-f]+) size=(0x[0-9A-Fa-f]+) kind=({TOKEN}) name=({TOKEN})"
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def values(text, label):
    return [match.strip() for match in re.findall(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)]


def field(text, label):
    found = values(text, label)
    return found[0] if len(found) == 1 else None


def valid_hash(value):
    return bool(re.fullmatch(r"[0-9A-Fa-f]{64}", value or ""))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def decimal_value(text, label):
    value = field(text, label)
    return int(value, 10) if value and re.fullmatch(r"[0-9]+", value) else None


def valid_utc_timestamp(value):
    if not value or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def valid_range(base, size):
    return (
        base is not None
        and size is not None
        and 0 <= base < UINT64_LIMIT
        and size > 0
        and base + size <= UINT64_LIMIT
    )


def end(region):
    return region[0] + region[1]


def contains(outer, inner):
    return valid_range(*outer[:2]) and valid_range(*inner[:2]) and outer[0] <= inner[0] and end(inner) <= end(outer)


def overlaps(left, right):
    return valid_range(*left[:2]) and valid_range(*right[:2]) and left[0] < end(right) and right[0] < end(left)


def parse_physical(lines):
    parsed = []
    for line in lines:
        match = PHYSICAL_RE.fullmatch(line)
        if match:
            parsed.append((int(match.group(1), 16), int(match.group(2), 16), match.group(3)))
    return parsed


def parse_exclusions(lines):
    parsed = []
    for line in lines:
        match = EXCLUSION_RE.fullmatch(line)
        if match:
            parsed.append((int(match.group(1), 16), int(match.group(2), 16), match.group(3), match.group(4)))
    return parsed


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [WRAPPER, FD_CAPACITY, SELECTED_DTB, FD, OWNERSHIP]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 runtime-destination ownership input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an input or FD artifact")

wrapper = WRAPPER.read_text(errors="replace")
fd_capacity = FD_CAPACITY.read_text(errors="replace")
selected_dtb = SELECTED_DTB.read_text(errors="replace")
ownership = OWNERSHIP.read_text(errors="replace")

wrapper_hash = sha256(WRAPPER)
fd_capacity_hash = sha256(FD_CAPACITY)
selected_dtb_report_hash = sha256(SELECTED_DTB)
fd_hash = sha256(FD)
ownership_hash = sha256(OWNERSHIP)

unique_fields = [
    "memory-ownership-schema",
    "capture-id",
    "capture-timestamp-utc",
    "evidence-source",
    "evidence-authenticity",
    "wrapper-execution-report-sha256",
    "fd-capacity-report-sha256",
    "selected-dtb-report-sha256",
    "selected-dtb-sha256",
    "fd-sha256",
    "exact-device-build",
    "physical-memory-range-count",
    "exclusion-range-count",
    "dynamic-pool-resolution",
    "bootloader-relocation-resolution",
    "kernel-resolution",
    "dtb-resolution",
    "vendor-ramdisk-resolution",
    "framebuffer-resolution",
    "secure-reserved-resolution",
    "ownership-snapshot-lifetime",
    "device-writes",
    "persistent-writes",
    "slot-changes",
    "launch-authorization",
]

physical_lines = values(ownership, "physical-memory-range")
exclusion_lines = values(ownership, "exclusion-range")
physical = parse_physical(physical_lines)
exclusions = parse_exclusions(exclusion_lines)
physical_count = decimal_value(ownership, "physical-memory-range-count")
exclusion_count = decimal_value(ownership, "exclusion-range-count")

fd_size = FD.stat().st_size
fd_base = hex_value(wrapper, "final-runtime-destination")
fd_range = (fd_base, fd_size)
prepi_entry = hex_value(wrapper, "prepi-entry-address")
temporary_ram = (hex_value(wrapper, "temporary-ram-base"), hex_value(wrapper, "temporary-ram-size"))
stack = (hex_value(wrapper, "stack-base"), hex_value(wrapper, "stack-size"))
dtb_address = hex_value(wrapper, "preserved-dtb-address")

required_kinds_present = {region[2] for region in exclusions}
dtb_exclusions = [region for region in exclusions if region[2] == "DTB"]
physical_sorted = sorted(physical, key=lambda region: region[0])

checks = [
    ("wrapper-assertion-classification-passes", field(wrapper, "classification") == "M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED"),
    ("wrapper-assertion-remains-self-reported", field(wrapper, "execution-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED" and field(wrapper, "execution-route-authorization") == "NOT_INCLUDED"),
    ("wrapper-assertion-leaves-destination-ownership-unproven", field(wrapper, "final-runtime-destination-ownership") == "NOT_INDEPENDENTLY_PROVEN"),
    ("wrapper-assertion-denies-promotion-container-and-launch", field(wrapper, "dsc-fdf-promotion-authorization") == "NO" and field(wrapper, "container-build-authorization") == "NO" and field(wrapper, "launch-authorization") == "NO"),
    ("fd-capacity-classification-passes", field(fd_capacity, "classification") == "M7_FD_CAPACITY_CONTRACT_PASS"),
    ("fd-capacity-report-binds-actual-fd", equal_hash(field(fd_capacity, "fd-sha256"), fd_hash) and decimal_value(fd_capacity, "fd-size-bytes") == fd_size and hex_value(fd_capacity, "fd-size-hex") == fd_size),
    ("fd-capacity-report-leaves-base-unproven", field(fd_capacity, "fd-base-policy") == "NOT_YET_PROVEN" and field(fd_capacity, "launch-authorization") == "NO"),
    ("selected-dtb-classification-passes", field(selected_dtb, "classification") == "M7_EXACT_SELECTED_DTB_BOUND"),
    ("selected-dtb-report-denies-placement-and-launch", field(selected_dtb, "fd-base-policy") == "NOT_YET_PROVEN" and field(selected_dtb, "launch-authorization") == "NO"),
    ("ownership-unique-fields-are-present-once", all(len(values(ownership, label)) == 1 for label in unique_fields)),
    ("ownership-schema-is-exact", field(ownership, "memory-ownership-schema") == SCHEMA),
    ("ownership-capture-identity-is-specific", bool(re.fullmatch(TOKEN, field(ownership, "capture-id") or "")) and valid_utc_timestamp(field(ownership, "capture-timestamp-utc"))),
    ("ownership-is-exact-device-read-only-self-report", field(ownership, "evidence-source") == "EXACT_DEVICE_RUNTIME_READ_ONLY_CAPTURE" and field(ownership, "evidence-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("ownership-binds-wrapper-report", equal_hash(field(ownership, "wrapper-execution-report-sha256"), wrapper_hash)),
    ("ownership-binds-fd-capacity-report", equal_hash(field(ownership, "fd-capacity-report-sha256"), fd_capacity_hash)),
    ("ownership-binds-selected-dtb-report", equal_hash(field(ownership, "selected-dtb-report-sha256"), selected_dtb_report_hash)),
    ("ownership-binds-selected-dtb-bytes", equal_hash(field(ownership, "selected-dtb-sha256"), field(selected_dtb, "selected-dtb-sha256"))),
    ("ownership-binds-fd-bytes", equal_hash(field(ownership, "fd-sha256"), fd_hash)),
    ("ownership-targets-exact-build", field(ownership, "exact-device-build") == TARGET_BUILD),
    ("physical-range-lines-are-valid", len(physical_lines) > 0 and len(physical) == len(physical_lines) and all(valid_range(region[0], region[1]) and region[2] == "RUNTIME_PHYSICAL_MEMORY" for region in physical)),
    ("physical-range-count-is-exact", physical_count == len(physical)),
    ("physical-ranges-are-page-aligned", all(region[0] % 0x1000 == 0 and region[1] % 0x1000 == 0 for region in physical)),
    ("physical-ranges-do-not-overlap", all(end(left) <= right[0] for left, right in zip(physical_sorted, physical_sorted[1:]))),
    ("exclusion-range-lines-are-valid", len(exclusion_lines) > 0 and len(exclusions) == len(exclusion_lines) and all(valid_range(region[0], region[1]) for region in exclusions)),
    ("exclusion-range-count-is-exact", exclusion_count == len(exclusions)),
    ("exclusion-names-are-unique", len({region[3] for region in exclusions}) == len(exclusions)),
    ("required-exclusion-kinds-are-complete", REQUIRED_EXCLUSION_KINDS <= required_kinds_present),
    ("all-exclusions-are-inside-declared-physical-memory", all(any(contains(memory, exclusion) for memory in physical) for exclusion in exclusions)),
    ("dynamic-pools-are-resolved-for-capture", field(ownership, "dynamic-pool-resolution") == "COMPLETE_FOR_EXACT_CAPTURE_INSTANT"),
    ("bootloader-kernel-dtb-and-ramdisk-are-resolved", field(ownership, "bootloader-relocation-resolution") == "CAPTURED_AND_EXCLUDED" and field(ownership, "kernel-resolution") == "CAPTURED_AND_EXCLUDED" and field(ownership, "dtb-resolution") == "CAPTURED_AND_EXCLUDED" and field(ownership, "vendor-ramdisk-resolution") == "CAPTURED_AND_EXCLUDED"),
    ("framebuffer-is-resolved-and-excluded", field(ownership, "framebuffer-resolution") == "CAPTURED_AND_EXCLUDED"),
    ("secure-reserved-map-is-reconciled", field(ownership, "secure-reserved-resolution") == "EXACT_SELECTED_DTB_AND_RUNTIME_CAPTURE_RECONCILED"),
    ("ownership-snapshot-lifetime-is-bounded", field(ownership, "ownership-snapshot-lifetime") == "EXACT_CAPTURE_INSTANT_ONLY"),
    ("fd-range-is-valid-and-page-aligned", valid_range(*fd_range) and fd_base % 0x1000 == 0 and fd_size % 0x1000 == 0),
    ("fd-range-is-inside-physical-memory", any(contains(memory, fd_range) for memory in physical)),
    ("fd-range-does-not-overlap-exclusions", not any(overlaps(fd_range, exclusion) for exclusion in exclusions)),
    ("prepi-entry-is-inside-fd", valid_range(*fd_range) and prepi_entry is not None and fd_base <= prepi_entry < end(fd_range)),
    ("temporary-ram-range-is-valid-and-page-aligned", valid_range(*temporary_ram) and temporary_ram[0] % 0x1000 == 0 and temporary_ram[1] % 0x1000 == 0),
    ("temporary-ram-is-inside-physical-memory", any(contains(memory, temporary_ram) for memory in physical)),
    ("temporary-ram-does-not-overlap-exclusions", not any(overlaps(temporary_ram, exclusion) for exclusion in exclusions)),
    ("stack-is-contained-in-temporary-ram", contains(temporary_ram, stack)),
    ("fd-and-temporary-ram-do-not-overlap", not overlaps(fd_range, temporary_ram)),
    ("preserved-dtb-address-is-in-dtb-exclusion", dtb_address is not None and any(region[0] <= dtb_address < end(region) for region in dtb_exclusions)),
    ("ownership-snapshot-denies-device-write-and-launch", field(ownership, "device-writes") == "NONE" and field(ownership, "persistent-writes") == "NONE" and field(ownership, "slot-changes") == "NONE" and field(ownership, "launch-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 final runtime-destination ownership gate",
    "Verifier mode: HOST_SIDE_RANGE_CONTAINMENT_AND_EXCLUSION_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"wrapper-execution-report-sha256: {wrapper_hash}",
    f"fd-capacity-report-sha256: {fd_capacity_hash}",
    f"selected-dtb-report-sha256: {selected_dtb_report_hash}",
    f"fd-sha256: {fd_hash}",
    f"fd-size: 0x{fd_size:X}",
    f"runtime-ownership-snapshot-sha256: {ownership_hash}",
    f"capture-id: {field(ownership, 'capture-id') or 'MISSING'}",
    f"capture-timestamp-utc: {field(ownership, 'capture-timestamp-utc') or 'MISSING'}",
    f"exact-device-build: {TARGET_BUILD}",
    f"final-runtime-destination: {field(wrapper, 'final-runtime-destination') or 'MISSING'}",
    f"prepi-entry-address: {field(wrapper, 'prepi-entry-address') or 'MISSING'}",
    f"temporary-ram-base: {field(wrapper, 'temporary-ram-base') or 'MISSING'}",
    f"temporary-ram-size: {field(wrapper, 'temporary-ram-size') or 'MISSING'}",
    f"stack-base: {field(wrapper, 'stack-base') or 'MISSING'}",
    f"stack-size: {field(wrapper, 'stack-size') or 'MISSING'}",
    f"preserved-dtb-address: {field(wrapper, 'preserved-dtb-address') or 'MISSING'}",
    f"physical-memory-range-count: {len(physical)}",
    f"exclusion-range-count: {len(exclusions)}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "ownership-evidence-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "ownership-snapshot-lifetime: EXACT_CAPTURE_INSTANT_ONLY",
    "final-runtime-destination-ownership: ARITHMETICALLY_CLEAR_IN_DECLARED_SNAPSHOT_ONLY",
    "dsc-fdf-promotion-authorization: NO",
    "container-build-authorization: NO",
    "device-commands: NONE",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M7_RUNTIME_DESTINATION_OWNERSHIP_BLOCKED",
        "decision: the exact FD, wrapper assertion, selected DTB, physical-memory ranges or exclusion snapshot are incomplete, contradictory, unsafe or not hash-bound. Do not select an FD base, promote DSC/FDF files, construct a container or run a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: OWNERSHIP_CAPTURE_AUTHENTICITY_NOT_INDEPENDENTLY_ATTESTED",
    "remaining-blocker: OWNERSHIP_SNAPSHOT_FRESHNESS_REQUIRED_AT_AUTHORIZED_EXECUTION",
    "remaining-blocker: WRAPPER_EXECUTION_ROUTE_NOT_AUTHORIZED",
    "classification: M7_RUNTIME_DESTINATION_OWNERSHIP_SCHEMA_PASS_AUTHENTICITY_FRESHNESS_REQUIRED",
    "decision: the FD, SEC/PrePi entry, temporary RAM and stack are contained in declared physical memory and avoid every declared exact-capture exclusion. This arithmetic result is bound to one self-reported instant; it does not independently attest ownership, remain valid after allocations change, authorize wrapper execution, promote DSC/FDF files, build a container or authorize launch.",
])
