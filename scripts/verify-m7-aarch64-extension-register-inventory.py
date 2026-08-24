#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

BASELINE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-qualcomm-entry-observation.txt")
INVENTORY = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-aarch64-extension-registers-raw.txt")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-aarch64-extension-registers.txt")

SCHEMA = "IZZOS_M7_AARCH64_EXTENSION_REGISTERS_V1"
ID_REGISTERS = (
    "midr-el1",
    "mpidr-el1",
    "id-aa64pfr0-el1",
    "id-aa64pfr1-el1",
    "id-aa64isar0-el1",
    "id-aa64isar1-el1",
    "id-aa64mmfr0-el1",
    "id-aa64mmfr1-el1",
    "id-aa64dfr0-el1",
)
EL2_CONTROL_REGISTERS = (
    "hcr-el2",
    "cptr-el2",
    "cnthctl-el2",
    "mdcr-el2",
    "icc-sre-el2",
)


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


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def nibble(value, shift):
    return (value >> shift) & 0xF if value is not None else None


def feature(field_value):
    return "PRESENT" if field_value not in (None, 0, 0xF) else "ABSENT"


def implemented_unless_absent(field_value):
    return "PRESENT" if field_value is not None and field_value != 0xF else "ABSENT"


def el2_value_is_explicit(text, label, current_el):
    value = field(text, label)
    if current_el == "EL2":
        return hex_value(text, label) is not None
    return hex_value(text, label) is not None or value == "UNAVAILABLE_AT_EL1"


def optional_el2_value_is_explicit(text, label, current_el, present):
    value = field(text, label)
    if current_el == "EL1":
        return hex_value(text, label) is not None or value == "UNAVAILABLE_AT_EL1"
    if present:
        return hex_value(text, label) is not None
    return value == "NOT_IMPLEMENTED"


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (BASELINE, INVENTORY):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 extension-register input not found: {required}")

baseline = BASELINE.read_text(errors="replace")
inventory = INVENTORY.read_text(errors="replace")
baseline_hash = sha256(BASELINE)
inventory_hash = sha256(INVENTORY)
current_el = field(baseline, "entry-current-el")

values = {label: hex_value(inventory, label) for label in ID_REGISTERS}
pfr0 = values["id-aa64pfr0-el1"]
pfr1 = values["id-aa64pfr1-el1"]
isar1 = values["id-aa64isar1-el1"]

el2_field = nibble(pfr0, 8)
fp_field = nibble(pfr0, 16)
asimd_field = nibble(pfr0, 20)
sve_field = nibble(pfr0, 32)
mte_field = nibble(pfr1, 8)
sme_field = nibble(pfr1, 24)
apa_field = nibble(isar1, 4)
api_field = nibble(isar1, 8)
gpa_field = nibble(isar1, 24)
gpi_field = nibble(isar1, 28)

has_sve = feature(sve_field) == "PRESENT"
has_sme = feature(sme_field) == "PRESENT"
has_pauth = any(value not in (None, 0, 0xF) for value in (apa_field, api_field, gpa_field, gpi_field))

checks = [
    ("qualcomm-entry-baseline-schema-pass", field(baseline, "classification") == "M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS"),
    ("baseline-authenticity-remains-self-reported", field(baseline, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("baseline-denies-wrapper-implementation", field(baseline, "sec-wrapper-implementation-authorization") == "NO"),
    ("baseline-denies-launch", field(baseline, "launch-authorization") == "NO"),
    ("inventory-schema-is-supported", field(inventory, "extension-register-schema") == SCHEMA),
    ("inventory-source-matches-baseline-snapshot", field(inventory, "capture-source") == "SAME_PRE_SEC_INSTRUMENTED_SNAPSHOT"),
    ("inventory-is-from-primary-cpu", field(inventory, "capture-cpu") == "PRIMARY"),
    ("inventory-binds-exact-baseline-report", equal_hash(field(inventory, "baseline-observation-sha256"), baseline_hash)),
    ("inventory-currentel-matches-baseline", field(inventory, "entry-current-el") == current_el and current_el in ("EL1", "EL2")),
    ("all-required-primary-cpu-id-registers-are-present", all(value is not None for value in values.values())),
    ("midr-is-nonzero", values["midr-el1"] is not None and values["midr-el1"] != 0),
    ("id-register-reports-aarch64-el1", nibble(pfr0, 4) not in (None, 0xF)),
    ("id-register-el2-state-matches-currentel", current_el != "EL2" or el2_field not in (None, 0xF)),
    ("el2-control-register-visibility-is-explicit", all(el2_value_is_explicit(inventory, label, current_el) for label in EL2_CONTROL_REGISTERS)),
    ("sve-control-register-visibility-is-explicit", optional_el2_value_is_explicit(inventory, "zcr-el2", current_el, has_sve)),
    ("sme-control-register-visibility-is-explicit", optional_el2_value_is_explicit(inventory, "smcr-el2", current_el, has_sme)),
    ("inventory-asserts-no-device-writes", field(inventory, "device-writes") == "NONE"),
    ("inventory-asserts-no-persistent-writes", field(inventory, "persistent-writes") == "NONE"),
    ("inventory-asserts-no-slot-changes", field(inventory, "slot-changes") == "NONE"),
    ("inventory-denies-launch-authorization", field(inventory, "launch-authorization") == "NO"),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 AArch64 extension-register inventory schema gate",
    "Collector mode: HOST_SIDE_SCHEMA_VALIDATION",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"baseline-observation-report: {BASELINE}",
    f"baseline-observation-sha256: {baseline_hash}",
    f"extension-register-inventory: {INVENTORY}",
    f"extension-register-inventory-sha256: {inventory_hash}",
    f"entry-current-el: {current_el or 'MISSING'}",
    "",
    *[f"{label}: {field(inventory, label) or 'MISSING'}" for label in ID_REGISTERS],
    *[f"{label}: {field(inventory, label) or 'MISSING'}" for label in EL2_CONTROL_REGISTERS],
    f"zcr-el2: {field(inventory, 'zcr-el2') or 'MISSING'}",
    f"smcr-el2: {field(inventory, 'smcr-el2') or 'MISSING'}",
    "",
    f"feature-aarch64-el2: {implemented_unless_absent(el2_field)}",
    f"feature-fp: {implemented_unless_absent(fp_field)}",
    f"feature-advanced-simd: {implemented_unless_absent(asimd_field)}",
    f"feature-sve: {feature(sve_field)}",
    f"feature-sme: {feature(sme_field)}",
    f"feature-mte2-or-newer: {'PRESENT' if mte_field not in (None, 0xF) and mte_field >= 2 else 'ABSENT'}",
    f"feature-pointer-authentication: {'PRESENT' if has_pauth else 'ABSENT'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "register-values-policy: RAW_INVENTORY_NOT_NORMALIZATION_AUTHORIZATION",
    "extension-specific-bit-compliance: NOT_YET_PROVEN",
    "cross-core-register-consistency: NOT_YET_PROVEN",
    "observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "capture-route-authorization: NOT_PROVEN",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "mmio-initialization-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_BLOCKED",
            "decision: the extension-register inventory is incomplete, inconsistent with the baseline snapshot, or contains an unsupported EL/control-register state. Do not infer extension compliance or authorize wrapper code, DSC/FDF promotion, MMIO, or launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS",
        "decision: the primary CPU ID and EL2 control-register inventory is structurally complete and bound to the exact baseline snapshot. Feature presence is enumerated only; conditional boot-bit compliance, cross-core consistency, snapshot authenticity, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
    ]
)
