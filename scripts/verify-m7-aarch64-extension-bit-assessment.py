#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

INVENTORY = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-aarch64-extension-registers.txt")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-aarch64-extension-bit-assessment.txt")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def bit(value, shift):
    return None if value is None else (value >> shift) & 1


def bits(value, shift, width):
    return None if value is None else (value >> shift) & ((1 << width) - 1)


def el2_status(el2_present, feature_present, passed):
    if not el2_present:
        return "NOT_REQUIRED_EL2_ABSENT"
    if not feature_present:
        return "NOT_REQUIRED_FEATURE_ABSENT"
    return "PASS" if passed else "FAIL"


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


if not INVENTORY.is_file():
    raise SystemExit(f"ERROR: required M7 extension-register inventory report not found: {INVENTORY}")

inventory = INVENTORY.read_text(errors="replace")
inventory_hash = sha256(INVENTORY)
current_el = field(inventory, "entry-current-el")
hcr = hex_value(inventory, "hcr-el2")
cptr = hex_value(inventory, "cptr-el2")
cnthctl = hex_value(inventory, "cnthctl-el2")
icc_sre = hex_value(inventory, "icc-sre-el2")
cntfrq = hex_value(inventory, "entry-cntfrq-el0")
cntvoff = hex_value(inventory, "entry-cntvoff-el2")
zcr = hex_value(inventory, "zcr-el2")
smcr = hex_value(inventory, "smcr-el2")

has_fp = field(inventory, "feature-fp") == "PRESENT"
has_asimd = field(inventory, "feature-advanced-simd") == "PRESENT"
has_el2 = field(inventory, "feature-aarch64-el2") == "PRESENT"
has_sve = field(inventory, "feature-sve") == "PRESENT"
has_sme = field(inventory, "feature-sme") == "PRESENT"
has_mte = field(inventory, "feature-mte2-or-newer") == "PRESENT"
has_pauth = field(inventory, "feature-pointer-authentication") == "PRESENT"
feature_labels = (
    "feature-aarch64-el2",
    "feature-fp",
    "feature-advanced-simd",
    "feature-sve",
    "feature-sme",
    "feature-mte2-or-newer",
    "feature-pointer-authentication",
)

common_checks = [
    ("inventory-schema-gate-passed", field(inventory, "classification") == "M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS"),
    ("inventory-is-raw-not-authorization", field(inventory, "register-values-policy") == "RAW_INVENTORY_NOT_NORMALIZATION_AUTHORIZATION"),
    ("inventory-bit-compliance-was-unproven", field(inventory, "extension-specific-bit-compliance") == "NOT_YET_PROVEN"),
    ("inventory-cross-core-consistency-was-unproven", field(inventory, "cross-core-register-consistency") == "NOT_YET_PROVEN"),
    ("inventory-remains-self-reported", field(inventory, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("inventory-capture-route-remains-unproven", field(inventory, "capture-route-authorization") == "NOT_PROVEN"),
    ("inventory-denies-wrapper-implementation", field(inventory, "sec-wrapper-implementation-authorization") == "NO"),
    ("inventory-denies-dsc-fdf-promotion", field(inventory, "dsc-fdf-promotion-authorization") == "NO"),
    ("inventory-denies-mmio-initialization", field(inventory, "mmio-initialization-authorization") == "NO"),
    ("inventory-denies-fastboot-boot", field(inventory, "fastboot-boot-authorization") == "NO"),
    ("inventory-denies-launch", field(inventory, "launch-authorization") == "NO"),
    ("entry-current-el-is-supported", current_el in ("EL1", "EL2")),
    ("feature-presence-labels-are-explicit", all(field(inventory, label) in ("PRESENT", "ABSENT") for label in feature_labels)),
    ("architected-counter-frequency-is-programmed", cntfrq not in (None, 0)),
    ("primary-cpu-virtual-counter-offset-is-visible", cntvoff is not None),
]
common_failed = [name for name, passed in common_checks if not passed]

el1_statuses = {
    "el1-aarch64-hcr-rw": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-physical-counter-access": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-gicv3-system-register-interface": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-fp-simd-trap-disabled": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-sve-traps-disabled": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-sve-vector-length-state-visible": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-sme-traps-disabled": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-sme-streaming-state-visible": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-sme-additional-controls-covered": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-pointer-authentication-enabled": "NOT_APPLICABLE_AT_EL2_ENTRY",
    "el1-mte-access-enabled": "NOT_APPLICABLE_AT_EL2_ENTRY",
}

conditional_failed = []
if current_el == "EL1":
    has_fp_or_asimd = has_fp or has_asimd
    el1_statuses = {
        "el1-aarch64-hcr-rw": el2_status(has_el2, True, bit(hcr, 31) == 1),
        "el1-physical-counter-access": el2_status(has_el2, True, bit(cnthctl, 0) == 1),
        "el1-gicv3-system-register-interface": el2_status(has_el2, True, bit(icc_sre, 3) == 1 and bit(icc_sre, 0) == 1),
        "el1-fp-simd-trap-disabled": el2_status(has_el2, has_fp_or_asimd, bit(cptr, 10) == 0),
        "el1-sve-traps-disabled": el2_status(has_el2, has_sve, bit(cptr, 8) == 0 and bits(cptr, 16, 2) == 3),
        "el1-sve-vector-length-state-visible": el2_status(has_el2, has_sve, zcr is not None),
        "el1-sme-traps-disabled": el2_status(has_el2, has_sme, bit(cptr, 12) == 0 and bits(cptr, 24, 2) == 3),
        "el1-sme-streaming-state-visible": el2_status(has_el2, has_sme, smcr is not None),
        "el1-sme-additional-controls-covered": el2_status(has_el2, has_sme, False),
        "el1-pointer-authentication-enabled": el2_status(has_el2, has_pauth, bit(hcr, 40) == 1 and bit(hcr, 41) == 1),
        "el1-mte-access-enabled": el2_status(has_el2, has_mte, bit(hcr, 56) == 1),
    }
    conditional_failed = [name for name, value in el1_statuses.items() if value == "FAIL"]

lines = [
    "IzzOS Milestone 7 AArch64 extension control-bit assessment",
    "Collector mode: HOST_SIDE_CONDITIONAL_ASSESSMENT",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"extension-register-inventory-report: {INVENTORY}",
    f"extension-register-inventory-report-sha256: {inventory_hash}",
    f"entry-current-el: {current_el or 'MISSING'}",
    "source-linux-entry-reference: https://www.kernel.org/doc/html/latest/arch/arm64/booting.html",
    "source-cpu-feature-reference: https://kernel.org/doc/html/next/arm64/cpu-feature-registers.html",
    "",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in common_checks],
    "",
    *[f"{name}: {value}" for name, value in el1_statuses.items()],
    "",
    "secure-el3-control-state: NOT_OBSERVABLE_IN_THIS_INVENTORY",
    "secure-el3-prerequisite-compliance: NOT_PROVEN",
    "cross-core-cntvoff-consistency: NOT_PROVEN",
    "cross-core-zcr-smcr-consistency: NOT_PROVEN",
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

if common_failed or conditional_failed:
    emit(
        lines + [
            "conditional-bit-compliance: BLOCKED",
            "classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_BLOCKED",
            "decision: the inventory provenance/denial contract or an applicable EL1 control-bit requirement failed. Do not infer boot readiness or authorize wrapper code, DSC/FDF promotion, MMIO, or launch.",
        ],
        1,
    )

if current_el == "EL2":
    emit(
        lines + [
            "conditional-bit-compliance: DEFERRED_SECURE_EL3_EVIDENCE_REQUIRED",
            "classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_DEFERRED_SECURE_EL3_EVIDENCE",
            "decision: EL1-specific EL2 controls are not applicable to an EL2 entry snapshot. Required Secure EL3 extension state is not observable from non-secure EL2, so compliance, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
        ]
    )
    raise SystemExit(0)

emit(
    lines + [
        "conditional-bit-compliance: EL1_ASSESSED_EL2_CONTROL_BITS_PASS",
        "classification: M7_AARCH64_EXTENSION_BIT_ASSESSMENT_PASS",
        "decision: the applicable EL2-owned control bits for an EL1 entry in this exact self-reported inventory satisfy the bounded assessment. Secure EL3 prerequisites, cross-core consistency, unassessed extensions, independent authenticity, capture route, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
    ]
)
