#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

INVENTORY = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-aarch64-extension-registers.txt")
ASSESSMENT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-aarch64-extension-bit-assessment.txt")
GIC = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-gic-timer-dtb.txt")
PROVENANCE = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-sm8475-coherency-provenance.txt")
RAW = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-secure-el3-handoff-state-raw.txt")
OUT = Path(sys.argv[6]) if len(sys.argv) > 6 else Path("out/m7-secure-el3-handoff-state.txt")

SCHEMA = "IZZOS_M7_SECURE_EL3_HANDOFF_STATE_V1"


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


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def bit(value, shift):
    return None if value is None else (value >> shift) & 1


def equal_hash(left, right):
    return bool(left and re.fullmatch(r"[0-9A-Fa-f]{64}", left) and left.lower() == right.lower())


def feature(text, label):
    value = field(text, label)
    return value == "PRESENT" if value in ("PRESENT", "ABSENT") else None


def applicable(present, passed):
    if present is None:
        return "BLOCKED_FEATURE_STATE_MISSING"
    if not present:
        return "NOT_REQUIRED_FEATURE_ABSENT"
    return "PASS" if passed else "FAIL"


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (INVENTORY, ASSESSMENT, GIC, PROVENANCE, RAW):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 Secure EL3 input not found: {required}")

inventory = INVENTORY.read_text(errors="replace")
assessment = ASSESSMENT.read_text(errors="replace")
gic = GIC.read_text(errors="replace")
provenance = PROVENANCE.read_text(errors="replace")
raw = RAW.read_text(errors="replace")

inventory_hash = sha256(INVENTORY)
assessment_hash = sha256(ASSESSMENT)
gic_hash = sha256(GIC)
provenance_hash = sha256(PROVENANCE)
raw_hash = sha256(RAW)

has_fp = feature(inventory, "feature-fp")
has_asimd = feature(inventory, "feature-advanced-simd")
has_sve = feature(inventory, "feature-sve")
has_sme = feature(inventory, "feature-sme")
has_mte = feature(inventory, "feature-mte2-or-newer")
has_pauth = feature(inventory, "feature-pointer-authentication")
has_fp_or_asimd = None if has_fp is None or has_asimd is None else has_fp or has_asimd

scr = hex_value(raw, "scr-el3")
cptr = hex_value(raw, "cptr-el3")
icc_sre = hex_value(raw, "icc-sre-el3")
icc_ctlr = hex_value(raw, "icc-ctlr-el3")
zcr = hex_value(raw, "zcr-el3")
smcr = hex_value(raw, "smcr-el3")

required_raw_fields = {
    "secure-el3-state-schema": SCHEMA,
    "capture-source": "EXISTING_PLATFORM_FIRMWARE_EL3_HANDOFF_RECORD",
    "capture-execution-level": "EL3",
    "capture-method": "FIRMWARE_GENERATED_READ_ONLY_REGISTER_RECORD",
    "nonsecure-el2-direct-read-claim": "NONE",
    "entry-target": "NONSECURE_AARCH64_EL2",
    "evidence-kind": "SELF_REPORTED_SECURE_EL3_HANDOFF_ASSERTION",
    "cross-cpu-scr-fiq-consistency": "ASSERTED",
    "cross-cpu-icc-ctlr-pmhe-consistency": "ASSERTED",
    "observation-authenticity": "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "capture-route-authorization": "NOT_PROVEN",
    "secure-monitor-modification-action": "NONE",
    "device-writes": "NONE",
    "persistent-writes": "NONE",
    "slot-changes": "NONE",
    "launch-authorization": "NO",
}

checks = [
    ("inventory-schema-gate-passed", field(inventory, "classification") == "M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS"),
    ("inventory-entry-is-el2", field(inventory, "entry-current-el") == "EL2"),
    ("inventory-remains-self-reported", field(inventory, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("inventory-denies-wrapper-implementation", field(inventory, "sec-wrapper-implementation-authorization") == "NO"),
    ("inventory-denies-launch", field(inventory, "launch-authorization") == "NO"),
    ("assessment-binds-exact-inventory", equal_hash(field(assessment, "extension-register-inventory-report-sha256"), inventory_hash)),
    ("assessment-deferred-secure-el3-evidence", field(assessment, "classification") == "M7_AARCH64_EXTENSION_BIT_ASSESSMENT_DEFERRED_SECURE_EL3_EVIDENCE"),
    ("assessment-says-el3-not-observable", field(assessment, "secure-el3-control-state") == "NOT_OBSERVABLE_IN_THIS_INVENTORY"),
    ("assessment-left-el3-compliance-unproven", field(assessment, "secure-el3-prerequisite-compliance") == "NOT_PROVEN"),
    ("assessment-denies-launch", field(assessment, "launch-authorization") == "NO"),
    ("gic-dtb-evidence-enumerated", field(gic, "classification") == "M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED"),
    ("gic-is-v3", field(gic, "gic-compatible") == "arm,gic-v3"),
    ("gic-runtime-ownership-was-unproven", field(gic, "runtime-controller-ownership") == "NOT_YET_PROVEN"),
    ("gic-denies-mmio-initialization", field(gic, "mmio-initialization-authorization") == "NO"),
    ("gic-denies-launch", field(gic, "launch-authorization") == "NO"),
    ("coherency-provenance-boundary-passed", field(provenance, "classification") == "M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS"),
    ("provenance-establishes-psci-smc-interface", field(provenance, "secondary-cpu-enable-interface") == "PSCI_VIA_SMC"),
    ("provenance-left-internal-mechanism-unproven", field(provenance, "coherency-mechanism-implementation") == "NOT_PUBLICLY_PROVEN"),
    ("provenance-denies-coherency-register", field(provenance, "coherency-register-authorization") == "NO"),
    ("provenance-denies-launch", field(provenance, "launch-authorization") == "NO"),
    ("raw-binds-exact-inventory", equal_hash(field(raw, "extension-register-inventory-sha256"), inventory_hash)),
    ("raw-binds-exact-assessment", equal_hash(field(raw, "extension-bit-assessment-sha256"), assessment_hash)),
    ("raw-binds-exact-gic-report", equal_hash(field(raw, "gic-timer-report-sha256"), gic_hash)),
    ("raw-binds-exact-coherency-provenance", equal_hash(field(raw, "coherency-provenance-report-sha256"), provenance_hash)),
]

for label, expected in required_raw_fields.items():
    checks.append((f"raw-{label}-is-exact", field(raw, label) == expected))

checks.extend(
    [
        ("raw-fields-are-unambiguous", all(len(values(raw, label)) == 1 for label in [
            "extension-register-inventory-sha256",
            "extension-bit-assessment-sha256",
            "gic-timer-report-sha256",
            "coherency-provenance-report-sha256",
            "scr-el3",
            "cptr-el3",
            "icc-sre-el3",
            "icc-ctlr-el3",
            "zcr-el3",
            "smcr-el3",
            "cross-cpu-zcr-len-consistency",
            "cross-cpu-smcr-len-consistency",
            *required_raw_fields,
        ])),
        ("scr-el3-is-visible", scr is not None),
        ("cptr-el3-is-visible", cptr is not None),
        ("icc-sre-el3-is-visible", icc_sre is not None),
        ("icc-ctlr-el3-is-visible", icc_ctlr is not None),
        ("scr-ns-selects-nonsecure", bit(scr, 0) == 1),
        ("scr-smd-allows-smc", bit(scr, 7) == 0),
        ("scr-hce-allows-el2-hvc", bit(scr, 8) == 1),
        ("scr-rw-selects-aarch64", bit(scr, 10) == 1),
        ("icc-sre-el3-enables-system-register-interface", bit(icc_sre, 3) == 1 and bit(icc_sre, 0) == 1),
    ]
)

conditional = {
    "el3-fp-simd-trap-disabled": applicable(has_fp_or_asimd, bit(cptr, 10) == 0),
    "el3-pointer-authentication-access-enabled": applicable(has_pauth, bit(scr, 16) == 1 and bit(scr, 17) == 1),
    "el3-mte-access-enabled": applicable(has_mte, bit(scr, 26) == 1),
    "el3-sve-access-enabled": applicable(has_sve, bit(cptr, 8) == 1),
    "el3-sve-vector-length-visible": applicable(has_sve, zcr is not None),
    "el3-sve-vector-length-cross-cpu-consistent": applicable(has_sve, field(raw, "cross-cpu-zcr-len-consistency") == "ASSERTED"),
    "el3-sme-access-enabled": applicable(has_sme, bit(cptr, 12) == 1 and bit(scr, 41) == 1),
    "el3-sme-vector-length-visible": applicable(has_sme, smcr is not None),
    "el3-sme-vector-length-cross-cpu-consistent": applicable(has_sme, field(raw, "cross-cpu-smcr-len-consistency") == "ASSERTED"),
}

if has_sve is False:
    checks.extend([
        ("sve-absent-zcr-is-not-implemented", field(raw, "zcr-el3") == "NOT_IMPLEMENTED"),
        ("sve-absent-consistency-is-not-required", field(raw, "cross-cpu-zcr-len-consistency") == "NOT_REQUIRED_FEATURE_ABSENT"),
    ])
if has_sme is False:
    checks.extend([
        ("sme-absent-smcr-is-not-implemented", field(raw, "smcr-el3") == "NOT_IMPLEMENTED"),
        ("sme-absent-consistency-is-not-required", field(raw, "cross-cpu-smcr-len-consistency") == "NOT_REQUIRED_FEATURE_ABSENT"),
    ])

failed = [name for name, passed in checks if not passed]
conditional_failed = [name for name, status in conditional.items() if status.startswith("FAIL") or status.startswith("BLOCKED")]

lines = [
    "IzzOS Milestone 7 Secure EL3 handoff-state assertion schema gate",
    "Collector mode: HOST_SIDE_EL3_HANDOFF_ASSERTION_VALIDATION",
    "Network requests executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Secure monitor commands executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"extension-register-inventory: {INVENTORY}",
    f"extension-register-inventory-sha256: {inventory_hash}",
    f"extension-bit-assessment: {ASSESSMENT}",
    f"extension-bit-assessment-sha256: {assessment_hash}",
    f"gic-timer-report: {GIC}",
    f"gic-timer-report-sha256: {gic_hash}",
    f"coherency-provenance-report: {PROVENANCE}",
    f"coherency-provenance-report-sha256: {provenance_hash}",
    f"secure-el3-handoff-state: {RAW}",
    f"secure-el3-handoff-state-sha256: {raw_hash}",
    "source-linux-entry-reference: https://www.kernel.org/doc/html/latest/arch/arm64/booting.html",
    "source-el3-runtime-reference: https://github.com/ARM-software/arm-trusted-firmware/blob/master/lib/el3_runtime/aarch64/context_mgmt.c",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    *[f"{name}: {status}" for name, status in conditional.items()],
    "",
    f"scr-el3-fiq-bit: {bit(scr, 2) if scr is not None else 'UNAVAILABLE'}",
    f"icc-ctlr-el3-pmhe-bit: {bit(icc_ctlr, 6) if icc_ctlr is not None else 'UNAVAILABLE'}",
    "el3-profile-scope: BOUNDED_NONSECURE_AARCH64_EL2_BASE_AND_ENUMERATED_EXTENSIONS",
    "unrepresented-el3-feature-controls: NOT_ASSESSED",
    "secure-el3-observation: SELF_REPORTED_HANDOFF_ASSERTION_ONLY",
    "secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN",
    "capture-route-authorization: NOT_PROVEN",
    "coherency-mechanism-implementation: NOT_PUBLICLY_PROVEN",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "mmio-initialization-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed or conditional_failed:
    emit(
        lines + [
            "classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_BLOCKED",
            "decision: the bound EL2/GIC/coherency inputs, EL3-only capture claim, base EL3 controls, applicable extension controls, cross-CPU assertions, or safety denials are incomplete or inconsistent. Do not infer Secure EL3 compliance or authorize wrapper code, DSC/FDF promotion, MMIO, or launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS",
        "decision: the self-reported EL3 handoff record satisfies the bounded non-secure AArch64 EL2, GICv3, and enumerated-extension schema. Because non-secure EL2 cannot directly establish this EL3 state and the capture route is not independently authorized, Secure EL3 compliance, unrepresented feature controls, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
    ]
)
