#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

EVIDENCE_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-standalone-readiness.txt")

REPORTS = [
    ("layout", "m7-layout-contract.txt", "M7_LAYOUT_REGION_CONTRACT_PASS"),
    ("fd-capacity", "m7-fd-capacity.txt", "M7_FD_CAPACITY_CONTRACT_PASS"),
    ("selected-dtb", "m7-selected-dtb.txt", "M7_EXACT_SELECTED_DTB_BOUND"),
    ("gic-timer", "m7-gic-timer-dtb.txt", "M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED"),
    ("entry", "m7-aarch64-entry-contract.txt", "M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED"),
    ("android-inputs", "m7-android-container-inputs.txt", "M7_ANDROID_CONTAINER_INPUTS_BOUND"),
    ("linuxloader", "m7-linuxloader-placement-evidence.txt", "M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND"),
    ("sec-requirements", "m7-standalone-sec-entry-requirements.txt", "M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND"),
    ("entry-observation", "m7-qualcomm-entry-observation.txt", "M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS"),
    ("extension-inventory", "m7-aarch64-extension-registers.txt", "M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS"),
    ("extension-assessment", "m7-aarch64-extension-bit-assessment.txt", "M7_AARCH64_EXTENSION_BIT_ASSESSMENT_PASS"),
    ("cross-core", "m7-aarch64-cross-core-registers.txt", "M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS"),
    ("coherency", "m7-coherency-secondary-state.txt", "M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS"),
    ("coherency-provenance", "m7-sm8475-coherency-provenance.txt", "M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS"),
    ("secure-handoff", "m7-secure-el3-handoff-state.txt", "M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS"),
    ("route-authorization", "m7-pre-sec-smccc-route-authorization.txt", "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS"),
    ("route-token", "m7-smccc-route-token-generation.txt", "M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS"),
    ("capture-provision", "m7-smccc-capture-provisioning.txt", "M7_SMCCC_CAPTURE_PROVISIONING_PASS"),
    ("capture-serialization", "m7-smccc-capture-serialization.txt", "M7_SMCCC_CAPTURE_SERIALIZATION_PASS"),
    ("smccc-gate", "m7-smccc-el3-feature-availability.txt", "M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS"),
]

HASH_EDGES = [
    ("entry-observation", "requirements-sha256", "sec-requirements"),
    ("extension-assessment", "extension-register-inventory-report-sha256", "extension-inventory"),
    ("cross-core", "extension-register-inventory-report-sha256", "extension-inventory"),
    ("cross-core", "selected-dtb-binding-report-sha256", "selected-dtb"),
    ("coherency", "cross-core-register-report-sha256", "cross-core"),
    ("coherency-provenance", "coherency-assertion-report-sha256", "coherency"),
    ("secure-handoff", "extension-register-inventory-sha256", "extension-inventory"),
    ("secure-handoff", "extension-bit-assessment-sha256", "extension-assessment"),
    ("secure-handoff", "gic-timer-report-sha256", "gic-timer"),
    ("secure-handoff", "coherency-provenance-report-sha256", "coherency-provenance"),
    ("route-authorization", "sec-requirements-sha256", "sec-requirements"),
    ("route-authorization", "qualcomm-entry-observation-sha256", "entry-observation"),
    ("route-token", "route-authorization-report-sha256", "route-authorization"),
    ("capture-provision", "secure-el3-handoff-report-sha256", "secure-handoff"),
    ("capture-provision", "route-authorization-report-sha256", "route-authorization"),
    ("capture-serialization", "secure-el3-handoff-report-sha256", "secure-handoff"),
    ("capture-serialization", "route-authorization-report-sha256", "route-authorization"),
    ("capture-serialization", "capture-provisioning-report-sha256", "capture-provision"),
    ("smccc-gate", "secure-el3-handoff-report-sha256", "secure-handoff"),
    ("smccc-gate", "route-authorization-report-sha256", "route-authorization"),
    ("smccc-gate", "capture-provisioning-report-sha256", "capture-provision"),
]

SAFE_BLOCKED_FIELDS = {
    "capture-route-device-authorization": "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "independent-observation-authenticity": "NOT_ESTABLISHED",
    "secure-el3-prerequisite-compliance": "NOT_INDEPENDENTLY_PROVEN",
    "sec-wrapper-implementation-authorization": "NO",
    "dsc-fdf-promotion-authorization": "NO",
    "fastboot-boot-authorization": "NO",
    "persistent-writes": "FORBIDDEN",
    "slot-changes": "FORBIDDEN",
    "launch-authorization": "NO",
}


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


def equal_hash(left, right):
    return bool(left and re.fullmatch(r"[0-9A-Fa-f]{64}", left) and left.lower() == right.lower())


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


paths = {key: EVIDENCE_DIR / filename for key, filename, _ in REPORTS}
if OUT.resolve() in {path.resolve() for path in paths.values()}:
    raise SystemExit("ERROR: readiness output must not overwrite a required evidence report")

texts = {}
hashes = {}
checks = []
report_status = []
for key, filename, expected_classification in REPORTS:
    path = paths[key]
    present = path.is_file()
    text = path.read_text(errors="replace") if present else ""
    digest = sha256(path) if present else None
    classification = field(text, "classification") if present else None
    texts[key] = text
    hashes[key] = digest
    checks.append((f"{key}-report-present", present))
    checks.append((f"{key}-classification-is-exact", classification == expected_classification))
    report_status.append((key, filename, digest, classification, present and classification == expected_classification))

for downstream, label, upstream in HASH_EDGES:
    checks.append((
        f"{downstream}-binds-{upstream}",
        bool(hashes.get(upstream)) and equal_hash(field(texts.get(downstream, ""), label), hashes[upstream]),
    ))

smccc = texts.get("smccc-gate", "")
for label, expected in SAFE_BLOCKED_FIELDS.items():
    checks.append((f"smccc-gate-{label}-is-safe", field(smccc, label) == expected))

checks.extend([
    ("smccc-gate-capture-route-binding-is-exact", field(smccc, "capture-route-binding") == "EXACT_SINGLE_USE_TOKEN_AND_CAPTURE_PROVISION_REPORT_MATCH"),
    ("capture-provision-remains-non-integrated", field(texts.get("capture-provision", ""), "current-dsc-inf-integration") == "FORBIDDEN_AND_ABSENT"),
    ("capture-provision-does-not-select-real-transport", field(texts.get("capture-provision", ""), "real-transport-selection") == "CALLER_SUPPLIED_NOT_GENERATED"),
    ("route-authorization-remains-one-capture-only", field(texts.get("route-authorization", ""), "collector-invocation-authorization") == "EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY"),
])

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 standalone host-readiness audit",
    "Auditor mode: HOST_SIDE_REPORT_CHAIN_ONLY",
    "Device commands executed by auditor: NONE",
    "Device writes executed by auditor: NONE",
    "Launch commands executed by auditor: NONE",
    "",
    f"evidence-directory: {EVIDENCE_DIR}",
    f"required-report-count: {len(REPORTS)}",
    "",
    "reports:",
    *[
        f"report: key={key} file={filename} sha256={digest or 'MISSING'} classification={classification or 'MISSING'} status={'PASS' if passed else 'BLOCKED'}"
        for key, filename, digest, classification, passed in report_status
    ],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "product-roadmap-milestone: M1_NON_DESTRUCTIVE_UEFI_DIAGNOSTIC_PAYLOAD",
    "internal-engineering-stage: M7_STANDALONE_LAYOUT_AND_ENTRY_EVIDENCE",
    "device-commands: NONE",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M7_HOST_READINESS_INCOMPLETE",
        "decision: one or more required reports, classifications, cross-report hashes, single-use route constraints, or safety denials are missing or inconsistent. Keep standalone DSC/FDF promotion, container construction and device launch blocked.",
    ], 1)

emit(lines + [
    "promotion-blocker: INDEPENDENT_DEVICE_OBSERVATION_AUTHENTICITY_NOT_ESTABLISHED",
    "promotion-blocker: SECURE_EL3_PREREQUISITE_COMPLIANCE_NOT_INDEPENDENTLY_PROVEN",
    "promotion-blocker: SEC_PREPI_WRAPPER_IMPLEMENTATION_NOT_AUTHORIZED_OR_EXECUTED",
    "promotion-blocker: EXACT_CLASSIC_FASTBOOT_DEVICE_EVIDENCE_NOT_BOUND",
    "classification: M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED",
    "decision: the host-side M7 report chain is complete and internally bound, but it deliberately denies DSC/FDF promotion and launch. Collect independently authenticated exact-device evidence and verify the SEC/PrePi wrapper before any next internal stage or device action.",
])
