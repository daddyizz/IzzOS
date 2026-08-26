#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

REQUIREMENTS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-standalone-sec-entry-requirements.txt")
OBSERVATION = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-qualcomm-entry-observation-raw.txt")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-qualcomm-entry-observation.txt")

SCHEMA = "IZZOS_M7_QUALCOMM_ENTRY_V1"
CAPTURE_SOURCE = "PRE_SEC_INSTRUMENTED_SNAPSHOT"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
DAIF_MASK_BITS = 0x3C0


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


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (REQUIREMENTS, OBSERVATION):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 Qualcomm-entry observation input not found: {required}")

requirements = REQUIREMENTS.read_text(errors="replace")
observation = OBSERVATION.read_text(errors="replace")
requirements_hash = sha256(REQUIREMENTS)
observation_hash = sha256(OBSERVATION)

required_build = field(requirements, "exact-device-build")
required_boot_hash = field(requirements, "boot-sha256")
required_loader_hash = field(requirements, "linuxloader-sha256")
required_dtb_hash = field(requirements, "selected-dtb-sha256")
required_dtb_address = hex_value(requirements, "stock-dtb-load-address")

current_el = field(observation, "entry-current-el")
x0 = hex_value(observation, "entry-x0")
x1 = hex_value(observation, "entry-x1")
x2 = hex_value(observation, "entry-x2")
x3 = hex_value(observation, "entry-x3")
daif = hex_value(observation, "entry-daif")
sctlr = hex_value(observation, "entry-sctlr")
cntfrq = hex_value(observation, "entry-cntfrq-el0")
cntvoff = hex_value(observation, "entry-cntvoff-el2")

checks = [
    ("sec-entry-requirements-pass", field(requirements, "classification") == "M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND"),
    ("sec-entry-requirements-deny-dsc-fdf-promotion", field(requirements, "dsc-fdf-promotion-authorization") == "NO"),
    ("sec-entry-requirements-deny-launch", field(requirements, "launch-authorization") == "NO"),
    ("requirements-target-exact-device-build", required_build == TARGET_BUILD),
    ("requirements-carry-valid-artifact-hashes", all(valid_hash(value) for value in (required_boot_hash, required_loader_hash, required_dtb_hash))),
    ("requirements-carry-stock-dtb-address", required_dtb_address is not None and required_dtb_address > 0),
    ("capture-schema-is-supported", field(observation, "capture-schema") == SCHEMA),
    ("capture-source-is-pre-sec-snapshot", field(observation, "capture-source") == CAPTURE_SOURCE),
    ("capture-route-evidence-remains-separate", field(observation, "capture-route-evidence") == "NOT_INCLUDED"),
    ("observation-binds-exact-requirements-report", equal_hash(field(observation, "requirements-sha256"), requirements_hash)),
    ("observation-targets-exact-device-build", field(observation, "exact-device-build") == required_build),
    ("observation-binds-exact-boot", equal_hash(field(observation, "boot-sha256"), required_boot_hash)),
    ("observation-binds-exact-linuxloader", equal_hash(field(observation, "linuxloader-sha256"), required_loader_hash)),
    ("observation-binds-exact-selected-dtb", equal_hash(field(observation, "selected-dtb-sha256"), required_dtb_hash)),
    ("entry-is-non-secure", field(observation, "entry-security-state") == "NON_SECURE"),
    ("capture-is-from-primary-cpu", field(observation, "capture-cpu") == "PRIMARY"),
    ("entry-currentel-is-linux-compatible", current_el in ("EL1", "EL2")),
    ("entry-sctlr-register-matches-currentel", current_el in ("EL1", "EL2") and field(observation, "entry-sctlr-register") == f"SCTLR_{current_el}"),
    ("entry-x0-matches-stock-dtb-address", required_dtb_address is not None and x0 == required_dtb_address),
    ("entry-x1-x3-are-zero", x1 == 0 and x2 == 0 and x3 == 0),
    ("entry-daif-masks-all-exceptions", daif is not None and daif & DAIF_MASK_BITS == DAIF_MASK_BITS),
    ("entry-mmu-is-off", sctlr is not None and sctlr & 1 == 0),
    ("entry-counter-frequency-is-nonzero", cntfrq is not None and cntfrq > 0),
    ("entry-virtual-counter-offset-is-zero", cntvoff == 0),
    ("loaded-image-is-clean-to-poc", field(observation, "entry-image-clean-to-poc") == "YES"),
    ("instruction-cache-has-no-stale-image-entry", field(observation, "entry-icache-stale-image-entries") == "NO"),
    ("secondary-cpus-are-not-running-the-payload", field(observation, "secondary-cpu-state") == "PARKED_OR_NOT_RELEASED"),
    ("observation-asserts-no-device-writes", field(observation, "device-writes") == "NONE"),
    ("observation-asserts-no-persistent-writes", field(observation, "persistent-writes") == "NONE"),
    ("observation-asserts-no-slot-changes", field(observation, "slot-changes") == "NONE"),
    ("observation-denies-launch-authorization", field(observation, "launch-authorization") == "NO"),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 Qualcomm entry observation schema gate",
    "Collector mode: HOST_SIDE_SCHEMA_VALIDATION",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"requirements-report: {REQUIREMENTS}",
    f"requirements-sha256: {requirements_hash}",
    f"observation-report: {OBSERVATION}",
    f"observation-sha256: {observation_hash}",
    f"exact-device-build: {required_build or 'MISSING'}",
    f"boot-sha256: {required_boot_hash or 'MISSING'}",
    f"linuxloader-sha256: {required_loader_hash or 'MISSING'}",
    f"selected-dtb-sha256: {required_dtb_hash or 'MISSING'}",
    "",
    f"entry-current-el: {current_el or 'MISSING'}",
    f"entry-sctlr-register: {field(observation, 'entry-sctlr-register') or 'MISSING'}",
    f"entry-x0: 0x{x0:X}" if x0 is not None else "entry-x0: MISSING",
    f"entry-daif: 0x{daif:X}" if daif is not None else "entry-daif: MISSING",
    f"entry-sctlr: 0x{sctlr:X}" if sctlr is not None else "entry-sctlr: MISSING",
    f"entry-sctlr-mmu-enabled: {'YES' if sctlr is not None and sctlr & 1 else 'NO' if sctlr is not None else 'UNKNOWN'}",
    f"entry-sctlr-data-cache-enabled: {'YES' if sctlr is not None and sctlr & 4 else 'NO' if sctlr is not None else 'UNKNOWN'}",
    f"entry-sctlr-instruction-cache-enabled: {'YES' if sctlr is not None and sctlr & 0x1000 else 'NO' if sctlr is not None else 'UNKNOWN'}",
    f"entry-cntfrq-el0: 0x{cntfrq:X}" if cntfrq is not None else "entry-cntfrq-el0: MISSING",
    f"entry-cntvoff-el2: 0x{cntvoff:X}" if cntvoff is not None else "entry-cntvoff-el2: MISSING",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "capture-route-authorization: NOT_PROVEN",
    "extension-specific-system-register-contract: NOT_YET_ENUMERATED",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "container-build-authorization: NO",
    "kernel-replacement-authorization: NO",
    "mmio-initialization-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_BLOCKED",
            "decision: the supplied snapshot is incomplete, internally inconsistent, or not bound to the exact M7 SEC requirements. Do not treat it as entry evidence or authorize wrapper implementation, DSC/FDF promotion, MMIO, container construction, or launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS",
        "decision: the self-reported pre-SEC snapshot is structurally consistent with the exact M7 baseline requirements and artifact hashes. This schema result does not attest snapshot authenticity, authorize its capture route, enumerate extension-specific registers, prove SEC equivalence, or authorize wrapper implementation, DSC/FDF promotion, MMIO, container construction, or launch.",
    ]
)
