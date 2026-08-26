#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path


if len(sys.argv) != 7:
    raise SystemExit(
        "Usage: verify-m7-sec-prepi-wrapper-execution.py "
        "<sec-requirements.txt> <qualcomm-entry-observation.txt> "
        "<device-promotion-readiness.txt> <wrapper-artifact> "
        "<wrapper-execution-assertion.txt> <output.txt>"
    )

REQUIREMENTS = Path(sys.argv[1])
OBSERVATION = Path(sys.argv[2])
DEVICE_PROMOTION = Path(sys.argv[3])
WRAPPER_ARTIFACT = Path(sys.argv[4])
ASSERTION = Path(sys.argv[5])
OUT = Path(sys.argv[6])

SCHEMA = "IZZOS_M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
DAIF_MASK_BITS = 0x3C0
UINT64_LIMIT = 1 << 64


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


def range_end(base, size):
    if base is None or size is None or base < 0 or size <= 0 or base >= UINT64_LIMIT:
        return None
    end = base + size
    return end if end <= UINT64_LIMIT else None


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [REQUIREMENTS, OBSERVATION, DEVICE_PROMOTION, WRAPPER_ARTIFACT, ASSERTION]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 SEC/PrePi wrapper assertion input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an input or wrapper artifact")

requirements = REQUIREMENTS.read_text(errors="replace")
observation = OBSERVATION.read_text(errors="replace")
device_promotion = DEVICE_PROMOTION.read_text(errors="replace")
assertion = ASSERTION.read_text(errors="replace")

requirements_hash = sha256(REQUIREMENTS)
observation_hash = sha256(OBSERVATION)
device_promotion_hash = sha256(DEVICE_PROMOTION)
wrapper_artifact_hash = sha256(WRAPPER_ARTIFACT)
assertion_hash = sha256(ASSERTION)

assertion_fields = [
    "wrapper-execution-schema",
    "execution-source",
    "execution-authenticity",
    "execution-route-authorization",
    "sec-requirements-sha256",
    "qualcomm-entry-observation-sha256",
    "device-promotion-readiness-sha256",
    "wrapper-artifact-sha256",
    "wrapper-artifact-kind",
    "exact-device-build",
    "capture-cpu",
    "entry-security-state",
    "entry-current-el",
    "before-x0",
    "before-x1",
    "before-x2",
    "before-x3",
    "after-x0",
    "after-x1",
    "after-x2",
    "after-x3",
    "before-daif",
    "after-daif",
    "before-sctlr",
    "after-sctlr",
    "before-cntfrq-el0",
    "after-cntfrq-el0",
    "before-cntvoff-el2",
    "after-cntvoff-el2",
    "stack-base",
    "stack-size",
    "temporary-ram-base",
    "temporary-ram-size",
    "prepi-entry-address",
    "final-runtime-destination",
    "final-runtime-destination-validation",
    "fd-entry-form",
    "image-coherency-normalization",
    "control-transfer-count",
    "prepi-returned",
    "exception-observed",
    "mmio-action",
    "smc-action",
    "secure-monitor-modification-action",
    "device-writes",
    "persistent-writes",
    "slot-changes",
    "flash-erase-format-action",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
    "launch-authorization",
]

before_x0 = hex_value(assertion, "before-x0")
after_x0 = hex_value(assertion, "after-x0")
before_x1_x3 = [hex_value(assertion, f"before-x{index}") for index in range(1, 4)]
after_x1_x3 = [hex_value(assertion, f"after-x{index}") for index in range(1, 4)]
before_daif = hex_value(assertion, "before-daif")
after_daif = hex_value(assertion, "after-daif")
before_sctlr = hex_value(assertion, "before-sctlr")
after_sctlr = hex_value(assertion, "after-sctlr")
before_cntfrq = hex_value(assertion, "before-cntfrq-el0")
after_cntfrq = hex_value(assertion, "after-cntfrq-el0")
before_cntvoff = hex_value(assertion, "before-cntvoff-el2")
after_cntvoff = hex_value(assertion, "after-cntvoff-el2")
stack_base = hex_value(assertion, "stack-base")
stack_size = hex_value(assertion, "stack-size")
temporary_ram_base = hex_value(assertion, "temporary-ram-base")
temporary_ram_size = hex_value(assertion, "temporary-ram-size")
prepi_entry = hex_value(assertion, "prepi-entry-address")
final_destination = hex_value(assertion, "final-runtime-destination")
stack_end = range_end(stack_base, stack_size)
temporary_ram_end = range_end(temporary_ram_base, temporary_ram_size)

observation_x0 = hex_value(observation, "entry-x0")
observation_daif = hex_value(observation, "entry-daif")
observation_sctlr = hex_value(observation, "entry-sctlr")
observation_cntfrq = hex_value(observation, "entry-cntfrq-el0")
observation_cntvoff = hex_value(observation, "entry-cntvoff-el2")

checks = [
    ("requirements-classification-passes", field(requirements, "classification") == "M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND"),
    ("requirements-target-exact-build", field(requirements, "exact-device-build") == TARGET_BUILD),
    ("requirements-demand-all-wrapper-functions", all(field(requirements, label) == "YES" for label in (
        "required-wrapper-currentel-capture",
        "required-wrapper-sctlr-state-capture",
        "required-wrapper-daif-state-capture",
        "required-wrapper-timer-state-capture",
        "required-wrapper-dtb-register-preservation",
        "required-wrapper-stack-and-temporary-ram-bootstrap",
        "required-wrapper-image-coherency-normalization",
    ))),
    ("requirements-deny-promotion-and-launch", field(requirements, "dsc-fdf-promotion-authorization") == "NO" and field(requirements, "launch-authorization") == "NO"),
    ("entry-observation-classification-passes", field(observation, "classification") == "M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS"),
    ("entry-observation-binds-requirements", equal_hash(field(observation, "requirements-sha256"), requirements_hash)),
    ("entry-observation-targets-exact-build", field(observation, "exact-device-build") == TARGET_BUILD),
    ("entry-observation-remains-self-reported", field(observation, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("entry-observation-route-remains-unproven", field(observation, "capture-route-authorization") == "NOT_PROVEN"),
    ("entry-observation-denies-wrapper-and-launch", field(observation, "sec-wrapper-implementation-authorization") == "NO" and field(observation, "launch-authorization") == "NO"),
    ("device-promotion-classification-passes", field(device_promotion, "classification") == "M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED"),
    ("device-promotion-remains-unattested", field(device_promotion, "independent-observation-authenticity") == "HASH_BOUND_NOT_CRYPTOGRAPHICALLY_ATTESTED"),
    ("device-promotion-still-requires-wrapper-proof", field(device_promotion, "sec-prepi-wrapper-execution") == "NOT_PROVEN"),
    ("device-promotion-denies-promotion-container-and-launch", field(device_promotion, "dsc-fdf-promotion-authorization") == "NO" and field(device_promotion, "android-container-construction-authorization") == "NO" and field(device_promotion, "launch-authorization") == "NO"),
    ("assertion-fields-are-present-once", all(len(values(assertion, label)) == 1 for label in assertion_fields)),
    ("assertion-schema-is-exact", field(assertion, "wrapper-execution-schema") == SCHEMA),
    ("assertion-is-explicitly-self-reported", field(assertion, "execution-source") == "PRE_SEC_WRAPPER_SELF_REPORTED_ASSERTION" and field(assertion, "execution-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("assertion-route-authorization-is-not-included", field(assertion, "execution-route-authorization") == "NOT_INCLUDED"),
    ("assertion-binds-exact-requirements", equal_hash(field(assertion, "sec-requirements-sha256"), requirements_hash)),
    ("assertion-binds-exact-observation", equal_hash(field(assertion, "qualcomm-entry-observation-sha256"), observation_hash)),
    ("assertion-binds-exact-device-promotion-report", equal_hash(field(assertion, "device-promotion-readiness-sha256"), device_promotion_hash)),
    ("assertion-binds-exact-wrapper-artifact", WRAPPER_ARTIFACT.stat().st_size > 0 and equal_hash(field(assertion, "wrapper-artifact-sha256"), wrapper_artifact_hash)),
    ("wrapper-artifact-kind-is-nonintegrated", field(assertion, "wrapper-artifact-kind") == "NON_INTEGRATED_TEST_ARTIFACT"),
    ("assertion-targets-exact-build", field(assertion, "exact-device-build") == TARGET_BUILD),
    ("assertion-is-primary-nonsecure-el2", field(assertion, "capture-cpu") == "PRIMARY" and field(assertion, "entry-security-state") == "NON_SECURE" and field(assertion, "entry-current-el") == "EL2"),
    ("assertion-currentel-matches-observation", field(assertion, "entry-current-el") == field(observation, "entry-current-el")),
    ("before-state-matches-entry-observation", before_x0 == observation_x0 and before_daif == observation_daif and before_sctlr == observation_sctlr and before_cntfrq == observation_cntfrq and before_cntvoff == observation_cntvoff),
    ("dtb-register-is-preserved", before_x0 is not None and before_x0 == after_x0),
    ("linux-scratch-registers-remain-zero", before_x1_x3 == [0, 0, 0] and after_x1_x3 == [0, 0, 0]),
    ("exceptions-remain-masked", before_daif is not None and after_daif is not None and before_daif & DAIF_MASK_BITS == DAIF_MASK_BITS and after_daif & DAIF_MASK_BITS == DAIF_MASK_BITS),
    ("mmu-remains-off", before_sctlr is not None and after_sctlr is not None and before_sctlr & 1 == 0 and after_sctlr & 1 == 0),
    ("timer-state-is-preserved", before_cntfrq is not None and before_cntfrq > 0 and before_cntfrq == after_cntfrq and before_cntvoff == 0 and after_cntvoff == 0),
    ("temporary-ram-range-is-bounded", temporary_ram_end is not None and 0x10000 <= temporary_ram_size <= 0x4000000 and temporary_ram_base % 0x1000 == 0),
    ("stack-range-is-bounded-and-aligned", stack_end is not None and 0x1000 <= stack_size <= 0x100000 and stack_base % 0x10 == 0 and stack_size % 0x10 == 0),
    ("stack-is-contained-in-temporary-ram", stack_end is not None and temporary_ram_end is not None and temporary_ram_base <= stack_base and stack_end <= temporary_ram_end),
    ("prepi-entry-address-is-structurally-valid", prepi_entry is not None and prepi_entry > 0 and prepi_entry % 4 == 0),
    ("final-destination-is-structurally-valid", final_destination is not None and final_destination > 0 and final_destination % 0x1000 == 0),
    ("final-destination-ownership-remains-unproven", field(assertion, "final-runtime-destination-validation") == "STRUCTURAL_ONLY_MEMORY_MAP_OWNERSHIP_NOT_INCLUDED"),
    ("fd-entry-form-is-prepi-patched", field(assertion, "fd-entry-form") == "FV_PATCHED_TO_SEC_OR_PREPI_ENTRYPOINT"),
    ("image-coherency-is-normalized", field(assertion, "image-coherency-normalization") == "CLEAN_TO_POC_AND_NO_STALE_ICACHE_ENTRIES"),
    ("control-transfer-is-single-and-nonreturning", decimal_value(assertion, "control-transfer-count") == 1 and field(assertion, "prepi-returned") == "NO" and field(assertion, "exception-observed") == "NONE"),
    ("assertion-forbids-mmio-smc-and-monitor-changes", field(assertion, "mmio-action") == "NONE" and field(assertion, "smc-action") == "NONE" and field(assertion, "secure-monitor-modification-action") == "NONE"),
    ("assertion-forbids-device-and-persistent-writes", field(assertion, "device-writes") == "NONE" and field(assertion, "persistent-writes") == "NONE"),
    ("assertion-forbids-slot-and-flash-actions", field(assertion, "slot-changes") == "NONE" and field(assertion, "flash-erase-format-action") == "NONE"),
    ("assertion-denies-promotion-container-and-launch", field(assertion, "dsc-fdf-promotion-authorization") == "NO" and field(assertion, "container-build-authorization") == "NO" and field(assertion, "launch-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 SEC/PrePi wrapper execution assertion schema gate",
    "Verifier mode: HOST_SIDE_FAIL_CLOSED_SCHEMA_AND_BYTE_BINDING",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"sec-requirements-sha256: {requirements_hash}",
    f"qualcomm-entry-observation-sha256: {observation_hash}",
    f"device-promotion-readiness-sha256: {device_promotion_hash}",
    f"wrapper-artifact-sha256: {wrapper_artifact_hash}",
    f"wrapper-artifact-size: {WRAPPER_ARTIFACT.stat().st_size}",
    f"wrapper-execution-assertion-sha256: {assertion_hash}",
    f"exact-device-build: {TARGET_BUILD}",
    f"entry-current-el: {field(assertion, 'entry-current-el') or 'MISSING'}",
    f"preserved-dtb-address: {field(assertion, 'after-x0') or 'MISSING'}",
    f"temporary-ram-base: {field(assertion, 'temporary-ram-base') or 'MISSING'}",
    f"temporary-ram-size: {field(assertion, 'temporary-ram-size') or 'MISSING'}",
    f"stack-base: {field(assertion, 'stack-base') or 'MISSING'}",
    f"stack-size: {field(assertion, 'stack-size') or 'MISSING'}",
    f"prepi-entry-address: {field(assertion, 'prepi-entry-address') or 'MISSING'}",
    f"final-runtime-destination: {field(assertion, 'final-runtime-destination') or 'MISSING'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "execution-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "execution-route-authorization: NOT_INCLUDED",
    "wrapper-artifact-code-semantics: NOT_INSPECTED_BY_THIS_SCHEMA_GATE",
    "final-runtime-destination-ownership: NOT_INDEPENDENTLY_PROVEN",
    "sec-prepi-wrapper-execution: PROVISIONAL_SELF_REPORTED_ASSERTION_ONLY",
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
        "classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_BLOCKED",
        "decision: the supplied assertion is incomplete, contradictory, unsafe, or not byte-bound to the exact prerequisite reports and wrapper artifact. Do not infer wrapper execution, authorize a route, promote DSC/FDF files, build a container, or run a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: EXECUTION_ROUTE_AUTHORIZATION_NOT_INCLUDED",
    "remaining-blocker: EXECUTION_AUTHENTICITY_NOT_INDEPENDENTLY_ATTESTED",
    "remaining-blocker: FINAL_RUNTIME_DESTINATION_MEMORY_MAP_OWNERSHIP_NOT_PROVEN",
    "classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED",
    "decision: the self-reported assertion is structurally consistent with the exact requirements, entry observation, device/recovery readiness and wrapper artifact bytes. It is not independent execution proof and does not authorize implementation, integration, promotion, container construction, MMIO, SMC, persistent writes, slot changes or launch.",
])
