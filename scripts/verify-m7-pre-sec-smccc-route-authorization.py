#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

REQUIREMENTS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-standalone-sec-entry-requirements.txt")
OBSERVATION = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-qualcomm-entry-observation.txt")
RECOVERY = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m2-recovery-evidence.txt")
ROUTE = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-pre-sec-smccc-route-evidence.txt")
OUT = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-pre-sec-smccc-route-authorization.txt")

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
COMPONENTS = {
    "collector-header-sha256": LIB / "M7SmcccFeatureAvailabilityCollector.h",
    "collector-source-sha256": LIB / "M7SmcccFeatureAvailabilityCollector.c",
    "collector-transport-sha256": LIB / "M7SmcccCallAArch64.S",
    "transcript-emitter-header-sha256": LIB / "M7SmcccCaptureTranscript.h",
    "transcript-emitter-source-sha256": LIB / "M7SmcccCaptureTranscript.c",
}

SCHEMA = "IZZOS_M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
TARGET_PRODUCT = "OnePlus 10T 5G / CPH2413 / OP5552L1"
TARGET_MODEL = "CPH2413"
TARGET_VENDOR_DEVICE = "OP5552L1"
TARGET_PLATFORM = "SM8475"
ALLOWED_RECOVERY = {
    "SELF_SERVICE_HARD_RECOVERY_VERIFIED",
    "AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED",
}
PLACEHOLDER = re.compile(r"(?i)^(?:|unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)$")


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
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{64}", value))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def is_power_of_two(value):
    return value is not None and value > 0 and value & (value - 1) == 0


def exact(text, label, expected):
    return field(text, label) == expected


def non_placeholder(text, label):
    value = field(text, label)
    return bool(value and not PLACEHOLDER.fullmatch(value))


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (REQUIREMENTS, OBSERVATION, RECOVERY, ROUTE, *COMPONENTS.values()):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 pre-SEC SMCCC route input not found: {required}")

requirements = REQUIREMENTS.read_text(errors="replace")
observation = OBSERVATION.read_text(errors="replace")
recovery = RECOVERY.read_text(errors="replace")
route = ROUTE.read_text(errors="replace")

input_hashes = {
    "sec-requirements-sha256": sha256(REQUIREMENTS),
    "qualcomm-entry-observation-sha256": sha256(OBSERVATION),
    "recovery-evidence-sha256": sha256(RECOVERY),
}
component_hashes = {label: sha256(path) for label, path in COMPONENTS.items()}

route_fields = [
    "route-authorization-schema",
    *input_hashes,
    *component_hashes,
    "exact-device-build",
    "device-model",
    "vendor-device",
    "platform",
    "route-kind",
    "route-candidate",
    "route-validation-authority",
    "route-validation-result",
    "entry-observation-authentication",
    "execution-phase",
    "caller-security-state",
    "caller-exception-level",
    "capture-cpu",
    "collector-invocation-count",
    "smccc-call-limit",
    "smccc-service-owner",
    "allowed-smccc-functions",
    "output-buffer-address",
    "output-buffer-capacity",
    "output-buffer-alignment",
    "output-buffer-security-state",
    "output-buffer-reservation",
    "output-buffer-lifetime",
    "transcript-output-policy",
    "transcript-serialization-required",
    "vendor-or-sip-smc-action",
    "direct-el3-register-read-action",
    "secure-monitor-modification-action",
    "mmio-action",
    "device-writes",
    "persistent-writes",
    "slot-changes",
    "flash-erase-format-action",
    "recovery-route-requirement",
    "collector-invocation-authorization",
    "payload-launch-authorization",
]

address = hex_value(route, "output-buffer-address")
capacity = hex_value(route, "output-buffer-capacity")
alignment = hex_value(route, "output-buffer-alignment")
route_candidate = field(route, "route-candidate")
recovery_emergency = field(recovery, "Emergency recovery status")

checks = [
    ("sec-requirements-classification-passes", exact(requirements, "classification", "M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND")),
    ("sec-requirements-target-exact-build", exact(requirements, "exact-device-build", TARGET_BUILD)),
    ("sec-requirements-deny-launch", exact(requirements, "launch-authorization", "NO")),
    ("sec-requirements-forbid-persistent-writes", exact(requirements, "persistent-writes", "FORBIDDEN")),
    ("sec-requirements-forbid-slot-changes", exact(requirements, "slot-changes", "FORBIDDEN")),
    ("entry-observation-classification-passes", exact(observation, "classification", "M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS")),
    ("entry-observation-binds-requirements", equal_hash(field(observation, "requirements-sha256"), input_hashes["sec-requirements-sha256"])),
    ("entry-observation-targets-exact-build", exact(observation, "exact-device-build", TARGET_BUILD)),
    ("entry-observation-is-nonsecure-el2", exact(observation, "entry-current-el", "EL2")),
    ("entry-observation-authenticity-was-left-unattested", exact(observation, "observation-authenticity", "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED")),
    ("entry-observation-route-was-left-unproven", exact(observation, "capture-route-authorization", "NOT_PROVEN")),
    ("entry-observation-denies-launch", exact(observation, "launch-authorization", "NO")),
    ("recovery-targets-exact-device", exact(recovery, "Device model/product", TARGET_PRODUCT)),
    ("recovery-targets-exact-build", exact(recovery, "OxygenOS build", TARGET_BUILD)),
    ("recovery-has-known-slot-context", field(recovery, "Current slot") in ("a", "b") and exact(recovery, "Slot count", "2")),
    ("recovery-has-unlocked-classic-fastboot", exact(recovery, "Bootloader unlocked", "YES") and exact(recovery, "Fastboot mode", "classic bootloader fastboot")),
    ("recovery-stock-image-source-is-exact", exact(recovery, "Stock image source", "exact official full package")),
    ("recovery-has-all-stock-images-verified", all(exact(recovery, label, "YES") for label in (
        "Stock boot image verified",
        "Stock vendor_boot verified",
        "Stock dtbo verified",
        "Stock vbmeta verified",
        "Stock recovery image verified",
    ))),
    ("recovery-hard-path-is-verified", recovery_emergency in ALLOWED_RECOVERY),
    ("recovery-route-candidate-matches", bool(route_candidate) and field(recovery, "Temporary route candidate") == route_candidate),
    ("recovery-forbids-persistent-write", exact(recovery, "Persistent write required", "NO")),
    ("recovery-forbids-slot-change", exact(recovery, "Slot change required", "NO")),
    ("recovery-procedure-reference-is-exact", non_placeholder(recovery, "Recovery procedure reference")),
    ("route-fields-are-present-once", all(len(values(route, label)) == 1 for label in route_fields)),
    ("route-schema-is-exact", exact(route, "route-authorization-schema", SCHEMA)),
    ("route-binds-exact-sec-requirements", equal_hash(field(route, "sec-requirements-sha256"), input_hashes["sec-requirements-sha256"])),
    ("route-binds-exact-entry-observation", equal_hash(field(route, "qualcomm-entry-observation-sha256"), input_hashes["qualcomm-entry-observation-sha256"])),
    ("route-binds-exact-recovery-evidence", equal_hash(field(route, "recovery-evidence-sha256"), input_hashes["recovery-evidence-sha256"])),
    ("route-targets-exact-device", exact(route, "exact-device-build", TARGET_BUILD) and exact(route, "device-model", TARGET_MODEL) and exact(route, "vendor-device", TARGET_VENDOR_DEVICE) and exact(route, "platform", TARGET_PLATFORM)),
    ("route-is-temporary-nonpersistent-pre-sec", exact(route, "route-kind", "TEMPORARY_NON_PERSISTENT_PRE_SEC_INSTRUMENTED_PATH")),
    ("route-candidate-is-not-placeholder", non_placeholder(route, "route-candidate")),
    ("route-review-authority-is-explicit", exact(route, "route-validation-authority", "PROJECT_OWNER_REVIEWED_BOUND_EVIDENCE")),
    ("route-validation-result-is-exact", exact(route, "route-validation-result", "EXACT_ROUTE_VALIDATED")),
    ("entry-observation-review-is-explicit", exact(route, "entry-observation-authentication", "INDEPENDENTLY_REVIEWED_EXACT_CAPTURE")),
    ("route-executes-at-pre-sec-nonsecure-el2", exact(route, "execution-phase", "PRE_SEC") and exact(route, "caller-security-state", "NONSECURE") and exact(route, "caller-exception-level", "EL2")),
    ("route-captures-on-primary-cpu", exact(route, "capture-cpu", "PRIMARY")),
    ("collector-invocation-is-exactly-once", exact(route, "collector-invocation-count", "1") and exact(route, "collector-invocation-authorization", "EXACTLY_ONCE")),
    ("smccc-call-limit-is-five", exact(route, "smccc-call-limit", "5")),
    ("smccc-service-owner-is-arm-architecture", exact(route, "smccc-service-owner", "ARM_ARCHITECTURE_SERVICE_OEN_0")),
    ("allowed-smccc-functions-are-bounded", exact(route, "allowed-smccc-functions", "SMCCC_VERSION,SMCCC_ARCH_FEATURES,SMCCC_ARCH_FEATURE_AVAILABILITY")),
    ("output-buffer-address-is-valid", address is not None and address > 0),
    ("output-buffer-capacity-is-bounded", capacity is not None and 0x1000 <= capacity <= 0x10000),
    ("output-buffer-alignment-is-safe", is_power_of_two(alignment) and alignment >= 0x40 and address is not None and address % alignment == 0),
    ("output-buffer-range-does-not-wrap", address is not None and capacity is not None and address + capacity <= 1 << 64),
    ("output-buffer-is-exact-nonsecure-scratch", exact(route, "output-buffer-security-state", "NONSECURE") and exact(route, "output-buffer-reservation", "EXACT_NONSECURE_SCRATCH_PROVEN") and exact(route, "output-buffer-lifetime", "PRE_SEC_CAPTURE_ONLY")),
    ("transcript-output-policy-is-exact", exact(route, "transcript-output-policy", "EMIT_V1_THEN_HOST_SERIALIZE_BOUND_CAPTURE") and exact(route, "transcript-serialization-required", "YES")),
    ("route-forbids-vendor-or-sip-smc", exact(route, "vendor-or-sip-smc-action", "NONE")),
    ("route-forbids-direct-el3-read", exact(route, "direct-el3-register-read-action", "NONE")),
    ("route-forbids-secure-monitor-modification", exact(route, "secure-monitor-modification-action", "NONE")),
    ("route-forbids-mmio", exact(route, "mmio-action", "NONE")),
    ("route-forbids-device-and-persistent-writes", exact(route, "device-writes", "NONE") and exact(route, "persistent-writes", "NONE")),
    ("route-forbids-slot-changes", exact(route, "slot-changes", "NONE")),
    ("route-forbids-flash-erase-format", exact(route, "flash-erase-format-action", "NONE")),
    ("route-requires-verified-hard-recovery", exact(route, "recovery-route-requirement", "VERIFIED_HARD_RECOVERY")),
    ("route-denies-payload-launch", exact(route, "payload-launch-authorization", "NO")),
]

for label, expected_hash in component_hashes.items():
    checks.append((f"route-{label}-matches", equal_hash(field(route, label), expected_hash)))

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 pre-SEC SMCCC collector route authorization gate",
    "Verifier mode: HOST_SIDE_FAIL_CLOSED_EVIDENCE_BINDING",
    "SMC calls executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    *[f"{label}: {value}" for label, value in input_hashes.items()],
    *[f"{label}: {value}" for label, value in component_hashes.items()],
    f"route-evidence-sha256: {sha256(ROUTE)}",
    f"exact-device-build: {TARGET_BUILD}",
    f"route-candidate: {route_candidate or 'MISSING'}",
    f"recovery-emergency-status: {recovery_emergency or 'MISSING'}",
    f"output-buffer-address: {field(route, 'output-buffer-address') or 'MISSING'}",
    f"output-buffer-capacity: {field(route, 'output-buffer-capacity') or 'MISSING'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "route-authorization-authenticity: DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "authorization-scope: BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(
        lines + [
            "collector-invocation-authorization: NO",
            "classification: M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_BLOCKED",
            "decision: the exact SEC-entry, EL2 observation, verified recovery, source identities, bounded output buffer, call policy, or no-write safety contract failed. Do not link or invoke the real SMC transport.",
        ],
        1,
    )

emit(
    lines + [
        "collector-invocation-authorization: EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY",
        "classification: M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS",
        "decision: the declared project-owner-reviewed route evidence binds one bounded collector invocation to the exact non-secure EL2 entry observation, verified recovery context, component identities and non-secure output buffer. This authorizes no payload launch, vendor/SiP call, MMIO, secure-monitor change, persistent write or slot change.",
    ]
)
