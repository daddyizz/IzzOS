#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

AUTHORIZATION = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-pre-sec-smccc-route-authorization.txt")
HEADER_OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/generated/M7SmcccRouteAuthorizationProvision.h")
SOURCE_OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/generated/M7SmcccRouteAuthorizationProvision.c")
REPORT = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-smccc-route-token-generation.txt")

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
COMPONENTS = {
    "collector-header-sha256": LIB / "M7SmcccFeatureAvailabilityCollector.h",
    "collector-source-sha256": LIB / "M7SmcccFeatureAvailabilityCollector.c",
    "collector-transport-sha256": LIB / "M7SmcccCallAArch64.S",
    "transcript-emitter-header-sha256": LIB / "M7SmcccCaptureTranscript.h",
    "transcript-emitter-source-sha256": LIB / "M7SmcccCaptureTranscript.c",
    "capture-orchestrator-header-sha256": LIB / "M7SmcccCaptureOrchestrator.h",
    "capture-orchestrator-source-sha256": LIB / "M7SmcccCaptureOrchestrator.c",
}

BINDING_SCHEMA = "IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1"
PASS_CLASSIFICATION = "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS"
GENERATION_CLASSIFICATION = "M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
ALLOWED_RECOVERY = {
    "SELF_SERVICE_HARD_RECOVERY_VERIFIED",
    "AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED",
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


def valid_hash(value):
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{64}", value))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def valid_nonzero_hash(value):
    return valid_hash(value) and not re.fullmatch(r"0{64}", value or "")


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def is_power_of_two(value):
    return value is not None and value > 0 and value & (value - 1) == 0


def digest_initializer(value, indentation="    "):
    octets = bytes.fromhex(value)
    rows = []
    for offset in range(0, len(octets), 8):
        rendered = ", ".join(f"UINT8_C(0x{octet:02X})" for octet in octets[offset:offset + 8])
        rows.append(f"{indentation}{rendered},")
    return "\n".join(rows)


def write_report(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


resolved = [path.resolve() for path in (AUTHORIZATION, HEADER_OUT, SOURCE_OUT, REPORT)]
if len(set(resolved)) != len(resolved):
    raise SystemExit("ERROR: authorization, generated header, generated source and report paths must be distinct")
if HEADER_OUT.suffix.lower() != ".h" or SOURCE_OUT.suffix.lower() != ".c":
    raise SystemExit("ERROR: generated token outputs must use .h and .c suffixes")
if not re.fullmatch(r"[A-Za-z0-9_.-]+", HEADER_OUT.name):
    raise SystemExit("ERROR: generated header basename contains unsupported characters")

for required in (AUTHORIZATION, *COMPONENTS.values()):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 route-token generation input not found: {required}")

authorization = AUTHORIZATION.read_text(errors="replace")
authorization_hash = sha256(AUTHORIZATION)
binding_hash = field(authorization, "authorization-binding-sha256")
address_text = field(authorization, "output-buffer-address")
capacity_text = field(authorization, "output-buffer-capacity")
alignment_text = field(authorization, "output-buffer-alignment")
address = hex_value(authorization, "output-buffer-address")
capacity = hex_value(authorization, "output-buffer-capacity")
alignment = hex_value(authorization, "output-buffer-alignment")
component_hashes = {label: sha256(path) for label, path in COMPONENTS.items()}

required_fields = [
    "classification",
    "authorization-binding-schema",
    "authorization-binding-sha256",
    "exact-device-build",
    "route-candidate",
    "recovery-emergency-status",
    "output-buffer-address",
    "output-buffer-capacity",
    "output-buffer-alignment",
    "route-authorization-authenticity",
    "authorization-scope",
    "collector-invocation-authorization",
    "payload-launch-authorization",
    "persistent-writes",
    "slot-changes",
    "sec-requirements-sha256",
    "qualcomm-entry-observation-sha256",
    "recovery-evidence-sha256",
    "route-evidence-sha256",
    *component_hashes,
]

checks = [
    ("authorization-fields-are-present-once", all(len(values(authorization, label)) == 1 for label in required_fields)),
    ("authorization-classification-passes", field(authorization, "classification") == PASS_CLASSIFICATION),
    ("authorization-binding-schema-is-exact", field(authorization, "authorization-binding-schema") == BINDING_SCHEMA),
    ("authorization-binding-digest-is-valid", valid_nonzero_hash(binding_hash)),
    ("authorization-targets-exact-build", field(authorization, "exact-device-build") == TARGET_BUILD),
    ("authorization-route-candidate-is-exact", bool(field(authorization, "route-candidate")) and field(authorization, "route-candidate").lower() not in ("unknown", "none", "todo", "tbd", "unset", "unvalidated")),
    ("authorization-recovery-is-verified", field(authorization, "recovery-emergency-status") in ALLOWED_RECOVERY),
    ("authorization-review-scope-is-exact", field(authorization, "route-authorization-authenticity") == "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED" and field(authorization, "authorization-scope") == "BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY"),
    ("authorization-permits-one-bound-capture", field(authorization, "collector-invocation-authorization") == "EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY"),
    ("authorization-denies-payload-launch", field(authorization, "payload-launch-authorization") == "NO"),
    ("authorization-forbids-writes-and-slot-changes", field(authorization, "persistent-writes") == "FORBIDDEN" and field(authorization, "slot-changes") == "FORBIDDEN"),
    ("authorization-input-digests-are-valid", all(valid_nonzero_hash(field(authorization, label)) for label in (
        "sec-requirements-sha256",
        "qualcomm-entry-observation-sha256",
        "recovery-evidence-sha256",
        "route-evidence-sha256",
    ))),
    ("authorization-buffer-address-is-valid", address is not None and address > 0),
    ("authorization-buffer-capacity-is-bounded", capacity is not None and 0x1000 <= capacity <= 0x10000),
    ("authorization-buffer-alignment-is-safe", is_power_of_two(alignment) and alignment >= 0x40 and address is not None and address % alignment == 0),
    ("authorization-buffer-range-does-not-wrap", address is not None and capacity is not None and address + capacity <= 1 << 64),
]
for label, expected in component_hashes.items():
    checks.append((f"authorization-{label}-matches", equal_hash(field(authorization, label), expected)))

failed = [name for name, passed in checks if not passed]
report_lines = [
    "IzzOS Milestone 7 deterministic SMCCC route-token provisioning",
    "Generator mode: HOST_SIDE_PASS_REPORT_TO_C_PROVISION",
    "SMC calls executed by generator: NONE",
    "Device commands executed by generator: NONE",
    "Device writes executed by generator: NONE",
    "Launch commands executed by generator: NONE",
    "",
    f"route-authorization-report-sha256: {authorization_hash}",
    f"authorization-binding-sha256: {binding_hash or 'MISSING'}",
    f"output-buffer-address: {address_text or 'MISSING'}",
    f"output-buffer-capacity: {capacity_text or 'MISSING'}",
    f"output-buffer-alignment: {alignment_text or 'MISSING'}",
    *[f"{label}: {value}" for label, value in component_hashes.items()],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    for stale in (HEADER_OUT, SOURCE_OUT):
        stale.unlink(missing_ok=True)
    write_report(
        report_lines + [
            "generated-header-write-action: NONE",
            "generated-source-write-action: NONE",
            "classification: M7_SMCCC_ROUTE_TOKEN_PROVISIONING_BLOCKED",
            "decision: the route-authorization report, evidence/source digest, exact recovery state, buffer geometry or no-write policy failed. No C token provision was retained.",
        ],
        1,
    )

report_digest = authorization_hash.lower()
binding_digest = binding_hash.lower()
header_rendered = f"""#ifndef IZZOS_GENERATED_M7_SMCCC_ROUTE_AUTHORIZATION_PROVISION_H
#define IZZOS_GENERATED_M7_SMCCC_ROUTE_AUTHORIZATION_PROVISION_H

#include \"M7SmcccFeatureAvailabilityCollector.h\"

#define IZZOS_M7_SMCCC_ROUTE_AUTHORIZATION_REPORT_SHA256 \"{report_digest}\"
#define IZZOS_M7_SMCCC_AUTHORIZATION_BINDING_SHA256 \"{binding_digest}\"

extern M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN gIzzOSM7SmcccRouteAuthorizationToken;
extern const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION gIzzOSM7SmcccRouteAuthorizationExpectation;

#endif
"""

source_rendered = f"""#include \"{HEADER_OUT.name}\"

M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN gIzzOSM7SmcccRouteAuthorizationToken = {{
  .Magic = M7_SMCCC_ROUTE_TOKEN_MAGIC,
  .FormatVersion = M7_SMCCC_ROUTE_TOKEN_VERSION,
  .TokenSize = (uint32_t)sizeof (M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN),
  .PolicyFlags = M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS,
  .InvocationBudget = UINT32_C(1),
  .SmcccCallLimit = M7_SMCCC_MAX_CALLS,
  .Consumed = UINT32_C(0),
  .OutputBufferAddress = UINT64_C(0x{address:X}),
  .OutputBufferCapacity = UINT64_C(0x{capacity:X}),
  .OutputBufferAlignment = UINT64_C(0x{alignment:X}),
  .RouteAuthorizationReportSha256 = {{
{digest_initializer(report_digest)}
  }},
  .AuthorizationBindingSha256 = {{
{digest_initializer(binding_digest)}
  }},
}};

const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION gIzzOSM7SmcccRouteAuthorizationExpectation = {{
  .OutputBufferAddress = UINT64_C(0x{address:X}),
  .OutputBufferCapacity = UINT64_C(0x{capacity:X}),
  .OutputBufferAlignment = UINT64_C(0x{alignment:X}),
  .RouteAuthorizationReportSha256 = {{
{digest_initializer(report_digest)}
  }},
  .AuthorizationBindingSha256 = {{
{digest_initializer(binding_digest)}
  }},
}};
"""

HEADER_OUT.parent.mkdir(parents=True, exist_ok=True)
SOURCE_OUT.parent.mkdir(parents=True, exist_ok=True)
HEADER_OUT.write_text(header_rendered)
SOURCE_OUT.write_text(source_rendered)
header_hash = hashlib.sha256(header_rendered.encode()).hexdigest()
source_hash = hashlib.sha256(source_rendered.encode()).hexdigest()

write_report(
    report_lines + [
        "generated-header-write-action: WRITTEN",
        "generated-source-write-action: WRITTEN",
        f"generated-header-sha256: {header_hash}",
        f"generated-source-sha256: {source_hash}",
        f"classification: {GENERATION_CLASSIFICATION}",
        "decision: the exact passing route-authorization report was deterministically provisioned into a mutable single-use C token and an immutable matching expectation. No SMC, device command, write or payload launch was executed.",
    ]
)
