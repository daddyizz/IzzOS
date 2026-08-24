#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

HANDOFF = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-secure-el3-handoff-state.txt")
AUTHORIZATION = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-pre-sec-smccc-route-authorization.txt")
TOKEN_HEADER = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/generated/M7SmcccRouteAuthorizationProvision.h")
TOKEN_SOURCE = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/generated/M7SmcccRouteAuthorizationProvision.c")
TOKEN_REPORT = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-smccc-route-token-generation.txt")
HEADER_OUT = Path(sys.argv[6]) if len(sys.argv) > 6 else Path("out/generated/M7SmcccCaptureProvision.h")
SOURCE_OUT = Path(sys.argv[7]) if len(sys.argv) > 7 else Path("out/generated/M7SmcccCaptureProvision.c")
REPORT = Path(sys.argv[8]) if len(sys.argv) > 8 else Path("out/m7-smccc-capture-provisioning.txt")

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
DSC = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc"
INF = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag/OvaltineDiag.inf"

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


def valid_nonzero_hash(value):
    return valid_hash(value) and int(value, 16) != 0


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


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


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


all_paths = (HANDOFF, AUTHORIZATION, TOKEN_HEADER, TOKEN_SOURCE, TOKEN_REPORT, HEADER_OUT, SOURCE_OUT, REPORT)
if len({path.resolve() for path in all_paths}) != len(all_paths):
    raise SystemExit("ERROR: capture-provision inputs and outputs must use distinct paths")
if TOKEN_HEADER.suffix.lower() != ".h" or TOKEN_SOURCE.suffix.lower() != ".c" or HEADER_OUT.suffix.lower() != ".h" or SOURCE_OUT.suffix.lower() != ".c":
    raise SystemExit("ERROR: token and capture-provision artifacts must use .h/.c suffixes")
if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", path.name) for path in (TOKEN_HEADER, TOKEN_SOURCE, HEADER_OUT, SOURCE_OUT)):
    raise SystemExit("ERROR: generated artifact basename contains unsupported characters")
if HEADER_OUT.parent.resolve() != SOURCE_OUT.parent.resolve() or HEADER_OUT.parent.resolve() != TOKEN_HEADER.parent.resolve():
    raise SystemExit("ERROR: generated token header and capture-provision outputs must share one directory")

for required in (HANDOFF, AUTHORIZATION, TOKEN_HEADER, TOKEN_SOURCE, TOKEN_REPORT, DSC, INF, *COMPONENTS.values()):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 capture-provision input not found: {required}")

handoff = HANDOFF.read_text(errors="replace")
authorization = AUTHORIZATION.read_text(errors="replace")
token_header = TOKEN_HEADER.read_text(errors="replace")
token_source = TOKEN_SOURCE.read_text(errors="replace")
token_report = TOKEN_REPORT.read_text(errors="replace")
integration = DSC.read_text(errors="replace") + "\n" + INF.read_text(errors="replace")
handoff_hash = sha256(HANDOFF)
authorization_hash = sha256(AUTHORIZATION)
token_header_hash = sha256(TOKEN_HEADER)
token_source_hash = sha256(TOKEN_SOURCE)
component_hashes = {label: sha256(path) for label, path in COMPONENTS.items()}
binding_hash = field(authorization, "authorization-binding-sha256")
address = hex_value(authorization, "output-buffer-address")
capacity = hex_value(authorization, "output-buffer-capacity")
alignment = hex_value(authorization, "output-buffer-alignment")
integration_absent = TOKEN_HEADER.name not in integration and HEADER_OUT.name not in integration and "M7RunProvisionedSmcccFeatureAvailabilityCapture" not in integration and "M7SmcccCaptureOrchestrator" not in integration

expected_token_header = ""
expected_token_source = ""
if valid_nonzero_hash(binding_hash) and address is not None and capacity is not None and alignment is not None:
    expected_token_header = f"""#ifndef IZZOS_GENERATED_M7_SMCCC_ROUTE_AUTHORIZATION_PROVISION_H
#define IZZOS_GENERATED_M7_SMCCC_ROUTE_AUTHORIZATION_PROVISION_H

#include "M7SmcccFeatureAvailabilityCollector.h"

#define IZZOS_M7_SMCCC_ROUTE_AUTHORIZATION_REPORT_SHA256 "{authorization_hash.lower()}"
#define IZZOS_M7_SMCCC_AUTHORIZATION_BINDING_SHA256 "{binding_hash.lower()}"

extern M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN gIzzOSM7SmcccRouteAuthorizationToken;
extern const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION gIzzOSM7SmcccRouteAuthorizationExpectation;

#endif
"""
    expected_token_source = f"""#include "{TOKEN_HEADER.name}"

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
{digest_initializer(authorization_hash.lower())}
  }},
  .AuthorizationBindingSha256 = {{
{digest_initializer(binding_hash.lower())}
  }},
}};

const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION gIzzOSM7SmcccRouteAuthorizationExpectation = {{
  .OutputBufferAddress = UINT64_C(0x{address:X}),
  .OutputBufferCapacity = UINT64_C(0x{capacity:X}),
  .OutputBufferAlignment = UINT64_C(0x{alignment:X}),
  .RouteAuthorizationReportSha256 = {{
{digest_initializer(authorization_hash.lower())}
  }},
  .AuthorizationBindingSha256 = {{
{digest_initializer(binding_hash.lower())}
  }},
}};
"""

authorization_fields = [
    "classification",
    "authorization-binding-schema",
    "authorization-binding-sha256",
    "exact-device-build",
    "recovery-emergency-status",
    "route-authorization-authenticity",
    "authorization-scope",
    "collector-invocation-authorization",
    "output-buffer-address",
    "output-buffer-capacity",
    "output-buffer-alignment",
    "payload-launch-authorization",
    "persistent-writes",
    "slot-changes",
    *component_hashes,
]
token_report_fields = [
    "route-authorization-report-sha256",
    "authorization-binding-sha256",
    "generated-header-sha256",
    "generated-source-sha256",
    "classification",
    "payload-launch-authorization",
    "persistent-writes",
    "slot-changes",
    *component_hashes,
]

checks = [
    ("handoff-classification-passes", field(handoff, "classification") == "M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS"),
    ("handoff-remains-self-reported", field(handoff, "secure-el3-observation") == "SELF_REPORTED_HANDOFF_ASSERTION_ONLY" and field(handoff, "secure-el3-prerequisite-compliance") == "NOT_INDEPENDENTLY_PROVEN"),
    ("handoff-denies-wrapper-and-launch", field(handoff, "sec-wrapper-implementation-authorization") == "NO" and field(handoff, "launch-authorization") == "NO"),
    ("authorization-fields-are-present-once", all(len(values(authorization, label)) == 1 for label in authorization_fields)),
    ("authorization-classification-passes", field(authorization, "classification") == "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS"),
    ("authorization-binding-is-exact", field(authorization, "authorization-binding-schema") == "IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1" and valid_nonzero_hash(binding_hash)),
    ("authorization-target-and-recovery-are-exact", field(authorization, "exact-device-build") == TARGET_BUILD and field(authorization, "recovery-emergency-status") in ALLOWED_RECOVERY),
    ("authorization-scope-is-one-reviewed-capture", field(authorization, "route-authorization-authenticity") == "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED" and field(authorization, "authorization-scope") == "BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY" and field(authorization, "collector-invocation-authorization") == "EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY"),
    ("authorization-denies-launch-and-writes", field(authorization, "payload-launch-authorization") == "NO" and field(authorization, "persistent-writes") == "FORBIDDEN" and field(authorization, "slot-changes") == "FORBIDDEN"),
    ("authorization-buffer-is-bounded-and-aligned", address is not None and capacity is not None and alignment is not None and address > 0 and 0x1000 <= capacity <= 0x10000 and is_power_of_two(alignment) and alignment >= 0x40 and address % alignment == 0 and address + capacity <= 1 << 64),
    ("token-report-fields-are-present-once", all(len(values(token_report, label)) == 1 for label in token_report_fields)),
    ("token-provisioning-classification-passes", field(token_report, "classification") == "M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS"),
    ("token-report-binds-exact-authorization", equal_hash(field(token_report, "route-authorization-report-sha256"), authorization_hash)),
    ("token-report-binds-exact-authorization-binding", equal_hash(field(token_report, "authorization-binding-sha256"), binding_hash)),
    ("token-report-binds-generated-header", equal_hash(field(token_report, "generated-header-sha256"), token_header_hash)),
    ("token-report-binds-generated-source", equal_hash(field(token_report, "generated-source-sha256"), token_source_hash)),
    ("token-report-denies-launch-and-writes", field(token_report, "payload-launch-authorization") == "NO" and field(token_report, "persistent-writes") == "FORBIDDEN" and field(token_report, "slot-changes") == "FORBIDDEN"),
    ("token-header-is-exact-deterministic-provision", bool(expected_token_header) and token_header == expected_token_header),
    ("token-source-is-exact-deterministic-provision", bool(expected_token_source) and token_source == expected_token_source),
    ("capture-provision-is-not-integrated-into-current-diagnostic", integration_absent),
]
for label, expected in component_hashes.items():
    checks.append((f"authorization-{label}-matches", equal_hash(field(authorization, label), expected)))
    checks.append((f"token-report-{label}-matches", equal_hash(field(token_report, label), expected)))

failed = [name for name, passed in checks if not passed]
report_lines = [
    "IzzOS Milestone 7 deterministic bound SMCCC capture provisioning",
    "Generator mode: HOST_SIDE_HANDOFF_ROUTE_TOKEN_TO_ORCHESTRATOR_PROVISION",
    "SMC calls executed by generator: NONE",
    "Device commands executed by generator: NONE",
    "Device writes executed by generator: NONE",
    "Launch commands executed by generator: NONE",
    "",
    f"secure-el3-handoff-report-sha256: {handoff_hash}",
    f"route-authorization-report-sha256: {authorization_hash}",
    f"route-token-header-sha256: {token_header_hash}",
    f"route-token-source-sha256: {token_source_hash}",
    f"authorization-binding-sha256: {binding_hash or 'MISSING'}",
    *[f"{label}: {value}" for label, value in component_hashes.items()],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"current-dsc-inf-integration: {'FORBIDDEN_AND_ABSENT' if integration_absent else 'PRESENT_OR_UNVERIFIED'}",
    "real-transport-selection: CALLER_SUPPLIED_NOT_GENERATED",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    for stale in (HEADER_OUT, SOURCE_OUT):
        stale.unlink(missing_ok=True)
    emit(
        report_lines + [
            "generated-header-write-action: NONE",
            "generated-source-write-action: NONE",
            "classification: M7_SMCCC_CAPTURE_PROVISIONING_BLOCKED",
            "decision: the handoff, route authorization, token artifacts/report, source identities, output buffer or no-launch policy failed. No orchestrator provision was retained.",
        ],
        1,
    )

header_rendered = f"""#ifndef IZZOS_GENERATED_M7_SMCCC_CAPTURE_PROVISION_H
#define IZZOS_GENERATED_M7_SMCCC_CAPTURE_PROVISION_H

#include "M7SmcccCaptureOrchestrator.h"
#include "{TOKEN_HEADER.name}"

#define IZZOS_M7_SMCCC_SECURE_EL3_HANDOFF_REPORT_SHA256 "{handoff_hash}"

extern const M7_SMCCC_TRANSCRIPT_BINDING gIzzOSM7SmcccTranscriptBinding;

M7_SMCCC_ORCHESTRATOR_STATUS
M7RunProvisionedSmcccFeatureAvailabilityCapture (
  M7_SMCCC_INVOKE Invoke,
  void *InvokeContext,
  char *OutputBuffer,
  size_t OutputBufferCapacity,
  M7_SMCCC_ORCHESTRATION_RESULT *Result
  );

#endif
"""

source_rendered = f"""#include "{HEADER_OUT.name}"

const M7_SMCCC_TRANSCRIPT_BINDING gIzzOSM7SmcccTranscriptBinding = {{
  .SecureEl3HandoffReportSha256 = IZZOS_M7_SMCCC_SECURE_EL3_HANDOFF_REPORT_SHA256,
  .CollectorHeaderSha256 = "{component_hashes['collector-header-sha256']}",
  .CollectorSourceSha256 = "{component_hashes['collector-source-sha256']}",
  .CollectorTransportSha256 = "{component_hashes['collector-transport-sha256']}",
  .TranscriptEmitterHeaderSha256 = "{component_hashes['transcript-emitter-header-sha256']}",
  .TranscriptEmitterSourceSha256 = "{component_hashes['transcript-emitter-source-sha256']}",
  .CaptureOrchestratorHeaderSha256 = "{component_hashes['capture-orchestrator-header-sha256']}",
  .CaptureOrchestratorSourceSha256 = "{component_hashes['capture-orchestrator-source-sha256']}"
}};

M7_SMCCC_ORCHESTRATOR_STATUS
M7RunProvisionedSmcccFeatureAvailabilityCapture (
  M7_SMCCC_INVOKE Invoke,
  void *InvokeContext,
  char *OutputBuffer,
  size_t OutputBufferCapacity,
  M7_SMCCC_ORCHESTRATION_RESULT *Result
  )
{{
  return M7RunBoundSmcccFeatureAvailabilityCapture (
           &gIzzOSM7SmcccTranscriptBinding,
           &gIzzOSM7SmcccRouteAuthorizationToken,
           &gIzzOSM7SmcccRouteAuthorizationExpectation,
           Invoke,
           InvokeContext,
           OutputBuffer,
           OutputBufferCapacity,
           Result
           );
}}
"""

HEADER_OUT.parent.mkdir(parents=True, exist_ok=True)
SOURCE_OUT.parent.mkdir(parents=True, exist_ok=True)
HEADER_OUT.write_text(header_rendered, newline="\n")
SOURCE_OUT.write_text(source_rendered, newline="\n")
generated_header_hash = hashlib.sha256(header_rendered.encode()).hexdigest()
generated_source_hash = hashlib.sha256(source_rendered.encode()).hexdigest()

emit(
    report_lines + [
        "generated-header-write-action: WRITTEN",
        "generated-source-write-action: WRITTEN",
        f"generated-header-sha256: {generated_header_hash}",
        f"generated-source-sha256: {generated_source_hash}",
        "classification: M7_SMCCC_CAPTURE_PROVISIONING_PASS",
        "decision: the exact self-reported handoff, reviewed route authorization, generated single-use token and all runtime component identities were deterministically bound to one non-integrated orchestrator wrapper. No real transport, device command, write or payload launch was executed.",
    ]
)
