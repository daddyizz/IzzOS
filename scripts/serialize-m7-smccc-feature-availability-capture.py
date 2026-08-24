#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

HANDOFF = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-secure-el3-handoff-state.txt")
CAPTURE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-smccc-collector-capture.txt")
RAW_OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-smccc-el3-feature-availability-raw.txt")
REPORT = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-smccc-capture-serialization.txt")
ROUTE_AUTHORIZATION = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-pre-sec-smccc-route-authorization.txt")

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
HEADER = LIB / "M7SmcccFeatureAvailabilityCollector.h"
SOURCE = LIB / "M7SmcccFeatureAvailabilityCollector.c"
TRANSPORT = LIB / "M7SmcccCallAArch64.S"
EMITTER_HEADER = LIB / "M7SmcccCaptureTranscript.h"
EMITTER_SOURCE = LIB / "M7SmcccCaptureTranscript.c"

CAPTURE_SCHEMA = "IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1"
RAW_SCHEMA = "IZZOS_M7_SMCCC_EL3_FEATURE_AVAILABILITY_V1"
VERSION_FID = 0x80000000
DISCOVERY_FID = 0x80000001
AVAILABILITY_FID = 0xC0000003
REGISTER_QUERIES = [
    ("SCR_EL3", 0x1E1100),
    ("CPTR_EL3", 0x1E1140),
    ("MDCR_EL3", 0x1E1320),
]
CALL = re.compile(
    r"^collector-call:\s+index=([0-9]+)\s+fid=(0x[0-9A-Fa-f]+)\s+"
    r"arg1=(0x[0-9A-Fa-f]+)\s+x0=(0x[0-9A-Fa-f]+)\s+"
    r"x1=(IGNORED|0x[0-9A-Fa-f]+)\s*$"
)
FORBIDDEN_RAW_EL3 = re.compile(
    r"(?mi)^(scr-el3|cptr-el3|mdcr-el3|icc-sre-el3|icc-ctlr-el3|zcr-el3|smcr-el3):"
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


def decimal_field(text, label):
    value = field(text, label)
    return int(value) if value and value.isdigit() else None


def hex_field(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def equal_hash(left, right):
    return bool(left and re.fullmatch(r"[0-9A-Fa-f]{64}", left) and left.lower() == right.lower())


def valid_version(value):
    return (value >> 16) == 1 and (value & 0xFFFF) >= 1


def not_supported(value):
    return value in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


def write_report(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (HANDOFF, CAPTURE, ROUTE_AUTHORIZATION, HEADER, SOURCE, TRANSPORT, EMITTER_HEADER, EMITTER_SOURCE):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 SMCCC serialization input not found: {required}")

handoff = HANDOFF.read_text(errors="replace")
capture = CAPTURE.read_text(errors="replace")
route_authorization = ROUTE_AUTHORIZATION.read_text(errors="replace")
handoff_hash = sha256(HANDOFF)
capture_hash = sha256(CAPTURE)
route_authorization_hash = sha256(ROUTE_AUTHORIZATION)
component_hashes = {
    "collector-header-sha256": sha256(HEADER),
    "collector-source-sha256": sha256(SOURCE),
    "collector-transport-sha256": sha256(TRANSPORT),
    "transcript-emitter-header-sha256": sha256(EMITTER_HEADER),
    "transcript-emitter-source-sha256": sha256(EMITTER_SOURCE),
}
outcome = field(capture, "collector-outcome")
declared_calls = decimal_field(capture, "calls-issued")
declared_queries = decimal_field(capture, "feature-queries-issued")
capture_buffer_address = hex_field(capture, "authorized-output-buffer-address")
capture_buffer_capacity = hex_field(capture, "authorized-output-buffer-capacity")
capture_buffer_alignment = hex_field(capture, "authorized-output-buffer-alignment")
route_buffer_address = hex_field(route_authorization, "output-buffer-address")
route_buffer_capacity = hex_field(route_authorization, "output-buffer-capacity")
route_buffer_alignment = hex_field(route_authorization, "output-buffer-alignment")

calls = []
malformed_calls = []
for line_number, line in enumerate(capture.splitlines(), 1):
    if not line.startswith("collector-call:"):
        continue
    match = CALL.fullmatch(line)
    if not match:
        malformed_calls.append(line_number)
        continue
    index_text, fid_text, arg1_text, x0_text, x1_text = match.groups()
    calls.append(
        {
            "index": int(index_text),
            "fid": int(fid_text, 16),
            "arg1": int(arg1_text, 16),
            "x0": int(x0_text, 16),
            "x1": None if x1_text == "IGNORED" else int(x1_text, 16),
            "x1_text": x1_text,
        }
    )

common_fields = {
    "collector-capture-schema": CAPTURE_SCHEMA,
    "capture-origin": "PRE_SEC_NONSECURE_EL2",
    "caller-security-state": "NONSECURE",
    "caller-exception-level": "EL2",
    "route-authorization-input": "BOUND_SINGLE_USE_TOKEN",
    "vendor-or-sip-smc-action": "NONE",
    "direct-el3-register-read-action": "NONE",
    "secure-monitor-modification-action": "NONE",
    "mmio-action": "NONE",
    "device-writes": "NONE",
    "persistent-writes": "NONE",
    "slot-changes": "NONE",
    "observation-authenticity": "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "launch-authorization": "NO",
}

checks = [
    ("handoff-schema-gate-passed", field(handoff, "classification") == "M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS"),
    ("capture-binds-exact-handoff", equal_hash(field(capture, "secure-el3-handoff-report-sha256"), handoff_hash)),
    ("route-authorization-classification-passed", field(route_authorization, "classification") == "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS"),
    ("route-authorization-binding-schema-is-exact", field(route_authorization, "authorization-binding-schema") == "IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1"),
    ("route-authorization-permits-one-bound-capture", field(route_authorization, "collector-invocation-authorization") == "EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY"),
    ("route-authorization-review-scope-is-exact", field(route_authorization, "route-authorization-authenticity") == "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED" and field(route_authorization, "authorization-scope") == "BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY"),
    ("route-authorization-denies-launch-and-writes", field(route_authorization, "payload-launch-authorization") == "NO" and field(route_authorization, "persistent-writes") == "FORBIDDEN" and field(route_authorization, "slot-changes") == "FORBIDDEN"),
    ("capture-binds-exact-route-authorization-report", equal_hash(field(capture, "route-authorization-report-sha256"), route_authorization_hash)),
    ("capture-binds-exact-authorization-binding", equal_hash(field(capture, "authorization-binding-sha256"), field(route_authorization, "authorization-binding-sha256"))),
    ("capture-buffer-matches-route-authorization", None not in (capture_buffer_address, capture_buffer_capacity, capture_buffer_alignment, route_buffer_address, route_buffer_capacity, route_buffer_alignment) and (capture_buffer_address, capture_buffer_capacity, capture_buffer_alignment) == (route_buffer_address, route_buffer_capacity, route_buffer_alignment)),
    ("capture-buffer-is-bounded-and-aligned", capture_buffer_address is not None and capture_buffer_capacity is not None and capture_buffer_alignment is not None and capture_buffer_address > 0 and 0x1000 <= capture_buffer_capacity <= 0x10000 and capture_buffer_alignment >= 0x40 and capture_buffer_alignment & (capture_buffer_alignment - 1) == 0 and capture_buffer_address % capture_buffer_alignment == 0 and capture_buffer_address + capture_buffer_capacity <= 1 << 64),
    ("capture-has-no-raw-el3-register-fields", FORBIDDEN_RAW_EL3.search(capture) is None),
    ("collector-outcome-is-serializable", outcome in ("COMPLETE", "FEATURE_UNAVAILABLE")),
    ("collector-call-lines-are-well-formed", not malformed_calls),
    ("collector-call-indexes-are-canonical", [call["index"] for call in calls] == list(range(len(calls)))),
    ("declared-call-count-matches", declared_calls is not None and declared_calls == len(calls)),
]

for label, expected in component_hashes.items():
    checks.append((f"capture-{label}-matches", equal_hash(field(capture, label), expected)))
    checks.append((f"route-authorization-{label}-matches", equal_hash(field(route_authorization, label), expected)))
for label, expected in common_fields.items():
    checks.append((f"capture-{label}-is-exact", field(capture, label) == expected))

checks.append(("capture-fields-are-unambiguous", all(len(values(capture, label)) == 1 for label in [
    "secure-el3-handoff-report-sha256",
    "collector-outcome",
    "calls-issued",
    "feature-queries-issued",
    "route-authorization-report-sha256",
    "authorization-binding-sha256",
    "authorized-output-buffer-address",
    "authorized-output-buffer-capacity",
    "authorized-output-buffer-alignment",
    *component_hashes,
    *common_fields,
])))

serialized_queries = []
support = None
discovery_result = None
query_action = None
if outcome == "COMPLETE":
    support = "SUPPORTED"
    query_action = "VERSION_DISCOVERY_AND_FEATURE_AVAILABILITY_READS_ONLY"
    checks.extend(
        [
            ("complete-outcome-has-five-calls", len(calls) == 5),
            ("complete-outcome-has-three-feature-queries", declared_queries == 3),
        ]
    )
    if len(calls) == 5:
        version_call, discovery_call = calls[:2]
        checks.extend(
            [
                ("version-call-is-exact", version_call["fid"] == VERSION_FID and version_call["arg1"] == 0 and version_call["x1_text"] == "IGNORED" and valid_version(version_call["x0"])),
                ("discovery-call-is-exact-success", discovery_call["fid"] == DISCOVERY_FID and discovery_call["arg1"] == AVAILABILITY_FID and discovery_call["x0"] == 0 and discovery_call["x1_text"] == "IGNORED"),
            ]
        )
        discovery_result = discovery_call["x0"]
        for call, (register, opcode) in zip(calls[2:], REGISTER_QUERIES):
            passed = call["fid"] == AVAILABILITY_FID and call["arg1"] == opcode and call["x0"] == 0 and call["x1"] is not None
            checks.append((f"{register.lower()}-availability-call-is-exact-success", passed))
            if passed:
                serialized_queries.append((register, opcode, call["x1"]))
elif outcome == "FEATURE_UNAVAILABLE":
    support = "NOT_SUPPORTED"
    query_action = "VERSION_AND_ARCH_FEATURE_DISCOVERY_ONLY"
    checks.extend(
        [
            ("unavailable-outcome-has-two-calls", len(calls) == 2),
            ("unavailable-outcome-has-no-feature-queries", declared_queries == 0),
        ]
    )
    if len(calls) == 2:
        version_call, discovery_call = calls
        checks.extend(
            [
                ("version-call-is-exact", version_call["fid"] == VERSION_FID and version_call["arg1"] == 0 and version_call["x1_text"] == "IGNORED" and valid_version(version_call["x0"])),
                ("discovery-call-is-exact-not-supported", discovery_call["fid"] == DISCOVERY_FID and discovery_call["arg1"] == AVAILABILITY_FID and not_supported(discovery_call["x0"]) and discovery_call["x1_text"] == "IGNORED"),
            ]
        )
        discovery_result = discovery_call["x0"]

failed = [name for name, passed in checks if not passed]
report_lines = [
    "IzzOS Milestone 7 deterministic SMCCC capture serialization",
    "Serializer mode: HOST_SIDE_WHITELISTED_TRANSCRIPT_TO_SANITIZED_MANIFEST",
    "SMC calls executed by serializer: NONE",
    "Device commands executed by serializer: NONE",
    "Device writes executed by serializer: NONE",
    "Launch commands executed by serializer: NONE",
    "",
    f"secure-el3-handoff-report-sha256: {handoff_hash}",
    f"route-authorization-report-sha256: {route_authorization_hash}",
    f"collector-capture-sha256: {capture_hash}",
    f"authorization-binding-sha256: {field(route_authorization, 'authorization-binding-sha256') or 'MISSING'}",
    *[f"{label}: {value}" for label, value in component_hashes.items()],
    f"collector-outcome: {outcome or 'MISSING'}",
    f"observed-call-count: {len(calls)}",
    f"malformed-call-lines: {','.join(str(value) for value in malformed_calls) if malformed_calls else 'NONE'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "raw-el3-register-disclosure: FORBIDDEN",
    "serialization-output-semantics: SANITIZED_FEATURE_ENABLEMENT_MASKS_ONLY",
    "capture-route-device-authorization: NOT_PROVEN",
    "launch-authorization: NO",
]

if failed:
    RAW_OUT.unlink(missing_ok=True)
    write_report(
        report_lines + [
            "raw-manifest-write-action: NONE",
            "classification: M7_SMCCC_CAPTURE_SERIALIZATION_BLOCKED",
            "decision: the exact handoff, route-authorization report/token digest, source identity, authorized buffer, collector outcome, call count/order, fixed FIDs/opcodes, return status, or no-raw/no-write safety policy failed. No sanitized gate manifest was retained.",
        ],
        1,
    )

version_result = calls[0]["x0"]
raw_lines = [
    f"smccc-feature-availability-schema: {RAW_SCHEMA}",
    f"secure-el3-handoff-report-sha256: {handoff_hash}",
    f"route-authorization-report-sha256: {route_authorization_hash}",
    f"authorization-binding-sha256: {field(route_authorization, 'authorization-binding-sha256')}",
    f"collector-capture-sha256: {capture_hash}",
    *[f"{label}: {value}" for label, value in component_hashes.items()],
    f"collector-outcome: {outcome}",
    "capture-serialization: DETERMINISTIC_COLLECTOR_TRANSCRIPT_V1",
    "capture-source: PRE_SEC_NONSECURE_EL2_SMCCC_ARCHITECTURE_SERVICE",
    "caller-security-state: NONSECURE",
    "caller-exception-level: EL2",
    "capture-route-authorization: BOUND_SINGLE_USE_TOKEN_TO_DECLARED_PROJECT_REVIEW",
    f"authorized-output-buffer-address: 0x{capture_buffer_address:X}",
    f"authorized-output-buffer-capacity: 0x{capture_buffer_capacity:X}",
    f"authorized-output-buffer-alignment: 0x{capture_buffer_alignment:X}",
    "smccc-conduit: SMC",
    "smccc-service-owner: ARM_ARCHITECTURE_SERVICE_OEN_0",
    f"smccc-version-fid: 0x{VERSION_FID:X}",
    f"smccc-version-x0: 0x{version_result:X}",
    f"smccc-arch-features-fid: 0x{DISCOVERY_FID:X}",
    f"feature-availability-discovery-target-fid: 0x{AVAILABILITY_FID:X}",
    f"feature-availability-discovery-x0: 0x{discovery_result:X}",
    f"feature-availability-fid: 0x{AVAILABILITY_FID:X}",
    f"feature-availability-support: {support}",
    "availability-result-semantics: SANITIZED_FEATURE_ENABLEMENT_MASK_NOT_RAW_EL3_REGISTER",
    f"feature-query-count: {len(serialized_queries)}",
    f"smc-query-action: {query_action}",
    "vendor-or-sip-smc-action: NONE",
    "direct-el3-register-read-action: NONE",
    "secure-monitor-modification-action: NONE",
    "mmio-action: NONE",
    "device-writes: NONE",
    "persistent-writes: NONE",
    "slot-changes: NONE",
    "observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "launch-authorization: NO",
    *[
        f"smccc-feature-query: register={register} opcode=0x{opcode:X} status=SUCCESS availability-mask=0x{mask:X}"
        for register, opcode, mask in serialized_queries
    ],
]
raw_rendered = "\n".join(raw_lines) + "\n"
RAW_OUT.parent.mkdir(parents=True, exist_ok=True)
RAW_OUT.write_text(raw_rendered)
raw_hash = hashlib.sha256(raw_rendered.encode()).hexdigest()

write_report(
    report_lines + [
        "raw-manifest-write-action: WRITTEN",
        f"raw-manifest-sha256: {raw_hash}",
        "classification: M7_SMCCC_CAPTURE_SERIALIZATION_PASS",
        "decision: the exact collector transcript was deterministically reduced to a sanitized feature-availability manifest. No raw EL3 register value, vendor/SiP call, write action, MMIO, or launch authorization was introduced.",
    ]
)
