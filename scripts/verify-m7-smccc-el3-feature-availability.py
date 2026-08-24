#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

HANDOFF = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-secure-el3-handoff-state.txt")
RAW = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-smccc-el3-feature-availability-raw.txt")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-smccc-el3-feature-availability.txt")
ROUTE_AUTHORIZATION = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-pre-sec-smccc-route-authorization.txt")

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

SCHEMA = "IZZOS_M7_SMCCC_EL3_FEATURE_AVAILABILITY_V1"
VERSION_FID = 0x80000000
DISCOVERY_FID = 0x80000001
AVAILABILITY_FID = 0xC0000003
REGISTER_OPCODES = {
    "SCR_EL3": 0x1E1100,
    "CPTR_EL3": 0x1E1140,
    "MDCR_EL3": 0x1E1320,
}
QUERY = re.compile(
    r"^smccc-feature-query:\s+register=(SCR_EL3|CPTR_EL3|MDCR_EL3)\s+"
    r"opcode=(0x[0-9A-Fa-f]+)\s+status=SUCCESS\s+availability-mask=(0x[0-9A-Fa-f]+)\s*$"
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


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def equal_hash(left, right):
    return bool(left and re.fullmatch(r"[0-9A-Fa-f]{64}", left) and left.lower() == right.lower())


def valid_nonzero_hash(value):
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{64}", value) and int(value, 16) != 0)


def bit(value, shift):
    return value is not None and ((value >> shift) & 1) == 1


def corroborate(handoff_status, mask, shift):
    if handoff_status == "NOT_REQUIRED_FEATURE_ABSENT":
        return "NOT_REQUIRED_FEATURE_ABSENT"
    if handoff_status != "PASS":
        return "BLOCKED_HANDOFF_STATUS"
    return "PASS" if bit(mask, shift) else "FAIL"


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (HANDOFF, RAW, ROUTE_AUTHORIZATION, *COMPONENTS.values()):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 SMCCC feature-availability input not found: {required}")

handoff = HANDOFF.read_text(errors="replace")
raw = RAW.read_text(errors="replace")
route_authorization = ROUTE_AUTHORIZATION.read_text(errors="replace")
handoff_hash = sha256(HANDOFF)
raw_hash = sha256(RAW)
route_authorization_hash = sha256(ROUTE_AUTHORIZATION)
component_hashes = {label: sha256(path) for label, path in COMPONENTS.items()}
support = field(raw, "feature-availability-support")
collector_outcome = field(raw, "collector-outcome")
version = hex_value(raw, "smccc-version-x0")
discovery = hex_value(raw, "feature-availability-discovery-x0")
raw_buffer_address = hex_value(raw, "authorized-output-buffer-address")
raw_buffer_capacity = hex_value(raw, "authorized-output-buffer-capacity")
raw_buffer_alignment = hex_value(raw, "authorized-output-buffer-alignment")
route_buffer_address = hex_value(route_authorization, "output-buffer-address")
route_buffer_capacity = hex_value(route_authorization, "output-buffer-capacity")
route_buffer_alignment = hex_value(route_authorization, "output-buffer-alignment")

queries = []
malformed_query_lines = []
for line_number, line in enumerate(raw.splitlines(), 1):
    if not line.startswith("smccc-feature-query:"):
        continue
    match = QUERY.fullmatch(line)
    if not match:
        malformed_query_lines.append(line_number)
        continue
    register, opcode_text, mask_text = match.groups()
    queries.append((register, int(opcode_text, 16), int(mask_text, 16)))

query_map = {register: mask for register, _, mask in queries}
declared_count_text = field(raw, "feature-query-count")
declared_count = int(declared_count_text) if declared_count_text and declared_count_text.isdigit() else None
expected_query_order = list(REGISTER_OPCODES)

common_raw_fields = {
    "smccc-feature-availability-schema": SCHEMA,
    "capture-source": "PRE_SEC_NONSECURE_EL2_SMCCC_ARCHITECTURE_SERVICE",
    "caller-security-state": "NONSECURE",
    "caller-exception-level": "EL2",
    "smccc-conduit": "SMC",
    "smccc-service-owner": "ARM_ARCHITECTURE_SERVICE_OEN_0",
    "smccc-version-fid": f"0x{VERSION_FID:X}",
    "smccc-arch-features-fid": f"0x{DISCOVERY_FID:X}",
    "feature-availability-discovery-target-fid": f"0x{AVAILABILITY_FID:X}",
    "feature-availability-fid": f"0x{AVAILABILITY_FID:X}",
    "availability-result-semantics": "SANITIZED_FEATURE_ENABLEMENT_MASK_NOT_RAW_EL3_REGISTER",
    "vendor-or-sip-smc-action": "NONE",
    "direct-el3-register-read-action": "NONE",
    "secure-monitor-modification-action": "NONE",
    "mmio-action": "NONE",
    "device-writes": "NONE",
    "persistent-writes": "NONE",
    "slot-changes": "NONE",
    "observation-authenticity": "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "capture-serialization": "DETERMINISTIC_COLLECTOR_TRANSCRIPT_V1",
    "capture-route-authorization": "BOUND_SINGLE_USE_TOKEN_TO_DECLARED_PROJECT_REVIEW",
    "launch-authorization": "NO",
}

checks = [
    ("secure-el3-handoff-schema-passed", field(handoff, "classification") == "M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS"),
    ("handoff-remains-self-reported", field(handoff, "secure-el3-observation") == "SELF_REPORTED_HANDOFF_ASSERTION_ONLY"),
    ("handoff-left-el3-compliance-unproven", field(handoff, "secure-el3-prerequisite-compliance") == "NOT_INDEPENDENTLY_PROVEN"),
    ("handoff-left-capture-route-unproven", field(handoff, "capture-route-authorization") == "NOT_PROVEN"),
    ("handoff-left-coherency-mechanism-unproven", field(handoff, "coherency-mechanism-implementation") == "NOT_PUBLICLY_PROVEN"),
    ("handoff-denies-wrapper-implementation", field(handoff, "sec-wrapper-implementation-authorization") == "NO"),
    ("handoff-denies-launch", field(handoff, "launch-authorization") == "NO"),
    ("raw-binds-exact-secure-el3-handoff", equal_hash(field(raw, "secure-el3-handoff-report-sha256"), handoff_hash)),
    ("route-authorization-classification-passed", field(route_authorization, "classification") == "M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS"),
    ("route-authorization-binding-schema-is-exact", field(route_authorization, "authorization-binding-schema") == "IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1"),
    ("route-authorization-permits-one-bound-capture", field(route_authorization, "collector-invocation-authorization") == "EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY"),
    ("route-authorization-review-scope-is-exact", field(route_authorization, "route-authorization-authenticity") == "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED" and field(route_authorization, "authorization-scope") == "BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY"),
    ("route-authorization-denies-launch-and-writes", field(route_authorization, "payload-launch-authorization") == "NO" and field(route_authorization, "persistent-writes") == "FORBIDDEN" and field(route_authorization, "slot-changes") == "FORBIDDEN"),
    ("raw-binds-exact-route-authorization-report", equal_hash(field(raw, "route-authorization-report-sha256"), route_authorization_hash)),
    ("raw-binds-exact-authorization-binding", equal_hash(field(raw, "authorization-binding-sha256"), field(route_authorization, "authorization-binding-sha256")) and valid_nonzero_hash(field(route_authorization, "authorization-binding-sha256"))),
    ("raw-buffer-matches-route-authorization", None not in (raw_buffer_address, raw_buffer_capacity, raw_buffer_alignment, route_buffer_address, route_buffer_capacity, route_buffer_alignment) and (raw_buffer_address, raw_buffer_capacity, raw_buffer_alignment) == (route_buffer_address, route_buffer_capacity, route_buffer_alignment)),
    ("raw-buffer-is-bounded-and-aligned", raw_buffer_address is not None and raw_buffer_capacity is not None and raw_buffer_alignment is not None and raw_buffer_address > 0 and 0x1000 <= raw_buffer_capacity <= 0x10000 and raw_buffer_alignment >= 0x40 and raw_buffer_alignment & (raw_buffer_alignment - 1) == 0 and raw_buffer_address % raw_buffer_alignment == 0 and raw_buffer_address + raw_buffer_capacity <= 1 << 64),
    ("collector-capture-digest-is-valid", valid_nonzero_hash(field(raw, "collector-capture-sha256"))),
]

for label, expected in component_hashes.items():
    checks.append((f"raw-{label}-matches", equal_hash(field(raw, label), expected)))
    checks.append((f"route-authorization-{label}-matches", equal_hash(field(route_authorization, label), expected)))

for label, expected in common_raw_fields.items():
    checks.append((f"raw-{label}-is-exact", field(raw, label) == expected))

checks.extend(
    [
        ("raw-common-fields-are-unambiguous", all(len(values(raw, label)) == 1 for label in [
            "secure-el3-handoff-report-sha256",
            "smccc-version-x0",
            "feature-availability-discovery-x0",
            "feature-availability-support",
            "feature-query-count",
            "smc-query-action",
            "route-authorization-report-sha256",
            "authorization-binding-sha256",
            "collector-capture-sha256",
            "collector-outcome",
            "authorized-output-buffer-address",
            "authorized-output-buffer-capacity",
            "authorized-output-buffer-alignment",
            *component_hashes,
            *common_raw_fields,
        ])),
        ("feature-availability-support-state-is-explicit", support in ("SUPPORTED", "NOT_SUPPORTED")),
        ("smccc-version-is-valid-v1-1-or-newer", version is not None and (version >> 16) == 1 and (version & 0xFFFF) >= 1),
        ("feature-query-lines-are-well-formed", not malformed_query_lines),
        ("declared-query-count-is-valid", declared_count is not None and declared_count == len(queries)),
        ("query-registers-are-unique", len(query_map) == len(queries)),
    ]
)

corroboration = {}
if support == "SUPPORTED":
    checks.extend(
        [
            ("supported-route-discovery-returned-success", discovery == 0),
            ("supported-route-uses-read-only-query-action", field(raw, "smc-query-action") == "VERSION_DISCOVERY_AND_FEATURE_AVAILABILITY_READS_ONLY"),
            ("supported-route-has-three-queries", len(queries) == len(REGISTER_OPCODES)),
            ("supported-route-query-order-is-canonical", [register for register, _, _ in queries] == expected_query_order),
            ("supported-route-opcodes-are-exact", all(REGISTER_OPCODES.get(register) == opcode for register, opcode, _ in queries)),
            ("supported-route-collector-outcome-is-complete", collector_outcome == "COMPLETE"),
        ]
    )
    scr_mask = query_map.get("SCR_EL3")
    cptr_mask = query_map.get("CPTR_EL3")
    corroboration = {
        "smccc-fp-simd-availability": corroborate(field(handoff, "el3-fp-simd-trap-disabled"), cptr_mask, 10),
        "smccc-pointer-authentication-availability": corroborate(field(handoff, "el3-pointer-authentication-access-enabled"), scr_mask, 16),
        "smccc-mte-availability": corroborate(field(handoff, "el3-mte-access-enabled"), scr_mask, 26),
        "smccc-sve-availability": corroborate(field(handoff, "el3-sve-access-enabled"), cptr_mask, 8),
        "smccc-sme-scr-availability": corroborate(field(handoff, "el3-sme-access-enabled"), scr_mask, 41),
        "smccc-sme-cptr-availability": corroborate(field(handoff, "el3-sme-access-enabled"), cptr_mask, 12),
    }
elif support == "NOT_SUPPORTED":
    checks.extend(
        [
            ("unsupported-route-discovery-returned-not-supported", discovery in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)),
            ("unsupported-route-stopped-after-discovery", field(raw, "smc-query-action") == "VERSION_AND_ARCH_FEATURE_DISCOVERY_ONLY"),
            ("unsupported-route-has-no-feature-queries", not queries),
            ("unsupported-route-collector-outcome-is-feature-unavailable", collector_outcome == "FEATURE_UNAVAILABLE"),
        ]
    )

failed = [name for name, passed in checks if not passed]
corroboration_failed = [name for name, status in corroboration.items() if status.startswith("FAIL") or status.startswith("BLOCKED")]
route_binding_checks = {
    "route-authorization-classification-passed",
    "route-authorization-binding-schema-is-exact",
    "route-authorization-permits-one-bound-capture",
    "route-authorization-review-scope-is-exact",
    "route-authorization-denies-launch-and-writes",
    "raw-binds-exact-route-authorization-report",
    "raw-binds-exact-authorization-binding",
    "raw-buffer-matches-route-authorization",
    "raw-buffer-is-bounded-and-aligned",
    *[f"raw-{label}-matches" for label in component_hashes],
    *[f"route-authorization-{label}-matches" for label in component_hashes],
}
route_binding_passed = all(passed for name, passed in checks if name in route_binding_checks)
route_review_passed = dict(checks)["route-authorization-review-scope-is-exact"]

lines = [
    "IzzOS Milestone 7 SMCCC EL3 feature-availability route gate",
    "Collector mode: HOST_SIDE_SMCCC_CAPTURE_VALIDATION",
    "SMC calls executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"secure-el3-handoff-report: {HANDOFF}",
    f"secure-el3-handoff-report-sha256: {handoff_hash}",
    f"smccc-feature-availability-capture: {RAW}",
    f"smccc-feature-availability-capture-sha256: {raw_hash}",
    f"route-authorization-report: {ROUTE_AUTHORIZATION}",
    f"route-authorization-report-sha256: {route_authorization_hash}",
    f"authorization-binding-sha256: {field(route_authorization, 'authorization-binding-sha256') or 'MISSING'}",
    f"authorized-output-buffer-address: 0x{raw_buffer_address:X}" if raw_buffer_address is not None else "authorized-output-buffer-address: UNAVAILABLE",
    f"authorized-output-buffer-capacity: 0x{raw_buffer_capacity:X}" if raw_buffer_capacity is not None else "authorized-output-buffer-capacity: UNAVAILABLE",
    f"authorized-output-buffer-alignment: 0x{raw_buffer_alignment:X}" if raw_buffer_alignment is not None else "authorized-output-buffer-alignment: UNAVAILABLE",
    "source-smccc-service-reference: https://github.com/ARM-software/arm-trusted-firmware/blob/master/services/arm_arch_svc/arm_arch_svc_setup.c",
    "source-smccc-identifiers-reference: https://github.com/ARM-software/arm-trusted-firmware/blob/master/include/services/arm_arch_svc.h",
    "",
    f"feature-availability-support: {support or 'MISSING'}",
    f"smccc-version: 0x{version:X}" if version is not None else "smccc-version: UNAVAILABLE",
    f"feature-availability-discovery-result: 0x{discovery:X}" if discovery is not None else "feature-availability-discovery-result: UNAVAILABLE",
    f"observed-feature-query-count: {len(queries)}",
    f"malformed-feature-query-lines: {','.join(str(value) for value in malformed_query_lines) if malformed_query_lines else 'NONE'}",
    *[f"normalized-smccc-feature-query: register={register} opcode=0x{opcode:X} availability-mask=0x{mask:X}" for register, opcode, mask in queries],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    *[f"{name}: {status}" for name, status in corroboration.items()],
    "",
    "smccc-route-scope: SANITIZED_EL3_EXTENSION_ENABLEMENT_ONLY",
    "scr-ns-rw-hce-fiq-corroboration: OUT_OF_SCOPE_NOT_REPORTED_BY_SERVICE",
    "gic-el3-state-corroboration: OUT_OF_SCOPE_NOT_REPORTED_BY_SERVICE",
    "coherency-mechanism-corroboration: OUT_OF_SCOPE_NOT_REPORTED_BY_SERVICE",
    "raw-el3-register-disclosure: NO",
    "capture-route-safety: ARCHITECTED_READ_ONLY_QUERY_CONTRACT",
    f"capture-route-binding: {'EXACT_SINGLE_USE_TOKEN_REPORT_MATCH' if route_binding_passed else 'INVALID_OR_MISMATCHED'}",
    f"capture-route-device-authorization: {'DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED' if route_review_passed else 'INVALID_OR_UNVERIFIED'}",
    "independent-observation-authenticity: NOT_ESTABLISHED",
    "secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "mmio-initialization-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed or corroboration_failed:
    emit(
        lines + [
            "classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_BLOCKED",
            "decision: the handoff, route authorization, source identity, authorization binding, output buffer, collector outcome, Arm Architecture Service identifiers, discovery result, normalized query set, applicable feature masks, or safety denials are invalid. Do not issue vendor/SiP calls, infer raw EL3/base/GIC/coherency state, or authorize wrapper code, MMIO, or launch.",
        ],
        1,
    )

if support == "NOT_SUPPORTED":
    emit(
        lines + [
            "classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_UNSUPPORTED",
            "decision: the standard Arm Architecture Service discovery call reports feature availability unsupported. Stop without issuing feature queries; require another independently specified read-only evidence route. Secure EL3 compliance, wrapper implementation, MMIO, and launch remain unproven and unauthorized.",
        ]
    )
    raise SystemExit(0)

emit(
    lines + [
        "classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS",
        "decision: the standard SMCCC service returned sanitized enablement masks consistent with the bounded extension claims. It does not expose raw EL3, base entry, GIC, coherency, cross-CPU state, or independent authenticity; Secure EL3 compliance, wrapper implementation, MMIO, and launch remain unproven and unauthorized.",
    ]
)
