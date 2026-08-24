#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

CROSS_CORE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-aarch64-cross-core-registers.txt")
RAW = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-coherency-secondary-state-raw.txt")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-coherency-secondary-state.txt")

SCHEMA = "IZZOS_M7_COHERENCY_SECONDARY_STATE_V1"
RECORD = re.compile(
    r"^cpu-coherency:\s+affinity=(0x[0-9A-Fa-f]+)\s+"
    r"role=(PRIMARY|SECONDARY)\s+domain-token=(0x[0-9A-Fa-f]+)\s+"
    r"maintenance-broadcast=(ENABLED|DISABLED|UNKNOWN)\s+"
    r"execution-state=(PRE_SEC_ENTRY|PARKED|NOT_RELEASED|RUNNING)\s+"
    r"payload-state=(PRE_SEC_ONLY|NOT_RUNNING|RUNNING)\s*$"
)


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


def affinity_list(text, label):
    value = field(text, label)
    if not value or value == "UNAVAILABLE":
        return None
    parts = value.split(",")
    if not parts or any(not re.fullmatch(r"0x[0-9A-Fa-f]+", part) for part in parts):
        return None
    return [int(part, 16) for part in parts]


def hex_field(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (CROSS_CORE, RAW):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 coherency input not found: {required}")

cross_core = CROSS_CORE.read_text(errors="replace")
raw = RAW.read_text(errors="replace")
cross_core_hash = sha256(CROSS_CORE)
raw_hash = sha256(RAW)
expected_affinities = affinity_list(cross_core, "expected-mpidr-affinities")
observed_affinities = affinity_list(cross_core, "observed-mpidr-affinities")
primary_affinity = hex_field(cross_core, "primary-mpidr-affinity")

records = []
malformed_records = []
for line_number, line in enumerate(raw.splitlines(), 1):
    if not line.startswith("cpu-coherency:"):
        continue
    match = RECORD.fullmatch(line)
    if not match:
        malformed_records.append(line_number)
        continue
    affinity, role, domain, broadcast, execution, payload = match.groups()
    records.append(
        {
            "affinity": int(affinity, 16),
            "role": role,
            "domain": int(domain, 16),
            "broadcast": broadcast,
            "execution": execution,
            "payload": payload,
        }
    )

record_count_text = field(raw, "cpu-record-count")
declared_count = int(record_count_text) if record_count_text and record_count_text.isdigit() else None
record_affinities = [record["affinity"] for record in records]
primary_records = [record for record in records if record["role"] == "PRIMARY"]
secondary_records = [record for record in records if record["role"] == "SECONDARY"]
domain_tokens = [record["domain"] for record in records]
one_domain = bool(domain_tokens) and len(set(domain_tokens)) == 1
broadcast_enabled = bool(records) and all(record["broadcast"] == "ENABLED" for record in records)
secondary_safe = bool(secondary_records) and all(
    record["execution"] in ("PARKED", "NOT_RELEASED") and record["payload"] == "NOT_RUNNING"
    for record in secondary_records
)

checks = [
    ("cross-core-register-consistency-pass", field(cross_core, "classification") == "M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS"),
    ("cross-core-report-left-coherency-unproven", field(cross_core, "coherency-domain-consistency") == "NOT_PROVEN"),
    ("cross-core-report-remains-self-reported", field(cross_core, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("cross-core-report-capture-route-remains-unproven", field(cross_core, "capture-route-authorization") == "NOT_PROVEN"),
    ("cross-core-report-denies-wrapper-implementation", field(cross_core, "sec-wrapper-implementation-authorization") == "NO"),
    ("cross-core-report-denies-launch", field(cross_core, "launch-authorization") == "NO"),
    ("cross-core-capture-source-is-supported", field(cross_core, "capture-source") == "SAME_PRE_SEC_CROSS_CORE_RENDEZVOUS"),
    ("cross-core-secondary-return-state-is-safe", field(cross_core, "secondary-cpu-return-state") == "HELD_OR_PARKED_AFTER_READ_ONLY_CAPTURE"),
    ("cross-core-affinity-lists-are-explicit", expected_affinities is not None and observed_affinities is not None),
    ("cross-core-affinity-lists-match", expected_affinities is not None and expected_affinities == observed_affinities),
    ("cross-core-primary-affinity-is-explicit", primary_affinity is not None and expected_affinities is not None and primary_affinity in expected_affinities),
    ("coherency-state-schema-is-supported", field(raw, "coherency-state-schema") == SCHEMA),
    ("raw-binds-exact-cross-core-report", equal_hash(field(raw, "cross-core-register-report-sha256"), cross_core_hash)),
    ("raw-capture-source-matches-cross-core", field(raw, "capture-source") == field(cross_core, "capture-source")),
    ("evidence-kind-is-bounded-implementation-defined-assertion", field(raw, "evidence-kind") == "IMPLEMENTATION_DEFINED_FIRMWARE_HANDOFF_ASSERTION"),
    ("domain-token-kind-is-opaque", field(raw, "domain-token-kind") == "PLATFORM_FIRMWARE_OPAQUE_ID"),
    ("cpu-record-lines-are-well-formed", not malformed_records),
    ("declared-cpu-record-count-is-valid", declared_count is not None and declared_count == len(records)),
    ("cpu-record-count-matches-cross-core-topology", expected_affinities is not None and len(records) == len(expected_affinities)),
    ("cpu-affinities-are-unique", len(record_affinities) == len(set(record_affinities))),
    ("cpu-affinities-are-canonical", record_affinities == sorted(record_affinities)),
    ("cpu-affinity-set-matches-cross-core-topology", expected_affinities is not None and set(record_affinities) == set(expected_affinities)),
    ("exactly-one-primary-role-is-declared", len(primary_records) == 1),
    ("primary-role-matches-cross-core-primary", len(primary_records) == 1 and primary_records[0]["affinity"] == primary_affinity),
    ("all-other-cpus-are-secondary", expected_affinities is not None and len(secondary_records) == len(expected_affinities) - 1),
    ("all-cpus-assert-one-opaque-domain", one_domain),
    ("maintenance-broadcast-is-asserted-enabled-on-all-cpus", broadcast_enabled),
    ("primary-is-at-pre-sec-entry-only", len(primary_records) == 1 and primary_records[0]["execution"] == "PRE_SEC_ENTRY" and primary_records[0]["payload"] == "PRE_SEC_ONLY"),
    ("secondary-cpus-are-held-and-not-running-payload", secondary_safe),
    ("raw-asserts-no-secondary-release-action", field(raw, "secondary-release-action") == "NONE"),
    ("raw-asserts-no-coherency-configuration-action", field(raw, "coherency-configuration-action") == "NONE"),
    ("raw-asserts-no-maintenance-operation-action", field(raw, "maintenance-operation-action") == "NONE"),
    ("raw-declares-self-reported-authenticity", field(raw, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("raw-keeps-capture-route-unproven", field(raw, "capture-route-authorization") == "NOT_PROVEN"),
    ("raw-asserts-no-device-writes", field(raw, "device-writes") == "NONE"),
    ("raw-asserts-no-persistent-writes", field(raw, "persistent-writes") == "NONE"),
    ("raw-asserts-no-slot-changes", field(raw, "slot-changes") == "NONE"),
    ("raw-denies-launch", field(raw, "launch-authorization") == "NO"),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 coherency-domain and secondary-CPU assertion schema gate",
    "Collector mode: HOST_SIDE_ASSERTION_SCHEMA_VALIDATION",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"cross-core-register-report: {CROSS_CORE}",
    f"cross-core-register-report-sha256: {cross_core_hash}",
    f"coherency-secondary-state-inventory: {RAW}",
    f"coherency-secondary-state-inventory-sha256: {raw_hash}",
    f"expected-cpu-affinities: {','.join(f'0x{value:X}' for value in expected_affinities) if expected_affinities else 'UNAVAILABLE'}",
    f"primary-cpu-affinity: 0x{primary_affinity:X}" if primary_affinity is not None else "primary-cpu-affinity: UNAVAILABLE",
    f"observed-cpu-record-count: {len(records)}",
    f"observed-cpu-affinities: {','.join(f'0x{value:X}' for value in record_affinities) if record_affinities else 'UNAVAILABLE'}",
    f"malformed-cpu-record-lines: {','.join(str(value) for value in malformed_records) if malformed_records else 'NONE'}",
    "",
    *[
        "normalized-cpu-coherency: "
        f"affinity=0x{record['affinity']:X} role={record['role']} domain-token=0x{record['domain']:X} "
        f"maintenance-broadcast={record['broadcast']} execution-state={record['execution']} payload-state={record['payload']}"
        for record in records
    ],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"coherency-domain-assertion: {'SELF_REPORTED_SINGLE_OPAQUE_DOMAIN' if one_domain else 'BLOCKED'}",
    f"maintenance-broadcast-assertion: {'SELF_REPORTED_ENABLED_ALL_CPUS' if broadcast_enabled else 'BLOCKED'}",
    f"secondary-cpu-state-assertion: {'SELF_REPORTED_HELD_NOT_RUNNING_PAYLOAD' if secondary_safe else 'BLOCKED'}",
    "implementation-defined-coherency-mechanism: NOT_INDEPENDENTLY_VALIDATED",
    "coherency-proof: NOT_YET_PROVEN",
    "secure-el3-state: NOT_PROVEN",
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

if failed:
    emit(
        lines + [
            "classification: M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_BLOCKED",
            "decision: the self-reported implementation-defined assertion is incomplete, topologically inconsistent, or claims an unsafe CPU/payload/action state. Do not treat it as coherency proof or authorize wrapper code, DSC/FDF promotion, MMIO, or launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS",
        "decision: the exact cross-core topology has one primary and held secondary CPUs asserting one opaque firmware coherency domain with maintenance broadcast enabled. This validates assertion structure only; the implementation-defined mechanism, authenticity, capture route, coherency proof, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
    ]
)
