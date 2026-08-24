#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

INVENTORY = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-aarch64-extension-registers.txt")
BINDING = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-selected-dtb.txt")
DTB = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/vendor-boot-dtb-set/dtb-1.dtb")
RAW = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-aarch64-cross-core-registers-raw.txt")
OUT = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-aarch64-cross-core-registers.txt")

SCHEMA = "IZZOS_M7_AARCH64_CROSS_CORE_REGISTERS_V1"
MPIDR_AFFINITY_MASK = 0xFF00FFFFFF
MPIDR_DEFINED_BITS_MASK = 0xFFFFFFFFFF
BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
RECORD = re.compile(
    r"^cpu-registers:\s+mpidr-el1=(0x[0-9A-Fa-f]+)\s+"
    r"cntfrq-el0=(0x[0-9A-Fa-f]+)\s+cntvoff-el2=(0x[0-9A-Fa-f]+)\s+"
    r"zcr-el2=(0x[0-9A-Fa-f]+|NOT_IMPLEMENTED)\s+"
    r"smcr-el2=(0x[0-9A-Fa-f]+|NOT_IMPLEMENTED)\s*$"
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


def hex_value(text, label):
    value = field(text, label)
    return int(value, 16) if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def align4(value):
    return (value + 3) & ~3


def cstring(data, offset, limit):
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ValueError("unterminated FDT string")
    return data[offset:end].decode("utf-8", "replace"), end + 1


def string_list(value):
    return [part.decode("utf-8", "replace") for part in value.split(b"\0") if part]


def one_u32(value):
    return struct.unpack(">I", value)[0] if value is not None and len(value) == 4 else None


def parent_path(path):
    parent = path.rsplit("/", 1)[0]
    return parent or "/"


def active(props):
    status = string_list(props.get("status", b""))
    return not status or status[0].lower() in ("ok", "okay")


def parse_dtb(path):
    data = path.read_bytes()
    if len(data) < 40 or data[:4] != b"\xd0\x0d\xfe\xed":
        raise ValueError("invalid FDT magic or truncated header")
    total, struct_off, strings_off, _, version, last_compatible, _, strings_size, struct_size = struct.unpack_from(
        ">9I", data, 4
    )
    struct_end = struct_off + struct_size
    strings_end = strings_off + strings_size
    if total != len(data) or version < 17 or last_compatible > 17:
        raise ValueError("invalid FDT totalsize or version")
    if struct_off < 40 or struct_end > total or strings_off < 40 or strings_end > total:
        raise ValueError("FDT blocks escape totalsize")

    cursor = struct_off
    stack = []
    nodes = {}
    saw_end = False
    while cursor + 4 <= struct_end:
        token = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4
        if token == BEGIN_NODE:
            name, cursor = cstring(data, cursor, struct_end)
            cursor = align4(cursor)
            stack.append(name)
            node_path = "/" + "/".join(part for part in stack if part)
            nodes.setdefault(node_path, {})
        elif token == END_NODE:
            if not stack:
                raise ValueError("unbalanced FDT end-node")
            stack.pop()
        elif token == PROP:
            if not stack or cursor + 8 > struct_end:
                raise ValueError("truncated or parentless FDT property")
            length, name_offset = struct.unpack_from(">II", data, cursor)
            cursor += 8
            if cursor + length > struct_end or name_offset >= strings_size:
                raise ValueError("FDT property escapes its block")
            name, _ = cstring(data, strings_off + name_offset, strings_end)
            value = data[cursor : cursor + length]
            cursor = align4(cursor + length)
            node_path = "/" + "/".join(part for part in stack if part)
            nodes.setdefault(node_path, {})[name] = value
        elif token == NOP:
            continue
        elif token == END:
            saw_end = True
            break
        else:
            raise ValueError(f"unknown FDT token {token}")
    if not saw_end or stack:
        raise ValueError("FDT structure ended without balanced nodes and END token")
    return nodes


def dtb_cpu_affinities(nodes):
    cpus = nodes.get("/cpus", {})
    address_cells = one_u32(cpus.get("#address-cells"))
    if address_cells not in (1, 2):
        raise ValueError("/cpus has unsupported or missing #address-cells")
    affinities = []
    for path, props in nodes.items():
        if parent_path(path) != "/cpus" or string_list(props.get("device_type", b"")) != ["cpu"] or not active(props):
            continue
        reg = props.get("reg")
        if reg is None or len(reg) != address_cells * 4:
            raise ValueError(f"enabled CPU node has malformed reg: {path}")
        value = int.from_bytes(reg, "big")
        if value & ~MPIDR_AFFINITY_MASK:
            raise ValueError(f"enabled CPU reg contains non-affinity MPIDR bits: {path}")
        affinities.append(value)
    if not affinities:
        raise ValueError("selected DTB has no enabled CPU nodes")
    if len(set(affinities)) != len(affinities):
        raise ValueError("selected DTB contains duplicate enabled CPU affinities")
    return sorted(affinities)


def register_value(value):
    return int(value, 16) if value.startswith("0x") else value


def same_numeric(values, expected):
    return expected is not None and all(isinstance(value, int) and value == expected for value in values)


def same_optional(values, expected, present):
    if present:
        return isinstance(expected, int) and all(isinstance(value, int) and value == expected for value in values)
    return expected == "NOT_IMPLEMENTED" and all(value == "NOT_IMPLEMENTED" for value in values)


def format_register(value):
    return f"0x{value:X}" if isinstance(value, int) else value


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (INVENTORY, BINDING, DTB, RAW):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 cross-core input not found: {required}")

inventory = INVENTORY.read_text(errors="replace")
binding = BINDING.read_text(errors="replace")
raw = RAW.read_text(errors="replace")
inventory_hash = sha256(INVENTORY)
binding_hash = sha256(BINDING)
dtb_hash = sha256(DTB)
raw_hash = sha256(RAW)

try:
    expected_affinities = dtb_cpu_affinities(parse_dtb(DTB))
    dtb_error = None
except ValueError as error:
    expected_affinities = []
    dtb_error = str(error)

records = []
malformed_records = []
for line_number, line in enumerate(raw.splitlines(), 1):
    if not line.startswith("cpu-registers:"):
        continue
    match = RECORD.fullmatch(line)
    if not match:
        malformed_records.append(line_number)
        continue
    mpidr, cntfrq, cntvoff, zcr, smcr = match.groups()
    mpidr_value = int(mpidr, 16)
    records.append(
        {
            "mpidr": mpidr_value,
            "affinity": mpidr_value & MPIDR_AFFINITY_MASK,
            "cntfrq": int(cntfrq, 16),
            "cntvoff": int(cntvoff, 16),
            "zcr": register_value(zcr),
            "smcr": register_value(smcr),
        }
    )

record_count_text = field(raw, "cpu-record-count")
declared_count = int(record_count_text) if record_count_text and record_count_text.isdigit() else None
record_affinities = [record["affinity"] for record in records]
primary_mpidr = hex_value(inventory, "mpidr-el1")
primary_affinity = primary_mpidr & MPIDR_AFFINITY_MASK if primary_mpidr is not None else None
primary_cntfrq = hex_value(inventory, "entry-cntfrq-el0")
primary_cntvoff = hex_value(inventory, "entry-cntvoff-el2")
primary_zcr = register_value(field(inventory, "zcr-el2")) if field(inventory, "zcr-el2") else None
primary_smcr = register_value(field(inventory, "smcr-el2")) if field(inventory, "smcr-el2") else None
has_sve = field(inventory, "feature-sve") == "PRESENT"
has_sme = field(inventory, "feature-sme") == "PRESENT"

checks = [
    ("primary-register-inventory-schema-pass", field(inventory, "classification") == "M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS"),
    ("primary-inventory-cross-core-state-was-unproven", field(inventory, "cross-core-register-consistency") == "NOT_YET_PROVEN"),
    ("primary-inventory-remains-self-reported", field(inventory, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("primary-inventory-denies-wrapper-implementation", field(inventory, "sec-wrapper-implementation-authorization") == "NO"),
    ("primary-inventory-denies-launch", field(inventory, "launch-authorization") == "NO"),
    ("primary-entry-currentel-is-supported", field(inventory, "entry-current-el") in ("EL1", "EL2")),
    ("primary-sve-sme-feature-labels-are-explicit", all(field(inventory, label) in ("PRESENT", "ABSENT") for label in ("feature-sve", "feature-sme"))),
    ("selected-dtb-binding-pass", field(binding, "classification") == "M7_EXACT_SELECTED_DTB_BOUND"),
    ("selected-dtb-binding-denies-launch", field(binding, "launch-authorization") == "NO"),
    ("selected-dtb-hash-matches-binding", equal_hash(field(binding, "selected-dtb-sha256"), dtb_hash)),
    ("selected-dtb-cpu-topology-parses", dtb_error is None),
    ("cross-core-schema-is-supported", field(raw, "cross-core-register-schema") == SCHEMA),
    ("capture-source-is-bounded", field(raw, "capture-source") == "SAME_PRE_SEC_CROSS_CORE_RENDEZVOUS"),
    ("capture-cpu-set-claims-all-enabled-dtb-cpus", field(raw, "capture-cpu-set") == "ALL_ENABLED_SELECTED_DTB_CPUS"),
    ("capture-currentel-matches-primary", field(raw, "entry-current-el") == field(inventory, "entry-current-el")),
    ("raw-binds-exact-primary-inventory", equal_hash(field(raw, "extension-register-inventory-sha256"), inventory_hash)),
    ("raw-binds-exact-selected-dtb-report", equal_hash(field(raw, "selected-dtb-binding-sha256"), binding_hash)),
    ("raw-binds-exact-selected-dtb", equal_hash(field(raw, "selected-dtb-sha256"), dtb_hash)),
    ("cpu-record-lines-are-well-formed", not malformed_records),
    ("declared-cpu-record-count-is-valid", declared_count is not None and declared_count == len(records)),
    ("cpu-record-count-matches-enabled-dtb-cpus", len(records) == len(expected_affinities)),
    ("mpidr-affinities-are-unique", len(record_affinities) == len(set(record_affinities))),
    ("mpidr-values-contain-no-high-reserved-bits", all(record["mpidr"] & ~MPIDR_DEFINED_BITS_MASK == 0 for record in records)),
    ("mpidr-affinities-are-canonical", record_affinities == sorted(record_affinities)),
    ("mpidr-affinity-set-matches-enabled-dtb-cpus", set(record_affinities) == set(expected_affinities)),
    ("primary-cpu-affinity-is-in-record-set", primary_affinity is not None and primary_affinity in record_affinities),
    ("cntfrq-matches-primary-on-all-cpus", same_numeric([record["cntfrq"] for record in records], primary_cntfrq)),
    ("cntvoff-matches-primary-on-all-cpus", same_numeric([record["cntvoff"] for record in records], primary_cntvoff)),
    ("zcr-state-matches-primary-on-all-cpus", same_optional([record["zcr"] for record in records], primary_zcr, has_sve)),
    ("smcr-state-matches-primary-on-all-cpus", same_optional([record["smcr"] for record in records], primary_smcr, has_sme)),
    ("raw-asserts-secondary-cpus-returned-to-safe-state", field(raw, "secondary-cpu-return-state") == "HELD_OR_PARKED_AFTER_READ_ONLY_CAPTURE"),
    ("raw-declares-self-reported-authenticity", field(raw, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("raw-keeps-capture-route-unproven", field(raw, "capture-route-authorization") == "NOT_PROVEN"),
    ("raw-asserts-no-device-writes", field(raw, "device-writes") == "NONE"),
    ("raw-asserts-no-persistent-writes", field(raw, "persistent-writes") == "NONE"),
    ("raw-asserts-no-slot-changes", field(raw, "slot-changes") == "NONE"),
    ("raw-denies-launch", field(raw, "launch-authorization") == "NO"),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 AArch64 cross-core register consistency gate",
    "Collector mode: HOST_SIDE_SCHEMA_AND_TOPOLOGY_VALIDATION",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"extension-register-inventory-report: {INVENTORY}",
    f"extension-register-inventory-report-sha256: {inventory_hash}",
    f"selected-dtb-binding-report: {BINDING}",
    f"selected-dtb-binding-report-sha256: {binding_hash}",
    f"selected-dtb: {DTB}",
    f"selected-dtb-sha256: {dtb_hash}",
    f"cross-core-register-inventory: {RAW}",
    f"cross-core-register-inventory-sha256: {raw_hash}",
    f"selected-dtb-cpu-parse-error: {dtb_error or 'NONE'}",
    f"expected-enabled-dtb-cpu-count: {len(expected_affinities)}",
    f"expected-mpidr-affinities: {','.join(f'0x{value:X}' for value in expected_affinities) if expected_affinities else 'UNAVAILABLE'}",
    f"observed-cpu-record-count: {len(records)}",
    f"observed-mpidr-affinities: {','.join(f'0x{value:X}' for value in record_affinities) if record_affinities else 'UNAVAILABLE'}",
    f"malformed-cpu-record-lines: {','.join(str(value) for value in malformed_records) if malformed_records else 'NONE'}",
    "",
    *[
        "normalized-cpu-registers: "
        f"affinity=0x{record['affinity']:X} cntfrq-el0=0x{record['cntfrq']:X} "
        f"cntvoff-el2=0x{record['cntvoff']:X} "
        f"zcr-el2={format_register(record['zcr'])} "
        f"smcr-el2={format_register(record['smcr'])}"
        for record in records
    ],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "cross-core-register-consistency: ASSESSED_FOR_CNTFRQ_CNTVOFF_ZCR_SMCR",
    "coherency-domain-consistency: NOT_PROVEN",
    "secure-el3-register-consistency: NOT_PROVEN",
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
            "classification: M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_BLOCKED",
            "decision: the self-reported cross-core inventory is incomplete, not bound to the exact primary inventory/DTB topology, or disagrees for an assessed register. Do not infer boot readiness or authorize wrapper code, DSC/FDF promotion, MMIO, or launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS",
        "decision: every enabled CPU affinity in the exact selected DTB has one bound self-reported record, and CNTFRQ, CNTVOFF, ZCR and SMCR match the primary snapshot where applicable. Coherency, Secure EL3 state, independent authenticity, capture route, wrapper implementation, DSC/FDF promotion, MMIO, and launch remain unproven and unauthorized.",
    ]
)
