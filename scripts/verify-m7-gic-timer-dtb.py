#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
from pathlib import Path

BINDING = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-selected-dtb.txt")
DTB = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/vendor-boot-dtb-set/dtb-1.dtb")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-gic-timer-dtb.txt")

BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


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


def active(props):
    status = string_list(props.get("status", b""))
    return not status or status[0].lower() in ("ok", "okay")


def parent_path(path):
    parent = path.rsplit("/", 1)[0]
    return parent or "/"


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (BINDING, DTB):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 platform input not found: {required}")

binding = BINDING.read_text(errors="replace")
actual_hash = sha256(DTB)
bound_hash = field(binding, "selected-dtb-sha256")
try:
    nodes = parse_dtb(DTB)
    parse_error = None
except ValueError as error:
    nodes = {}
    parse_error = str(error)

root_compatibles = string_list(nodes.get("/", {}).get("compatible", b""))
gic_candidates = []
timer_candidates = []
for path, props in nodes.items():
    compatibles = string_list(props.get("compatible", b""))
    if "arm,gic-v3" in compatibles and active(props):
        gic_candidates.append((path, props, compatibles))
    if "arm,armv8-timer" in compatibles and active(props):
        timer_candidates.append((path, props, compatibles))

gic_path, gic, gic_compatibles = gic_candidates[0] if len(gic_candidates) == 1 else ("UNAVAILABLE", {}, [])
timer_path, timer, timer_compatibles = timer_candidates[0] if len(timer_candidates) == 1 else ("UNAVAILABLE", {}, [])
gic_interrupt_cells = one_u32(gic.get("#interrupt-cells"))
gic_parent = nodes.get(parent_path(gic_path), {}) if gic_path != "UNAVAILABLE" else {}
address_cells = one_u32(gic_parent.get("#address-cells")) or 2
size_cells = one_u32(gic_parent.get("#size-cells")) or 1
reg = gic.get("reg", b"")
reg_entry_bytes = 4 * (address_cells + size_cells)
reg_entries = len(reg) // reg_entry_bytes if reg_entry_bytes and len(reg) % reg_entry_bytes == 0 else 0
interrupts = timer.get("interrupts", b"")
interrupt_specifier_bytes = 4 * gic_interrupt_cells if gic_interrupt_cells else 0
timer_interrupt_entries = (
    len(interrupts) // interrupt_specifier_bytes
    if interrupt_specifier_bytes and len(interrupts) % interrupt_specifier_bytes == 0
    else 0
)

checks = [
    ("selected-dtb-binding-pass", field(binding, "classification") == "M7_EXACT_SELECTED_DTB_BOUND"),
    ("selected-dtb-hash-is-bound", bool(bound_hash and re.fullmatch(r"[0-9A-Fa-f]{64}", bound_hash))),
    ("selected-dtb-hash-matches-binding", bound_hash is not None and actual_hash == bound_hash.lower()),
    ("selected-dtb-structure-parses", parse_error is None),
    ("selected-dtb-root-is-cape", "qcom,cape" in root_compatibles),
    ("one-enabled-arm-gic-v3-node", len(gic_candidates) == 1),
    ("gic-node-declares-interrupt-controller", "interrupt-controller" in gic),
    ("gic-node-uses-supported-interrupt-cells", gic_interrupt_cells in (3, 4)),
    ("gic-reg-has-at-least-two-complete-entries", reg_entries >= 2),
    ("one-enabled-armv8-timer-node", len(timer_candidates) == 1),
    ("timer-interrupts-have-complete-gic-specifiers", timer_interrupt_entries >= 2),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 bound-DTB GIC and timer evidence",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "MMIO reads/writes executed: NO",
    "Launch commands executed: NO",
    "",
    f"binding-evidence: {BINDING}",
    f"selected-dtb: {DTB}",
    f"bound-selected-dtb-sha256: {bound_hash or 'MISSING'}",
    f"actual-selected-dtb-sha256: {actual_hash}",
    f"fdt-parse-error: {parse_error or 'NONE'}",
    f"root-compatible: {','.join(root_compatibles) if root_compatibles else 'UNAVAILABLE'}",
    "",
    f"enabled-arm-gic-v3-node-count: {len(gic_candidates)}",
    f"gic-node-path: {gic_path}",
    f"gic-compatible: {','.join(gic_compatibles) if gic_compatibles else 'UNAVAILABLE'}",
    f"gic-interrupt-cells: {gic_interrupt_cells if gic_interrupt_cells is not None else 'UNAVAILABLE'}",
    f"gic-parent-address-cells: {address_cells}",
    f"gic-parent-size-cells: {size_cells}",
    f"gic-reg-entry-count: {reg_entries}",
    f"gic-reg-raw-hex: {reg.hex() if reg else 'UNAVAILABLE'}",
    "",
    f"enabled-armv8-timer-node-count: {len(timer_candidates)}",
    f"timer-node-path: {timer_path}",
    f"timer-compatible: {','.join(timer_compatibles) if timer_compatibles else 'UNAVAILABLE'}",
    f"timer-interrupt-specifier-count: {timer_interrupt_entries}",
    f"timer-interrupts-raw-hex: {interrupts.hex() if interrupts else 'UNAVAILABLE'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "static-address-promotion-to-pcd: FORBIDDEN",
    "mmio-initialization-authorization: NO",
    "exception-level-contract: NOT_YET_PROVEN",
    "runtime-controller-ownership: NOT_YET_PROVEN",
    "gic-timer-policy: DTB_EVIDENCE_ONLY_RUNTIME_INIT_NOT_PROVEN",
    "storage-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_GIC_TIMER_DTB_EVIDENCE_BLOCKED",
            "decision: the bound DTB does not provide a complete, structurally valid GICv3 and architectural-timer evidence set. Do not infer platform initialization values or authorize launch.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED",
        "decision: the exact bound DTB contains a structurally complete GICv3 and architectural-timer description. These static properties are evidence inputs only; runtime ownership, exception level, initialization state, MMIO use, and launch remain unproven and unauthorized.",
    ]
)
