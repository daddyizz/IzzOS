#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-gic-timer-dtb.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP" <<'PY'
import struct, sys
from pathlib import Path

def pad4(value):
    return value + b"\0" * ((-len(value)) & 3)

def u32(*values):
    return struct.pack(">" + "I" * len(values), *values)

def build(path, include_gic=True, timer_interrupts=None):
    timer_interrupts = timer_interrupts if timer_interrupts is not None else u32(
        1, 13, 0xF08, 1, 14, 0xF08, 1, 11, 0xF08, 1, 10, 0xF08
    )
    root = [
        ("#address-cells", u32(2)),
        ("#size-cells", u32(2)),
        ("compatible", b"qcom,cape\0"),
    ]
    gic = [
        ("compatible", b"arm,gic-v3\0"),
        ("#interrupt-cells", u32(3)),
        ("interrupt-controller", b""),
        ("reg", u32(0, 0x17A00000, 0, 0x10000, 0, 0x17A60000, 0, 0x100000)),
        ("status", b"okay\0"),
    ]
    timer = [
        ("compatible", b"arm,armv8-timer\0"),
        ("interrupts", timer_interrupts),
        ("always-on", b""),
    ]
    all_props = root + timer + (gic if include_gic else [])
    names = []
    for name, _ in all_props:
        if name not in names:
            names.append(name)
    strings = b""
    offsets = {}
    for name in names:
        offsets[name] = len(strings)
        strings += name.encode() + b"\0"

    def node(name, props, children=()):
        out = u32(1) + pad4(name.encode() + b"\0")
        for prop_name, value in props:
            out += u32(3, len(value), offsets[prop_name]) + pad4(value)
        for child in children:
            out += child
        return out + u32(2)

    children = []
    if include_gic:
        children.append(node("interrupt-controller@17a00000", gic))
    children.append(node("timer", timer))
    structure = node("", root, children) + u32(9)
    reserve = b"\0" * 16
    struct_off = 40 + len(reserve)
    strings_off = struct_off + len(structure)
    total = strings_off + len(strings)
    header = struct.pack(">10I", 0xD00DFEED, total, struct_off, strings_off, 40, 17, 16, 0, len(strings), len(structure))
    Path(path).write_bytes(header + reserve + structure + strings)

root = Path(sys.argv[1])
build(root / "good.dtb")
build(root / "no-gic.dtb", include_gic=False)
build(root / "bad-timer.dtb", timer_interrupts=u32(1, 13))
PY

make_binding() {
  local dtb="$1" out="$2" sha
  sha="$(sha256sum "$dtb" | awk '{print $1}')"
  cat > "$out" <<EOF
selected-dtb-sha256: $sha
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF
}

make_binding "$TMP/good.dtb" "$TMP/good-binding.txt"
"$PYTHON" "$VERIFY" "$TMP/good-binding.txt" "$TMP/good.dtb" "$TMP/good.txt" >/dev/null
grep -q '^selected-dtb-hash-matches-binding: PASS$' "$TMP/good.txt"
grep -q '^one-enabled-arm-gic-v3-node: PASS$' "$TMP/good.txt"
grep -q '^gic-reg-entry-count: 2$' "$TMP/good.txt"
grep -q '^timer-interrupt-specifier-count: 4$' "$TMP/good.txt"
grep -q '^classification: M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED$' "$TMP/good.txt"
grep -q '^mmio-initialization-authorization: NO$' "$TMP/good.txt"
grep -q '^launch-authorization: NO$' "$TMP/good.txt"

cat > "$TMP/wrong-binding.txt" <<'EOF'
selected-dtb-sha256: 0000000000000000000000000000000000000000000000000000000000000000
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF
if "$PYTHON" "$VERIFY" "$TMP/wrong-binding.txt" "$TMP/good.dtb" "$TMP/wrong-hash.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 GIC/timer verifier accepted a DTB hash mismatch" >&2
  exit 1
fi
grep -q '^selected-dtb-hash-matches-binding: FAIL$' "$TMP/wrong-hash.txt"

make_binding "$TMP/no-gic.dtb" "$TMP/no-gic-binding.txt"
if "$PYTHON" "$VERIFY" "$TMP/no-gic-binding.txt" "$TMP/no-gic.dtb" "$TMP/no-gic.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 GIC/timer verifier accepted a DTB without GICv3" >&2
  exit 1
fi
grep -q '^one-enabled-arm-gic-v3-node: FAIL$' "$TMP/no-gic.txt"

make_binding "$TMP/bad-timer.dtb" "$TMP/bad-timer-binding.txt"
if "$PYTHON" "$VERIFY" "$TMP/bad-timer-binding.txt" "$TMP/bad-timer.dtb" "$TMP/bad-timer.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 GIC/timer verifier accepted malformed timer interrupts" >&2
  exit 1
fi
grep -q '^timer-interrupts-have-complete-gic-specifiers: FAIL$' "$TMP/bad-timer.txt"
grep -q '^classification: M7_GIC_TIMER_DTB_EVIDENCE_BLOCKED$' "$TMP/bad-timer.txt"

echo "PASS: M7 bound-DTB GIC and timer evidence"
