#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-aarch64-cross-core-registers.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/dtb-1.dtb" <<'PY'
import struct, sys
from pathlib import Path

def pad4(value):
    return value + b"\0" * ((-len(value)) & 3)

def u32(*values):
    return struct.pack(">" + "I" * len(values), *values)

names = ["#address-cells", "#size-cells", "compatible", "device_type", "reg", "status"]
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

cpus = []
for affinity in range(4):
    cpus.append(node(f"cpu@{affinity:x}", [
        ("device_type", b"cpu\0"),
        ("reg", affinity.to_bytes(8, "big")),
        ("status", b"okay\0"),
    ]))

structure = node("", [
    ("#address-cells", u32(2)),
    ("#size-cells", u32(2)),
    ("compatible", b"qcom,cape\0"),
], [node("cpus", [
    ("#address-cells", u32(2)),
    ("#size-cells", u32(0)),
], cpus)]) + u32(9)
reserve = b"\0" * 16
struct_off = 40 + len(reserve)
strings_off = struct_off + len(structure)
total = strings_off + len(strings)
header = struct.pack(">10I", 0xD00DFEED, total, struct_off, strings_off, 40, 17, 16, 0, len(strings), len(structure))
Path(sys.argv[1]).write_bytes(header + reserve + structure + strings)
PY

DTB_SHA="$(sha256sum "$TMP/dtb-1.dtb" | awk '{print $1}')"
cat > "$TMP/binding.txt" <<EOF
selected-dtb-sha256: $DTB_SHA
launch-authorization: NO
classification: M7_EXACT_SELECTED_DTB_BOUND
EOF

cat > "$TMP/inventory.txt" <<'EOF'
entry-current-el: EL2
mpidr-el1: 0x80000000
entry-cntfrq-el0: 0x124F800
entry-cntvoff-el2: 0x0
zcr-el2: 0xF
smcr-el2: NOT_IMPLEMENTED
feature-sve: PRESENT
feature-sme: ABSENT
cross-core-register-consistency: NOT_YET_PROVEN
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS
EOF

INVENTORY_SHA="$(sha256sum "$TMP/inventory.txt" | awk '{print $1}')"
BINDING_SHA="$(sha256sum "$TMP/binding.txt" | awk '{print $1}')"

write_raw() {
  local path="$1"
  cat > "$path" <<EOF
cross-core-register-schema: IZZOS_M7_AARCH64_CROSS_CORE_REGISTERS_V1
capture-source: SAME_PRE_SEC_CROSS_CORE_RENDEZVOUS
capture-cpu-set: ALL_ENABLED_SELECTED_DTB_CPUS
entry-current-el: EL2
extension-register-inventory-sha256: $INVENTORY_SHA
selected-dtb-binding-sha256: $BINDING_SHA
selected-dtb-sha256: $DTB_SHA
cpu-record-count: 4
cpu-registers: mpidr-el1=0x80000000 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=NOT_IMPLEMENTED
cpu-registers: mpidr-el1=0x80000001 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=NOT_IMPLEMENTED
cpu-registers: mpidr-el1=0x80000002 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=NOT_IMPLEMENTED
cpu-registers: mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=NOT_IMPLEMENTED
secondary-cpu-return-state: HELD_OR_PARKED_AFTER_READ_ONLY_CAPTURE
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF
}

run_verify() {
  local raw="$1" out="$2" inventory="${3:-$TMP/inventory.txt}" dtb="${4:-$TMP/dtb-1.dtb}"
  "$PYTHON" "$VERIFY" "$inventory" "$TMP/binding.txt" "$dtb" "$raw" "$out"
}

write_raw "$TMP/raw.txt"
run_verify "$TMP/raw.txt" "$TMP/pass.txt" >/dev/null
grep -q '^selected-dtb-cpu-topology-parses: PASS$' "$TMP/pass.txt"
grep -q '^expected-enabled-dtb-cpu-count: 4$' "$TMP/pass.txt"
grep -q '^mpidr-affinity-set-matches-enabled-dtb-cpus: PASS$' "$TMP/pass.txt"
grep -q '^cntfrq-matches-primary-on-all-cpus: PASS$' "$TMP/pass.txt"
grep -q '^cntvoff-matches-primary-on-all-cpus: PASS$' "$TMP/pass.txt"
grep -q '^zcr-state-matches-primary-on-all-cpus: PASS$' "$TMP/pass.txt"
grep -q '^smcr-state-matches-primary-on-all-cpus: PASS$' "$TMP/pass.txt"
grep -q '^coherency-domain-consistency: NOT_PROVEN$' "$TMP/pass.txt"
grep -q '^sec-wrapper-implementation-authorization: NO$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS$' "$TMP/pass.txt"

sed '/mpidr-el1=0x80000003/d; s/cpu-record-count: 4/cpu-record-count: 3/' "$TMP/raw.txt" > "$TMP/missing-core.txt"
if run_verify "$TMP/missing-core.txt" "$TMP/missing-core-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted a missing enabled DTB CPU" >&2
  exit 1
fi
grep -q '^mpidr-affinity-set-matches-enabled-dtb-cpus: FAIL$' "$TMP/missing-core-out.txt"

sed 's/mpidr-el1=0x80000003/mpidr-el1=0x80000002/' "$TMP/raw.txt" > "$TMP/duplicate-mpidr.txt"
if run_verify "$TMP/duplicate-mpidr.txt" "$TMP/duplicate-mpidr-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted a duplicate MPIDR affinity" >&2
  exit 1
fi
grep -q '^mpidr-affinities-are-unique: FAIL$' "$TMP/duplicate-mpidr-out.txt"

sed 's/mpidr-el1=0x80000003/mpidr-el1=0x10080000003/' "$TMP/raw.txt" > "$TMP/high-reserved-mpidr.txt"
if run_verify "$TMP/high-reserved-mpidr.txt" "$TMP/high-reserved-mpidr-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted high reserved MPIDR bits" >&2
  exit 1
fi
grep -q '^mpidr-values-contain-no-high-reserved-bits: FAIL$' "$TMP/high-reserved-mpidr-out.txt"

sed 's/mpidr-el1=0x80000003 cntfrq-el0=0x124F800/mpidr-el1=0x80000003 cntfrq-el0=0x124F801/' "$TMP/raw.txt" > "$TMP/wrong-cntfrq.txt"
if run_verify "$TMP/wrong-cntfrq.txt" "$TMP/wrong-cntfrq-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted inconsistent CNTFRQ" >&2
  exit 1
fi
grep -q '^cntfrq-matches-primary-on-all-cpus: FAIL$' "$TMP/wrong-cntfrq-out.txt"

sed 's/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x1/' "$TMP/raw.txt" > "$TMP/wrong-cntvoff.txt"
if run_verify "$TMP/wrong-cntvoff.txt" "$TMP/wrong-cntvoff-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted inconsistent CNTVOFF" >&2
  exit 1
fi
grep -q '^cntvoff-matches-primary-on-all-cpus: FAIL$' "$TMP/wrong-cntvoff-out.txt"

sed 's/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xE/' "$TMP/raw.txt" > "$TMP/wrong-zcr.txt"
if run_verify "$TMP/wrong-zcr.txt" "$TMP/wrong-zcr-out.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted inconsistent ZCR" >&2
  exit 1
fi
grep -q '^zcr-state-matches-primary-on-all-cpus: FAIL$' "$TMP/wrong-zcr-out.txt"

sed 's/smcr-el2: NOT_IMPLEMENTED/smcr-el2: 0x3/; s/feature-sme: ABSENT/feature-sme: PRESENT/' "$TMP/inventory.txt" > "$TMP/sme-inventory.txt"
SME_INVENTORY_SHA="$(sha256sum "$TMP/sme-inventory.txt" | awk '{print $1}')"
sed "s/$INVENTORY_SHA/$SME_INVENTORY_SHA/; s/smcr-el2=NOT_IMPLEMENTED/smcr-el2=0x3/g" "$TMP/raw.txt" > "$TMP/sme-raw.txt"
run_verify "$TMP/sme-raw.txt" "$TMP/sme-pass.txt" "$TMP/sme-inventory.txt" >/dev/null
grep -q '^smcr-state-matches-primary-on-all-cpus: PASS$' "$TMP/sme-pass.txt"

sed 's/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=0x3/mpidr-el1=0x80000003 cntfrq-el0=0x124F800 cntvoff-el2=0x0 zcr-el2=0xF smcr-el2=0x2/' "$TMP/sme-raw.txt" > "$TMP/wrong-smcr.txt"
if run_verify "$TMP/wrong-smcr.txt" "$TMP/wrong-smcr-out.txt" "$TMP/sme-inventory.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted inconsistent SMCR" >&2
  exit 1
fi
grep -q '^smcr-state-matches-primary-on-all-cpus: FAIL$' "$TMP/wrong-smcr-out.txt"

cp "$TMP/inventory.txt" "$TMP/tampered-inventory.txt"
printf X >> "$TMP/tampered-inventory.txt"
if run_verify "$TMP/raw.txt" "$TMP/tampered-inventory-out.txt" "$TMP/tampered-inventory.txt" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted a tampered primary inventory" >&2
  exit 1
fi
grep -q '^raw-binds-exact-primary-inventory: FAIL$' "$TMP/tampered-inventory-out.txt"

cp "$TMP/dtb-1.dtb" "$TMP/tampered.dtb"
printf X >> "$TMP/tampered.dtb"
if run_verify "$TMP/raw.txt" "$TMP/tampered-dtb-out.txt" "$TMP/inventory.txt" "$TMP/tampered.dtb" >/dev/null 2>&1; then
  echo "ERROR: cross-core verifier accepted tampered selected-DTB bytes" >&2
  exit 1
fi
grep -q '^selected-dtb-hash-matches-binding: FAIL$' "$TMP/tampered-dtb-out.txt"

echo "PASS: M7 AArch64 cross-core register consistency gate"
