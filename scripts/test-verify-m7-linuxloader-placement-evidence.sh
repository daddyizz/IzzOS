#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-linuxloader-placement-evidence.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" - "$TMP/LinuxLoader.efi" "$TMP/boot.img" "$TMP/vendor_boot.img" <<'PY'
import struct, sys
from pathlib import Path

loader = bytearray(512)
loader[:2] = b"MZ"
struct.pack_into("<I", loader, 0x3C, 0x80)
loader[0x80:0x84] = b"PE\0\0"
struct.pack_into("<H", loader, 0x84, 0xAA64)
struct.pack_into("<H", loader, 0x98, 0x20B)
Path(sys.argv[1]).write_bytes(loader)
Path(sys.argv[2]).write_bytes(b"ANDROID!" + b"B" * 4088)
Path(sys.argv[3]).write_bytes(b"VNDRBOOT" + b"V" * 4088)
PY

LOADER_SHA="$(sha256sum "$TMP/LinuxLoader.efi" | awk '{print $1}')"
BOOT_SHA="$(sha256sum "$TMP/boot.img" | awk '{print $1}')"
VENDOR_SHA="$(sha256sum "$TMP/vendor_boot.img" | awk '{print $1}')"

cat > "$TMP/inputs.txt" <<EOF
exact-device-build: CPH2413_15.0.0.1901(EX01)
boot-sha256: $BOOT_SHA
vendor-boot-sha256: $VENDOR_SHA
container-build-authorization: NO
kernel-replacement-authorization: NO
launch-authorization: NO
classification: M7_ANDROID_CONTAINER_INPUTS_BOUND
EOF

cat > "$TMP/placement.txt" <<EOF
sha256: $LOADER_SHA
tmp32 = field_0x78 + field_0x94 + field_0x98
candidate_guard = candidate - (field_0x6C + 0x200000)
classification: LINUXLOADER_DYNAMIC_PLACEMENT_FUNCTION_ISOLATED
EOF

cat > "$TMP/bootparam.txt" <<EOF
sha256: $LOADER_SHA
  +0x6C = PageSize
RamdiskLoadAddr = KernelEndAddr - rounded(total ramdisk-related bytes, PageSize)
DeviceTreeLoadAddr = RamdiskLoadAddr - (0x200000 + PageSize)
classification: LINUXLOADER_BOOTPARAM_WRITE_SITES_ENUMERATED
EOF

cat > "$TMP/provenance.txt" <<EOF
sha256: $LOADER_SHA
classification: LINUXLOADER_SIZE_TERM_PROVENANCE_WINDOWS_ENUMERATED
EOF

cat > "$TMP/v4.txt" <<EOF
boot-sha256: $BOOT_SHA
vendor-boot-sha256: $VENDOR_SHA
struct+0x6C = PageSize
struct+0x78 = RamdiskSize
struct+0x94 = VendorRamdiskSize
struct+0x98 = VendorBootConfigSize (v4-only; zero on non-v4 path)
RamdiskLoadAddr = KernelEndAddr - (ROUND_UP(RamdiskSize + VendorRamdiskSize + VendorBootConfigSize, PageSize) + PageSize)
classification: LINUXLOADER_V4_SIZE_TERM_SEMANTICS_CROSS_EVIDENCE_CONSISTENT
EOF

run_verify() {
  local out="$1" loader="${2:-$TMP/LinuxLoader.efi}" placement="${3:-$TMP/placement.txt}" inputs="${4:-$TMP/inputs.txt}" v4="${5:-$TMP/v4.txt}"
  "$PYTHON" "$VERIFY" "$inputs" "$loader" "$placement" "$TMP/bootparam.txt" "$TMP/provenance.txt" "$v4" "$TMP/boot.img" "$TMP/vendor_boot.img" "$out"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^linuxloader-is-aarch64-pe32-plus: PASS$' "$TMP/pass.txt"
grep -q '^placement-analysis-matches-exact-linuxloader: PASS$' "$TMP/pass.txt"
grep -q '^v4-size-term-formula-is-explicit: PASS$' "$TMP/pass.txt"
grep -q '^fd-kernel-substitution-equivalence: NOT_PROVEN$' "$TMP/pass.txt"
grep -q '^classification: M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND$' "$TMP/pass.txt"

cp "$TMP/LinuxLoader.efi" "$TMP/tampered-loader.efi"
printf X >> "$TMP/tampered-loader.efi"
if run_verify "$TMP/tampered-loader.txt" "$TMP/tampered-loader.efi" >/dev/null 2>&1; then
  echo "ERROR: M7 placement verifier accepted a tampered LinuxLoader" >&2
  exit 1
fi
grep -q '^placement-analysis-matches-exact-linuxloader: FAIL$' "$TMP/tampered-loader.txt"

sed 's/candidate_guard = candidate - (field_0x6C + 0x200000)/candidate_guard = UNKNOWN/' "$TMP/placement.txt" > "$TMP/wrong-formula.txt"
if run_verify "$TMP/wrong-formula-out.txt" "$TMP/LinuxLoader.efi" "$TMP/wrong-formula.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 placement verifier accepted a missing placement guard" >&2
  exit 1
fi
grep -q '^dynamic-guard-is-explicit: FAIL$' "$TMP/wrong-formula-out.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/inputs.txt" > "$TMP/authorized-inputs.txt"
if run_verify "$TMP/authorized-inputs-out.txt" "$TMP/LinuxLoader.efi" "$TMP/placement.txt" "$TMP/authorized-inputs.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 placement verifier accepted launch-authorizing inputs" >&2
  exit 1
fi
grep -q '^container-input-report-denies-launch: FAIL$' "$TMP/authorized-inputs-out.txt"

sed 's/LINUXLOADER_V4_SIZE_TERM_SEMANTICS_CROSS_EVIDENCE_CONSISTENT/LINUXLOADER_V4_SIZE_TERM_SEMANTICS_REVIEW_REQUIRED/' "$TMP/v4.txt" > "$TMP/review-v4.txt"
if run_verify "$TMP/review-v4-out.txt" "$TMP/LinuxLoader.efi" "$TMP/placement.txt" "$TMP/inputs.txt" "$TMP/review-v4.txt" >/dev/null 2>&1; then
  echo "ERROR: M7 placement verifier accepted unproven v4 semantics" >&2
  exit 1
fi
grep -q '^v4-size-semantics-classification-pass: FAIL$' "$TMP/review-v4-out.txt"
grep -q '^classification: M7_LINUXLOADER_PLACEMENT_EVIDENCE_BLOCKED$' "$TMP/review-v4-out.txt"

echo "PASS: M7 exact LinuxLoader placement evidence binding"
