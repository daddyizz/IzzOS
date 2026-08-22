#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MERGER="$ROOT_DIR/scripts/merge-m1-device-inspections.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_dir() {
  local dir="$1" target="$2" class="$3" build="$4" slot="$5" unlocked="$6" userspace="$7"
  mkdir -p "$dir"
  cat > "$dir/INSPECTION_SUMMARY.txt" <<EOF
IzzOS M1 exact-device inspection summary
Target: OnePlus 10T 5G / ovaltine / SM8475
Target match: $target
Classification: $class
Build ID: $build
Current slot: $slot
Bootloader unlocked: $unlocked
Userspace fastboot: $userspace
Collector mode: READ_ONLY
Device writes: NONE
Launch commands executed: NO
EOF
  printf 'Classification: %s\n' "$class" > "$dir/ovaltine-inspection-analysis.txt"
}

make_dir "$TMP_DIR/adb" yes NEED_EXACT_FASTBOOT_INSPECTION CPH2415_15.0.0.1901 _a unknown unknown
make_dir "$TMP_DIR/fastboot" yes CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED unknown a yes no

bash "$MERGER" "$TMP_DIR/adb" "$TMP_DIR/fastboot" "$TMP_DIR/out-ok" >/dev/null
grep -q '^Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT$' "$TMP_DIR/out-ok/M1_EXACT_DEVICE_EVIDENCE.txt"
grep -q '^Build ID: CPH2415_15.0.0.1901$' "$TMP_DIR/out-ok/M1_EXACT_DEVICE_EVIDENCE.txt"
grep -q '^Current slot: a$' "$TMP_DIR/out-ok/M1_EXACT_DEVICE_EVIDENCE.txt"
grep -q '^Launch authorization: NO$' "$TMP_DIR/out-ok/M1_EXACT_DEVICE_EVIDENCE.txt"
( cd "$TMP_DIR/out-ok" && sha256sum -c SHA256SUMS >/dev/null )

make_dir "$TMP_DIR/fastboot-slot-b" yes CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED unknown b yes no
if bash "$MERGER" "$TMP_DIR/adb" "$TMP_DIR/fastboot-slot-b" "$TMP_DIR/out-slot" >/dev/null 2>&1; then
  echo "ERROR: slot mismatch must be blocked" >&2
  exit 1
fi
grep -q '^Classification: M1_EXACT_DEVICE_EVIDENCE_BLOCKED$' "$TMP_DIR/out-slot/M1_EXACT_DEVICE_EVIDENCE.txt"
grep -q '^Blocker: ADB and fastboot slot observations disagree$' "$TMP_DIR/out-slot/M1_EXACT_DEVICE_EVIDENCE.txt"

make_dir "$TMP_DIR/fastboot-wrong-target" no CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED unknown a yes no
if bash "$MERGER" "$TMP_DIR/adb" "$TMP_DIR/fastboot-wrong-target" "$TMP_DIR/out-target" >/dev/null 2>&1; then
  echo "ERROR: target mismatch must be blocked" >&2
  exit 1
fi
grep -q '^Classification: M1_EXACT_DEVICE_EVIDENCE_BLOCKED$' "$TMP_DIR/out-target/M1_EXACT_DEVICE_EVIDENCE.txt"
grep -q '^Blocker: fastboot capture does not positively match ovaltine$' "$TMP_DIR/out-target/M1_EXACT_DEVICE_EVIDENCE.txt"

echo "M1 exact-device evidence merge tests: PASS"
