#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYZER="${ROOT_DIR}/scripts/analyze-ovaltine-inspection.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

assert_classification() {
  local name="$1"
  local expected="$2"
  local input="$3"
  local output
  output="$(bash "${ANALYZER}" "${input}")"
  if ! grep -Fq "Classification: ${expected}" <<<"${output}"; then
    echo "FAIL: ${name}: expected ${expected}" >&2
    echo "${output}" >&2
    exit 1
  fi
  echo "PASS: ${name} -> ${expected}"
}

cat > "${TMP_DIR}/candidate.txt" <<'EOF'
[ADB] authorized devices: 1
[ADB] device identity / firmware
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
vendor-device: ovaltine
android: 16
build-id: TEST.BUILD
slot-suffix: _a
verified-boot-state: orange
vbmeta-device-state: unlocked
[FASTBOOT] connected devices: 1
[FASTBOOT] read-only bootloader variables
--- product ---
(bootloader) product: ovaltine
--- current-slot ---
(bootloader) current-slot: a
--- slot-count ---
(bootloader) slot-count: 2
--- unlocked ---
(bootloader) unlocked: yes
--- secure ---
(bootloader) secure: yes
--- is-userspace ---
(bootloader) is-userspace: no
--- version-bootloader ---
(bootloader) version-bootloader: test
EOF

cat > "${TMP_DIR}/cph2413-oos15-adb.txt" <<'EOF'
[ADB] authorized devices: 1
[ADB] device identity / firmware
model: OnePlus 10T 5G
device: OP5552L1
product: CPH2413
vendor-device: OP5552L1
android: 15
build-id: CPH2413_15.0.0.1901(EX01)
slot-suffix: _a
verified-boot-state: green
vbmeta-device-state: locked
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/cph2413-inconsistent.txt" <<'EOF'
[ADB] authorized devices: 1
[ADB] device identity / firmware
model: OnePlus 10T 5G
device: OP5552L1
product: CPH2413
vendor-device: WRONGDEVICE
android: 15
build-id: CPH2413_15.0.0.1901(EX01)
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/taro-fastboot.txt" <<'EOF'
[ADB] authorized devices: 0
[FASTBOOT] connected devices: 1
--- product ---
(bootloader) product: taro
--- current-slot ---
(bootloader) current-slot: a
--- slot-count ---
(bootloader) slot-count: 2
--- unlocked ---
(bootloader) unlocked: yes
--- secure ---
(bootloader) secure: yes
--- is-userspace ---
(bootloader) is-userspace: no
--- version-bootloader ---
(bootloader) version-bootloader: test
EOF

cat > "${TMP_DIR}/fastbootd.txt" <<'EOF'
[ADB] authorized devices: 0
[FASTBOOT] connected devices: 1
--- product ---
(bootloader) product: ovaltine
--- unlocked ---
(bootloader) unlocked: yes
--- is-userspace ---
(bootloader) is-userspace: yes
EOF

cat > "${TMP_DIR}/locked.txt" <<'EOF'
[ADB] authorized devices: 1
model: OnePlus 10T 5G
device: ovaltine
[FASTBOOT] connected devices: 1
--- product ---
(bootloader) product: ovaltine
--- unlocked ---
(bootloader) unlocked: no
--- is-userspace ---
(bootloader) is-userspace: no
EOF

cat > "${TMP_DIR}/mismatch.txt" <<'EOF'
[ADB] authorized devices: 1
model: Some Other Phone
device: otherdevice
product: otherproduct
[FASTBOOT] connected devices: 1
--- product ---
(bootloader) product: otherdevice
--- unlocked ---
(bootloader) unlocked: yes
--- is-userspace ---
(bootloader) is-userspace: no
EOF

cat > "${TMP_DIR}/adb-only.txt" <<'EOF'
[ADB] authorized devices: 1
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
[FASTBOOT] connected devices: 0
EOF

assert_classification "classic fastboot candidate" "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED" "${TMP_DIR}/candidate.txt"
assert_classification "CPH2413 OxygenOS 15 ADB identity" "NEED_EXACT_FASTBOOT_INSPECTION" "${TMP_DIR}/cph2413-oos15-adb.txt"
assert_classification "CPH2413 inconsistent tuple blocked" "TARGET_MISMATCH_BLOCKED" "${TMP_DIR}/cph2413-inconsistent.txt"
assert_classification "taro classic fastboot candidate" "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED" "${TMP_DIR}/taro-fastboot.txt"
grep -Fq 'Target match: platform-compatible' < <(bash "${ANALYZER}" "${TMP_DIR}/taro-fastboot.txt")
assert_classification "fastbootd blocked" "FASTBOOTD_DETECTED_BLOCKED" "${TMP_DIR}/fastbootd.txt"
assert_classification "locked bootloader blocked" "LOCKED_BOOTLOADER_BLOCKED" "${TMP_DIR}/locked.txt"
assert_classification "target mismatch blocked" "TARGET_MISMATCH_BLOCKED" "${TMP_DIR}/mismatch.txt"
assert_classification "ADB-only needs fastboot" "NEED_EXACT_FASTBOOT_INSPECTION" "${TMP_DIR}/adb-only.txt"

echo "All Ovaltine inspection analyzer tests passed."
