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
dtb-index: 1
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
[ADB] no authorized Android device detected.
[FASTBOOT] connected devices: 1
[FASTBOOT] read-only bootloader variables
--- product ---
product: taro
finished. total time: 0.031s
--- current-slot ---
current-slot: a
finished. total time: 0.031s
--- slot-count ---
slot-count: 2
finished. total time: 0.031s
--- unlocked ---
unlocked: yes
finished. total time: 0.029s
--- secure ---
secure: yes
finished. total time: 0.031s
--- is-userspace ---
is-userspace: no
finished. total time: 0.031s
--- version-bootloader ---
version-bootloader:
finished. total time: 0.029s
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

cat > "${TMP_DIR}/adb-unauthorized.txt" <<'EOF'
[ADB] authorized devices: 0
[ADB] unauthorized/offline/other entries: 1
[ADB] no authorized Android device detected.
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/disconnected.txt" <<'EOF'
[ADB] authorized devices: 0
[ADB] no authorized Android device detected.
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/multiple-adb.txt" <<'EOF'
[ADB] authorized devices: 2
[ADB] multiple authorized devices detected; identity queries skipped to avoid targeting ambiguity.
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/mixed-adb.txt" <<'EOF'
[ADB] authorized devices: 1
[ADB] unauthorized/offline/other entries: 1
[ADB] multiple device entries detected; identity queries skipped to avoid targeting ambiguity.
[FASTBOOT] connected devices: 0
EOF

cat > "${TMP_DIR}/missing-fastboot-tool.txt" <<'EOF'
[ADB] authorized devices: 1
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
[FASTBOOT] fastboot not installed; skipping bootloader-side inspection.
EOF

cat > "${TMP_DIR}/legacy-platform-tools.txt" <<'EOF'
[HOST] selected Android Platform-Tools versions
adb-protocol-version: 1.0.31
adb-platform-tools-version: unknown
fastboot-version: 37.0.0
[ADB] authorized devices: 0
[ADB] unauthorized/offline/other entries: 1
[ADB] no authorized Android device detected.
[FASTBOOT] connected devices: 0
EOF

assert_classification "classic fastboot candidate" "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED" "${TMP_DIR}/candidate.txt"
CANDIDATE_OUTPUT="$(bash "${ANALYZER}" "${TMP_DIR}/candidate.txt")"
grep -Fq 'DTB index: 1' <<<"${CANDIDATE_OUTPUT}"
assert_classification "CPH2413 OxygenOS 15 ADB identity" "NEED_EXACT_FASTBOOT_INSPECTION" "${TMP_DIR}/cph2413-oos15-adb.txt"
assert_classification "CPH2413 inconsistent tuple blocked" "TARGET_MISMATCH_BLOCKED" "${TMP_DIR}/cph2413-inconsistent.txt"
assert_classification "taro classic fastboot candidate" "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED" "${TMP_DIR}/taro-fastboot.txt"
TARO_OUTPUT="$(bash "${ANALYZER}" "${TMP_DIR}/taro-fastboot.txt")"
grep -Fq 'Target match: platform-compatible' <<<"${TARO_OUTPUT}"
grep -Fq 'Product: unknown' <<<"${TARO_OUTPUT}"
grep -Fq $'Observed bootloader-side data\n-----------------------------\nFastboot devices: 1\nProduct: taro' <<<"${TARO_OUTPUT}"
assert_classification "fastbootd blocked" "FASTBOOTD_DETECTED_BLOCKED" "${TMP_DIR}/fastbootd.txt"
assert_classification "locked bootloader blocked" "LOCKED_BOOTLOADER_BLOCKED" "${TMP_DIR}/locked.txt"
assert_classification "target mismatch blocked" "TARGET_MISMATCH_BLOCKED" "${TMP_DIR}/mismatch.txt"
assert_classification "ADB-only needs fastboot" "NEED_EXACT_FASTBOOT_INSPECTION" "${TMP_DIR}/adb-only.txt"
assert_classification "unauthorized ADB requires local approval" "ADB_AUTHORIZATION_REQUIRED" "${TMP_DIR}/adb-unauthorized.txt"
UNAUTHORIZED_OUTPUT="$(bash "${ANALYZER}" "${TMP_DIR}/adb-unauthorized.txt")"
grep -Fq 'Unauthorized/offline/other ADB entries: 1' <<<"${UNAUTHORIZED_OUTPUT}"
grep -Fq 'A person at the phone must unlock Android' <<<"${UNAUTHORIZED_OUTPUT}"
assert_classification "disconnected device requires connection" "DEVICE_CONNECTION_REQUIRED" "${TMP_DIR}/disconnected.txt"
assert_classification "multiple devices are ambiguous" "DEVICE_SELECTION_AMBIGUOUS_BLOCKED" "${TMP_DIR}/multiple-adb.txt"
assert_classification "mixed authorized and unauthorized devices are ambiguous" "DEVICE_SELECTION_AMBIGUOUS_BLOCKED" "${TMP_DIR}/mixed-adb.txt"
assert_classification "missing fastboot tool blocks attendance handoff" "DEVICE_TOOLCHAIN_REQUIRED" "${TMP_DIR}/missing-fastboot-tool.txt"
assert_classification "legacy ADB is rejected before authorization advice" "DEVICE_TOOLCHAIN_REQUIRED" "${TMP_DIR}/legacy-platform-tools.txt"
LEGACY_OUTPUT="$(bash "${ANALYZER}" "${TMP_DIR}/legacy-platform-tools.txt")"
grep -Fq 'adb protocol is older than 1.0.41' <<<"${LEGACY_OUTPUT}"

echo "All Ovaltine inspection analyzer tests passed."
