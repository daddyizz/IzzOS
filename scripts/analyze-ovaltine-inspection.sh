#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <inspection-output.txt>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
INPUT="$1"
[[ -f "${INPUT}" ]] || { echo "ERROR: inspection output not found: ${INPUT}" >&2; exit 2; }

trim() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

value_after_label() {
  local label="$1"
  awk -v label="${label}:" 'index($0, label) == 1 {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "${INPUT}" | trim
}

fastboot_value() {
  local key="$1"
  awk -v marker="--- ${key} ---" '
    $0 == marker {inside=1; next}
    inside && /^--- / {exit}
    inside {
      line=$0
      sub(/^\(bootloader\)[[:space:]]*/, "", line)
      sub(/^INFO[[:space:]]*/, "", line)
      if (line ~ /^[^:]+:[[:space:]]*/) {
        sub(/^[^:]+:[[:space:]]*/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    }
  ' "${INPUT}" | trim
}

lower() { tr '[:upper:]' '[:lower:]'; }

MODEL="$(value_after_label model || true)"
DEVICE="$(value_after_label device || true)"
PRODUCT_ADB="$(value_after_label product || true)"
VENDOR_DEVICE="$(value_after_label vendor-device || true)"
ANDROID="$(value_after_label android || true)"
BUILD_ID="$(value_after_label build-id || true)"
SLOT_SUFFIX="$(value_after_label slot-suffix || true)"
VB_STATE="$(value_after_label verified-boot-state || true)"
VBMETA_STATE="$(value_after_label vbmeta-device-state || true)"

ADB_COUNT="$(awk -F': ' '/^\[ADB\] authorized devices:/ {print $2; exit}' "${INPUT}" | trim)"
FASTBOOT_COUNT="$(awk -F': ' '/^\[FASTBOOT\] connected devices:/ {print $2; exit}' "${INPUT}" | trim)"

FB_PRODUCT="$(fastboot_value product || true)"
FB_SLOT="$(fastboot_value current-slot || true)"
FB_SLOT_COUNT="$(fastboot_value slot-count || true)"
FB_UNLOCKED="$(fastboot_value unlocked || true)"
FB_SECURE="$(fastboot_value secure || true)"
FB_USERSPACE="$(fastboot_value is-userspace || true)"
FB_VERSION="$(fastboot_value version-bootloader || true)"

DEVICE_LC="$(printf '%s' "${DEVICE}" | lower)"
PRODUCT_LC="$(printf '%s' "${PRODUCT_ADB}" | lower)"
VENDOR_DEVICE_LC="$(printf '%s' "${VENDOR_DEVICE}" | lower)"
BUILD_ID_LC="$(printf '%s' "${BUILD_ID}" | lower)"
FB_PRODUCT_LC="$(printf '%s' "${FB_PRODUCT}" | lower)"
UNLOCKED_LC="$(printf '%s' "${FB_UNLOCKED}" | lower)"
USERSPACE_LC="$(printf '%s' "${FB_USERSPACE}" | lower)"

TARGET_MATCH="unknown"
if [[ -n "${DEVICE_LC}" || -n "${PRODUCT_LC}" || -n "${VENDOR_DEVICE_LC}" || -n "${FB_PRODUCT_LC}" ]]; then
  if [[ "${DEVICE_LC}" == "ovaltine" || "${PRODUCT_LC}" == *"ovaltine"* || "${FB_PRODUCT_LC}" == *"ovaltine"* ]]; then
    TARGET_MATCH="yes"
  elif [[ "${PRODUCT_LC}" == "cph2413" && "${DEVICE_LC}" == "op5552l1" && "${VENDOR_DEVICE_LC}" == "op5552l1" && "${BUILD_ID_LC}" == cph2413_* ]]; then
    TARGET_MATCH="yes"
  elif [[ -z "${DEVICE_LC}" && -z "${PRODUCT_LC}" && -z "${VENDOR_DEVICE_LC}" && "${FB_PRODUCT_LC}" == "taro" ]]; then
    # Qualcomm bootloaders may expose a platform-level product rather than the OEM codename.
    # This is NOT sufficient to prove OnePlus 10T identity by itself; merger must bind it
    # to an ADB capture that positively identifies the exact device/build.
    TARGET_MATCH="platform-compatible"
  else
    TARGET_MATCH="no"
  fi
fi

CLASSIFICATION="INSUFFICIENT_DATA"
NEXT_GATE="Collect one authorized ADB inspection and one exact-device bootloader inspection."

if [[ "${TARGET_MATCH}" == "no" ]]; then
  CLASSIFICATION="TARGET_MISMATCH_BLOCKED"
  NEXT_GATE="Stop M1 launch preparation until the exact OnePlus 10T / ovaltine target is confirmed."
elif [[ "${FASTBOOT_COUNT:-0}" != "1" ]]; then
  CLASSIFICATION="NEED_EXACT_FASTBOOT_INSPECTION"
  NEXT_GATE="Collect the privacy-safe inspector output with exactly one device in bootloader/fastboot mode."
elif [[ "${USERSPACE_LC}" == "yes" || "${USERSPACE_LC}" == "true" || "${USERSPACE_LC}" == "1" ]]; then
  CLASSIFICATION="FASTBOOTD_DETECTED_BLOCKED"
  NEXT_GATE="Fastbootd is userspace fastboot. Collect classic bootloader-fastboot capability data before choosing a temporary UEFI route."
elif [[ "${UNLOCKED_LC}" == "no" || "${UNLOCKED_LC}" == "false" || "${UNLOCKED_LC}" == "0" ]]; then
  CLASSIFICATION="LOCKED_BOOTLOADER_BLOCKED"
  NEXT_GATE="Do not package or launch unsigned temporary boot payloads. Seek a non-destructive OEM/loader path or make a separate, explicit unlock-risk decision later."
elif [[ "${UNLOCKED_LC}" == "yes" || "${UNLOCKED_LC}" == "true" || "${UNLOCKED_LC}" == "1" ]]; then
  CLASSIFICATION="CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED"
  NEXT_GATE="Classic fastboot is a candidate only. Verify exact-firmware support for temporary boot/chain-load before creating any launch image."
else
  CLASSIFICATION="BOOTLOADER_STATE_UNKNOWN_BLOCKED"
  NEXT_GATE="Resolve the bootloader unlock state and confirm classic fastboot before launch preparation."
fi

cat <<EOF
IzzOS M1 capability assessment
==============================
Target match: ${TARGET_MATCH}
Classification: ${CLASSIFICATION}

Observed Android-side data
--------------------------
Authorized ADB devices: ${ADB_COUNT:-unknown}
Model: ${MODEL:-unknown}
Device: ${DEVICE:-unknown}
Product: ${PRODUCT_ADB:-unknown}
Vendor device: ${VENDOR_DEVICE:-unknown}
Android: ${ANDROID:-unknown}
Build ID: ${BUILD_ID:-unknown}
Slot suffix: ${SLOT_SUFFIX:-unknown}
Verified boot: ${VB_STATE:-unknown}
VBMeta device state: ${VBMETA_STATE:-unknown}

Observed bootloader-side data
-----------------------------
Fastboot devices: ${FASTBOOT_COUNT:-unknown}
Product: ${FB_PRODUCT:-unknown}
Current slot: ${FB_SLOT:-unknown}
Slot count: ${FB_SLOT_COUNT:-unknown}
Unlocked: ${FB_UNLOCKED:-unknown}
Secure: ${FB_SECURE:-unknown}
Userspace fastboot: ${FB_USERSPACE:-unknown}
Bootloader version: ${FB_VERSION:-unknown}

Next gate
---------
${NEXT_GATE}

Safety rule: this analyzer never executes adb, fastboot, flash, erase, format, unlock, or slot-changing commands.
EOF
