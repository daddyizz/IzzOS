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

adb_value() {
  local label="$1"
  awk -v label="${label}:" '
    /^\[FASTBOOT\]/ {exit}
    index($0, label) == 1 {
      sub("^[^:]+:[[:space:]]*", "")
      print
      exit
    }
  ' "${INPUT}" | trim
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

MODEL="$(adb_value model || true)"
DEVICE="$(adb_value device || true)"
PRODUCT_ADB="$(adb_value product || true)"
VENDOR_DEVICE="$(adb_value vendor-device || true)"
ANDROID="$(adb_value android || true)"
BUILD_ID="$(adb_value build-id || true)"
SLOT_SUFFIX="$(adb_value slot-suffix || true)"
DTB_INDEX="$(adb_value dtb-index || true)"
VB_STATE="$(adb_value verified-boot-state || true)"
VBMETA_STATE="$(adb_value vbmeta-device-state || true)"

ADB_COUNT="$(awk -F': ' '/^\[ADB\] authorized devices:/ {print $2; exit}' "${INPUT}" | trim)"
ADB_OTHER_COUNT="$(awk -F': ' '/^\[ADB\] unauthorized\/offline\/other entries:/ {print $2; exit}' "${INPUT}" | trim)"
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

if [[ "${ADB_COUNT:-}" =~ ^[0-9]+$ && "${ADB_OTHER_COUNT:-0}" =~ ^[0-9]+$ && $((ADB_COUNT + ADB_OTHER_COUNT)) -gt 1 ]] ||
   [[ "${FASTBOOT_COUNT:-}" =~ ^[0-9]+$ && "${FASTBOOT_COUNT}" -gt 1 ]]; then
  CLASSIFICATION="DEVICE_SELECTION_AMBIGUOUS_BLOCKED"
  NEXT_GATE="Disconnect every unrelated device and repeat the privacy-safe inspection with exactly one target in one transport mode."
elif [[ "${TARGET_MATCH}" == "no" ]]; then
  CLASSIFICATION="TARGET_MISMATCH_BLOCKED"
  NEXT_GATE="Stop M1 launch preparation until the exact OnePlus 10T / ovaltine target is confirmed."
elif [[ "${FASTBOOT_COUNT:-}" == "1" ]]; then
  if [[ "${USERSPACE_LC}" == "yes" || "${USERSPACE_LC}" == "true" || "${USERSPACE_LC}" == "1" ]]; then
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
elif [[ "${ADB_COUNT:-}" == "0" && "${ADB_OTHER_COUNT:-0}" =~ ^[0-9]+$ && "${ADB_OTHER_COUNT:-0}" -gt 0 ]]; then
  CLASSIFICATION="ADB_AUTHORIZATION_REQUIRED"
  NEXT_GATE="A person at the phone must unlock Android, accept the USB-debugging fingerprint for this host, keep the cable connected and rerun the read-only inspection."
elif [[ "${ADB_COUNT:-}" == "0" && "${FASTBOOT_COUNT:-}" == "0" ]]; then
  CLASSIFICATION="DEVICE_CONNECTION_REQUIRED"
  NEXT_GATE="Connect exactly one target phone by USB in Android or classic bootloader-fastboot mode, then rerun the read-only inspection."
elif [[ ! "${ADB_COUNT:-}" =~ ^[0-9]+$ || ! "${FASTBOOT_COUNT:-}" =~ ^[0-9]+$ ]]; then
  CLASSIFICATION="DEVICE_TOOLCHAIN_REQUIRED"
  NEXT_GATE="Install both adb and fastboot on the host, then repeat the privacy-safe presence and capability inspection."
elif [[ "${ADB_COUNT}" == "1" && "${FASTBOOT_COUNT}" == "0" ]]; then
  CLASSIFICATION="NEED_EXACT_FASTBOOT_INSPECTION"
  NEXT_GATE="A person at the phone must enter classic bootloader-fastboot without changing slots or flashing, then rerun the privacy-safe inspection."
fi

cat <<EOF
IzzOS M1 capability assessment
==============================
Target match: ${TARGET_MATCH}
Classification: ${CLASSIFICATION}

Observed Android-side data
--------------------------
Authorized ADB devices: ${ADB_COUNT:-unknown}
Unauthorized/offline/other ADB entries: ${ADB_OTHER_COUNT:-0}
Model: ${MODEL:-unknown}
Device: ${DEVICE:-unknown}
Product: ${PRODUCT_ADB:-unknown}
Vendor device: ${VENDOR_DEVICE:-unknown}
Android: ${ANDROID:-unknown}
Build ID: ${BUILD_ID:-unknown}
Slot suffix: ${SLOT_SUFFIX:-unknown}
DTB index: ${DTB_INDEX:-unknown}
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
