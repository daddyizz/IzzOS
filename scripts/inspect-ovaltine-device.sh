#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=android-platform-tools.sh
source "$SCRIPT_DIR/android-platform-tools.sh"

ADB_TOOL="$(izzos_resolve_android_tool adb "${ADB_BIN:-}" || true)"
FASTBOOT_TOOL="$(izzos_resolve_android_tool fastboot "${FASTBOOT_BIN:-}" || true)"

ADB_VERSION_OUT=""
ADB_PROTOCOL_VERSION="unknown"
ADB_PLATFORM_VERSION="unknown"
if [[ -n "$ADB_TOOL" ]]; then
  ADB_VERSION_OUT="$("$ADB_TOOL" version 2>&1 || true)"
  ADB_PROTOCOL_VERSION="$(printf '%s\n' "$ADB_VERSION_OUT" | sed -nE 's/^Android Debug Bridge version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)"
  ADB_PLATFORM_VERSION="$(printf '%s\n' "$ADB_VERSION_OUT" | sed -nE 's/^Version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)"
  ADB_PROTOCOL_VERSION="${ADB_PROTOCOL_VERSION:-unknown}"
  ADB_PLATFORM_VERSION="${ADB_PLATFORM_VERSION:-unknown}"
fi

FASTBOOT_TOOL_VERSION="unknown"
if [[ -n "$FASTBOOT_TOOL" ]]; then
  FASTBOOT_TOOL_VERSION="$("$FASTBOOT_TOOL" --version 2>&1 | sed -nE 's/^fastboot version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1 || true)"
  FASTBOOT_TOOL_VERSION="${FASTBOOT_TOOL_VERSION:-unknown}"
fi

echo "IzzOS OnePlus 10T 5G read-only capability inspector"
echo "====================================================="
echo "This script does not flash, erase, format, unlock, or change slots."
echo "Device serial numbers are intentionally not printed."
echo

echo "[HOST] selected Android Platform-Tools versions"
echo "adb-protocol-version: ${ADB_PROTOCOL_VERSION}"
echo "adb-platform-tools-version: ${ADB_PLATFORM_VERSION}"
echo "fastboot-version: ${FASTBOOT_TOOL_VERSION}"
echo

if [[ -n "$ADB_TOOL" ]]; then
  ADB_DEVICES_OUT="$("$ADB_TOOL" devices 2>/dev/null || true)"
  ADB_AUTH_COUNT="$(printf '%s\n' "$ADB_DEVICES_OUT" | awk 'NR > 1 && $2 == "device" {count++} END {print count + 0}')"
  ADB_OTHER_COUNT="$(printf '%s\n' "$ADB_DEVICES_OUT" | awk 'NR > 1 && NF >= 2 && $2 != "device" {count++} END {print count + 0}')"

  echo "[ADB] authorized devices: ${ADB_AUTH_COUNT}"
  if [[ "${ADB_OTHER_COUNT}" -gt 0 ]]; then
    echo "[ADB] unauthorized/offline/other entries: ${ADB_OTHER_COUNT}"
  fi
  echo

  if [[ "${ADB_AUTH_COUNT}" -eq 1 && "${ADB_OTHER_COUNT}" -eq 0 ]]; then
    echo "[ADB] device identity / firmware"
    printf 'model: '; "$ADB_TOOL" shell getprop ro.product.model | tr -d '\r'
    printf 'device: '; "$ADB_TOOL" shell getprop ro.product.device | tr -d '\r'
    printf 'product: '; "$ADB_TOOL" shell getprop ro.product.name | tr -d '\r'
    printf 'vendor-device: '; "$ADB_TOOL" shell getprop ro.product.vendor.device | tr -d '\r'
    printf 'android: '; "$ADB_TOOL" shell getprop ro.build.version.release | tr -d '\r'
    printf 'build-id: '; "$ADB_TOOL" shell getprop ro.build.display.id | tr -d '\r'
    printf 'slot-suffix: '; "$ADB_TOOL" shell getprop ro.boot.slot_suffix | tr -d '\r'
    printf 'dtb-index: '; "$ADB_TOOL" shell getprop ro.boot.dtb_idx | tr -d '\r'
    printf 'verified-boot-state: '; "$ADB_TOOL" shell getprop ro.boot.verifiedbootstate | tr -d '\r'
    printf 'vbmeta-device-state: '; "$ADB_TOOL" shell getprop ro.boot.vbmeta.device_state | tr -d '\r'
    echo
  elif [[ $((ADB_AUTH_COUNT + ADB_OTHER_COUNT)) -gt 1 ]]; then
    echo "[ADB] multiple device entries detected; identity queries skipped to avoid targeting ambiguity."
    echo
  else
    echo "[ADB] no authorized Android device detected."
    echo
  fi
else
  echo "[ADB] adb not installed; skipping Android-side inspection."
  echo
fi

if [[ -n "$FASTBOOT_TOOL" ]]; then
  FASTBOOT_COUNT="$("$FASTBOOT_TOOL" devices 2>/dev/null | awk 'NF {count++} END {print count + 0}')"
  echo "[FASTBOOT] connected devices: ${FASTBOOT_COUNT}"
  echo

  if [[ "${FASTBOOT_COUNT}" -eq 1 ]]; then
    echo "[FASTBOOT] read-only bootloader variables"
    for key in product current-slot slot-count unlocked secure is-userspace version-bootloader; do
      echo "--- ${key} ---"
      "$FASTBOOT_TOOL" getvar "${key}" 2>&1 || true
    done
    echo
    echo "[FASTBOOT] NOTE: this inspector intentionally does not run 'fastboot getvar all'"
    echo "because broad dumps can expose device identifiers that are not needed for M1."
  elif [[ "${FASTBOOT_COUNT}" -gt 1 ]]; then
    echo "[FASTBOOT] multiple devices detected; bootloader queries skipped to avoid targeting ambiguity."
  else
    echo "[FASTBOOT] no device detected in fastboot mode."
  fi
else
  echo "[FASTBOOT] fastboot not installed; skipping bootloader-side inspection."
fi

echo
echo "Inspection complete. No device state was modified by this script."
