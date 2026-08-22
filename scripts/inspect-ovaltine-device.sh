#!/usr/bin/env bash
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

echo "IzzOS OnePlus 10T 5G read-only capability inspector"
echo "====================================================="
echo "This script does not flash, erase, format, unlock, or change slots."
echo

if have adb; then
  echo "[ADB] connected devices"
  adb devices -l || true
  echo

  if adb get-state >/dev/null 2>&1; then
    echo "[ADB] device identity / firmware"
    printf 'model: '; adb shell getprop ro.product.model | tr -d '\r'
    printf 'device: '; adb shell getprop ro.product.device | tr -d '\r'
    printf 'product: '; adb shell getprop ro.product.name | tr -d '\r'
    printf 'android: '; adb shell getprop ro.build.version.release | tr -d '\r'
    printf 'build-id: '; adb shell getprop ro.build.display.id | tr -d '\r'
    printf 'slot-suffix: '; adb shell getprop ro.boot.slot_suffix | tr -d '\r'
    printf 'verified-boot-state: '; adb shell getprop ro.boot.verifiedbootstate | tr -d '\r'
    printf 'vbmeta-device-state: '; adb shell getprop ro.boot.vbmeta.device_state | tr -d '\r'
    echo
  else
    echo "[ADB] no authorized Android device detected."
    echo
  fi
else
  echo "[ADB] adb not installed; skipping Android-side inspection."
  echo
fi

if have fastboot; then
  echo "[FASTBOOT] connected devices"
  fastboot devices || true
  echo

  if fastboot devices 2>/dev/null | grep -q .; then
    echo "[FASTBOOT] read-only bootloader variables"
    for key in product current-slot slot-count unlocked secure is-userspace version-bootloader; do
      echo "--- ${key} ---"
      fastboot getvar "${key}" 2>&1 || true
    done
    echo
    echo "[FASTBOOT] NOTE: this inspector intentionally does not run 'fastboot getvar all'"
    echo "because broad dumps can expose device identifiers that are not needed for M1."
  else
    echo "[FASTBOOT] no device detected in fastboot mode."
  fi
else
  echo "[FASTBOOT] fastboot not installed; skipping bootloader-side inspection."
fi

echo
echo "Inspection complete. No device state was modified by this script."
