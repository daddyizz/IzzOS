#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-out/runtime-uefi-kernel-vars.txt}"
ADB="${ADB:-adb}"
mkdir -p "$(dirname "$OUT")"

{
  echo "IzzOS runtime UEFI kernel-variable evidence"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo
  echo "Target product: $($ADB shell getprop ro.product.name 2>/dev/null | tr -d '\r' || true)"
  echo "Build ID: $($ADB shell getprop ro.build.display.id 2>/dev/null | tr -d '\r' || true)"
  echo "Slot suffix: $($ADB shell getprop ro.boot.slot_suffix 2>/dev/null | tr -d '\r' || true)"
  echo
  echo "efivarfs mount hints:"
  $ADB shell 'mount 2>/dev/null | grep -i efivar || true; ls -ld /sys/firmware/efi /sys/firmware/efi/efivars 2>&1 || true' | tr -d '\r'
  echo
  echo "KernelBaseAddr/KernelSize efivar name hints:"
  $ADB shell 'for d in /sys/firmware/efi/efivars /sys/firmware/efi/vars; do if [ -d "$d" ]; then ls -1 "$d" 2>/dev/null | grep -E "^(KernelBaseAddr|KernelSize)(-|$)" || true; fi; done' | tr -d '\r'
  echo
  echo "readability diagnostics:"
  $ADB shell 'for d in /sys/firmware/efi/efivars /sys/firmware/efi/vars; do if [ -d "$d" ]; then for f in "$d"/KernelBaseAddr-* "$d"/KernelSize-*; do [ -e "$f" ] || continue; ls -lZ "$f" 2>&1 || true; dd if="$f" bs=1 count=32 2>/dev/null | od -An -tx1 2>/dev/null || true; done; fi; done' | tr -d '\r'
  echo
  echo "firmware DT/chosen hints:"
  $ADB shell 'for p in /proc/device-tree/chosen /sys/firmware/devicetree/base/chosen; do [ -d "$p" ] && { ls -l "$p" 2>&1 || true; find "$p" -maxdepth 1 -type f -printf "%f\n" 2>/dev/null | grep -Ei "kernel|boot|memory" || true; }; done' | tr -d '\r'
  echo
  echo "classification: RUNTIME_UEFI_KERNEL_VARIABLE_ACCESS_PROBED"
  echo "decision: runtime exposure of KernelBaseAddr/KernelSize was probed read-only. Absence or permission denial does not prove the variables are absent from pre-Linux UEFI runtime; no FD base or device launch is authorized."
} | tee "$OUT"
