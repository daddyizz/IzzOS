#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-out/m1-running-kernel-placement-hints.txt}"
mkdir -p "$(dirname "$OUT")"

if ! command -v adb >/dev/null 2>&1; then
  echo "ERROR: adb not found" >&2
  exit 2
fi

count="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{n++} END{print n+0}')"
if [[ "$count" -ne 1 ]]; then
  echo "ERROR: expected exactly one authorized adb device; found $count" >&2
  exit 1
fi

shell() { adb shell "$1" 2>/dev/null | tr -d '\r' || true; }

{
  echo "IzzOS M1 running-kernel placement hints"
  echo "======================================"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo "Target product: $(shell 'getprop ro.product.name' | head -n1)"
  echo "Build ID: $(shell 'getprop ro.build.display.id' | head -n1)"
  echo "Slot suffix: $(shell 'getprop ro.boot.slot_suffix' | head -n1)"
  echo

  echo "Kernel log placement hints:"
  logs="$(shell "dmesg 2>/dev/null | grep -Ei 'Kernel Offset|Memory:|Virtual kernel memory layout|PHYS_OFFSET|kimage|Kernel command line' | head -n 80")"
  if [[ -n "$logs" ]]; then printf '%s\n' "$logs"; else echo "UNAVAILABLE"; fi
  echo

  echo "Kernel symbol placement hints:"
  syms="$(shell "awk '\$3==\"_text\" || \$3==\"_stext\" || \$3==\"_end\" || \$3==\"kimage_voffset\" {print}' /proc/kallsyms 2>/dev/null | head -n 20")"
  if [[ -n "$syms" ]]; then printf '%s\n' "$syms"; else echo "UNAVAILABLE"; fi
  echo

  echo "Kernel address exposure controls:"
  echo "kptr_restrict: $(shell 'cat /proc/sys/kernel/kptr_restrict 2>/dev/null' | head -n1)"
  echo "dmesg_restrict: $(shell 'cat /proc/sys/kernel/dmesg_restrict 2>/dev/null' | head -n1)"
  echo

  echo "Boot/debug properties relevant to placement:"
  props="$(shell "getprop | grep -Ei '\[(ro\.boot\.|ro\.kernel\.).*(addr|offset|base|mem|kernel|dtb)|\[ro\.boot\.slot_suffix\]' | head -n 80")"
  if [[ -n "$props" ]]; then printf '%s\n' "$props"; else echo "UNAVAILABLE"; fi
} > "$OUT"

if grep -Eq 'Kernel Offset|(^|[[:space:]])[0-9a-fA-F]{8,16}[[:space:]]+[A-Za-z][[:space:]]+(_text|_stext|_end|kimage_voffset)' "$OUT"; then
  echo "classification: RUNNING_KERNEL_PLACEMENT_HINTS_CAPTURED" >> "$OUT"
  echo "decision: non-root runtime kernel-placement hints were exposed. Analyze them conservatively; this does not authorize an FD address or device launch." >> "$OUT"
else
  echo "classification: RUNNING_KERNEL_PLACEMENT_HINTS_RESTRICTED" >> "$OUT"
  echo "decision: Android did not expose a trustworthy running-kernel physical placement to the unprivileged shell. Keep FD placement unproven and continue with host-side exact-firmware research only." >> "$OUT"
fi

cat "$OUT"
