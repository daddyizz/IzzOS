#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-out/runtime-cma-placement-hints.txt}"
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
  echo "IzzOS runtime CMA / allocation placement hints"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo "Target product: $(shell 'getprop ro.product.name' | head -n1)"
  echo "Build ID: $(shell 'getprop ro.build.display.id' | head -n1)"
  echo "Slot suffix: $(shell 'getprop ro.boot.slot_suffix' | head -n1)"
  echo

  echo "Meminfo CMA summary:"
  m="$(shell "grep -E '^(MemTotal|CmaTotal|CmaFree):' /proc/meminfo")"
  [[ -n "$m" ]] && printf '%s\n' "$m" || echo "UNAVAILABLE"
  echo

  echo "Zoneinfo placement hints:"
  z="$(shell "grep -E '^(Node|[[:space:]]*(start_pfn|spanned|present|managed))' /proc/zoneinfo | head -n 120")"
  [[ -n "$z" ]] && printf '%s\n' "$z" || echo "UNAVAILABLE"
  echo

  echo "Pagetypeinfo CMA hints:"
  p="$(shell "grep -Ei 'CMA|Movable|Free pages count per migrate type' /proc/pagetypeinfo | head -n 160")"
  [[ -n "$p" ]] && printf '%s\n' "$p" || echo "UNAVAILABLE"
  echo

  echo "Sysfs CMA hints:"
  s="$(shell "for d in /sys/kernel/debug/cma/* /sys/kernel/cma/* /sys/devices/system/memory/*; do [ -e \"\$d\" ] || continue; case \"\$d\" in *cma*) echo \"\$d\";; esac; done | head -n 120")"
  [[ -n "$s" ]] && printf '%s\n' "$s" || echo "UNAVAILABLE"
  echo

  echo "Kernel log CMA hints:"
  d="$(shell "dmesg 2>/dev/null | grep -Ei 'Reserved memory: created CMA|cma: Reserved|CMA:' | head -n 80")"
  [[ -n "$d" ]] && printf '%s\n' "$d" || echo "UNAVAILABLE"
} > "$OUT"

if grep -Eq 'start_pfn:|CmaTotal:|CMA' "$OUT"; then
  echo "classification: RUNTIME_CMA_HINTS_CAPTURED" >> "$OUT"
  echo "decision: non-root runtime allocation hints were captured. They may reject candidate ranges if physical placement is exposed, but totals alone do not prove a specific address. No FD address or device launch is authorized." >> "$OUT"
else
  echo "classification: RUNTIME_CMA_HINTS_RESTRICTED" >> "$OUT"
  echo "decision: Android did not expose useful runtime CMA placement to the unprivileged shell. Continue host-side exact-firmware analysis only; do not bypass platform security." >> "$OUT"
fi
cat "$OUT"
