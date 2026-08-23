#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-out/high-memory-block-details.txt}"
ROOT=/sys/devices/system/memory
mkdir -p "$(dirname "$OUT")"
{
  echo "IzzOS high-memory block detail evidence"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo "Target product: $(adb shell getprop ro.product.name 2>/dev/null | tr -d '\r')"
  echo "Build ID: $(adb shell getprop ro.build.display.id 2>/dev/null | tr -d '\r')"
  echo "High-memory derived gross bank: 0x800000000-0xB80000000"
  echo "Derived block size: 0x8000000 (128 MiB)"
  echo
  total=0; state_ok=0; zone_normal=0; readable=0
  for i in $(seq 256 367); do
    d="$ROOT/memory$i"
    if adb shell test -d "$d" 2>/dev/null; then
      total=$((total+1))
      state="$(adb shell cat "$d/state" 2>/dev/null | tr -d '\r' || true)"
      removable="$(adb shell cat "$d/removable" 2>/dev/null | tr -d '\r' || true)"
      zones="$(adb shell cat "$d/valid_zones" 2>/dev/null | tr -d '\r' || true)"
      phys="$(adb shell cat "$d/phys_index" 2>/dev/null | tr -d '\r' || true)"
      [[ -n "$state$removable$zones$phys" ]] && readable=$((readable+1))
      [[ "$state" == "online" ]] && state_ok=$((state_ok+1))
      [[ "$zones" == *Normal* ]] && zone_normal=$((zone_normal+1))
      base=$((i * 0x8000000)); end=$(((i+1) * 0x8000000))
      printf 'memory%d 0x%X-0x%X state=%s removable=%s valid_zones=%s phys_index=%s\n' "$i" "$base" "$end" "${state:-UNAVAILABLE}" "${removable:-UNAVAILABLE}" "${zones:-UNAVAILABLE}" "${phys:-UNAVAILABLE}"
    fi
  done
  echo
  echo "high-memory-block-count: $total"
  echo "metadata-readable-block-count: $readable"
  echo "online-block-count: $state_ok"
  echo "normal-zone-block-count: $zone_normal"
  if (( total == 112 && state_ok == 112 )); then
    echo "classification: HIGH_MEMORY_BLOCKS_ONLINE_CONFIRMED"
  elif (( total == 112 && readable == 0 )); then
    echo "classification: HIGH_MEMORY_BLOCKS_PRESENT_METADATA_RESTRICTED"
  else
    echo "classification: HIGH_MEMORY_BLOCK_DETAILS_PARTIAL"
  fi
  echo "decision: block state/zone metadata is read-only evidence only. Online or Normal status proves kernel ownership/availability at block granularity, not that every byte is free or suitable for standalone firmware placement. Dynamic pools and firmware ownership still require reconciliation; no FD address or device launch is authorized."
} > "$OUT"
cat "$OUT"
