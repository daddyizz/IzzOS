#!/usr/bin/env bash
set -u

OUT="${1:-out/sysfs-physical-memory-blocks.txt}"
mkdir -p "$(dirname "$OUT")"
ADB="${ADB:-adb}"

{
  echo "IzzOS sysfs physical-memory block evidence"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo

  echo "Target properties:"
  "$ADB" shell getprop ro.product.name 2>/dev/null | sed 's/^/Product: /' || true
  "$ADB" shell getprop ro.build.display.id 2>/dev/null | sed 's/^/Build ID: /' || true
  "$ADB" shell getprop ro.boot.slot_suffix 2>/dev/null | sed 's/^/Slot suffix: /' || true
  echo

  echo "Memory sysfs root:"
  "$ADB" shell 'ls -ld /sys/devices/system/memory 2>&1' || true
  echo

  echo "block_size_bytes:"
  "$ADB" shell 'cat /sys/devices/system/memory/block_size_bytes 2>&1' || true
  echo

  echo "Present memory block directories:"
  "$ADB" shell 'for d in /sys/devices/system/memory/memory[0-9]*; do [ -d "$d" ] || continue; b=${d##*/}; printf "%s" "$b"; [ -r "$d/phys_index" ] && printf " phys_index=%s" "$(cat "$d/phys_index" 2>/dev/null)"; [ -r "$d/state" ] && printf " state=%s" "$(cat "$d/state" 2>/dev/null)"; [ -r "$d/valid_zones" ] && printf " valid_zones=%s" "$(cat "$d/valid_zones" 2>/dev/null)"; echo; done' || true
  echo

  echo "NUMA node memory links:"
  "$ADB" shell 'for n in /sys/devices/system/node/node*; do [ -d "$n" ] || continue; echo "node=${n##*/}"; ls -1 "$n"/memory[0-9]* 2>/dev/null | sed "s#^.*/##" || true; done' || true
  echo

  echo "Zoneinfo cross-check:"
  "$ADB" shell 'grep -E "^Node [0-9]+, zone|^[[:space:]]*(start_pfn|spanned|present|managed)" /proc/zoneinfo 2>/dev/null' || true
  echo

  echo "classification: SYSFS_PHYSICAL_MEMORY_BLOCK_EVIDENCE_COLLECTED"
  echo "decision: read-only sysfs memory-block metadata was collected. A listed memory block proves that some memory in its covered physical range is present, but a block may still contain holes; do not infer an FD-safe range from block presence alone. Reconcile block ranges with exact-device reservations and firmware placement constraints before any launch decision."
} | tee "$OUT"
