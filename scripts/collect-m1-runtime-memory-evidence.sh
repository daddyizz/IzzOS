#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-out/m1-runtime-memory-evidence.txt}"
mkdir -p "$(dirname "$OUT")"

if ! command -v adb >/dev/null 2>&1; then
  echo "ERROR: adb not found" >&2
  exit 2
fi

ADB_COUNT="$(adb devices 2>/dev/null | awk 'NR > 1 && $2 == "device" {count++} END {print count + 0}')"
if [[ "$ADB_COUNT" -ne 1 ]]; then
  echo "ERROR: expected exactly one authorized adb device; found $ADB_COUNT" >&2
  exit 1
fi

hex_remote_file() {
  local path="$1"
  if adb shell "test -r '$path'" >/dev/null 2>&1; then
    adb exec-out cat "$path" 2>/dev/null | od -An -tx1 -v | tr -d ' \n'
  else
    printf 'UNAVAILABLE'
  fi
}

text_prop() {
  local key="$1"
  adb shell getprop "$key" 2>/dev/null | tr -d '\r\n'
}

DT_BASE=""
for candidate in /proc/device-tree /sys/firmware/devicetree/base; do
  if adb shell "test -d '$candidate'" >/dev/null 2>&1; then
    DT_BASE="$candidate"
    break
  fi
done

{
  echo "IzzOS M1 runtime memory evidence"
  echo "================================"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo "Target product: $(text_prop ro.product.name)"
  echo "Target device: $(text_prop ro.product.device)"
  echo "Build ID: $(text_prop ro.build.display.id)"
  echo "Slot suffix: $(text_prop ro.boot.slot_suffix)"
  echo "Device-tree base: ${DT_BASE:-UNAVAILABLE}"
  echo

  if [[ -n "$DT_BASE" ]]; then
    memory_reg="$(hex_remote_file "$DT_BASE/memory/reg")"
    if [[ "$memory_reg" == "UNAVAILABLE" ]]; then
      memory_reg="$(hex_remote_file "$DT_BASE/memory@0/reg")"
    fi
    echo "Memory reg hex: $memory_reg"

    echo "Reserved-memory nodes:"
    if adb shell "test -d '$DT_BASE/reserved-memory'" >/dev/null 2>&1; then
      while IFS= read -r node; do
        [[ -n "$node" ]] || continue
        clean="${node%$'\r'}"
        case "$clean" in
          '#address-cells'|'#size-cells'|ranges|name) continue ;;
        esac
        if ! adb shell "test -d '$DT_BASE/reserved-memory/$clean'" >/dev/null 2>&1; then
          continue
        fi
        reg="$(hex_remote_file "$DT_BASE/reserved-memory/$clean/reg")"
        no_map="no"
        reusable="no"
        adb shell "test -e '$DT_BASE/reserved-memory/$clean/no-map'" >/dev/null 2>&1 && no_map="yes"
        adb shell "test -e '$DT_BASE/reserved-memory/$clean/reusable'" >/dev/null 2>&1 && reusable="yes"
        printf '  %s | reg=%s | no-map=%s | reusable=%s\n' "$clean" "$reg" "$no_map" "$reusable"
      done < <(adb shell "ls -1 '$DT_BASE/reserved-memory' 2>/dev/null" | tr -d '\r' | LC_ALL=C sort)
    else
      echo "  UNAVAILABLE"
    fi

    echo "Chosen usable-memory-range hex: $(hex_remote_file "$DT_BASE/chosen/linux,usable-memory-range")"
  else
    echo "Memory reg hex: UNAVAILABLE"
    echo "Reserved-memory nodes:"
    echo "  UNAVAILABLE"
    echo "Chosen usable-memory-range hex: UNAVAILABLE"
  fi

  echo
  echo "Proc iomem snapshot:"
  adb shell cat /proc/iomem 2>/dev/null | tr -d '\r' || echo "UNAVAILABLE"
  echo
  echo "Proc meminfo summary:"
  adb shell "grep -E '^(MemTotal|MemFree|MemAvailable|CmaTotal|CmaFree):' /proc/meminfo 2>/dev/null" | tr -d '\r' || true
} > "$OUT"

memory_hex="$(awk -F': ' '$1 == "Memory reg hex" {print $2; exit}' "$OUT")"
classification="M1_RUNTIME_MEMORY_EVIDENCE_INCOMPLETE"
if [[ -n "$memory_hex" && "$memory_hex" != "UNAVAILABLE" && "$memory_hex" != "00000000000000000000000000000000" ]]; then
  classification="M1_RUNTIME_MEMORY_EVIDENCE_CAPTURED"
fi

echo "classification: $classification" >> "$OUT"
if [[ "$classification" == "M1_RUNTIME_MEMORY_EVIDENCE_CAPTURED" ]]; then
  echo "decision: runtime-patched DRAM evidence was captured. This does not yet select a firmware load range; reserved-memory and overlap analysis are still required before Ovaltine.dsc/Ovaltine.fdf or device launch." >> "$OUT"
else
  echo "decision: runtime DRAM evidence is missing or unusable. Keep standalone firmware layout and device launch blocked." >> "$OUT"
fi

cat "$OUT"
