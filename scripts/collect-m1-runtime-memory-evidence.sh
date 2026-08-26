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
  local data

  # Android's adb exec-out can surface the remote toybox/cat diagnostic on the
  # data stream even when the property itself is unreadable. Probe readability
  # with the remote shell exit status first so strings such as "Permission
  # denied" can never be hex-encoded and mistaken for DT cell data.
  if ! adb shell "cat '$path' >/dev/null 2>&1" >/dev/null 2>&1; then
    printf 'UNAVAILABLE'
    return
  fi

  data="$(adb exec-out cat "$path" 2>/dev/null | od -An -tx1 -v | tr -d ' \n' || true)"
  if [[ -n "$data" && "$data" =~ ^[0-9a-fA-F]+$ && $(( ${#data} % 2 )) -eq 0 ]]; then
    printf '%s' "$data"
  else
    printf 'UNAVAILABLE'
  fi
}

text_prop() {
  local key="$1"
  adb shell getprop "$key" 2>/dev/null | tr -d '\r\n'
}

safe_shell() {
  adb shell "$1" 2>/dev/null | tr -d '\r' || true
}

DT_BASE=""
for candidate in /proc/device-tree /sys/firmware/devicetree/base; do
  if adb shell "test -d '$candidate'" >/dev/null 2>&1; then
    DT_BASE="$candidate"
    break
  fi
done

PAGE_SIZE="$(safe_shell 'getconf PAGESIZE 2>/dev/null || toybox getconf PAGESIZE 2>/dev/null' | head -n1)"
[[ "$PAGE_SIZE" =~ ^[0-9]+$ ]] || PAGE_SIZE="UNAVAILABLE"

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
  echo "Kernel page size: $PAGE_SIZE"
  echo "Device-tree base: ${DT_BASE:-UNAVAILABLE}"
  echo

  if [[ -n "$DT_BASE" ]]; then
    echo "Device-tree access diagnostics:"
    safe_shell "ls -ldZ '$DT_BASE' '$DT_BASE/memory' '$DT_BASE/memory@0' '$DT_BASE/reserved-memory' 2>/dev/null"
    echo

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
    echo "Device-tree access diagnostics: UNAVAILABLE"
    echo "Memory reg hex: UNAVAILABLE"
    echo "Reserved-memory nodes:"
    echo "  UNAVAILABLE"
    echo "Chosen usable-memory-range hex: UNAVAILABLE"
  fi

  echo
  echo "Raw FDT fallback:"
  if adb shell "test -e /sys/firmware/fdt" >/dev/null 2>&1; then
    safe_shell "ls -lZ /sys/firmware/fdt"
    fdt_size="$(safe_shell 'stat -c %s /sys/firmware/fdt 2>/dev/null' | head -n1)"
    [[ "$fdt_size" =~ ^[0-9]+$ ]] || fdt_size="UNAVAILABLE"
    echo "FDT size: $fdt_size"
    if adb shell "dd if=/sys/firmware/fdt bs=32 count=1 of=/dev/null 2>/dev/null" >/dev/null 2>&1; then
      echo "FDT first 32 bytes hex: $(adb exec-out dd if=/sys/firmware/fdt bs=32 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n' || true)"
    else
      echo "FDT first 32 bytes hex: UNAVAILABLE"
    fi
  else
    echo "UNAVAILABLE"
  fi

  echo
  echo "Proc iomem snapshot:"
  iomem="$(safe_shell 'cat /proc/iomem')"
  if [[ -n "$iomem" ]]; then
    printf '%s\n' "$iomem"
  else
    echo "UNAVAILABLE"
  fi

  echo
  echo "Proc zoneinfo physical-page fallback:"
  zoneinfo="$(safe_shell "awk '/^Node [0-9]+, zone / {print; next} /^[[:space:]]+start_pfn:/ {print; next} /^[[:space:]]+spanned[[:space:]]+/ {print; next} /^[[:space:]]+present[[:space:]]+/ {print; next} /^[[:space:]]+managed[[:space:]]+/ {print; next}' /proc/zoneinfo")"
  if [[ -n "$zoneinfo" ]]; then
    printf '%s\n' "$zoneinfo"
  else
    echo "UNAVAILABLE"
  fi

  echo
  echo "Sysfs memory-block fallback:"
  block_size="$(safe_shell 'cat /sys/devices/system/memory/block_size_bytes 2>/dev/null' | head -n1)"
  if [[ -n "$block_size" ]]; then
    echo "block_size_bytes: $block_size"
    safe_shell "for d in /sys/devices/system/memory/memory[0-9]*; do [ -d \"\$d\" ] || continue; i=\$(basename \"\$d\"); p=\$(cat \"\$d/phys_index\" 2>/dev/null); s=\$(cat \"\$d/state\" 2>/dev/null); printf '%s phys_index=%s state=%s\\n' \"\$i\" \"\$p\" \"\$s\"; done"
  else
    echo "UNAVAILABLE"
  fi

  echo
  echo "Boot property memory hints:"
  safe_shell "getprop | grep -E '\\[ro\\.boot\\..*(mem|ddr|ram)|\\[ro\\.hardware\\.ram|\\[ro\\.config\\.low_ram'"

  echo
  echo "Proc meminfo summary:"
  safe_shell "grep -E '^(MemTotal|MemFree|MemAvailable|CmaTotal|CmaFree):' /proc/meminfo"
} > "$OUT"

memory_hex="$(awk -F': ' '$1 == "Memory reg hex" {print $2; exit}' "$OUT")"
zone_start="$(awk '$1 == "start_pfn:" && $2 ~ /^[0-9]+$/ {print $2; exit}' "$OUT")"
block_size="$(awk -F': ' '$1 == "block_size_bytes" {print $2; exit}' "$OUT")"
classification="M1_RUNTIME_MEMORY_EVIDENCE_INCOMPLETE"
if [[ -n "$memory_hex" && "$memory_hex" != "UNAVAILABLE" && "$memory_hex" =~ ^[0-9a-fA-F]+$ && ${#memory_hex} -ge 32 && $(( ${#memory_hex} % 16 )) -eq 0 && "$memory_hex" != "00000000000000000000000000000000" ]]; then
  classification="M1_RUNTIME_MEMORY_EVIDENCE_CAPTURED"
elif [[ -n "$zone_start" || -n "$block_size" ]]; then
  classification="M1_RUNTIME_MEMORY_FALLBACK_EVIDENCE_CAPTURED"
fi

echo "classification: $classification" >> "$OUT"
case "$classification" in
  M1_RUNTIME_MEMORY_EVIDENCE_CAPTURED)
    echo "decision: runtime-patched DT DRAM evidence was captured. This does not yet select a firmware load range; reserved-memory and overlap analysis are still required before Ovaltine.dsc/Ovaltine.fdf or device launch." >> "$OUT"
    ;;
  M1_RUNTIME_MEMORY_FALLBACK_EVIDENCE_CAPTURED)
    echo "decision: direct DT DRAM cells remain restricted, but kernel-exposed physical-memory fallback evidence was captured. Analyze it conservatively and do not select an FD range unless it can be reconciled with reserved-memory exclusions and exact-device evidence." >> "$OUT"
    ;;
  *)
    echo "decision: runtime DRAM evidence is missing or unusable. Keep standalone firmware layout and device launch blocked." >> "$OUT"
    ;;
esac

cat "$OUT"
