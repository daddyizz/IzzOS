#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-out/temporary-route-preflight.txt}"
mkdir -p "$(dirname "$OUT")"

if ! command -v fastboot >/dev/null 2>&1; then
  echo "ERROR: fastboot not found" >&2
  exit 2
fi

mapfile -t devices < <(fastboot devices | awk 'NF {print $1}')
if [[ ${#devices[@]} -ne 1 ]]; then
  echo "ERROR: expected exactly one fastboot device; found ${#devices[@]}" >&2
  exit 1
fi

getvar() {
  local key="$1"
  local out
  out="$(fastboot getvar "$key" 2>&1 || true)"
  printf '%s\n' "$out" \
    | tr -d '\r' \
    | sed -nE "s/^[[:space:]]*(\(bootloader\)[[:space:]]*)?${key}:[[:space:]]*//p" \
    | head -n1
}

product="$(getvar product)"
slot="$(getvar current-slot)"
slot_count="$(getvar slot-count)"
unlocked="$(getvar unlocked)"
secure="$(getvar secure)"
is_userspace="$(getvar is-userspace)"
max_download="$(getvar max-download-size)"

{
  echo "IzzOS temporary-route preflight"
  echo "================================"
  echo "Collector mode: READ_ONLY"
  echo "Device writes: NONE"
  echo "Launch commands executed: NO"
  echo "Flash/erase/format/set_active: FORBIDDEN"
  echo ""
  echo "Product: ${product:-UNKNOWN}"
  echo "Current slot: ${slot:-UNKNOWN}"
  echo "Slot count: ${slot_count:-UNKNOWN}"
  echo "Unlocked: ${unlocked:-UNKNOWN}"
  echo "Secure: ${secure:-UNKNOWN}"
  echo "Userspace fastboot: ${is_userspace:-UNKNOWN}"
  echo "Max download size: ${max_download:-UNKNOWN}"
} > "$OUT"

status="TEMPORARY_ROUTE_PREFLIGHT_INCOMPLETE"
if [[ "${is_userspace,,}" == "no" && "${unlocked,,}" == "yes" && "$slot_count" == "2" && -n "$slot" && "$slot" != "UNKNOWN" ]]; then
  status="TEMPORARY_ROUTE_PREFLIGHT_PASS"
fi

echo "classification: $status" >> "$OUT"
if [[ "$status" == "TEMPORARY_ROUTE_PREFLIGHT_PASS" ]]; then
  echo "decision: classic bootloader fastboot, unlocked state, and A/B slot context are confirmed. This validates preflight conditions only; it does not prove that the device accepts fastboot boot and does not authorize launch." >> "$OUT"
else
  echo "decision: keep temporary route and device launch blocked until preflight evidence is complete and consistent." >> "$OUT"
fi

cat "$OUT"
