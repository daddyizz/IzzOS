#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <vendor-boot-metadata.txt>" >&2
  exit 2
fi

INPUT="$1"
[[ -f "$INPUT" ]] || { echo "ERROR: file not found: $INPUT" >&2; exit 2; }

text="$(tr -d '\r' < "$INPUT")"

extract_first() {
  local pattern="$1"
  printf '%s\n' "$text" | sed -nE "s/.*${pattern}.*/\\1/p" | head -n1
}

header="$(extract_first '[Vv]endor boot image header version:[[:space:]]*([0-9]+)')"
pagesize_hex="$(extract_first '[Pp]age size:[[:space:]]*(0x[0-9A-Fa-f]+)')"
dtb_size="$(extract_first '[Dd]tb size:[[:space:]]*([0-9]+)')"
ramdisk_total="$(extract_first '[Vv]endor ramdisk total size:[[:space:]]*([0-9]+)')"
ramdisk_table="$(extract_first '[Vv]endor ramdisk table size:[[:space:]]*([0-9]+)')"
bootconfig_size="$(extract_first '[Vv]endor bootconfig size:[[:space:]]*([0-9]+)')"

pagesize_dec=""
if [[ -n "$pagesize_hex" ]]; then
  pagesize_dec="$((pagesize_hex))"
fi

printf 'IzzOS stock vendor_boot metadata analyzer\n'
printf '=========================================\n'
printf 'Expected vendor_boot header: 4\n'
printf 'Expected page size: 4096\n\n'

echo "observed-header-version: ${header:-UNKNOWN}"
echo "observed-page-size: ${pagesize_dec:-UNKNOWN}"
echo "observed-dtb-size: ${dtb_size:-UNKNOWN}"
echo "observed-vendor-ramdisk-total-size: ${ramdisk_total:-UNKNOWN}"
echo "observed-vendor-ramdisk-table-size: ${ramdisk_table:-UNKNOWN}"
echo "observed-vendor-bootconfig-size: ${bootconfig_size:-UNKNOWN}"

status="INCOMPLETE_METADATA"
if [[ -n "$header" && -n "$pagesize_dec" ]]; then
  if [[ "$header" == "4" && "$pagesize_dec" == "4096" ]]; then
    if [[ -n "$dtb_size" && "$dtb_size" -gt 0 && -n "$ramdisk_total" && "$ramdisk_total" -gt 0 && -n "$ramdisk_table" && "$ramdisk_table" -gt 0 ]]; then
      status="MATCHES_SOURCE_EXPECTATION"
    fi
  else
    status="MISMATCH_HARD_STOP"
  fi
fi

echo "classification: $status"
case "$status" in
  MATCHES_SOURCE_EXPECTATION)
    echo "decision: vendor_boot metadata is structurally consistent with the current source-backed expectation. Continue to independent DTBO and AVB verification; route-specific packaging remains blocked."
    ;;
  MISMATCH_HARD_STOP)
    echo "decision: stop automatic packaging; exact vendor_boot format differs from the current source-backed expectation."
    ;;
  *)
    echo "decision: insufficient vendor_boot metadata; do not infer missing structure or generate a route-specific package."
    ;;
esac
