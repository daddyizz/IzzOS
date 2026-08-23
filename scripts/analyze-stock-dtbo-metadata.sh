#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <dtbo-metadata.txt>" >&2
  exit 2
fi

INPUT="$1"
[[ -f "$INPUT" ]] || { echo "ERROR: file not found: $INPUT" >&2; exit 2; }

text="$(tr -d '\r' < "$INPUT")"

field() {
  local name="$1"
  printf '%s\n' "$text" | sed -nE "s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\\1/p" | head -n1
}

magic="$(field 'magic')"
total_size="$(field 'total_size')"
header_size="$(field 'header_size')"
entry_size="$(field 'dt_entry_size')"
entry_count="$(field 'dt_entry_count')"
entries_offset="$(field 'dt_entries_offset')"
page_size="$(field 'page_size')"
version="$(field 'version')"

printf 'IzzOS stock DTBO metadata analyzer\n'
printf '==================================\n'
printf 'Expected DTBO magic: d7b7ab1e\n'
printf 'Expected page size: 4096\n\n'

echo "observed-magic: ${magic:-UNKNOWN}"
echo "observed-total-size: ${total_size:-UNKNOWN}"
echo "observed-header-size: ${header_size:-UNKNOWN}"
echo "observed-entry-size: ${entry_size:-UNKNOWN}"
echo "observed-entry-count: ${entry_count:-UNKNOWN}"
echo "observed-entries-offset: ${entries_offset:-UNKNOWN}"
echo "observed-page-size: ${page_size:-UNKNOWN}"
echo "observed-version: ${version:-UNKNOWN}"

status="INCOMPLETE_METADATA"
if [[ -n "$magic" && -n "$page_size" && -n "$entry_count" && -n "$version" ]]; then
  if [[ "$magic" == "d7b7ab1e" && "$page_size" == "4096" && "$entry_count" =~ ^[1-9][0-9]*$ ]]; then
    status="DTBO_STRUCTURE_CONSISTENT"
  else
    status="DTBO_STRUCTURE_MISMATCH_BLOCKED"
  fi
fi

echo "classification: $status"

case "$status" in
  DTBO_STRUCTURE_CONSISTENT)
    echo "decision: DTBO table structure is internally consistent for read-only analysis. Continue to independent AVB/vbmeta verification; route-specific packaging remains blocked."
    ;;
  DTBO_STRUCTURE_MISMATCH_BLOCKED)
    echo "decision: stop route-specific packaging; DTBO structure differs from the expected Android DT table invariants."
    ;;
  *)
    echo "decision: insufficient DTBO metadata; do not infer overlay layout or authorize route-specific packaging."
    ;;
esac
