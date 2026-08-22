#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <metadata.txt>" >&2
  echo "Input should be text produced by a boot-image inspection tool such as unpack_bootimg." >&2
  exit 2
fi

INPUT="$1"
if [[ ! -f "$INPUT" ]]; then
  echo "ERROR: file not found: $INPUT" >&2
  exit 2
fi

text="$(tr -d '\r' < "$INPUT")"

extract_first() {
  local pattern="$1"
  printf '%s\n' "$text" | sed -nE "s/.*${pattern}.*/\\1/p" | head -n1
}

header="$(extract_first '[Hh]eader[^0-9]*version[^0-9]*([0-9]+)')"
pagesize="$(extract_first '[Pp]age[^0-9]*size[^0-9]*([0-9]+)')"

printf 'IzzOS stock boot metadata analyzer\n'
printf '==================================\n'
printf 'Expected source-backed boot header: 4\n'
printf 'Expected source-backed kernel page size: 4096\n\n'

if [[ -n "$header" ]]; then
  echo "observed-header-version: $header"
else
  echo "observed-header-version: UNKNOWN"
fi

if [[ -n "$pagesize" ]]; then
  echo "observed-page-size: $pagesize"
else
  echo "observed-page-size: UNKNOWN"
fi

status="INCOMPLETE_METADATA"
if [[ -n "$header" && -n "$pagesize" ]]; then
  if [[ "$header" == "4" && "$pagesize" == "4096" ]]; then
    status="MATCHES_SOURCE_EXPECTATION"
  else
    status="MISMATCH_HARD_STOP"
  fi
fi

echo "classification: $status"

case "$status" in
  MATCHES_SOURCE_EXPECTATION)
    echo "decision: metadata is consistent with current source-backed expectation, but route-specific packaging remains blocked until exact vendor_boot/DTBO/AVB and recovery gates are verified."
    ;;
  MISMATCH_HARD_STOP)
    echo "decision: stop automatic packaging; exact stock firmware format differs from current source-backed expectation."
    ;;
  *)
    echo "decision: insufficient metadata; do not infer or generate a route-specific package."
    ;;
esac
