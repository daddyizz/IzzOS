#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <vbmeta-metadata.txt>" >&2
  exit 2
fi

INPUT="$1"
[[ -f "$INPUT" ]] || { echo "ERROR: file not found: $INPUT" >&2; exit 2; }
text="$(tr -d '\r' < "$INPUT")"

extract_value() {
  local label="$1"
  printf '%s\n' "$text" | awk -F':[[:space:]]*' -v key="$label" '$1 ~ "^[[:space:]]*" key "$" {print $2; exit}'
}

minimum="$(extract_value 'Minimum libavb version')"
algorithm="$(extract_value 'Algorithm')"
rollback="$(extract_value 'Rollback Index')"
flags="$(extract_value 'Flags')"
release="$(extract_value 'Release String')"

chains="$(printf '%s\n' "$text" | awk '
  /Chain Partition descriptor:/ {inchain=1; next}
  inchain && /^[[:space:]]*Partition Name:/ {sub(/^[[:space:]]*Partition Name:[[:space:]]*/, ""); print; inchain=0}
')"

printf 'IzzOS stock vbmeta metadata analyzer\n'
printf '====================================\n'
printf 'Expected minimum libavb version: 1.0\n'
printf 'Expected algorithm: SHA256_RSA4096\n'
printf 'Expected top-level flags: 0\n'
printf 'Expected chained partitions: boot vendor_boot dtbo recovery vbmeta_system vbmeta_vendor\n\n'

echo "observed-minimum-libavb-version: ${minimum:-UNKNOWN}"
echo "observed-algorithm: ${algorithm:-UNKNOWN}"
echo "observed-rollback-index: ${rollback:-UNKNOWN}"
echo "observed-flags: ${flags:-UNKNOWN}"
echo "observed-release-string: ${release:-UNKNOWN}"

for p in boot vendor_boot dtbo recovery vbmeta_system vbmeta_vendor; do
  if grep -Fxq "$p" <<<"$chains"; then
    echo "chain-$p: present"
  else
    echo "chain-$p: missing"
  fi
done

status="AVB_METADATA_INCOMPLETE"
if [[ "$minimum" == "1.0" && "$algorithm" == "SHA256_RSA4096" && "$flags" == "0" ]]; then
  missing=0
  for p in boot vendor_boot dtbo recovery vbmeta_system vbmeta_vendor; do
    grep -Fxq "$p" <<<"$chains" || missing=1
  done
  if [[ $missing -eq 0 ]]; then
    status="AVB_TRUST_GRAPH_CONSISTENT"
  else
    status="AVB_CHAIN_MISMATCH_BLOCKED"
  fi
elif [[ -n "$minimum" && -n "$algorithm" && -n "$flags" ]]; then
  status="AVB_METADATA_MISMATCH_BLOCKED"
fi

echo "classification: $status"
case "$status" in
  AVB_TRUST_GRAPH_CONSISTENT)
    echo "decision: top-level vbmeta metadata and required chain partitions are structurally consistent. This closes the stock-image structure gate only; recovery and temporary launch-route validation remain required before any device launch."
    ;;
  *)
    echo "decision: keep route-specific packaging and device launch blocked until AVB metadata is complete and consistent."
    ;;
esac
