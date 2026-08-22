#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <provenance-manifest-1.txt> <provenance-manifest-2.txt> [...]" >&2
  exit 2
fi

extract_field() {
  local manifest="$1"
  local field="$2"
  awk -F': ' -v key="$field" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$manifest"
}

reference_device=""
reference_build=""
roles_seen=""

for manifest in "$@"; do
  [[ -f "$manifest" ]] || { echo "ERROR: manifest not found: $manifest" >&2; exit 2; }
  bash "$(dirname "$0")/verify-stock-image-provenance.sh" "$manifest" >/dev/null

  device="$(extract_field "$manifest" "Device model/product")"
  build="$(extract_field "$manifest" "OxygenOS build")"
  role="$(extract_field "$manifest" "Image role")"

  if [[ -z "$reference_device" ]]; then
    reference_device="$device"
    reference_build="$build"
  fi

  if [[ "$device" != "$reference_device" ]]; then
    echo "ERROR: device mismatch in stock image set: $manifest" >&2
    echo "classification: STOCK_IMAGE_SET_MISMATCH_BLOCKED"
    exit 1
  fi

  if [[ "$build" != "$reference_build" ]]; then
    echo "ERROR: OxygenOS build mismatch in stock image set: $manifest" >&2
    echo "classification: STOCK_IMAGE_SET_MISMATCH_BLOCKED"
    exit 1
  fi

  if grep -Fxq "$role" <<<"$roles_seen"; then
    echo "ERROR: duplicate image role in stock image set: $role" >&2
    echo "classification: STOCK_IMAGE_SET_DUPLICATE_ROLE_BLOCKED"
    exit 1
  fi
  roles_seen="${roles_seen}${roles_seen:+$'\n'}${role}"
done

echo "classification: STOCK_IMAGE_SET_CONSISTENT"
echo "Device model/product: $reference_device"
echo "OxygenOS build: $reference_build"
echo "Image count: $#"
echo "decision: image manifests are mutually consistent, but this does not authorize route-specific packaging or device launch."
