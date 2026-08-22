#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <provenance-manifest.txt>" >&2
  exit 2
fi

MANIFEST="$1"
[[ -f "$MANIFEST" ]] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 2; }

required_fields=(
  "Device model/product"
  "OxygenOS build"
  "Image role"
  "Image file"
  "Image size bytes"
  "Image SHA256"
  "Image source"
  "Extraction method"
)

bad_placeholder_regex='^(unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)?$'

missing=0
for field in "${required_fields[@]}"; do
  value="$(awk -F': ' -v key="$field" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$MANIFEST")"
  if [[ -z "$value" || "${value,,}" =~ $bad_placeholder_regex ]]; then
    echo "ERROR: required provenance field missing/placeholder: $field" >&2
    missing=1
  fi
done

sha="$(awk -F': ' '$1 == "Image SHA256" {print $2; exit}' "$MANIFEST" | tr 'A-F' 'a-f')"
size="$(awk -F': ' '$1 == "Image size bytes" {print $2; exit}' "$MANIFEST")"

if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: Image SHA256 must be exactly 64 hexadecimal characters" >&2
  missing=1
fi

if [[ ! "$size" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: Image size bytes must be a positive integer" >&2
  missing=1
fi

if [[ "$missing" -ne 0 ]]; then
  echo "classification: PROVENANCE_INCOMPLETE_BLOCKED"
  exit 1
fi

echo "classification: PROVENANCE_COMPLETE"
echo "decision: provenance is auditable, but this does not authorize route-specific packaging or device launch."
