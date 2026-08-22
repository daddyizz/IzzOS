#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <recovery-evidence.txt>" >&2
  exit 2
fi

EVIDENCE="$1"
[[ -f "$EVIDENCE" ]] || { echo "ERROR: recovery evidence not found: $EVIDENCE" >&2; exit 2; }

required_fields=(
  "Device model/product"
  "OxygenOS build"
  "Current slot"
  "Slot count"
  "Bootloader unlocked"
  "Fastboot mode"
  "Stock image source"
  "Stock boot image verified"
  "Stock vendor_boot verified"
  "Stock dtbo verified"
  "Stock vbmeta verified"
  "Emergency recovery status"
  "Temporary route candidate"
  "Persistent write required"
  "Slot change required"
  "Recovery procedure reference"
)

bad_placeholder_regex='^(unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)?$'
missing=0

field_value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$EVIDENCE"
}

for field in "${required_fields[@]}"; do
  value="$(field_value "$field")"
  if [[ -z "$value" || "${value,,}" =~ $bad_placeholder_regex ]]; then
    echo "ERROR: required recovery field missing/placeholder: $field" >&2
    missing=1
  fi
done

persistent="$(field_value "Persistent write required" | tr '[:upper:]' '[:lower:]')"
slot_change="$(field_value "Slot change required" | tr '[:upper:]' '[:lower:]')"
stock_boot="$(field_value "Stock boot image verified" | tr '[:upper:]' '[:lower:]')"
stock_vendor_boot="$(field_value "Stock vendor_boot verified" | tr '[:upper:]' '[:lower:]')"
stock_dtbo="$(field_value "Stock dtbo verified" | tr '[:upper:]' '[:lower:]')"
stock_vbmeta="$(field_value "Stock vbmeta verified" | tr '[:upper:]' '[:lower:]')"

if [[ "$persistent" != "no" ]]; then
  echo "ERROR: recovery gate requires Persistent write required: NO" >&2
  missing=1
fi

if [[ "$slot_change" != "no" ]]; then
  echo "ERROR: recovery gate requires Slot change required: NO" >&2
  missing=1
fi

for pair in \
  "Stock boot image verified:$stock_boot" \
  "Stock vendor_boot verified:$stock_vendor_boot" \
  "Stock dtbo verified:$stock_dtbo" \
  "Stock vbmeta verified:$stock_vbmeta"; do
  key="${pair%%:*}"
  value="${pair#*:}"
  if [[ "$value" != "yes" ]]; then
    echo "ERROR: recovery gate requires $key: YES" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "classification: RECOVERY_EVIDENCE_BLOCKED"
  exit 1
fi

echo "classification: RECOVERY_EVIDENCE_COMPLETE"
echo "decision: rollback evidence is complete enough for route validation review; this does not itself authorize launch."
