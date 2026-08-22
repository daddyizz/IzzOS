#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <current-inspection.txt> <m2-manifest.txt> <recovery-evidence.txt>" >&2
  exit 2
fi

INSPECTION="$1"
MANIFEST="$2"
RECOVERY="$3"
for f in "$INSPECTION" "$MANIFEST" "$RECOVERY"; do
  [[ -f "$f" ]] || { echo "ERROR: evidence file not found: $f" >&2; exit 2; }
done

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

inspection_value() {
  local key="$1"
  awk -v key="$key:" 'index($0,key)==1 {sub("^[^:]+:[[:space:]]*",""); print; exit}' "$INSPECTION" | trim
}

manifest_value() {
  local file="$1" key="$2"
  awk -F': ' -v key="$key" '$1==key {sub("^[^:]+:[[:space:]]*",""); print; exit}' "$file" | trim
}

CURRENT_MODEL="$(inspection_value model || true)"
CURRENT_PRODUCT="$(inspection_value product || true)"
CURRENT_BUILD="$(inspection_value build-id || true)"
CURRENT_SLOT="$(inspection_value slot-suffix || true)"

MANIFEST_FIRMWARE="$(manifest_value "$MANIFEST" 'Firmware ID' || true)"
RECOVERY_MODEL="$(manifest_value "$RECOVERY" 'Device model/product' || true)"
RECOVERY_BUILD="$(manifest_value "$RECOVERY" 'OxygenOS build' || true)"
RECOVERY_SLOT="$(manifest_value "$RECOVERY" 'Current slot' || true)"

blocked=0
placeholder='^(unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)?$'
for pair in \
  "current model|$CURRENT_MODEL" \
  "current product|$CURRENT_PRODUCT" \
  "current build|$CURRENT_BUILD" \
  "manifest firmware|$MANIFEST_FIRMWARE" \
  "recovery model|$RECOVERY_MODEL" \
  "recovery build|$RECOVERY_BUILD"; do
  label="${pair%%|*}"; value="${pair#*|}"
  if [[ "${value,,}" =~ $placeholder ]]; then
    echo "ERROR: freshness evidence missing/placeholder: $label" >&2
    blocked=1
  fi
done

if [[ -n "$CURRENT_BUILD" && -n "$MANIFEST_FIRMWARE" && "$CURRENT_BUILD" != "$MANIFEST_FIRMWARE" ]]; then
  echo "ERROR: current device build differs from route manifest firmware" >&2
  blocked=1
fi
if [[ -n "$CURRENT_BUILD" && -n "$RECOVERY_BUILD" && "$CURRENT_BUILD" != "$RECOVERY_BUILD" ]]; then
  echo "ERROR: current device build differs from recovery evidence build" >&2
  blocked=1
fi
if [[ -n "$CURRENT_PRODUCT" && -n "$RECOVERY_MODEL" && "${RECOVERY_MODEL,,}" != *"${CURRENT_PRODUCT,,}"* && "${RECOVERY_MODEL,,}" != *"${CURRENT_MODEL,,}"* ]]; then
  echo "ERROR: current device identity differs from recovery evidence" >&2
  blocked=1
fi

if [[ -n "$CURRENT_SLOT" && -n "$RECOVERY_SLOT" ]]; then
  normalized_slot="${CURRENT_SLOT#_}"
  if [[ "$normalized_slot" != "$RECOVERY_SLOT" ]]; then
    echo "ERROR: current slot differs from recovery evidence slot" >&2
    blocked=1
  fi
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: EVIDENCE_STALE_OR_MISMATCHED_BLOCKED"
  exit 1
fi

echo "classification: EVIDENCE_FRESH_FOR_CURRENT_DEVICE_STATE"
echo "current-build: $CURRENT_BUILD"
echo "decision: evidence matches the current inspected firmware/device state; this does not itself authorize launch."
