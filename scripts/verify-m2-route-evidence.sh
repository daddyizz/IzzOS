#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <m2-manifest.txt> <route-evidence.txt>" >&2
  exit 2
fi

MANIFEST="$1"
EVIDENCE="$2"
[[ -f "$MANIFEST" ]] || { echo "ERROR: M2 manifest not found: $MANIFEST" >&2; exit 2; }
[[ -f "$EVIDENCE" ]] || { echo "ERROR: route evidence not found: $EVIDENCE" >&2; exit 2; }

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

value() {
  local file="$1" key="$2"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$file" | trim
}

field_count() {
  local file="$1" key="$2"
  awk -F': ' -v key="$key" '$1 == key {count++} END {print count + 0}' "$file"
}

required_fields=(
  "Schema"
  "Target"
  "Firmware ID"
  "Selected launch route"
  "Route decision"
  "Device execution observed"
  "Diagnostic payload reached"
  "Controlled result recorded"
  "Stock boot restored"
  "Persistent writes observed"
  "Slot change observed"
  "User data mutation observed"
  "Required artifact roles"
)

manifest_required_fields=(
  "Target"
  "Firmware ID"
  "Selected launch route"
  "Route decision"
  "Persistent writes"
  "Slot changes"
  "Route validation evidence reference"
)

blocked=0
for field in "${required_fields[@]}"; do
  count="$(field_count "$EVIDENCE" "$field")"
  if [[ "$count" -ne 1 ]]; then
    echo "ERROR: route evidence field must appear exactly once: $field (found $count)" >&2
    blocked=1
  fi
done
for field in "${manifest_required_fields[@]}"; do
  count="$(field_count "$MANIFEST" "$field")"
  if [[ "$count" -ne 1 ]]; then
    echo "ERROR: M2 manifest field must appear exactly once: $field (found $count)" >&2
    blocked=1
  fi
done

schema="$(value "$EVIDENCE" 'Schema' || true)"
target="$(value "$EVIDENCE" 'Target' || true)"
firmware="$(value "$EVIDENCE" 'Firmware ID' || true)"
route="$(value "$EVIDENCE" 'Selected launch route' || true)"
decision="$(value "$EVIDENCE" 'Route decision' || true)"
device_execution="$(value "$EVIDENCE" 'Device execution observed' || true)"
payload_reached="$(value "$EVIDENCE" 'Diagnostic payload reached' || true)"
controlled_result="$(value "$EVIDENCE" 'Controlled result recorded' || true)"
stock_restored="$(value "$EVIDENCE" 'Stock boot restored' || true)"
writes_observed="$(value "$EVIDENCE" 'Persistent writes observed' || true)"
slot_change="$(value "$EVIDENCE" 'Slot change observed' || true)"
userdata_mutation="$(value "$EVIDENCE" 'User data mutation observed' || true)"
required_roles="$(value "$EVIDENCE" 'Required artifact roles' || true)"

manifest_target="$(value "$MANIFEST" 'Target' || true)"
manifest_firmware="$(value "$MANIFEST" 'Firmware ID' || true)"
manifest_route="$(value "$MANIFEST" 'Selected launch route' || true)"
manifest_decision="$(value "$MANIFEST" 'Route decision' || true)"
manifest_reference="$(value "$MANIFEST" 'Route validation evidence reference' || true)"

if [[ "$schema" != "IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1" ]]; then
  echo "ERROR: unsupported route evidence schema: ${schema:-MISSING}" >&2
  blocked=1
fi

if [[ "$target" != *"OnePlus 10T"* || "$target" != *"SM8475"* || "$manifest_target" != *"OnePlus 10T"* || "$manifest_target" != *"SM8475"* ]]; then
  echo "ERROR: route evidence/manifest target is not the expected OnePlus 10T / SM8475 target" >&2
  blocked=1
fi

placeholder='^(unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)?$'
if [[ "${firmware,,}" =~ $placeholder || "$firmware" != "$manifest_firmware" ]]; then
  echo "ERROR: route evidence firmware does not match the exact manifest firmware" >&2
  blocked=1
fi

if [[ "${route,,}" =~ $placeholder || "$route" != "$manifest_route" ]]; then
  echo "ERROR: route evidence route does not match the selected manifest route" >&2
  blocked=1
fi

if [[ "$decision" != "TEMPORARY_ROUTE_VALIDATED" || "$manifest_decision" != "TEMPORARY_ROUTE_VALIDATED" ]]; then
  echo "ERROR: route evidence and manifest must both record TEMPORARY_ROUTE_VALIDATED" >&2
  blocked=1
fi

for pair in \
  "Device execution observed|$device_execution" \
  "Diagnostic payload reached|$payload_reached" \
  "Controlled result recorded|$controlled_result" \
  "Stock boot restored|$stock_restored"; do
  label="${pair%%|*}"
  observed="${pair#*|}"
  if [[ "$observed" != "YES" ]]; then
    echo "ERROR: route evidence requires $label: YES" >&2
    blocked=1
  fi
done

for pair in \
  "Persistent writes observed|$writes_observed" \
  "Slot change observed|$slot_change" \
  "User data mutation observed|$userdata_mutation"; do
  label="${pair%%|*}"
  observed="${pair#*|}"
  if [[ "$observed" != "NO" ]]; then
    echo "ERROR: route evidence requires $label: NO" >&2
    blocked=1
  fi
done

if [[ -z "$manifest_reference" || "$manifest_reference" != "$(basename "$manifest_reference")" || "$manifest_reference" != "$(basename "$EVIDENCE")" ]]; then
  echo "ERROR: route evidence reference must be the exact evidence basename with no path component" >&2
  blocked=1
fi

expected_roles="before-state route-transcript diagnostic-output after-state"
if [[ "$required_roles" != "$expected_roles" ]]; then
  echo "ERROR: required route artifact roles must be exactly: $expected_roles" >&2
  blocked=1
fi

mapfile -t records < <(awk -F': ' '$1 == "Artifact record" {sub("^[^:]+:[[:space:]]*", ""); print}' "$EVIDENCE")
if [[ "${#records[@]}" -ne 4 ]]; then
  echo "ERROR: route evidence must contain exactly four Artifact record lines" >&2
  blocked=1
fi

declare -A seen_roles=()
declare -A seen_files=()
evidence_dir="$(cd "$(dirname "$EVIDENCE")" && pwd)"
for record in "${records[@]}"; do
  IFS='|' read -r role file expected_size expected_sha extra <<<"$record"
  if [[ -n "${extra:-}" || -z "${role:-}" || -z "${file:-}" || -z "${expected_size:-}" || -z "${expected_sha:-}" ]]; then
    echo "ERROR: malformed Artifact record: $record" >&2
    blocked=1
    continue
  fi

  case "$role" in
    before-state|route-transcript|diagnostic-output|after-state) ;;
    *) echo "ERROR: unexpected route artifact role: $role" >&2; blocked=1; continue ;;
  esac

  if [[ -n "${seen_roles[$role]:-}" ]]; then
    echo "ERROR: duplicate route artifact role: $role" >&2
    blocked=1
    continue
  fi
  seen_roles[$role]=1

  if [[ "$file" != "$(basename "$file")" || "$file" == "." || "$file" == ".." ]]; then
    echo "ERROR: route artifact filename must be a basename: $file" >&2
    blocked=1
    continue
  fi
  if [[ -n "${seen_files[$file]:-}" ]]; then
    echo "ERROR: route artifact filename is reused by multiple roles: $file" >&2
    blocked=1
    continue
  fi
  seen_files[$file]=1
  if [[ ! "$expected_size" =~ ^[0-9]+$ || ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: malformed size/SHA256 for route artifact: $file" >&2
    blocked=1
    continue
  fi

  artifact="$evidence_dir/$file"
  if [[ ! -f "$artifact" ]]; then
    echo "ERROR: route artifact missing beside evidence: $file" >&2
    blocked=1
    continue
  fi

  actual_size="$(stat -c '%s' "$artifact")"
  actual_sha="$(sha256sum "$artifact" | awk '{print $1}')"
  if [[ "$actual_size" != "$expected_size" || "$actual_sha" != "$expected_sha" ]]; then
    echo "ERROR: route artifact content mismatch: $file" >&2
    blocked=1
  fi
done

for role in before-state route-transcript diagnostic-output after-state; do
  if [[ -z "${seen_roles[$role]:-}" ]]; then
    echo "ERROR: required route artifact role missing: $role" >&2
    blocked=1
  fi
done

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: TEMPORARY_ROUTE_EVIDENCE_BLOCKED"
  exit 1
fi

echo "classification: TEMPORARY_ROUTE_EVIDENCE_CONTENT_BOUND"
echo "firmware-id: $firmware"
echo "selected-route: $route"
echo "artifact-count: ${#records[@]}"
echo "content-binding: PASS"
echo "decision: the referenced physical-route evidence is internally consistent and unchanged; independent authenticity and launch authorization remain separate gates."
