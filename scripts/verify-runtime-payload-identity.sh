#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <runtime-output.txt> <payload-manifest.txt> <OvaltineDiag.efi>" >&2
  exit 2
fi

RUNTIME="$1"
MANIFEST="$2"
EFI="$3"

for f in "$RUNTIME" "$MANIFEST" "$EFI"; do
  [[ -f "$f" ]] || { echo "ERROR: required file missing: $f" >&2; exit 2; }
done

value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$MANIFEST"
}

manifest_id="$(value 'Payload ID')"
manifest_schema="$(value 'Identity schema')"
manifest_sha="$(value 'EFI SHA256')"
manifest_size="$(value 'EFI size bytes')"
manifest_status="$(value 'Status')"

runtime_line="$(grep -m1 -E '^\[IDENTITY\] payload-id=' "$RUNTIME" || true)"
runtime_id="$(printf '%s\n' "$runtime_line" | sed -n 's/.*payload-id=\([^ ]*\).*/\1/p')"
runtime_schema="$(printf '%s\n' "$runtime_line" | sed -n 's/.*schema=\([0-9][0-9]*\).*/\1/p')"

actual_sha="$(sha256sum "$EFI" | awk '{print $1}')"
actual_size="$(wc -c < "$EFI" | tr -d '[:space:]')"

blocked=0
placeholder='^(unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)?$'
for pair in \
  "manifest payload id|$manifest_id" \
  "manifest schema|$manifest_schema" \
  "manifest sha|$manifest_sha" \
  "manifest size|$manifest_size" \
  "runtime payload id|$runtime_id" \
  "runtime schema|$runtime_schema"; do
  label="${pair%%|*}"
  val="${pair#*|}"
  if [[ "${val,,}" =~ $placeholder ]]; then
    echo "ERROR: identity field missing/placeholder: $label" >&2
    blocked=1
  fi
done

if [[ "$manifest_status" != "CURRENT_M1_DEVICE_TEST_CANDIDATE" ]]; then
  echo "ERROR: payload manifest is not marked CURRENT_M1_DEVICE_TEST_CANDIDATE" >&2
  blocked=1
fi

if [[ -n "$runtime_id" && -n "$manifest_id" && "$runtime_id" != "$manifest_id" ]]; then
  echo "ERROR: runtime payload ID does not match pinned manifest" >&2
  blocked=1
fi
if [[ -n "$runtime_schema" && -n "$manifest_schema" && "$runtime_schema" != "$manifest_schema" ]]; then
  echo "ERROR: runtime identity schema does not match pinned manifest" >&2
  blocked=1
fi
if [[ "$actual_sha" != "$manifest_sha" ]]; then
  echo "ERROR: EFI SHA256 does not match pinned manifest" >&2
  blocked=1
fi
if [[ "$actual_size" != "$manifest_size" ]]; then
  echo "ERROR: EFI size does not match pinned manifest" >&2
  blocked=1
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: RUNTIME_PAYLOAD_IDENTITY_BLOCKED"
  exit 1
fi

echo "classification: RUNTIME_PAYLOAD_IDENTITY_VERIFIED"
echo "payload-id: $manifest_id"
echo "identity-schema: $manifest_schema"
echo "efi-sha256: $actual_sha"
echo "efi-size-bytes: $actual_size"
echo "decision: runtime identity and the exact EFI artifact match the pinned M1 payload manifest; this does not authorize a device launch route."
