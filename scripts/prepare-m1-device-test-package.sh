#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 9 ]]; then
  echo "Usage: $0 <OvaltineDiag.efi> <payload-manifest.txt> <inspection.txt> <m2-manifest.txt> <recovery-evidence.txt> <route-evidence.txt> <exact-stock-hash-lock.txt> <output-dir> <stock-manifest...>" >&2
  exit 2
fi

EFI="$1"
PAYLOAD_MANIFEST="$2"
INSPECTION="$3"
M2_MANIFEST="$4"
RECOVERY="$5"
ROUTE_EVIDENCE="$6"
STOCK_HASH_LOCK="$7"
OUTPUT_ROOT="$8"
shift 8
STOCK_MANIFESTS=("$@")

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for f in "$EFI" "$PAYLOAD_MANIFEST" "$INSPECTION" "$M2_MANIFEST" "$RECOVERY" "$ROUTE_EVIDENCE" "$STOCK_HASH_LOCK" "${STOCK_MANIFESTS[@]}"; do
  [[ -f "$f" ]] || { echo "ERROR: required input missing: $f" >&2; exit 2; }
done

value() {
  local file="$1" key="$2"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$file"
}

PAYLOAD_ID="$(value "$PAYLOAD_MANIFEST" 'Payload ID')"
EXPECTED_SHA="$(value "$PAYLOAD_MANIFEST" 'EFI SHA256')"
EXPECTED_SIZE="$(value "$PAYLOAD_MANIFEST" 'EFI size bytes')"
PAYLOAD_STATUS="$(value "$PAYLOAD_MANIFEST" 'Status')"
FIRMWARE_ID="$(value "$M2_MANIFEST" 'Firmware ID')"
ROUTE="$(value "$M2_MANIFEST" 'Selected launch route')"
ROUTE_DECISION="$(value "$M2_MANIFEST" 'Route decision')"

ACTUAL_SHA="$(sha256sum "$EFI" | awk '{print $1}')"
ACTUAL_SIZE="$(wc -c < "$EFI" | tr -d '[:space:]')"

if [[ "$PAYLOAD_STATUS" != "CURRENT_M1_DEVICE_TEST_CANDIDATE" ]]; then
  echo "ERROR: payload manifest is not current" >&2
  exit 1
fi
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" || "$ACTUAL_SIZE" != "$EXPECTED_SIZE" ]]; then
  echo "ERROR: EFI does not match pinned current payload manifest" >&2
  exit 1
fi

READINESS_OUT="$(bash "$ROOT_DIR/scripts/report-m2-readiness.sh" "$INSPECTION" "$M2_MANIFEST" "$RECOVERY" "$ROUTE_EVIDENCE" "$STOCK_HASH_LOCK" "${STOCK_MANIFESTS[@]}" 2>&1)" || {
  echo "$READINESS_OUT" >&2
  echo "ERROR: host-side M2 readiness gates are not complete" >&2
  exit 1
}
if ! grep -q '^classification: READY_FOR_ROUTE_SPECIFIC_PACKAGING$' <<<"$READINESS_OUT"; then
  echo "ERROR: readiness report did not authorize route-specific packaging" >&2
  exit 1
fi

case "$ROUTE" in
  ""|NONE)
    echo "ERROR: no concrete validated route selected" >&2
    exit 1
    ;;
esac
if [[ "$ROUTE_DECISION" != "TEMPORARY_ROUTE_VALIDATED" ]]; then
  echo "ERROR: route is not TEMPORARY_ROUTE_VALIDATED" >&2
  exit 1
fi

# Keep '-' last in the tr set so GNU/BSD tr cannot interpret it as a range.
SAFE_ID="$(printf '%s' "$FIRMWARE_ID" | tr -cs 'A-Za-z0-9._()-' '_')"
PACKAGE_DIR="$OUTPUT_ROOT/${SAFE_ID}/${PAYLOAD_ID}"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/payload" "$PACKAGE_DIR/evidence/route" "$PACKAGE_DIR/evidence/stock" "$PACKAGE_DIR/notes"

cp "$EFI" "$PACKAGE_DIR/payload/OvaltineDiag.efi"
cp "$PAYLOAD_MANIFEST" "$PACKAGE_DIR/payload/M1_CURRENT_PAYLOAD.txt"
cp "$INSPECTION" "$PACKAGE_DIR/evidence/device-inspection.txt"
cp "$M2_MANIFEST" "$PACKAGE_DIR/evidence/m2-route-manifest.txt"
cp "$RECOVERY" "$PACKAGE_DIR/evidence/recovery-evidence.txt"
cp "$ROUTE_EVIDENCE" "$PACKAGE_DIR/evidence/route/$(basename "$ROUTE_EVIDENCE")"
cp "$STOCK_HASH_LOCK" "$PACKAGE_DIR/evidence/stock/exact-stock-hash-lock.txt"

ROUTE_EVIDENCE_DIR="$(cd "$(dirname "$ROUTE_EVIDENCE")" && pwd)"
while IFS='|' read -r _role artifact_name _size _sha; do
  [[ -n "${artifact_name:-}" ]] || continue
  cp "$ROUTE_EVIDENCE_DIR/$artifact_name" "$PACKAGE_DIR/evidence/route/$artifact_name"
done < <(awk -F': ' '$1 == "Artifact record" {sub("^[^:]+:[[:space:]]*", ""); print}' "$ROUTE_EVIDENCE")

index=0
for manifest in "${STOCK_MANIFESTS[@]}"; do
  index=$((index + 1))
  role="$(value "$manifest" 'Image role')"
  [[ -n "$role" ]] || role="stock-$index"
  cp "$manifest" "$PACKAGE_DIR/evidence/stock/${index}-${role}.txt"
done

cat > "$PACKAGE_DIR/PACKAGE_INFO.txt" <<EOF
IzzOS M1 device-test package
Payload ID: $PAYLOAD_ID
Firmware ID: $FIRMWARE_ID
Selected launch route: $ROUTE
Route decision: $ROUTE_DECISION
EFI SHA256: $ACTUAL_SHA
EFI size bytes: $ACTUAL_SIZE
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Launch commands included: NO
Device commands executed by assembler: NO
Package classification: M1_DEVICE_TEST_PACKAGE_ASSEMBLED

This package is evidence-bound preparation only. It intentionally contains no adb/fastboot/flash/erase/unlock/set_active command and does not itself authorize execution on a device.
EOF

(
  cd "$PACKAGE_DIR"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

# Block executable-looking device commands, while allowing documentation that
# merely names forbidden commands in prose. A command must begin a line (aside
# from optional whitespace) to trigger this gate.
if grep -RIEq --exclude='SHA256SUMS' -- '^[[:space:]]*(fastboot[[:space:]]+(flash|erase|format|flashing|oem|set_active|boot)|adb[[:space:]]+reboot|flashall)([[:space:]]|$)' "$PACKAGE_DIR"; then
  echo "ERROR: forbidden device command line found in assembled package" >&2
  rm -rf "$PACKAGE_DIR"
  exit 1
fi

echo "classification: M1_DEVICE_TEST_PACKAGE_ASSEMBLED"
echo "package-dir: $PACKAGE_DIR"
echo "payload-id: $PAYLOAD_ID"
echo "firmware-id: $FIRMWARE_ID"
echo "efi-sha256: $ACTUAL_SHA"
echo "decision: package contains only the verified payload and auditable evidence; launch remains a separate manual gate."
