#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <inspection-output.txt> <m2-staging-manifest.txt> <stock-manifest> [stock-manifest ...]" >&2
  exit 2
fi

INSPECTION="$1"
STAGING="$2"
shift 2
STOCK_MANIFESTS=("$@")

for path in "$INSPECTION" "$STAGING" "${STOCK_MANIFESTS[@]}"; do
  [[ -f "$path" ]] || { echo "ERROR: required evidence file missing: $path" >&2; exit 2; }
done

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

inspection_value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$INSPECTION" | trim
}

manifest_value() {
  local file="$1"
  local key="$2"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$file" | trim
}

DEVICE="$(inspection_value device || true)"
PRODUCT="$(inspection_value product || true)"
BUILD_ID="$(inspection_value build-id || true)"
STAGE_TARGET="$(manifest_value "$STAGING" Target || true)"
STAGE_FIRMWARE="$(manifest_value "$STAGING" 'Firmware ID' || true)"
STAGE_ROUTE="$(manifest_value "$STAGING" 'Selected launch route' || true)"
STAGE_WRITES="$(manifest_value "$STAGING" 'Persistent writes' || true)"
STAGE_SLOT_CHANGES="$(manifest_value "$STAGING" 'Slot changes' || true)"

blocked=0

if [[ "${DEVICE,,}" != "ovaltine" ]]; then
  echo "ERROR: inspection device is not ovaltine: ${DEVICE:-UNKNOWN}" >&2
  blocked=1
fi

if [[ -z "$BUILD_ID" ]]; then
  echo "ERROR: inspection build-id is missing" >&2
  blocked=1
fi

if [[ "$STAGE_TARGET" != *"OnePlus 10T"* || "$STAGE_TARGET" != *"SM8475"* ]]; then
  echo "ERROR: staging target is unexpected: ${STAGE_TARGET:-UNKNOWN}" >&2
  blocked=1
fi

if [[ "$STAGE_ROUTE" != "NONE" && "$STAGE_ROUTE" != "TEMPORARY_ROUTE_VALIDATED" ]]; then
  echo "ERROR: staging route state is not an allowed evidence state: ${STAGE_ROUTE:-UNKNOWN}" >&2
  blocked=1
fi

if [[ "$STAGE_WRITES" != "FORBIDDEN" || "$STAGE_SLOT_CHANGES" != "FORBIDDEN" ]]; then
  echo "ERROR: staging safety invariants changed" >&2
  blocked=1
fi

first_stock_device=""
first_stock_build=""
for manifest in "${STOCK_MANIFESTS[@]}"; do
  stock_device="$(manifest_value "$manifest" 'Device model/product' || true)"
  stock_build="$(manifest_value "$manifest" 'OxygenOS build' || true)"
  stock_role="$(manifest_value "$manifest" 'Image role' || true)"

  if [[ -z "$stock_device" || -z "$stock_build" || -z "$stock_role" ]]; then
    echo "ERROR: incomplete stock manifest: $manifest" >&2
    blocked=1
    continue
  fi

  if [[ -z "$first_stock_device" ]]; then
    first_stock_device="$stock_device"
    first_stock_build="$stock_build"
  else
    if [[ "$stock_device" != "$first_stock_device" || "$stock_build" != "$first_stock_build" ]]; then
      echo "ERROR: stock image set is not from one device/build" >&2
      blocked=1
    fi
  fi

done

if [[ -n "$first_stock_build" && "$first_stock_build" != "$BUILD_ID" ]]; then
  echo "ERROR: stock image build ($first_stock_build) does not match inspected device build ($BUILD_ID)" >&2
  blocked=1
fi

if [[ -n "$STAGE_FIRMWARE" && "$STAGE_FIRMWARE" != "UNVALIDATED-FIRMWARE" && "$STAGE_FIRMWARE" != "CI-UNVALIDATED" && "$STAGE_FIRMWARE" != "$BUILD_ID" ]]; then
  echo "ERROR: staging firmware ID ($STAGE_FIRMWARE) does not match inspected device build ($BUILD_ID)" >&2
  blocked=1
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: M2_EVIDENCE_BUNDLE_BLOCKED"
  exit 1
fi

echo "classification: M2_EVIDENCE_BUNDLE_CONSISTENT"
echo "device: ${DEVICE}"
echo "product: ${PRODUCT:-unknown}"
echo "build-id: ${BUILD_ID}"
echo "stock-image-count: ${#STOCK_MANIFESTS[@]}"
echo "decision: evidence is internally consistent, but this does not validate or execute a temporary boot route."
