#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <OvaltineDiag.efi> <output-dir> [firmware-id]" >&2
  exit 2
fi

EFI_INPUT="$1"
OUT_DIR="$2"
FIRMWARE_ID="${3:-UNVALIDATED-FIRMWARE}"

if [[ ! -f "${EFI_INPUT}" ]]; then
  echo "ERROR: EFI payload not found: ${EFI_INPUT}" >&2
  exit 2
fi

if ! command -v file >/dev/null 2>&1; then
  echo "ERROR: 'file' command is required" >&2
  exit 2
fi

CLASSIFICATION="$(file "${EFI_INPUT}")"
if ! grep -Eq 'PE32\+.*EFI.*(ARM64|Aarch64|aarch64)' <<<"${CLASSIFICATION}"; then
  echo "ERROR: payload is not recognized as a PE32+ ARM64 EFI application" >&2
  echo "Detected: ${CLASSIFICATION}" >&2
  exit 1
fi

EFI_SHA256="$(sha256sum "${EFI_INPUT}" | awk '{print $1}')"
EFI_SIZE="$(stat -c '%s' "${EFI_INPUT}")"
IZZOS_REV="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

STAGE_DIR="${OUT_DIR%/}/${FIRMWARE_ID}"
PAYLOAD_DIR="${STAGE_DIR}/payload"
DERIVED_DIR="${STAGE_DIR}/derived"
LOG_DIR="${STAGE_DIR}/logs"

mkdir -p "${PAYLOAD_DIR}" "${DERIVED_DIR}" "${LOG_DIR}"
cp "${EFI_INPUT}" "${PAYLOAD_DIR}/OvaltineDiag.efi"
printf '%s  OvaltineDiag.efi\n' "${EFI_SHA256}" > "${PAYLOAD_DIR}/SHA256SUMS"

cat > "${STAGE_DIR}/manifest.txt" <<EOF
IzzOS source revision: ${IZZOS_REV}
Payload: OvaltineDiag.efi
Payload size: ${EFI_SIZE} bytes
Payload SHA256: ${EFI_SHA256}
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: ${FIRMWARE_ID}
Expected slot topology: UNVALIDATED
Expected bootloader mode: UNVALIDATED
Selected launch route: NONE
Route decision: INSUFFICIENT_DEVICE_DATA
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: NONE
EOF

cat > "${LOG_DIR}/packaging-report.txt" <<EOF
Route-neutral staging created successfully.
No boot image was generated.
No fastboot command was generated.
No partition write command was generated.
The derived directory must remain empty until TEMPORARY_ROUTE_VALIDATED.
Payload classification: ${CLASSIFICATION}
EOF

if find "${DERIVED_DIR}" -mindepth 1 -print -quit | grep -q .; then
  echo "ERROR: derived directory is not empty after route-neutral staging" >&2
  exit 1
fi

echo "M2 route-neutral staging prepared: ${STAGE_DIR}"
echo "Payload SHA256: ${EFI_SHA256}"
echo "Route decision: INSUFFICIENT_DEVICE_DATA"
