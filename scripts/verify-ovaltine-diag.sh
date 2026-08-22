#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out/ovaltine-diag}"
EFI_FILE="${OUT_DIR}/OvaltineDiag.efi"
SUM_FILE="${OUT_DIR}/SHA256SUMS"
INFO_FILE="${OUT_DIR}/BUILD_INFO.txt"

for path in "${EFI_FILE}" "${SUM_FILE}" "${INFO_FILE}"; do
  if [[ ! -s "${path}" ]]; then
    echo "ERROR: expected non-empty build artifact missing: ${path}" >&2
    exit 1
  fi
done

(
  cd "${OUT_DIR}"
  sha256sum -c SHA256SUMS
)

FILE_DESC="$(file -b "${EFI_FILE}")"
echo "Artifact format: ${FILE_DESC}"

if [[ "${FILE_DESC}" != *"PE32+"* ]]; then
  echo "ERROR: OvaltineDiag.efi is not reported as PE32+" >&2
  exit 1
fi

if [[ "${FILE_DESC,,}" != *"aarch64"* && "${FILE_DESC,,}" != *"arm64"* ]]; then
  echo "ERROR: OvaltineDiag.efi is not reported as AArch64/ARM64" >&2
  exit 1
fi

if ! grep -Fq 'Target: OnePlus 10T 5G / ovaltine / SM8475' "${INFO_FILE}"; then
  echo "ERROR: BUILD_INFO.txt target metadata is missing or unexpected" >&2
  exit 1
fi

echo "OvaltineDiag artifact verification passed."
