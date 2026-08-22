#!/usr/bin/env bash
set -euo pipefail

EDK2_REV="${EDK2_REV:-d98a39d4ceeb7204b33fc330fdfee8cdb5ddbb43}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-${ROOT_DIR}/.work/edk2}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out/ovaltine-diag}"

mkdir -p "$(dirname "${WORK_DIR}")" "${OUT_DIR}"

if [[ ! -d "${WORK_DIR}/.git" ]]; then
  git clone https://github.com/tianocore/edk2.git "${WORK_DIR}"
fi

git -C "${WORK_DIR}" fetch origin "${EDK2_REV}" --depth=1
git -C "${WORK_DIR}" checkout --detach "${EDK2_REV}"

# OvaltineDiag uses only MdePkg plus BaseTools. Avoid cloning every EDK2
# third-party submodule. BaseTools requires Brotli, while MdePkg.dec exposes
# the MipiSysT include directory unconditionally, so both must be present.
git -C "${WORK_DIR}" submodule update --init --depth=1 \
  BaseTools/Source/C/BrotliCompress/brotli \
  MdePkg/Library/MipiSysTLib/mipisyst

rm -rf "${WORK_DIR}/Platform/IzzOS"
mkdir -p "${WORK_DIR}/Platform"
cp -a "${ROOT_DIR}/uefi/Platform/IzzOS" "${WORK_DIR}/Platform/IzzOS"

pushd "${WORK_DIR}" >/dev/null
make -C BaseTools
export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"
# edksetup.sh references variables before defining them, so temporarily
# disable nounset while sourcing upstream EDK2's environment setup.
set +u
source edksetup.sh
set -u
export GCC_AARCH64_PREFIX="${GCC_AARCH64_PREFIX:-aarch64-linux-gnu-}"
build -a AARCH64 -t GCC -b DEBUG -p Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc
popd >/dev/null

EFI_PATH="$(find "${WORK_DIR}/Build/OvaltineDiag" -type f -name 'OvaltineDiag.efi' -print -quit)"
if [[ -z "${EFI_PATH}" ]]; then
  echo "ERROR: OvaltineDiag.efi not found after build" >&2
  exit 1
fi

EFI_OUT="${OUT_DIR}/OvaltineDiag.efi"
cp "${EFI_PATH}" "${EFI_OUT}"

IZZOS_REV="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
EFI_SIZE="$(stat -c '%s' "${EFI_OUT}")"
EFI_SHA256="$(sha256sum "${EFI_OUT}" | awk '{print $1}')"

printf 'IzzOS revision: %s\nEDK2 revision: %s\nTarget: OnePlus 10T 5G / ovaltine / SM8475\nEFI file: OvaltineDiag.efi\nEFI size: %s bytes\nEFI SHA256: %s\n' \
  "${IZZOS_REV}" \
  "${EDK2_REV}" \
  "${EFI_SIZE}" \
  "${EFI_SHA256}" > "${OUT_DIR}/BUILD_INFO.txt"

printf '%s  %s\n' "${EFI_SHA256}" "OvaltineDiag.efi" > "${OUT_DIR}/SHA256SUMS"

echo "Built: ${EFI_OUT}"
echo "SHA256: ${EFI_SHA256}"
