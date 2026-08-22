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
git -C "${WORK_DIR}" submodule update --init --recursive

rm -rf "${WORK_DIR}/Platform/IzzOS"
mkdir -p "${WORK_DIR}/Platform"
cp -a "${ROOT_DIR}/uefi/Platform/IzzOS" "${WORK_DIR}/Platform/IzzOS"

pushd "${WORK_DIR}" >/dev/null
make -C BaseTools
export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"
source edksetup.sh
export GCC_AARCH64_PREFIX="${GCC_AARCH64_PREFIX:-aarch64-linux-gnu-}"
build -a AARCH64 -t GCC -b DEBUG -p Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc
popd >/dev/null

EFI_PATH="$(find "${WORK_DIR}/Build/OvaltineDiag" -type f -name 'OvaltineDiag.efi' -print -quit)"
if [[ -z "${EFI_PATH}" ]]; then
  echo "ERROR: OvaltineDiag.efi not found after build" >&2
  exit 1
fi

cp "${EFI_PATH}" "${OUT_DIR}/OvaltineDiag.efi"
printf 'IzzOS revision: %s\nEDK2 revision: %s\nTarget: OnePlus 10T 5G / ovaltine / SM8475\n' \
  "$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  "${EDK2_REV}" > "${OUT_DIR}/BUILD_INFO.txt"

echo "Built: ${OUT_DIR}/OvaltineDiag.efi"
