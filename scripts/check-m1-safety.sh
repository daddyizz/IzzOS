#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/uefi/Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag"

if [[ ! -d "${TARGET_DIR}" ]]; then
  echo "ERROR: OvaltineDiag source directory not found: ${TARGET_DIR}" >&2
  exit 1
fi

# M1 is intentionally read-only. These patterns represent APIs or helpers that
# could write storage, modify firmware state, write MMIO, or leave boot services.
SOURCE_FORBIDDEN_REGEX='gBS->ExitBootServices|gRT->SetVariable|gEfiBlockIoProtocolGuid|gEfiDiskIoProtocolGuid|->WriteBlocks[[:space:]]*\(|->WriteDisk[[:space:]]*\(|MmioWrite(8|16|32|64)[[:space:]]*\(|IoWrite(8|16|32|64)[[:space:]]*\('

if grep -RInE --include='*.c' --include='*.h' "${SOURCE_FORBIDDEN_REGEX}" "${TARGET_DIR}"; then
  echo
  echo "ERROR: M1 safety gate detected a forbidden write/destructive API pattern." >&2
  echo "OvaltineDiag must remain read-only until a later milestone explicitly changes this policy." >&2
  exit 1
fi

# Prevent storage protocols from being declared in module metadata even if the
# current C source does not yet call them. M1 has no BlockIo/DiskIo dependency.
INF_FORBIDDEN_REGEX='gEfi(BlockIo|DiskIo)ProtocolGuid'

if grep -RInE --include='*.inf' "${INF_FORBIDDEN_REGEX}" "${TARGET_DIR}"; then
  echo
  echo "ERROR: M1 safety gate detected a forbidden storage protocol declaration in INF metadata." >&2
  echo "OvaltineDiag must not declare BlockIo or DiskIo during M1." >&2
  exit 1
fi

echo "M1 safety gate passed: no forbidden write/destructive APIs or storage protocol declarations detected."
