#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DOC="${1:-docs/M1_STANDALONE_FIRMWARE_BRINGUP.md}"
PLATFORM_DSC="uefi/Platform/IzzOS/OvaltinePkg/Ovaltine.dsc"
PLATFORM_FDF="uefi/Platform/IzzOS/OvaltinePkg/Ovaltine.fdf"

blocked=0

if [[ ! -f "$EVIDENCE_DOC" ]]; then
  echo "ERROR: standalone firmware bring-up evidence document not found: $EVIDENCE_DOC" >&2
  blocked=1
fi

if [[ -f "$EVIDENCE_DOC" ]]; then
  if ! grep -q '^`M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED`$' "$EVIDENCE_DOC"; then
    echo "ERROR: standalone firmware evidence state is not explicitly recorded" >&2
    blocked=1
  fi
fi

if [[ -f "$PLATFORM_DSC" || -f "$PLATFORM_FDF" ]]; then
  if [[ ! -f "$PLATFORM_DSC" || ! -f "$PLATFORM_FDF" ]]; then
    echo "ERROR: standalone platform DSC/FDF must be introduced as a reviewed pair" >&2
    blocked=1
  fi
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: M1_STANDALONE_FIRMWARE_SOURCE_INCONSISTENT"
  echo "decision: keep standalone firmware build and device launch blocked until the source/evidence state is internally consistent."
  exit 1
fi

if [[ ! -f "$PLATFORM_DSC" && ! -f "$PLATFORM_FDF" ]]; then
  echo "standalone-platform-dsc: NOT_YET_CREATED"
  echo "standalone-platform-fdf: NOT_YET_CREATED"
  echo "memory-layout-evidence: REQUIRED"
  echo "classification: M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED"
  echo "decision: current diagnostic EFI remains an application only. Derive and review exact SM8475 memory/entry evidence before creating launch-oriented Ovaltine.dsc/Ovaltine.fdf. No device launch is authorized."
  exit 0
fi

echo "standalone-platform-dsc: PRESENT"
echo "standalone-platform-fdf: PRESENT"
echo "classification: M1_STANDALONE_FIRMWARE_SOURCE_PRESENT_UNVALIDATED"
echo "decision: standalone source files exist, but their mere presence or successful compilation does not authorize packaging or device launch; independent memory-layout and firmware-artifact validation are still required."
