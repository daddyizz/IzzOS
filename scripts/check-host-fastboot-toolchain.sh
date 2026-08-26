#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=android-platform-tools.sh
source "$SCRIPT_DIR/android-platform-tools.sh"

FASTBOOT_TOOL="$(izzos_resolve_android_tool fastboot "${FASTBOOT_BIN:-}" || true)"

if [[ -z "$FASTBOOT_TOOL" ]]; then
  echo "classification: HOST_FASTBOOT_TOOLCHAIN_BLOCKED"
  echo "reason: fastboot not found"
  exit 1
fi

version_out="$("$FASTBOOT_TOOL" --version 2>&1 || true)"
version="$(printf '%s\n' "$version_out" | sed -nE 's/^fastboot version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)"

printf 'IzzOS host fastboot toolchain check\n'
printf '===================================\n'
echo "fastboot-selection: deterministic resolver (override, SDK, then PATH)"
echo "fastboot-version: ${version:-UNKNOWN}"

if [[ -z "$version" ]]; then
  echo "classification: HOST_FASTBOOT_TOOLCHAIN_BLOCKED"
  echo "decision: legacy or unversioned fastboot detected. Do not use it for route validation or temporary boot of modern Android boot-header-v4 images; install current official Android SDK Platform-Tools first."
  exit 1
fi

major="${version%%.*}"
if [[ "$major" -lt 37 ]]; then
  echo "classification: HOST_FASTBOOT_TOOLCHAIN_BLOCKED"
  echo "decision: fastboot is older than the project minimum (37.x). Update to current official Android SDK Platform-Tools before route validation."
  exit 1
fi

echo "classification: HOST_FASTBOOT_TOOLCHAIN_PASS"
echo "decision: current-generation versioned fastboot is present. This is a host-tooling prerequisite only and does not authorize device launch."
