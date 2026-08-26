#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=android-platform-tools.sh
source "$ROOT_DIR/scripts/android-platform-tools.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/path" "$TMP/sdk/platform-tools" "$TMP/home-sdk/platform-tools"
for tool in adb fastboot; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/path/$tool"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/sdk/platform-tools/$tool"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/home-sdk/platform-tools/$tool"
  chmod +x "$TMP/path/$tool" "$TMP/sdk/platform-tools/$tool" "$TMP/home-sdk/platform-tools/$tool"
done

resolved="$(ANDROID_SDK_ROOT="$TMP/sdk" ANDROID_HOME="$TMP/home-sdk" LOCALAPPDATA= PATH="$TMP/path:$PATH" izzos_resolve_android_tool adb)"
[[ "$resolved" == "$TMP/sdk/platform-tools/adb" ]]

resolved="$(ANDROID_SDK_ROOT= ANDROID_HOME="$TMP/home-sdk" LOCALAPPDATA= PATH="$TMP/path:$PATH" izzos_resolve_android_tool fastboot)"
[[ "$resolved" == "$TMP/home-sdk/platform-tools/fastboot" ]]

resolved="$(ANDROID_SDK_ROOT="$TMP/sdk" ANDROID_HOME= LOCALAPPDATA= PATH="$TMP/path:$PATH" izzos_resolve_android_tool adb "$TMP/path/adb")"
[[ "$resolved" == "$TMP/path/adb" ]]

if ANDROID_SDK_ROOT= ANDROID_HOME= LOCALAPPDATA= PATH="$TMP/path:$PATH" izzos_resolve_android_tool adb "$TMP/missing-adb" >/dev/null 2>&1; then
  echo 'ERROR: invalid explicit override must not silently fall back' >&2
  exit 1
fi

echo 'Android Platform-Tools deterministic selection tests: PASS'
