#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
PREBUILT_DIR="$(cd "${1:-$TREE_DIR/prebuilt}" && pwd -P)"
check() {
  local rel="$1" size="$2" file="$PREBUILT_DIR/$1"
  [ -f "$file" ] && [ ! -L "$file" ] || { echo "Missing regular prebuilt: $file" >&2; exit 1; }
  [ "$(stat -c '%s' "$file")" = "$size" ] || { echo "Unexpected size: $rel" >&2; exit 1; }
  case "$(realpath -e "$file")" in "$PREBUILT_DIR"/*) ;; *) exit 1 ;; esac
}
check kernel 48113892
check dtbo.img 25165824
check dtbs/stock.dtb 1434126
(cd "$PREBUILT_DIR" && sha256sum -c "$TREE_DIR/prebuilt/BUILD_SHA256SUMS")
