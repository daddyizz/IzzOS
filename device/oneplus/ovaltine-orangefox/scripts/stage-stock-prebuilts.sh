#!/usr/bin/env bash
set -Eeuo pipefail
[ "$#" -eq 1 ] || { echo "Usage: $0 /secure/prebuilts" >&2; exit 2; }
SRC="$(cd "$1" && pwd -P)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
case "$SRC/" in "$TREE_DIR/"*) exit 1 ;; esac
for p in prebuilt/kernel prebuilt/dtbo.img prebuilt/dtbs/stock.dtb; do git -C "$TREE_DIR" check-ignore -q "$p" || { echo "Unignored stock path: $p" >&2; exit 1; }; done
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
install -d "$tmp/dtbs"
install -m 0644 "$SRC/kernel" "$tmp/kernel"
install -m 0644 "$SRC/dtbo.img" "$tmp/dtbo.img"
install -m 0644 "$SRC/dtbs/stock.dtb" "$tmp/dtbs/stock.dtb"
"$SCRIPT_DIR/verify-stock-prebuilts.sh" "$tmp"
install -d "$TREE_DIR/prebuilt/dtbs"
install -m 0644 "$tmp/kernel" "$TREE_DIR/prebuilt/kernel"
install -m 0644 "$tmp/dtbo.img" "$TREE_DIR/prebuilt/dtbo.img"
install -m 0644 "$tmp/dtbs/stock.dtb" "$TREE_DIR/prebuilt/dtbs/stock.dtb"
"$SCRIPT_DIR/verify-stock-prebuilts.sh"
