#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /absolute/path/to/OrangeFox_14.1" >&2
  exit 2
fi

FOX_SOURCE="$(cd "$1" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

for required in \
  "$TREE_DIR/prebuilt/kernel" \
  "$TREE_DIR/prebuilt/dtbs/stock.dtb" \
  "$TREE_DIR/prebuilt/dtbo.img"; do
  if [ ! -s "$required" ]; then
    echo "Missing prebuilt: $required" >&2
    echo "Run scripts/import-stock.sh first." >&2
    exit 1
  fi
done

if [ ! -f "$FOX_SOURCE/build/envsetup.sh" ]; then
  echo "Not an initialized OrangeFox 14.1 source tree: $FOX_SOURCE" >&2
  exit 1
fi

TARGET_TREE="$FOX_SOURCE/device/oneplus/ovaltine"
mkdir -p "$(dirname "$TARGET_TREE")"
rm -rf "$TARGET_TREE"
cp -a "$TREE_DIR" "$TARGET_TREE"
rm -rf "$TARGET_TREE/.git" "$TARGET_TREE/.github"

export ALLOW_MISSING_DEPENDENCIES=true
export FOX_BUILD_DEVICE=ovaltine
export FOX_BUILD_TYPE=Alpha
export FOX_USE_TWRP_RECOVERY_IMAGE_BUILDER=1
export ALLOW_NINJA_ENV=true
export LC_ALL=C

# Keep Soong below a 14 GiB container/runner memory limit. The Go analysis
# phase, rather than Ninja compilation, was the previous OOM point.
: "${GOMAXPROCS:=2}"
: "${GOMEMLIMIT:=10GiB}"
: "${SOONG_UI_NINJA_ARGS:=-j1 -l1}"
export GOMAXPROCS GOMEMLIMIT SOONG_UI_NINJA_ARGS

cd "$FOX_SOURCE"
source build/envsetup.sh
lunch twrp_ovaltine-ap2a-eng
m -j1 recoveryimage

OUT_PATH="${OUT_DIR:-$FOX_SOURCE/out}/target/product/ovaltine"
echo "Build output: $OUT_PATH"
find "$OUT_PATH" -maxdepth 1 -type f \( -name 'recovery.img' -o -name 'OrangeFox-*' \) -print
