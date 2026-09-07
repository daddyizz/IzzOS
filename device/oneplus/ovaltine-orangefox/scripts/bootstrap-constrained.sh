#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: bootstrap-constrained.sh /absolute/OrangeFox_14.1 /absolute/OrangeFox_sync

Environment overrides:
  REPO_BIN=/path/to/repo    Android repo launcher (default: repo from PATH)
  SYNC_JOBS=4               repo sync workers
  DROP_REPO_CACHE=0         delete .repo only when explicitly requested
  DROP_CLONE_METADATA=0     delete sparse-clone .git only when requested
  REPO_NO_VERIFY=0          set to 1 only where gpg-agent cannot run
  REPO_REV=                 optional repo implementation revision
EOF
  exit 2
}

[ "$#" -eq 2 ] || usage

FOX_SOURCE="$1"
FOX_SYNC="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TREE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_BIN="${REPO_BIN:-$(command -v repo || true)}"
SYNC_JOBS="${SYNC_JOBS:-4}"
DROP_REPO_CACHE="${DROP_REPO_CACHE:-0}"
DROP_CLONE_METADATA="${DROP_CLONE_METADATA:-0}"
REPO_NO_VERIFY="${REPO_NO_VERIFY:-0}"
REPO_REV="${REPO_REV:-}"

case "$FOX_SOURCE" in
  /*) ;;
  *) echo "FOX source path must be absolute: $FOX_SOURCE" >&2; exit 2 ;;
esac

case "$FOX_SYNC" in
  /*) ;;
  *) echo "OrangeFox sync path must be absolute: $FOX_SYNC" >&2; exit 2 ;;
esac

[ -n "$REPO_BIN" ] && [ -x "$REPO_BIN" ] || {
  echo "Android repo launcher was not found. Set REPO_BIN=/absolute/path/repo." >&2
  exit 1
}

[ -f "$TREE_DIR/manifests/ovaltine-qpr3.xml" ] || {
  echo "Missing pinned QPR3 manifest." >&2
  exit 1
}

[ -f "$FOX_SYNC/patches/patch-manifest-fox_14.1.diff" ] || {
  echo "Not an OrangeFox sync checkout: $FOX_SYNC" >&2
  exit 1
}

if [ -d "$FOX_SOURCE" ] && \
   [ -n "$(find "$FOX_SOURCE" -mindepth 1 -maxdepth 1 -print -quit)" ] && \
   [ ! -f "$FOX_SOURCE/.repo/manifest.xml" ]; then
  echo "Refusing non-empty directory without an Android repo checkout: $FOX_SOURCE" >&2
  exit 1
fi

mkdir -p "$FOX_SOURCE"
FOX_SOURCE="$(cd "$FOX_SOURCE" && pwd -P)"

case "$FOX_SOURCE/" in
  "$TREE_DIR/"*|"$TREE_DIR/")
    echo "FOX source must not be inside the device-tree checkout." >&2
    exit 1
    ;;
esac
case "$TREE_DIR/" in
  "$FOX_SOURCE/"*)
    echo "Device-tree checkout must not be inside FOX source." >&2
    exit 1
    ;;
esac

safe_delete() {
  local target="$1"
  case "$target" in
    "$FOX_SOURCE"/*) ;;
    *) echo "Refusing to delete outside source root: $target" >&2; exit 1 ;;
  esac
  [ "$target" != "$FOX_SOURCE" ] || {
    echo "Refusing to delete source root." >&2
    exit 1
  }
  [ ! -e "$target" ] || find "$target" -depth -delete
}

clone_sparse() {
  local url="$1" branch="$2" dest="$3"
  shift 3
  safe_delete "$dest"
  git clone --depth=1 --filter=blob:none --sparse --branch "$branch" "$url" "$dest"
  git -C "$dest" sparse-checkout set --no-cone "$@"
}

apply_patch_once() {
  local root="$1" strip="$2" patch_file="$3"
  if patch --batch --dry-run --silent -d "$root" -p"$strip" < "$patch_file"; then
    patch --batch -d "$root" -p"$strip" < "$patch_file"
  elif patch --batch --dry-run --silent -R -d "$root" -p"$strip" < "$patch_file"; then
    echo "Patch already applied: $patch_file"
  else
    echo "Patch does not match source checkout: $patch_file" >&2
    exit 1
  fi
}

echo "[1/8] Initialising pinned TWRP/OrangeFox 14.1 source"
cd "$FOX_SOURCE"
repo_init_args=(init --depth=1)
if [ "$REPO_NO_VERIFY" = "1" ]; then
  repo_init_args+=(--no-repo-verify)
fi
if [ -n "$REPO_REV" ]; then
  repo_init_args+=(--repo-rev="$REPO_REV")
fi
"$REPO_BIN" "${repo_init_args[@]}" \
  -u https://github.com/nebrassy/platform_manifest_twrp_aosp.git \
  -b twrp-14 \
  -m default.xml
if [ "$REPO_REV" = "v2.14" ]; then
  python3 "$TREE_DIR/scripts/compat-repo-v214.py" \
    "$FOX_SOURCE/.repo/manifests"
fi
mkdir -p .repo/local_manifests
cp "$TREE_DIR/manifests/ovaltine-qpr3.xml" \
  .repo/local_manifests/ovaltine-qpr3.xml

echo "[2/8] Syncing the constrained QPR3 graph"
"$REPO_BIN" sync --force-sync -c -j"$SYNC_JOBS" \
  --no-clone-bundle --no-tags

echo "[3/8] Installing official OrangeFox components"
safe_delete "$FOX_SOURCE/bootable/recovery"
safe_delete "$FOX_SOURCE/vendor/recovery"
safe_delete "$FOX_SOURCE/external/se_omapi"
git clone --depth=1 --branch fox_14.1 \
  https://gitlab.com/OrangeFox/bootable/Recovery.git \
  "$FOX_SOURCE/bootable/recovery"
git clone --depth=1 --branch fox_14.1 \
  https://gitlab.com/OrangeFox/vendor/recovery.git \
  "$FOX_SOURCE/vendor/recovery"
git clone --depth=1 --branch fox_14.1 \
  https://gitlab.com/OrangeFox/external/se_omapi.git \
  "$FOX_SOURCE/external/se_omapi"

if [ ! -d "$FOX_SOURCE/device/qcom/common" ]; then
  git clone --depth=1 --branch android-14.1 \
    https://github.com/TeamWin/android_device_qcom_common \
    "$FOX_SOURCE/device/qcom/common"
fi
if [ ! -d "$FOX_SOURCE/device/qcom/twrp-common" ]; then
  git clone --depth=1 --branch android-14 \
    https://github.com/TeamWin/android_device_qcom_twrp-common \
    "$FOX_SOURCE/device/qcom/twrp-common"
fi

echo "[4/8] Applying official OrangeFox patches"
apply_patch_once "$FOX_SOURCE/build" 1 \
  "$FOX_SYNC/patches/patch-manifest-fox_14.1.diff"
apply_patch_once "$FOX_SOURCE/system/update_engine" 1 \
  "$FOX_SYNC/patches/patch-update-engine-fox_14.1.diff"

soong_mk="$FOX_SOURCE/vendor/twrp/config/BoardConfigSoong.mk"
fox_include='include bootable/recovery/orangefox_soong.mk'
if ! grep -qxF "$fox_include" "$soong_mk"; then
  sed -i "/SOONG_CONFIG_NAMESPACES += twrpVarsPlugin/i $fox_include\n" "$soong_mk"
fi

echo "[5/8] Installing Linux-only host prebuilts"
clone_sparse \
  https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86 \
  android-14.0.0_r67 "$FOX_SOURCE/prebuilts/clang/host/linux-x86" \
  /Android.bp /soong/ /clang-r510928/

clone_sparse \
  https://android.googlesource.com/platform/prebuilts/sdk \
  android-14.0.0_r67 "$FOX_SOURCE/prebuilts/sdk" \
  /Android.bp /NOTICE /34/ /extensions/ \
  /current/Android.bp /current/placeholder-api.txt \
  /current/androidx-api.txt /current/support-api.txt \
  /current/public/ /current/system/ /current/module-lib/ /current/core/ \
  /current/test/ /current/system-server/ \
  /27/public/api/android.txt /30/public/android.jar \
  '/tools/*' '!/tools/*/' /tools/linux/

clone_sparse \
  https://android.googlesource.com/platform/prebuilts/misc \
  android-14.0.0_r67 "$FOX_SOURCE/prebuilts/misc" \
  /Android.bp /common/ /linux-x86/

safe_delete "$FOX_SOURCE/prebuilts/misc/common/robolectric"
safe_delete "$FOX_SOURCE/prebuilts/misc/common/robolectric-native-prebuilt"

echo "[6/8] Applying constrained-host patches"
apply_patch_once "$FOX_SOURCE" 1 \
  "$TREE_DIR/patches/constrained/host-prebuilts.patch"
apply_patch_once "$FOX_SOURCE/build/soong" 1 \
  "$TREE_DIR/patches/constrained/soong-path-no-socket.patch"

# MediaProvider is not part of a recovery image, but keep it until a constrained
# checkout has passed a fresh Soong graph test. Set DROP_MEDIAPROVIDER=1 only
# after that proof has been recorded.
if [ "${DROP_MEDIAPROVIDER:-0}" = "1" ]; then
  safe_delete "$FOX_SOURCE/packages/providers/MediaProvider"
  # Keep an empty sentinel: OrangeFox roomservice restores this project when
  # the directory is absent, which reintroduces the unreleased PDF API graph.
  mkdir -p "$FOX_SOURCE/packages/providers/MediaProvider"
fi

echo "[7/8] Installing the verified ovaltine device tree"
safe_delete "$FOX_SOURCE/device/oneplus/ovaltine"
mkdir -p "$FOX_SOURCE/device/oneplus/ovaltine"
cp -a "$TREE_DIR/." "$FOX_SOURCE/device/oneplus/ovaltine/"
safe_delete "$FOX_SOURCE/device/oneplus/ovaltine/.git"
safe_delete "$FOX_SOURCE/device/oneplus/ovaltine/.github"
"$FOX_SOURCE/device/oneplus/ovaltine/scripts/validate-tree.sh"

if [ "$DROP_CLONE_METADATA" = "1" ]; then
  safe_delete "$FOX_SOURCE/prebuilts/clang/host/linux-x86/.git"
  safe_delete "$FOX_SOURCE/prebuilts/sdk/.git"
  safe_delete "$FOX_SOURCE/prebuilts/misc/.git"
fi

echo "[8/8] Verifying the source checkpoint"
test -x "$FOX_SOURCE/prebuilts/clang/host/linux-x86/clang-r510928/bin/clang"
test -x "$FOX_SOURCE/prebuilts/go/linux-x86/bin/go"
test -x "$FOX_SOURCE/prebuilts/jdk/jdk17/linux-x86/bin/java"
test -f "$FOX_SOURCE/bootable/recovery/orangefox_soong.mk"
test -f "$FOX_SOURCE/build/envsetup.sh"
test -f "$FOX_SOURCE/prebuilts/sdk/27/public/api/android.txt"
test -f "$FOX_SOURCE/prebuilts/sdk/30/public/android.jar"
test ! -e "$FOX_SOURCE/prebuilts/sdk/tools/darwin"
test ! -e "$FOX_SOURCE/prebuilts/sdk/tools/windows"

if [ "$DROP_REPO_CACHE" = "1" ]; then
  safe_delete "$FOX_SOURCE/.repo"
fi

cat <<EOF
Constrained OrangeFox source is ready: $FOX_SOURCE
Next command:
  $TREE_DIR/scripts/build-orangefox.sh $FOX_SOURCE
EOF
