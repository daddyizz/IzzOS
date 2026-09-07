#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "Use a 64-bit Linux runner." >&2
  exit 1
fi

if [ "${EUID}" -eq 0 ]; then
  SUDO=()
else
  command -v sudo >/dev/null
  SUDO=(sudo)
fi

"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y \
  bc bison build-essential ccache curl flex g++-multilib gcc-multilib git \
  git-lfs gnupg gperf imagemagick lib32readline-dev lib32z1-dev libelf-dev \
  liblz4-tool libncurses5-dev libssl-dev libxml2 libxml2-utils lzop \
  openjdk-17-jdk patch python3 rsync squashfs-tools unzip xsltproc zip \
  zlib1g-dev

echo "Runner dependencies installed. Register the GitHub Actions runner with labels:"
echo "self-hosted,linux,x64,orangefox-builder"
echo "Keep the verified stock files outside the repository, for example:"
echo "/srv/orangefox/ovaltine-prebuilts/{kernel,dtbo.img,dtbs/stock.dtb}"
