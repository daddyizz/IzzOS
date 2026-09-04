#!/usr/bin/env bash
set -Eeuo pipefail
mode="${1:---constrained}"
case "$mode" in --constrained) min_mem=$((14*1024*1024*1024)); min_disk=$((24*1024*1024*1024));; --recommended) min_mem=$((30*1024*1024*1024)); min_disk=$((135*1024*1024*1024));; *) exit 2;; esac
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || exit 1
mem=$(( $(awk '/MemTotal:/ {print $2}' /proc/meminfo) * 1024 )); free=$(df --output=avail -B1 "${BUILD_ROOT:-$PWD}" | tail -1 | tr -d ' ')
[ "$mem" -ge "$min_mem" ] && [ "$free" -ge "$min_disk" ] || { echo "Insufficient host capacity" >&2; exit 1; }
echo "Host accepted: $((mem/1024/1024/1024)) GiB RAM, $((free/1024/1024/1024)) GiB free"
