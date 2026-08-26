#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

make_manifest() {
  local name="$1"
  local role="$2"
  local build="$3"
  printf '%s\n' "$name-$build" > "$ROOT/$name.img"
  bash scripts/create-stock-image-provenance.sh \
    "$ROOT/$name.img" \
    "OnePlus 10T 5G / ovaltine / CPH2415" \
    "$build" \
    "$role" \
    "official-stock-package:test-fixture" \
    "synthetic-test-extraction" >/dev/null
}

make_manifest boot boot BUILD_A
make_manifest vendor_boot vendor_boot BUILD_A
make_manifest dtbo dtbo BUILD_A

bash scripts/verify-stock-image-set.sh \
  "$ROOT/boot.img.provenance.txt" \
  "$ROOT/vendor_boot.img.provenance.txt" \
  "$ROOT/dtbo.img.provenance.txt" | grep -q '^classification: STOCK_IMAGE_SET_CONSISTENT$'

make_manifest badbuild vbmeta BUILD_B
if bash scripts/verify-stock-image-set.sh \
  "$ROOT/boot.img.provenance.txt" \
  "$ROOT/badbuild.img.provenance.txt" >/dev/null 2>&1; then
  echo "FAIL: mixed-build image set unexpectedly passed" >&2
  exit 1
fi

make_manifest duplicate boot BUILD_A
if bash scripts/verify-stock-image-set.sh \
  "$ROOT/boot.img.provenance.txt" \
  "$ROOT/duplicate.img.provenance.txt" >/dev/null 2>&1; then
  echo "FAIL: duplicate-role image set unexpectedly passed" >&2
  exit 1
fi

echo "stock image set tests: PASS"
