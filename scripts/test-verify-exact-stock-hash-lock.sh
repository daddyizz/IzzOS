#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="$ROOT/scripts/verify-exact-stock-hash-lock.sh"
CREATOR="$ROOT/scripts/create-stock-image-provenance.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TARGET='OnePlus 10T 5G / ovaltine / SM8475'
BUILD='CPH2413_TEST_BUILD'
SOURCE_PACKAGE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
PAYLOAD_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
SOURCE="oneplus-full-ota:test.zip;ota-sha256=$SOURCE_PACKAGE_SHA;payload-sha256=$PAYLOAD_SHA"

for role in boot vendor_boot dtbo vbmeta recovery; do
  printf 'synthetic-%s-exact-stock\n' "$role" > "$TMP/$role.img"
done

record() {
  local role="$1" policy="$2" file
  file="$TMP/$role.img"
  printf 'Image record: %s|%s.img|%s|%s|%s\n' \
    "$role" "$role" "$(stat -c '%s' "$file")" "$(sha256sum "$file" | awk '{print $1}')" "$policy"
}

{
  echo 'IzzOS exact-build stock image hash lock fixture'
  echo 'Schema: IZZOS_EXACT_STOCK_HASH_LOCK_V1'
  echo "Target: $TARGET"
  echo 'Product/region: CPH2413 / test'
  echo "Build ID: $BUILD"
  echo 'Source package: test.zip'
  echo "Source package SHA256: $SOURCE_PACKAGE_SHA"
  echo "Payload SHA256: $PAYLOAD_SHA"
  echo "Canonical image source: $SOURCE"
  echo 'Required roles: boot vendor_boot dtbo vbmeta'
  echo 'Absent roles: init_boot'
  record boot required
  record vendor_boot required
  record dtbo required
  record vbmeta required
  record recovery optional-recovery
} > "$TMP/lock.txt"

for role in boot vendor_boot dtbo vbmeta recovery; do
  bash "$CREATOR" "$TMP/$role.img" "$TARGET" "$BUILD" "$role" "$SOURCE" 'synthetic-test-extraction' >/dev/null
done

schema_out="$(bash "$VERIFIER" "$TMP/lock.txt")"
grep -q '^classification: EXACT_STOCK_HASH_LOCK_VALID$' <<<"$schema_out"

pass_out="$(bash "$VERIFIER" "$TMP/lock.txt" \
  "$TMP/boot.img.provenance.txt" \
  "$TMP/vendor_boot.img.provenance.txt" \
  "$TMP/dtbo.img.provenance.txt" \
  "$TMP/vbmeta.img.provenance.txt")"
grep -q '^classification: EXACT_STOCK_IMAGE_LOCK_PASS$' <<<"$pass_out"
grep -q '^content-binding: PASS$' <<<"$pass_out"
grep -q '^launch-authorization: NO$' <<<"$pass_out"

if bash "$VERIFIER" "$TMP/lock.txt" \
  "$TMP/boot.img.provenance.txt" "$TMP/vendor_boot.img.provenance.txt" "$TMP/dtbo.img.provenance.txt" >/dev/null 2>&1; then
  echo 'ERROR: exact-stock verifier accepted a set missing vbmeta' >&2
  exit 1
fi

cp "$TMP/dtbo.img.provenance.txt" "$TMP/wrong-source.txt"
sed -i 's|^Image source:.*|Image source: unrelated-source|' "$TMP/wrong-source.txt"
if bash "$VERIFIER" "$TMP/lock.txt" \
  "$TMP/boot.img.provenance.txt" "$TMP/vendor_boot.img.provenance.txt" \
  "$TMP/wrong-source.txt" "$TMP/vbmeta.img.provenance.txt" >/dev/null 2>&1; then
  echo 'ERROR: exact-stock verifier accepted source identity drift' >&2
  exit 1
fi

printf 'tamper\n' >> "$TMP/boot.img"
if bash "$VERIFIER" "$TMP/lock.txt" \
  "$TMP/boot.img.provenance.txt" "$TMP/vendor_boot.img.provenance.txt" \
  "$TMP/dtbo.img.provenance.txt" "$TMP/vbmeta.img.provenance.txt" >/dev/null 2>&1; then
  echo 'ERROR: exact-stock verifier accepted mutated image bytes' >&2
  exit 1
fi

committed_out="$(bash "$VERIFIER" "$ROOT/docs/CPH2413_15.0.0.1901_EX01_STOCK_HASHES.txt")"
grep -q '^classification: EXACT_STOCK_HASH_LOCK_VALID$' <<<"$committed_out"
grep -q '^Build ID: CPH2413_15.0.0.1901(EX01)$' <<<"$committed_out"

echo 'Exact-stock hash-lock tests: PASS'
