#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

printf 'synthetic-stock-image\n' > "$ROOT/boot.img"

bash scripts/create-stock-image-provenance.sh \
  "$ROOT/boot.img" \
  "OnePlus 10T 5G / ovaltine / CPH2415" \
  "CPH2415_TEST_BUILD" \
  "boot" \
  "official-stock-package:test-fixture" \
  "synthetic-test-extraction" >/dev/null

MANIFEST="$ROOT/boot.img.provenance.txt"
[[ -s "$MANIFEST" ]]

bash scripts/verify-stock-image-provenance.sh "$MANIFEST" | grep -q '^classification: PROVENANCE_COMPLETE$'

cp "$MANIFEST" "$ROOT/bad-sha.txt"
sed -i 's/^Image SHA256:.*/Image SHA256: deadbeef/' "$ROOT/bad-sha.txt"
if bash scripts/verify-stock-image-provenance.sh "$ROOT/bad-sha.txt" >/dev/null 2>&1; then
  echo "FAIL: invalid SHA256 unexpectedly passed" >&2
  exit 1
fi

cp "$MANIFEST" "$ROOT/bad-field.txt"
sed -i 's/^OxygenOS build:.*/OxygenOS build: unknown/' "$ROOT/bad-field.txt"
if bash scripts/verify-stock-image-provenance.sh "$ROOT/bad-field.txt" >/dev/null 2>&1; then
  echo "FAIL: placeholder provenance unexpectedly passed" >&2
  exit 1
fi

printf 'mutation\n' >> "$ROOT/boot.img"
if bash scripts/verify-stock-image-provenance.sh "$MANIFEST" >"$ROOT/content-mismatch.out" 2>&1; then
  echo "FAIL: mutated image unexpectedly matched its provenance" >&2
  exit 1
fi
grep -q '^classification: PROVENANCE_CONTENT_MISMATCH_BLOCKED$' "$ROOT/content-mismatch.out"

echo "stock image provenance round-trip tests: PASS"
