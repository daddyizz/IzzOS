#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat > "$TMP_DIR/complete.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / CPH2415 / ovaltine
OxygenOS build: CPH2415_15.0.0.TEST
Image role: boot
Image file: boot.img
Image size bytes: 67108864
Image SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Image source: exact matching full OTA payload
Extraction method: payload extraction with recorded tool/version
EOF

cat > "$TMP_DIR/incomplete.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / CPH2415 / ovaltine
OxygenOS build: unknown
Image role: boot
Image file: boot.img
Image size bytes: 0
Image SHA256: bad
Image source: TODO
Extraction method: payload extraction
EOF

out="$(bash scripts/verify-stock-image-provenance.sh "$TMP_DIR/complete.txt")"
grep -q '^classification: PROVENANCE_COMPLETE$' <<<"$out"

if bash scripts/verify-stock-image-provenance.sh "$TMP_DIR/incomplete.txt" >"$TMP_DIR/out" 2>&1; then
  echo "FAIL: incomplete provenance unexpectedly passed" >&2
  exit 1
fi
grep -q '^classification: PROVENANCE_INCOMPLETE_BLOCKED$' "$TMP_DIR/out"

echo "stock image provenance tests: PASS"
