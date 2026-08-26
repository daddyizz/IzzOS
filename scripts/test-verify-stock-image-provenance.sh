#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

printf 'synthetic-complete-image\n' > "$TMP_DIR/boot.img"
complete_size="$(stat -c '%s' "$TMP_DIR/boot.img")"
complete_sha="$(sha256sum "$TMP_DIR/boot.img" | awk '{print $1}')"

cat > "$TMP_DIR/complete.txt" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415 / ovaltine
OxygenOS build: CPH2415_15.0.0.TEST
Image role: boot
Image file: boot.img
Image size bytes: $complete_size
Image SHA256: $complete_sha
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
grep -q '^content-binding: PASS$' <<<"$out"

if bash scripts/verify-stock-image-provenance.sh "$TMP_DIR/incomplete.txt" >"$TMP_DIR/out" 2>&1; then
  echo "FAIL: incomplete provenance unexpectedly passed" >&2
  exit 1
fi
grep -q '^classification: PROVENANCE_INCOMPLETE_BLOCKED$' "$TMP_DIR/out"

cp "$TMP_DIR/complete.txt" "$TMP_DIR/duplicate.txt"
printf 'Image SHA256: %s\n' "$complete_sha" >> "$TMP_DIR/duplicate.txt"
if bash scripts/verify-stock-image-provenance.sh "$TMP_DIR/duplicate.txt" >"$TMP_DIR/duplicate.out" 2>&1; then
  echo "FAIL: duplicate critical field unexpectedly passed" >&2
  exit 1
fi
grep -q '^classification: PROVENANCE_INCOMPLETE_BLOCKED$' "$TMP_DIR/duplicate.out"

sed 's/^Image file:.*/Image file: ..\/boot.img/' "$TMP_DIR/complete.txt" > "$TMP_DIR/path-shaped.txt"
if bash scripts/verify-stock-image-provenance.sh "$TMP_DIR/path-shaped.txt" >/dev/null 2>&1; then
  echo "FAIL: path-shaped image filename unexpectedly passed" >&2
  exit 1
fi

echo "stock image provenance tests: PASS"
