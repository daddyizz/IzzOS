#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYZER="$ROOT_DIR/scripts/analyze-stock-vendor-boot-metadata.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat > "$TMP_DIR/valid.txt" <<'EOF'
boot magic: VNDRBOOT
vendor boot image header version: 4
page size: 0x00001000
vendor ramdisk total size: 21868539
dtb size: 1434126
vendor ramdisk table size: 108
vendor bootconfig size: 85
EOF

cat > "$TMP_DIR/bad-header.txt" <<'EOF'
boot magic: VNDRBOOT
vendor boot image header version: 3
page size: 0x00001000
vendor ramdisk total size: 21868539
dtb size: 1434126
vendor ramdisk table size: 108
EOF

cat > "$TMP_DIR/bad-page.txt" <<'EOF'
boot magic: VNDRBOOT
vendor boot image header version: 4
page size: 0x00002000
vendor ramdisk total size: 21868539
dtb size: 1434126
vendor ramdisk table size: 108
EOF

out="$(bash "$ANALYZER" "$TMP_DIR/valid.txt")"
grep -Fq 'classification: MATCHES_SOURCE_EXPECTATION' <<<"$out"
grep -Fq 'observed-page-size: 4096' <<<"$out"
grep -Fq 'observed-dtb-size: 1434126' <<<"$out"

out="$(bash "$ANALYZER" "$TMP_DIR/bad-header.txt")"
grep -Fq 'classification: MISMATCH_HARD_STOP' <<<"$out"

out="$(bash "$ANALYZER" "$TMP_DIR/bad-page.txt")"
grep -Fq 'classification: MISMATCH_HARD_STOP' <<<"$out"

echo "stock vendor_boot metadata analyzer tests: PASS"
