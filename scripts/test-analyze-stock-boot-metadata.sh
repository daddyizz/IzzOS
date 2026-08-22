#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/match.txt" <<'EOF'
boot image header version: 4
page size: 4096
EOF

cat > "$ROOT/mismatch.txt" <<'EOF'
boot image header version: 3
page size: 4096
EOF

cat > "$ROOT/incomplete.txt" <<'EOF'
boot image header version: 4
EOF

run_case() {
  local input="$1"
  local expected="$2"
  local output
  output="$(bash scripts/analyze-stock-boot-metadata.sh "$input")"
  grep -Fq "classification: $expected" <<<"$output"
}

run_case "$ROOT/match.txt" MATCHES_SOURCE_EXPECTATION
run_case "$ROOT/mismatch.txt" MISMATCH_HARD_STOP
run_case "$ROOT/incomplete.txt" INCOMPLETE_METADATA

echo "stock boot metadata analyzer tests: PASS"
