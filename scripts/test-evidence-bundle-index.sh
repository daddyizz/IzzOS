#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/device.txt" <<'EOF'
Device: ovaltine
Build: TEST.BUILD
EOF
cat > "$ROOT/recovery.txt" <<'EOF'
Decision: COMPLETE
EOF
cat > "$ROOT/route.txt" <<'EOF'
Route decision: TEMPORARY_ROUTE_VALIDATED
EOF

INDEX="$ROOT/EVIDENCE_SHA256SUMS"
bash scripts/create-evidence-bundle-index.sh "$INDEX" \
  "$ROOT/device.txt" "$ROOT/recovery.txt" "$ROOT/route.txt" >/dev/null

OUT="$(bash scripts/verify-evidence-bundle-index.sh "$INDEX")"
grep -q '^classification: EVIDENCE_INDEX_VERIFIED$' <<<"$OUT"

echo 'tampered' >> "$ROOT/recovery.txt"
if bash scripts/verify-evidence-bundle-index.sh "$INDEX" >/dev/null 2>&1; then
  echo 'FAIL: modified evidence must be rejected' >&2
  exit 1
fi

rm "$ROOT/recovery.txt"
if bash scripts/verify-evidence-bundle-index.sh "$INDEX" >/dev/null 2>&1; then
  echo 'FAIL: missing evidence must be rejected' >&2
  exit 1
fi

echo 'evidence bundle index tests: PASS'
