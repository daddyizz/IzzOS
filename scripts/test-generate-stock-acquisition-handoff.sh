#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT_DIR/.work/test-stock-acquisition-handoff"
rm -rf "$WORK"
mkdir -p "$WORK"

PLAN="$WORK/plan.txt"
OUT="$WORK/handoff.txt"

cat > "$PLAN" <<'EOF'
IzzOS stock-image request plan
Classification: STOCK_IMAGE_REQUEST_PLAN_READY
Target: OnePlus 10T 5G / ovaltine / SM8475
Build ID: CPH2415_15.0.0.1901(EX01)
Current slot: a
Fastboot classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
Required first-wave images:
- boot.img | REQUIRED | verify boot header/layout and temporary-route derivation inputs
- vendor_boot.img | REQUIRED | verify vendor boot header/fragments and matching firmware context
- dtbo.img | REQUIRED | verify exact device-tree overlay payload for the same build
- vbmeta.img | REQUIRED | verify AVB metadata and exact build pairing
Conditional images:
- init_boot.img | CONDITIONAL | request only if present/relevant on this exact firmware and confirmed by stock metadata
Extraction authorized: NO
Device writes authorized: NO
Launch authorization: NO
EOF

bash "$ROOT_DIR/scripts/generate-stock-acquisition-handoff.sh" "$PLAN" "$OUT" >/dev/null

grep -q '^Classification: STOCK_ACQUISITION_HANDOFF_PREPARED$' "$OUT"
grep -q '^Build ID: CPH2415_15.0.0.1901(EX01)$' "$OUT"
grep -q '^Extraction authorized: NO$' "$OUT"
for role in boot vendor_boot dtbo vbmeta; do
  grep -Fq "'$role' '<EXACT_OFFICIAL_SOURCE>' '<EXTRACTION_METHOD>'" "$OUT"
done

BAD_AUTH="$WORK/bad-auth.txt"
sed 's/^Extraction authorized: NO$/Extraction authorized: YES/' "$PLAN" > "$BAD_AUTH"
if bash "$ROOT_DIR/scripts/generate-stock-acquisition-handoff.sh" "$BAD_AUTH" "$WORK/bad-auth-out.txt" >/dev/null 2>&1; then
  echo 'ERROR: handoff generator accepted extraction authorization drift' >&2
  exit 1
fi

BLOCKED="$WORK/blocked.txt"
sed 's/^Classification: STOCK_IMAGE_REQUEST_PLAN_READY$/Classification: STOCK_IMAGE_REQUEST_BLOCKED/' "$PLAN" > "$BLOCKED"
if bash "$ROOT_DIR/scripts/generate-stock-acquisition-handoff.sh" "$BLOCKED" "$WORK/blocked-out.txt" >/dev/null 2>&1; then
  echo 'ERROR: handoff generator accepted blocked request plan' >&2
  exit 1
fi

MISSING_ROLE="$WORK/missing-role.txt"
grep -v '^- dtbo.img | REQUIRED |' "$PLAN" > "$MISSING_ROLE"
if bash "$ROOT_DIR/scripts/generate-stock-acquisition-handoff.sh" "$MISSING_ROLE" "$WORK/missing-role-out.txt" >/dev/null 2>&1; then
  echo 'ERROR: handoff generator accepted a plan missing a required first-wave role' >&2
  exit 1
fi

echo 'stock acquisition handoff generator tests: PASS'
