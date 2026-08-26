#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLANNER="$ROOT_DIR/scripts/plan-stock-image-request.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/valid.txt" <<'EOF'
IzzOS M1 exact-device evidence merge
Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
Target: OnePlus 10T 5G / ovaltine / SM8475
Target match: yes
Build ID: CPH2415_15.0.0.1901(EX01)
Current slot: a
Bootloader unlocked: yes
Userspace fastboot: no
ADB classification: NEED_EXACT_FASTBOOT_INSPECTION
Fastboot classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
EOF

bash "$PLANNER" "$TMP/valid.txt" "$TMP/plan.txt" >/dev/null
grep -q '^Classification: STOCK_IMAGE_REQUEST_PLAN_READY$' "$TMP/plan.txt"
grep -q '^Build ID: CPH2415_15.0.0.1901(EX01)$' "$TMP/plan.txt"
grep -q '^- boot.img | REQUIRED |' "$TMP/plan.txt"
grep -q '^- vendor_boot.img | REQUIRED |' "$TMP/plan.txt"
grep -q '^- dtbo.img | REQUIRED |' "$TMP/plan.txt"
grep -q '^- vbmeta.img | REQUIRED |' "$TMP/plan.txt"
grep -q '^- init_boot.img | CONDITIONAL |' "$TMP/plan.txt"
grep -q '^Extraction authorized: NO$' "$TMP/plan.txt"
grep -q '^Device writes authorized: NO$' "$TMP/plan.txt"
grep -q '^Launch authorization: NO$' "$TMP/plan.txt"

cat > "$TMP/blocked.txt" <<'EOF'
Classification: M1_EXACT_DEVICE_EVIDENCE_BLOCKED
Target match: yes
Build ID: CPH2415_15.0.0.1901(EX01)
Current slot: a
Fastboot classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
EOF
if bash "$PLANNER" "$TMP/blocked.txt" "$TMP/blocked-plan.txt" >/dev/null 2>&1; then
  echo 'ERROR: blocked canonical evidence must not produce a ready stock-image plan' >&2
  exit 1
fi
grep -q '^Classification: STOCK_IMAGE_REQUEST_BLOCKED$' "$TMP/blocked-plan.txt"
grep -q '^Extraction authorized: NO$' "$TMP/blocked-plan.txt"

cat > "$TMP/no-build.txt" <<'EOF'
Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
Target match: yes
Build ID: unknown
Current slot: a
Fastboot classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
EOF
if bash "$PLANNER" "$TMP/no-build.txt" "$TMP/no-build-plan.txt" >/dev/null 2>&1; then
  echo 'ERROR: missing exact build must block stock-image request planning' >&2
  exit 1
fi
grep -q '^Classification: STOCK_IMAGE_REQUEST_BLOCKED$' "$TMP/no-build-plan.txt"

echo 'stock image request planner tests: PASS'
