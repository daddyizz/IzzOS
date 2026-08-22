#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/pass.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2415_15.0.TEST
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Emergency recovery status: exact-variant procedure documented; authorization constraints recorded
Temporary route candidate: classic fastboot temporary boot candidate
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: docs/recovery/CPH2415_15.0.TEST.md
EOF

cat > "$ROOT/write-required.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2415_15.0.TEST
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Emergency recovery status: documented
Temporary route candidate: candidate
Persistent write required: YES
Slot change required: NO
Recovery procedure reference: docs/recovery/test.md
EOF

cat > "$ROOT/missing-vbmeta.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2415_15.0.TEST
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: NO
Emergency recovery status: documented
Temporary route candidate: candidate
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: docs/recovery/test.md
EOF

PASS_OUT="$(bash scripts/verify-m2-recovery-evidence.sh "$ROOT/pass.txt")"
grep -q '^classification: RECOVERY_EVIDENCE_COMPLETE$' <<<"$PASS_OUT"

if bash scripts/verify-m2-recovery-evidence.sh "$ROOT/write-required.txt" >/dev/null 2>&1; then
  echo "FAIL: persistent-write recovery evidence should be blocked" >&2
  exit 1
fi

if bash scripts/verify-m2-recovery-evidence.sh "$ROOT/missing-vbmeta.txt" >/dev/null 2>&1; then
  echo "FAIL: unverified vbmeta should be blocked" >&2
  exit 1
fi

echo "M2 recovery evidence gate tests passed."
