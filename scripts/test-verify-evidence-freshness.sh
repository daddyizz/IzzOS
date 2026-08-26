#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/current.txt" <<'EOF'
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
build-id: CPH2415_14.0.0.710(EX01)
slot-suffix: _a
EOF

cat > "$ROOT/manifest.txt" <<'EOF'
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: evidence/m2-route-validation.txt
EOF

cat > "$ROOT/recovery.txt" <<'EOF'
Device model/product: OnePlus 10T 5G CPH2415
OxygenOS build: CPH2415_14.0.0.710(EX01)
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic
Bootloader version: test
Stock image source: official exact-build package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock init_boot verified/NA: NA
Stock dtbo verified: YES
Stock vbmeta verified: YES
Emergency recovery status: documented with authorization constraints understood
Temporary route candidate: temporary-chainload-example
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: evidence/recovery-procedure.txt
Decision: TEMPORARY_ROUTE_VALIDATED
EOF

OUT="$(bash scripts/verify-evidence-freshness.sh "$ROOT/current.txt" "$ROOT/manifest.txt" "$ROOT/recovery.txt")"
grep -q '^classification: EVIDENCE_FRESH_FOR_CURRENT_DEVICE_STATE$' <<<"$OUT"

sed 's/CPH2415_14.0.0.710(EX01)/CPH2415_14.0.0.720(EX01)/' "$ROOT/current.txt" > "$ROOT/updated.txt"
if bash scripts/verify-evidence-freshness.sh "$ROOT/updated.txt" "$ROOT/manifest.txt" "$ROOT/recovery.txt" >/dev/null 2>&1; then
  echo 'FAIL: firmware update must invalidate prior evidence' >&2
  exit 1
fi

sed 's/Current slot: a/Current slot: b/' "$ROOT/recovery.txt" > "$ROOT/recovery-slot-b.txt"
if bash scripts/verify-evidence-freshness.sh "$ROOT/current.txt" "$ROOT/manifest.txt" "$ROOT/recovery-slot-b.txt" >/dev/null 2>&1; then
  echo 'FAIL: slot mismatch must block freshness' >&2
  exit 1
fi

echo 'M2 evidence freshness tests: PASS'
