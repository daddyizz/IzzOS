#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

BUILD='CPH2415_14.0.0.710(EX01)'

cat > "$ROOT/inspection.txt" <<EOF
[ADB] authorized devices: 1
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
build-id: $BUILD
slot-suffix: _a
[FASTBOOT] connected devices: 1
--- current-slot ---
(bootloader) current-slot: a
--- unlocked ---
(bootloader) unlocked: yes
--- is-userspace ---
(bootloader) is-userspace: no
EOF

cat > "$ROOT/m2.txt" <<EOF
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: $BUILD
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: evidence/m2-route-validation.txt
EOF

cat > "$ROOT/recovery.txt" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415 / ovaltine
OxygenOS build: $BUILD
Current slot: a
Slot count: 2
Bootloader unlocked: yes
Fastboot mode: classic
Bootloader version: test
Stock image source: exact official full package fixture
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock init_boot verified/NA: NA
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: SELF_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: temporary-chainload-example
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: evidence/recovery-procedure.txt
Decision: TEMPORARY_ROUTE_VALIDATED
EOF

make_stock() {
  local path="$1" role="$2"
  cat > "$path" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415 / ovaltine
OxygenOS build: $BUILD
Image role: $role
Image file: $role.img
Image size bytes: 4096
Image SHA256: 1111111111111111111111111111111111111111111111111111111111111111
Image source: exact official full package fixture
Extraction method: synthetic CI fixture
EOF
}

make_stock "$ROOT/boot.txt" boot
make_stock "$ROOT/vendor_boot.txt" vendor_boot
make_stock "$ROOT/dtbo.txt" dtbo
make_stock "$ROOT/vbmeta.txt" vbmeta

READY_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt")"
grep -q '^classification: READY_FOR_ROUTE_SPECIFIC_PACKAGING$' <<<"$READY_OUT"

grep -q '^stock image set consistency.*PASS$' <<<"$READY_OUT"
grep -q '^M2 evidence bundle consistency.*PASS$' <<<"$READY_OUT"
grep -q '^recovery evidence.*PASS$' <<<"$READY_OUT"
grep -q '^evidence freshness.*PASS$' <<<"$READY_OUT"
grep -q '^route authorization.*PASS$' <<<"$READY_OUT"

cp "$ROOT/recovery.txt" "$ROOT/recovery-bad.txt"
sed -i 's/Persistent write required: NO/Persistent write required: YES/' "$ROOT/recovery-bad.txt"
if BLOCKED_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery-bad.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt" 2>&1)"; then
  echo 'FAIL: unsafe recovery evidence must block readiness' >&2
  exit 1
fi
grep -q '^classification: M2_READINESS_BLOCKED$' <<<"$BLOCKED_OUT"
grep -q '^blocker: recovery evidence$' <<<"$BLOCKED_OUT"
grep -q '^blocker: route authorization$' <<<"$BLOCKED_OUT"

cp "$ROOT/inspection.txt" "$ROOT/inspection-new-slot.txt"
sed -i 's/slot-suffix: _a/slot-suffix: _b/' "$ROOT/inspection-new-slot.txt"
if STALE_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection-new-slot.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt" 2>&1)"; then
  echo 'FAIL: changed slot must invalidate readiness' >&2
  exit 1
fi
grep -q '^classification: M2_READINESS_BLOCKED$' <<<"$STALE_OUT"
grep -q '^blocker: evidence freshness$' <<<"$STALE_OUT"

echo 'M2 readiness report tests: PASS'
