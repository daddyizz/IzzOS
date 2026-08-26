#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

BUILD='CPH2415_14.0.0.710(EX01)'
TARGET='OnePlus 10T 5G / CPH2415 / ovaltine'
SOURCE_PACKAGE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
PAYLOAD_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
SOURCE="oneplus-full-ota:fixture.zip;ota-sha256=$SOURCE_PACKAGE_SHA;payload-sha256=$PAYLOAD_SHA"

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
Route validation evidence reference: route-evidence.txt
EOF

for role in before-state route-transcript diagnostic-output after-state; do
  printf 'synthetic-%s-%s\n' "$role" "$BUILD" > "$ROOT/route-$role.txt"
done
{
  echo 'Schema: IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1'
  echo 'Target: OnePlus 10T 5G / CPH2415 / ovaltine / SM8475'
  echo "Firmware ID: $BUILD"
  echo 'Selected launch route: temporary-chainload-example'
  echo 'Route decision: TEMPORARY_ROUTE_VALIDATED'
  echo 'Device execution observed: YES'
  echo 'Diagnostic payload reached: YES'
  echo 'Controlled result recorded: YES'
  echo 'Stock boot restored: YES'
  echo 'Persistent writes observed: NO'
  echo 'Slot change observed: NO'
  echo 'User data mutation observed: NO'
  echo 'Required artifact roles: before-state route-transcript diagnostic-output after-state'
  for role in before-state route-transcript diagnostic-output after-state; do
    file="$ROOT/route-$role.txt"
    printf 'Artifact record: %s|route-%s.txt|%s|%s\n' \
      "$role" "$role" "$(stat -c '%s' "$file")" "$(sha256sum "$file" | awk '{print $1}')"
  done
} > "$ROOT/route-evidence.txt"

cat > "$ROOT/recovery.txt" <<EOF
Device model/product: $TARGET
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
  local image="$ROOT/$(basename "$path" .txt).img"
  printf '%s\n' "$role-$BUILD-$(basename "$path")" > "$image"
  local size sha
  size="$(stat -c '%s' "$image")"
  sha="$(sha256sum "$image" | awk '{print $1}')"
  cat > "$path" <<EOF
Device model/product: $TARGET
OxygenOS build: $BUILD
Image role: $role
Image file: $(basename "$image")
Image size bytes: $size
Image SHA256: $sha
Image source: $SOURCE
Extraction method: synthetic CI fixture
EOF
}

make_stock "$ROOT/boot.txt" boot
make_stock "$ROOT/vendor_boot.txt" vendor_boot
make_stock "$ROOT/dtbo.txt" dtbo
make_stock "$ROOT/vbmeta.txt" vbmeta

printf 'synthetic-recovery-lock-only\n' > "$ROOT/recovery.img"
record() {
  local role="$1" policy="$2" image
  image="$ROOT/$role.img"
  printf 'Image record: %s|%s.img|%s|%s|%s\n' \
    "$role" "$role" "$(stat -c '%s' "$image")" "$(sha256sum "$image" | awk '{print $1}')" "$policy"
}
{
  echo 'Schema: IZZOS_EXACT_STOCK_HASH_LOCK_V1'
  echo "Target: $TARGET"
  echo 'Product/region: CPH2415 / test'
  echo "Build ID: $BUILD"
  echo 'Source package: fixture.zip'
  echo "Source package SHA256: $SOURCE_PACKAGE_SHA"
  echo "Payload SHA256: $PAYLOAD_SHA"
  echo "Canonical image source: $SOURCE"
  echo 'Required roles: boot vendor_boot dtbo vbmeta'
  echo 'Absent roles: init_boot'
  record boot required
  record vendor_boot required
  record dtbo required
  record vbmeta required
  record recovery optional-recovery
} > "$ROOT/stock-lock.txt"

READY_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" "$ROOT/route-evidence.txt" \
  "$ROOT/stock-lock.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt")"
grep -q '^classification: READY_FOR_ROUTE_SPECIFIC_PACKAGING$' <<<"$READY_OUT"

grep -q '^stock image set consistency.*PASS$' <<<"$READY_OUT"
grep -q '^exact stock content lock.*PASS$' <<<"$READY_OUT"
grep -q '^M2 evidence bundle consistency.*PASS$' <<<"$READY_OUT"
grep -q '^recovery evidence.*PASS$' <<<"$READY_OUT"
grep -q '^evidence freshness.*PASS$' <<<"$READY_OUT"
grep -q '^content-bound route evidence.*PASS$' <<<"$READY_OUT"
grep -q '^route authorization.*PASS$' <<<"$READY_OUT"

cp "$ROOT/recovery.txt" "$ROOT/recovery-bad.txt"
sed -i 's/Persistent write required: NO/Persistent write required: YES/' "$ROOT/recovery-bad.txt"
if BLOCKED_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery-bad.txt" "$ROOT/route-evidence.txt" \
  "$ROOT/stock-lock.txt" \
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
  "$ROOT/inspection-new-slot.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" "$ROOT/route-evidence.txt" \
  "$ROOT/stock-lock.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt" 2>&1)"; then
  echo 'FAIL: changed slot must invalidate readiness' >&2
  exit 1
fi
grep -q '^classification: M2_READINESS_BLOCKED$' <<<"$STALE_OUT"
grep -q '^blocker: evidence freshness$' <<<"$STALE_OUT"

printf 'tamper\n' >> "$ROOT/route-diagnostic-output.txt"
if ROUTE_TAMPER_OUT="$(bash scripts/report-m2-readiness.sh \
  "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" "$ROOT/route-evidence.txt" \
  "$ROOT/stock-lock.txt" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt" 2>&1)"; then
  echo 'FAIL: mutated route artifact must invalidate readiness' >&2
  exit 1
fi
grep -q '^blocker: content-bound route evidence$' <<<"$ROUTE_TAMPER_OUT"
grep -q '^blocker: route authorization$' <<<"$ROUTE_TAMPER_OUT"

echo 'M2 readiness report tests: PASS'
