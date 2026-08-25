#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

EFI="$ROOT/OvaltineDiag.efi"
printf 'synthetic-efi-for-package-test\n' > "$EFI"
EFI_SHA="$(sha256sum "$EFI" | awk '{print $1}')"
EFI_SIZE="$(wc -c < "$EFI" | tr -d '[:space:]')"
BUILD='CPH2415_14.0.0.710(EX01)'
STOCK_TARGET='OnePlus 10T 5G / CPH2415'
SOURCE_PACKAGE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
PAYLOAD_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
STOCK_SOURCE="oneplus-full-ota:fixture.zip;ota-sha256=$SOURCE_PACKAGE_SHA;payload-sha256=$PAYLOAD_SHA"

cat > "$ROOT/payload.txt" <<EOF
IzzOS M1 current diagnostic payload
Payload ID: M1-DIAG-TEST
Identity schema: 1
EFI file: OvaltineDiag.efi
EFI size bytes: $EFI_SIZE
EFI SHA256: $EFI_SHA
Target: OnePlus 10T 5G / ovaltine / SM8475
Status: CURRENT_M1_DEVICE_TEST_CANDIDATE
EOF

cat > "$ROOT/inspection.txt" <<EOF
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
build-id: $BUILD
slot-suffix: _a
EOF

cat > "$ROOT/m2.txt" <<EOF
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: $BUILD
Selected launch route: OEM_UEFI_CHAINLOAD
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

for role in before-state route-transcript diagnostic-output after-state; do
  printf 'synthetic-%s-%s\n' "$role" "$BUILD" > "$ROOT/$role.txt"
done
{
  echo 'Schema: IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1'
  echo 'Target: OnePlus 10T 5G / CPH2415 / ovaltine / SM8475'
  echo "Firmware ID: $BUILD"
  echo 'Selected launch route: OEM_UEFI_CHAINLOAD'
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
    file="$ROOT/$role.txt"
    printf 'Artifact record: %s|%s.txt|%s|%s\n' \
      "$role" "$role" "$(stat -c '%s' "$file")" "$(sha256sum "$file" | awk '{print $1}')"
  done
} > "$ROOT/route-evidence.txt"

cat > "$ROOT/recovery.txt" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415
OxygenOS build: $BUILD
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: CLASSIC_FASTBOOT
Stock image source: official full update package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: SELF_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: OEM_UEFI_CHAINLOAD
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: synthetic-recovery.md
EOF

make_stock() {
  local path="$1" role="$2" image size sha
  image="$ROOT/$role.img"
  printf 'synthetic-%s-stock-input\n' "$role" > "$image"
  size="$(stat -c '%s' "$image")"
  sha="$(sha256sum "$image" | awk '{print $1}')"
  cat > "$path" <<EOF
Device model/product: $STOCK_TARGET
OxygenOS build: $BUILD
Image role: $role
Image file: $role.img
Image size bytes: $size
Image SHA256: $sha
Image source: $STOCK_SOURCE
Extraction method: payload extraction
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
  echo "Target: $STOCK_TARGET"
  echo 'Product/region: CPH2415 / test'
  echo "Build ID: $BUILD"
  echo 'Source package: fixture.zip'
  echo "Source package SHA256: $SOURCE_PACKAGE_SHA"
  echo "Payload SHA256: $PAYLOAD_SHA"
  echo "Canonical image source: $STOCK_SOURCE"
  echo 'Required roles: boot vendor_boot dtbo vbmeta'
  echo 'Absent roles: init_boot'
  record boot required
  record vendor_boot required
  record dtbo required
  record vbmeta required
  record recovery optional-recovery
} > "$ROOT/stock-lock.txt"

OUT="$(bash scripts/prepare-m1-device-test-package.sh \
  "$EFI" "$ROOT/payload.txt" "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/route-evidence.txt" "$ROOT/stock-lock.txt" "$ROOT/out" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt")"
grep -q '^classification: M1_DEVICE_TEST_PACKAGE_ASSEMBLED$' <<<"$OUT"
PACKAGE_DIR="$(sed -n 's/^package-dir: //p' <<<"$OUT")"
test -f "$PACKAGE_DIR/payload/OvaltineDiag.efi"
test -f "$PACKAGE_DIR/PACKAGE_INFO.txt"
test -f "$PACKAGE_DIR/SHA256SUMS"
test -f "$PACKAGE_DIR/evidence/route/route-evidence.txt"
test -f "$PACKAGE_DIR/evidence/route/before-state.txt"
test -f "$PACKAGE_DIR/evidence/route/route-transcript.txt"
test -f "$PACKAGE_DIR/evidence/route/diagnostic-output.txt"
test -f "$PACKAGE_DIR/evidence/route/after-state.txt"
grep -q '^Launch commands included: NO$' "$PACKAGE_DIR/PACKAGE_INFO.txt"
grep -q '^Device commands executed by assembler: NO$' "$PACKAGE_DIR/PACKAGE_INFO.txt"
(
  cd "$PACKAGE_DIR"
  sha256sum -c SHA256SUMS >/dev/null
)

printf 'tamper\n' >> "$EFI"
if bash scripts/prepare-m1-device-test-package.sh \
  "$EFI" "$ROOT/payload.txt" "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/route-evidence.txt" "$ROOT/stock-lock.txt" "$ROOT/out2" \
  "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" "$ROOT/dtbo.txt" "$ROOT/vbmeta.txt" >/dev/null 2>&1; then
  echo 'FAIL: modified EFI must not assemble a device-test package' >&2
  exit 1
fi

echo 'M1 device-test package assembly tests: PASS'
