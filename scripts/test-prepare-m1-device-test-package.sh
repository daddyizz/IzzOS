#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

EFI="$ROOT/OvaltineDiag.efi"
printf 'synthetic-efi-for-package-test\n' > "$EFI"
EFI_SHA="$(sha256sum "$EFI" | awk '{print $1}')"
EFI_SIZE="$(wc -c < "$EFI" | tr -d '[:space:]')"
BUILD='CPH2415_14.0.0.710(EX01)'

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
Route validation evidence reference: synthetic-route-evidence.txt
EOF

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
Emergency recovery status: DOCUMENTED
Temporary route candidate: OEM_UEFI_CHAINLOAD
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: synthetic-recovery.md
EOF

make_stock() {
  local path="$1" role="$2" hashchar="$3"
  cat > "$path" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415
OxygenOS build: $BUILD
Image role: $role
Image file: $role.img
Image size bytes: 4096
Image SHA256: $(printf '%064s' '' | tr ' ' "$hashchar")
Image source: official full update package
Extraction method: payload extraction
EOF
}

make_stock "$ROOT/boot.txt" boot a
make_stock "$ROOT/vendor_boot.txt" vendor_boot b

OUT="$(bash scripts/prepare-m1-device-test-package.sh \
  "$EFI" "$ROOT/payload.txt" "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/out" "$ROOT/boot.txt" "$ROOT/vendor_boot.txt")"
grep -q '^classification: M1_DEVICE_TEST_PACKAGE_ASSEMBLED$' <<<"$OUT"
PACKAGE_DIR="$(sed -n 's/^package-dir: //p' <<<"$OUT")"
test -f "$PACKAGE_DIR/payload/OvaltineDiag.efi"
test -f "$PACKAGE_DIR/PACKAGE_INFO.txt"
test -f "$PACKAGE_DIR/SHA256SUMS"
grep -q '^Launch commands included: NO$' "$PACKAGE_DIR/PACKAGE_INFO.txt"
grep -q '^Device commands executed by assembler: NO$' "$PACKAGE_DIR/PACKAGE_INFO.txt"
(
  cd "$PACKAGE_DIR"
  sha256sum -c SHA256SUMS >/dev/null
)

printf 'tamper\n' >> "$EFI"
if bash scripts/prepare-m1-device-test-package.sh \
  "$EFI" "$ROOT/payload.txt" "$ROOT/inspection.txt" "$ROOT/m2.txt" "$ROOT/recovery.txt" \
  "$ROOT/out2" "$ROOT/boot.txt" "$ROOT/vendor_boot.txt" >/dev/null 2>&1; then
  echo 'FAIL: modified EFI must not assemble a device-test package' >&2
  exit 1
fi

echo 'M1 device-test package assembly tests: PASS'
