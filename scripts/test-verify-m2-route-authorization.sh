#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/recovery-valid.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2415_14.0.0.710(EX01)
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: SELF_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: temporary-chainload-example
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: evidence/recovery.txt
EOF

cat > "$ROOT/recovery-mismatch.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2415_OTHER_BUILD
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: SELF_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: temporary-chainload-example
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: evidence/recovery.txt
EOF

cat > "$ROOT/blocked.txt" <<'EOF'
Firmware ID: CI-UNVALIDATED
Selected launch route: NONE
Route decision: INSUFFICIENT_DEVICE_DATA
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: UNVALIDATED
EOF

if bash scripts/verify-m2-route-authorization.sh "$ROOT/blocked.txt" "$ROOT/recovery-valid.txt" >/dev/null 2>&1; then
  echo 'FAIL: unvalidated route must be blocked' >&2
  exit 1
fi

cat > "$ROOT/valid.txt" <<'EOF'
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: evidence/m2-route-validation.txt
EOF

OUT="$(bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt" "$ROOT/recovery-valid.txt")"
grep -q '^classification: M2_ROUTE_AUTHORIZED_FOR_PACKAGING$' <<<"$OUT"
grep -q '^recovery-evidence: COMPLETE$' <<<"$OUT"

cat > "$ROOT/writes-bad.txt" <<'EOF'
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: ALLOWED
Slot changes: FORBIDDEN
Route validation evidence reference: evidence/m2-route-validation.txt
EOF

if bash scripts/verify-m2-route-authorization.sh "$ROOT/writes-bad.txt" "$ROOT/recovery-valid.txt" >/dev/null 2>&1; then
  echo 'FAIL: persistent writes must never pass route authorization' >&2
  exit 1
fi

if bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt" "$ROOT/recovery-mismatch.txt" >/dev/null 2>&1; then
  echo 'FAIL: firmware/recovery build mismatch must be blocked' >&2
  exit 1
fi

echo 'M2 route authorization tests: PASS'
