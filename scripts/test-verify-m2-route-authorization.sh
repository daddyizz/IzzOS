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
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: CI-UNVALIDATED
Selected launch route: NONE
Route decision: INSUFFICIENT_DEVICE_DATA
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

for role in before-state route-transcript diagnostic-output after-state; do
  printf 'synthetic-%s-route-evidence\n' "$role" > "$ROOT/$role.txt"
done
{
  echo 'Schema: IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1'
  echo 'Target: OnePlus 10T 5G / CPH2415 / ovaltine / SM8475'
  echo 'Firmware ID: CPH2415_14.0.0.710(EX01)'
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
    file="$ROOT/$role.txt"
    printf 'Artifact record: %s|%s.txt|%s|%s\n' \
      "$role" "$role" "$(stat -c '%s' "$file")" "$(sha256sum "$file" | awk '{print $1}')"
  done
} > "$ROOT/route-evidence.txt"

if bash scripts/verify-m2-route-authorization.sh "$ROOT/blocked.txt" "$ROOT/recovery-valid.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: unvalidated route must be blocked' >&2
  exit 1
fi

cat > "$ROOT/valid.txt" <<'EOF'
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

OUT="$(bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt" "$ROOT/recovery-valid.txt" "$ROOT/route-evidence.txt")"
grep -q '^classification: M2_ROUTE_AUTHORIZED_FOR_PACKAGING$' <<<"$OUT"
grep -q '^recovery-evidence: COMPLETE$' <<<"$OUT"
grep -q '^route-evidence: CONTENT_BOUND$' <<<"$OUT"

cat > "$ROOT/writes-bad.txt" <<'EOF'
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: ALLOWED
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

if bash scripts/verify-m2-route-authorization.sh "$ROOT/writes-bad.txt" "$ROOT/recovery-valid.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: persistent writes must never pass route authorization' >&2
  exit 1
fi

if bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt" "$ROOT/recovery-mismatch.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: firmware/recovery build mismatch must be blocked' >&2
  exit 1
fi

printf 'tamper\n' >> "$ROOT/route-transcript.txt"
if bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt" "$ROOT/recovery-valid.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: modified physical-route evidence must block authorization' >&2
  exit 1
fi

echo 'M2 route authorization tests: PASS'
