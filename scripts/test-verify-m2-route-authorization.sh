#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/blocked.txt" <<'EOF'
Firmware ID: CI-UNVALIDATED
Selected launch route: NONE
Route decision: INSUFFICIENT_DEVICE_DATA
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: UNVALIDATED
EOF

if bash scripts/verify-m2-route-authorization.sh "$ROOT/blocked.txt" >/dev/null 2>&1; then
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

OUT="$(bash scripts/verify-m2-route-authorization.sh "$ROOT/valid.txt")"
grep -q '^classification: M2_ROUTE_AUTHORIZED_FOR_PACKAGING$' <<<"$OUT"

cat > "$ROOT/writes-bad.txt" <<'EOF'
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: temporary-chainload-example
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: ALLOWED
Slot changes: FORBIDDEN
Route validation evidence reference: evidence/m2-route-validation.txt
EOF

if bash scripts/verify-m2-route-authorization.sh "$ROOT/writes-bad.txt" >/dev/null 2>&1; then
  echo 'FAIL: persistent writes must never pass route authorization' >&2
  exit 1
fi

echo 'M2 route authorization tests: PASS'
