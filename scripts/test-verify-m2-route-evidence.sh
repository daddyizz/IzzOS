#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

BUILD='CPH2413_15.0.0.1901(EX01)'
ROUTE='temporary-chainload-fixture'

cat > "$ROOT/m2.txt" <<EOF
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: $BUILD
Selected launch route: $ROUTE
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

for role in before-state route-transcript diagnostic-output after-state; do
  printf 'synthetic-%s-for-%s\n' "$role" "$BUILD" > "$ROOT/$role.txt"
done

write_evidence() {
  {
    echo 'Schema: IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1'
    echo 'Target: OnePlus 10T 5G / CPH2413 / ovaltine / SM8475'
    echo "Firmware ID: $BUILD"
    echo "Selected launch route: $ROUTE"
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
}

write_evidence
OUT="$(bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt")"
grep -q '^classification: TEMPORARY_ROUTE_EVIDENCE_CONTENT_BOUND$' <<<"$OUT"
grep -q '^artifact-count: 4$' <<<"$OUT"
grep -q '^content-binding: PASS$' <<<"$OUT"

cp "$ROOT/route-evidence.txt" "$ROOT/route-evidence-good.txt"
printf 'tamper\n' >> "$ROOT/diagnostic-output.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: mutated route artifact must be blocked' >&2
  exit 1
fi

printf 'synthetic-diagnostic-output-for-%s\n' "$BUILD" > "$ROOT/diagnostic-output.txt"
write_evidence
sed -i 's/Stock boot restored: YES/Stock boot restored: NO/' "$ROOT/route-evidence.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: missing stock-boot restoration must be blocked' >&2
  exit 1
fi

write_evidence
sed -i 's/after-state.txt/..\/after-state.txt/' "$ROOT/route-evidence.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: path-shaped artifact filename must be blocked' >&2
  exit 1
fi

write_evidence
sed -i '/^Artifact record: after-state|/d' "$ROOT/route-evidence.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: missing route artifact role must be blocked' >&2
  exit 1
fi

write_evidence
sed -i 's/Firmware ID: CPH2413_15.0.0.1901(EX01)/Firmware ID: CPH2413_OTHER_BUILD/' "$ROOT/route-evidence.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: route evidence firmware drift must be blocked' >&2
  exit 1
fi

write_evidence
sed -i 's/after-state|after-state.txt/after-state|before-state.txt/' "$ROOT/route-evidence.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: one artifact file reused by two roles must be blocked' >&2
  exit 1
fi

write_evidence
printf 'Firmware ID: %s\n' "$BUILD" >> "$ROOT/m2.txt"
if bash scripts/verify-m2-route-evidence.sh "$ROOT/m2.txt" "$ROOT/route-evidence.txt" >/dev/null 2>&1; then
  echo 'FAIL: duplicate manifest field must be blocked' >&2
  exit 1
fi

echo 'M2 content-bound route evidence tests: PASS'
