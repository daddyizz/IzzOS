#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cat > "$ROOT/inspection.txt" <<'EOF'
[ADB] authorized devices: 1
model: OnePlus 10T 5G
device: ovaltine
product: CPH2415
build-id: CPH2415_14.0.0.710(EX01)
EOF

cat > "$ROOT/staging.txt" <<'EOF'
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: CPH2415_14.0.0.710(EX01)
Selected launch route: NONE
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
EOF

make_stock() {
  local path="$1" role="$2" build="$3"
  cat > "$path" <<EOF
Device model/product: OnePlus 10T 5G / CPH2415
OxygenOS build: $build
Image role: $role
Image file: $role.img
Image size bytes: 4096
Image SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Image source: official full update package
Extraction method: payload extraction
EOF
}

make_stock "$ROOT/boot.txt" boot 'CPH2415_14.0.0.710(EX01)'
make_stock "$ROOT/vendor_boot.txt" vendor_boot 'CPH2415_14.0.0.710(EX01)'

OUT="$(bash scripts/verify-m2-evidence-bundle.sh "$ROOT/inspection.txt" "$ROOT/staging.txt" "$ROOT/boot.txt" "$ROOT/vendor_boot.txt")"
grep -q '^classification: M2_EVIDENCE_BUNDLE_CONSISTENT$' <<<"$OUT"

make_stock "$ROOT/vendor_boot-bad.txt" vendor_boot 'CPH2415_14.0.0.700(EX01)'
if bash scripts/verify-m2-evidence-bundle.sh "$ROOT/inspection.txt" "$ROOT/staging.txt" "$ROOT/boot.txt" "$ROOT/vendor_boot-bad.txt" >/dev/null 2>&1; then
  echo 'FAIL: mixed stock builds should be blocked' >&2
  exit 1
fi

cat > "$ROOT/staging-bad.txt" <<'EOF'
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: CPH2415_14.0.0.700(EX01)
Selected launch route: NONE
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
EOF
if bash scripts/verify-m2-evidence-bundle.sh "$ROOT/inspection.txt" "$ROOT/staging-bad.txt" "$ROOT/boot.txt" >/dev/null 2>&1; then
  echo 'FAIL: staging/device build mismatch should be blocked' >&2
  exit 1
fi

echo 'M2 evidence bundle tests: PASS'
