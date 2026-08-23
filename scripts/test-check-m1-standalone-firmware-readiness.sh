#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/check-m1-standalone-firmware-readiness.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/repo/scripts" "$TMP/repo/docs" "$TMP/repo/uefi/Platform/IzzOS/OvaltinePkg"
cp "$SCRIPT" "$TMP/repo/scripts/"
cat > "$TMP/repo/docs/M1_STANDALONE_FIRMWARE_BRINGUP.md" <<'EOF'
# test evidence
`M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED`
EOF

pushd "$TMP/repo" >/dev/null
out="$(bash scripts/check-m1-standalone-firmware-readiness.sh)"
grep -q '^classification: M1_STANDALONE_FIRMWARE_LAYOUT_EVIDENCE_REQUIRED$' <<<"$out"

touch uefi/Platform/IzzOS/OvaltinePkg/Ovaltine.dsc
if bash scripts/check-m1-standalone-firmware-readiness.sh >/dev/null 2>&1; then
  echo "ERROR: gate accepted an unpaired standalone DSC" >&2
  exit 1
fi

class="$(bash scripts/check-m1-standalone-firmware-readiness.sh 2>&1 || true)"
grep -q '^classification: M1_STANDALONE_FIRMWARE_SOURCE_INCONSISTENT$' <<<"$class"

touch uefi/Platform/IzzOS/OvaltinePkg/Ovaltine.fdf
out="$(bash scripts/check-m1-standalone-firmware-readiness.sh)"
grep -q '^classification: M1_STANDALONE_FIRMWARE_SOURCE_PRESENT_UNVALIDATED$' <<<"$out"
popd >/dev/null

echo "PASS: standalone firmware readiness gate"
