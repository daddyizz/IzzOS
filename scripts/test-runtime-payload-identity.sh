#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

printf 'synthetic-efi-payload\n' > "$ROOT/test.efi"
SHA="$(sha256sum "$ROOT/test.efi" | awk '{print $1}')"
SIZE="$(wc -c < "$ROOT/test.efi" | tr -d '[:space:]')"

cat > "$ROOT/manifest.txt" <<EOF
Payload ID: M1-DIAG-R3
Identity schema: 1
EFI SHA256: $SHA
EFI size bytes: $SIZE
Status: CURRENT_M1_DEVICE_TEST_CANDIDATE
EOF

cat > "$ROOT/runtime.txt" <<'EOF'
IzzOS Ovaltine Diagnostic Payload
[IDENTITY] payload-id=M1-DIAG-R3 schema=1 hash-source=external-manifest
[RESULT] memory-map dump completed
EOF

OUT="$(bash scripts/verify-runtime-payload-identity.sh "$ROOT/runtime.txt" "$ROOT/manifest.txt" "$ROOT/test.efi")"
grep -q '^classification: RUNTIME_PAYLOAD_IDENTITY_VERIFIED$' <<<"$OUT"

gsed() { sed "$@"; }

gsed 's/payload-id=M1-DIAG-R3/payload-id=M1-DIAG-R2/' "$ROOT/runtime.txt" > "$ROOT/runtime-bad.txt"
if bash scripts/verify-runtime-payload-identity.sh "$ROOT/runtime-bad.txt" "$ROOT/manifest.txt" "$ROOT/test.efi" >/dev/null 2>&1; then
  echo 'FAIL: wrong runtime payload ID must be blocked' >&2
  exit 1
fi

cp "$ROOT/test.efi" "$ROOT/test-bad.efi"
printf 'tamper\n' >> "$ROOT/test-bad.efi"
if bash scripts/verify-runtime-payload-identity.sh "$ROOT/runtime.txt" "$ROOT/manifest.txt" "$ROOT/test-bad.efi" >/dev/null 2>&1; then
  echo 'FAIL: modified EFI must be blocked' >&2
  exit 1
fi

sed 's/Status: CURRENT_M1_DEVICE_TEST_CANDIDATE/Status: SUPERSEDED/' "$ROOT/manifest.txt" > "$ROOT/manifest-old.txt"
if bash scripts/verify-runtime-payload-identity.sh "$ROOT/runtime.txt" "$ROOT/manifest-old.txt" "$ROOT/test.efi" >/dev/null 2>&1; then
  echo 'FAIL: superseded payload manifest must be blocked' >&2
  exit 1
fi

echo 'runtime payload identity tests: PASS'
