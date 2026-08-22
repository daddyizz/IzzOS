#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYZER="${ROOT_DIR}/scripts/analyze-ovaltine-diag.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/complete.txt" <<'EOF'
[IDENTITY] payload-id=M1-DIAG-R3 schema=1 sha256-association=EXTERNAL-MANIFEST
[GOP] mode=1 max=2
[GOP] resolution=2412x1080 pixels-per-scanline=2432 format=1
[GOP] framebuffer-base=0x00000000A0000000 framebuffer-size=0x0000000000A00000
[GOP] NOTE: values above are runtime firmware hand-off data, not hard-coded constants.
[MEM] descriptors=3 descriptor-size=48 version=1
[MEM] 000 Reserved           base=0x0000000080000000 pages=0x10 attr=0x0000000000000000
[MEM] 001 Conventional       base=0x0000000080100000 pages=0x20 attr=0x0000000000000008
[MEM] 002 MMIO               base=0x000000001D840000 pages=0x3 attr=0x8000000000000001
[RESULT] memory-map dump completed
EOF

COMPLETE_OUT="$(bash "${ANALYZER}" "${TMP_DIR}/complete.txt" M1-DIAG-R3)"
grep -q '^payload-identity: PRESENT$' <<<"${COMPLETE_OUT}"
grep -q '^payload-id: M1-DIAG-R3$' <<<"${COMPLETE_OUT}"
grep -q '^identity-schema: 1$' <<<"${COMPLETE_OUT}"
grep -q '^sha256-association: EXTERNAL-MANIFEST$' <<<"${COMPLETE_OUT}"
grep -q '^payload-identity-match: YES$' <<<"${COMPLETE_OUT}"
grep -q '^GOP: AVAILABLE$' <<<"${COMPLETE_OUT}"
grep -q '^resolution: 2412x1080$' <<<"${COMPLETE_OUT}"
grep -q '^framebuffer-base: 0x00000000A0000000$' <<<"${COMPLETE_OUT}"
grep -q '^framebuffer-end-exclusive: 0xA0A00000$' <<<"${COMPLETE_OUT}"
grep -q '^memory-map-integrity: OK$' <<<"${COMPLETE_OUT}"
grep -q '^classification: DIAGNOSTIC_CAPTURE_COMPLETE$' <<<"${COMPLETE_OUT}"

if bash "${ANALYZER}" "${TMP_DIR}/complete.txt" M1-DIAG-R2 >/dev/null 2>&1; then
  echo 'FAIL: wrong expected payload ID must be blocked' >&2
  exit 1
fi

MISMATCH_ID_OUT="$(bash "${ANALYZER}" "${TMP_DIR}/complete.txt" M1-DIAG-R2 2>/dev/null || true)"
grep -q '^payload-identity-match: NO$' <<<"${MISMATCH_ID_OUT}"
grep -q '^classification: DIAGNOSTIC_CAPTURE_IDENTITY_MISMATCH$' <<<"${MISMATCH_ID_OUT}"

cat > "${TMP_DIR}/mismatch.txt" <<'EOF'
[IDENTITY] payload-id=M1-DIAG-R3 schema=1 sha256-association=EXTERNAL-MANIFEST
[GOP] unavailable: Not Found
[MEM] descriptors=2 descriptor-size=48 version=1
[MEM] 000 Reserved           base=0x0000000080000000 pages=0x10 attr=0x0000000000000000
[RESULT] memory-map dump completed
EOF

MISMATCH_OUT="$(bash "${ANALYZER}" "${TMP_DIR}/mismatch.txt")"
grep -q '^GOP: UNAVAILABLE$' <<<"${MISMATCH_OUT}"
grep -q '^memory-map-integrity: MISMATCH$' <<<"${MISMATCH_OUT}"
grep -q '^classification: DIAGNOSTIC_CAPTURE_COMPLETE$' <<<"${MISMATCH_OUT}"

cat > "${TMP_DIR}/incomplete.txt" <<'EOF'
IzzOS Ovaltine Diagnostic Payload
Target: OnePlus 10T 5G / ovaltine / Qualcomm SM8475 (Cape)
EOF

INCOMPLETE_OUT="$(bash "${ANALYZER}" "${TMP_DIR}/incomplete.txt")"
grep -q '^payload-identity: MISSING$' <<<"${INCOMPLETE_OUT}"
grep -q '^GOP: INSUFFICIENT_DATA$' <<<"${INCOMPLETE_OUT}"
grep -q '^memory-map: MISSING$' <<<"${INCOMPLETE_OUT}"
grep -q '^classification: DIAGNOSTIC_CAPTURE_INCOMPLETE$' <<<"${INCOMPLETE_OUT}"

echo "Ovaltine diagnostic analyzer tests passed."
