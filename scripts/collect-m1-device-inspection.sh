#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [output-dir]" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/out/m1-device-inspection}"
RAW="$OUTPUT_DIR/ovaltine-inspection.txt"
ANALYSIS="$OUTPUT_DIR/ovaltine-inspection-analysis.txt"
SUMMARY="$OUTPUT_DIR/INSPECTION_SUMMARY.txt"
CHECKSUMS="$OUTPUT_DIR/SHA256SUMS"

mkdir -p "$OUTPUT_DIR"
rm -f "$RAW" "$ANALYSIS" "$SUMMARY" "$CHECKSUMS"

bash "$ROOT_DIR/scripts/inspect-ovaltine-device.sh" | tee "$RAW"
bash "$ROOT_DIR/scripts/analyze-ovaltine-inspection.sh" "$RAW" | tee "$ANALYSIS"

CLASSIFICATION="$(awk -F': ' '/^Classification:/ {print $2; exit}' "$ANALYSIS")"
TARGET_MATCH="$(awk -F': ' '/^Target match:/ {print $2; exit}' "$ANALYSIS")"
BUILD_ID="$(awk -F': ' '/^Build ID:/ {print $2; exit}' "$ANALYSIS")"
CURRENT_SLOT="$(awk -F': ' '/^Current slot:/ {print $2; exit}' "$ANALYSIS")"
UNLOCKED="$(awk -F': ' '/^Unlocked:/ {print $2; exit}' "$ANALYSIS")"
USERSPACE="$(awk -F': ' '/^Userspace fastboot:/ {print $2; exit}' "$ANALYSIS")"

cat > "$SUMMARY" <<EOF
IzzOS M1 exact-device inspection summary
Target: OnePlus 10T 5G / ovaltine / SM8475
Target match: ${TARGET_MATCH:-unknown}
Classification: ${CLASSIFICATION:-INSUFFICIENT_DATA}
Build ID: ${BUILD_ID:-unknown}
Current slot: ${CURRENT_SLOT:-unknown}
Bootloader unlocked: ${UNLOCKED:-unknown}
Userspace fastboot: ${USERSPACE:-unknown}
Collector mode: READ_ONLY
Device writes: NONE
Launch commands executed: NO
Flash/erase/format/unlock/set_active: FORBIDDEN

This bundle contains inspection evidence only. It does not authorize temporary boot, packaging, flashing, unlocking, slot changes, or any persistent device modification.
EOF

(
  cd "$OUTPUT_DIR"
  sha256sum ovaltine-inspection.txt ovaltine-inspection-analysis.txt INSPECTION_SUMMARY.txt > SHA256SUMS
)

case "${CLASSIFICATION:-}" in
  TARGET_MISMATCH_BLOCKED|FASTBOOTD_DETECTED_BLOCKED|LOCKED_BOOTLOADER_BLOCKED|BOOTLOADER_STATE_UNKNOWN_BLOCKED|INSUFFICIENT_DATA|NEED_EXACT_FASTBOOT_INSPECTION)
    echo
    echo "classification: ${CLASSIFICATION:-INSUFFICIENT_DATA}"
    echo "decision: inspection evidence collected; hardware launch preparation remains blocked."
    ;;
  CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED)
    echo
    echo "classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED"
    echo "decision: candidate route evidence collected; temporary boot support is still unverified and no launch command is authorized."
    ;;
  *)
    echo "ERROR: unexpected analyzer classification: ${CLASSIFICATION:-missing}" >&2
    exit 1
    ;;
esac

echo "evidence-dir: $OUTPUT_DIR"
echo "checksums: $CHECKSUMS"
