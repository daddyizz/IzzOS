#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <adb-inspection-dir> <fastboot-inspection-dir> <output-dir>" >&2
  exit 2
fi

ADB_DIR="$1"
FASTBOOT_DIR="$2"
OUTPUT_DIR="$3"

ADB_SUMMARY="$ADB_DIR/INSPECTION_SUMMARY.txt"
ADB_ANALYSIS="$ADB_DIR/ovaltine-inspection-analysis.txt"
FASTBOOT_SUMMARY="$FASTBOOT_DIR/INSPECTION_SUMMARY.txt"
FASTBOOT_ANALYSIS="$FASTBOOT_DIR/ovaltine-inspection-analysis.txt"

for f in "$ADB_SUMMARY" "$ADB_ANALYSIS" "$FASTBOOT_SUMMARY" "$FASTBOOT_ANALYSIS"; do
  [[ -f "$f" ]] || { echo "ERROR: required inspection file missing: $f" >&2; exit 2; }
done

value() {
  local file="$1" key="$2"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$file"
}

normalize_slot() {
  local slot="${1:-}"
  slot="${slot#_}"
  printf '%s' "$slot" | tr '[:upper:]' '[:lower:]'
}

placeholder() {
  local v="${1,,}"
  [[ -z "$v" || "$v" == "unknown" || "$v" == "n/a" || "$v" == "na" || "$v" == "none" || "$v" == "unset" || "$v" == "unvalidated" || "$v" == "-" ]]
}

ADB_TARGET="$(value "$ADB_SUMMARY" 'Target match')"
ADB_CLASS="$(value "$ADB_SUMMARY" 'Classification')"
ADB_BUILD="$(value "$ADB_SUMMARY" 'Build ID')"
ADB_SLOT="$(normalize_slot "$(value "$ADB_SUMMARY" 'Current slot')")"

FB_TARGET="$(value "$FASTBOOT_SUMMARY" 'Target match')"
FB_CLASS="$(value "$FASTBOOT_SUMMARY" 'Classification')"
FB_BUILD="$(value "$FASTBOOT_SUMMARY" 'Build ID')"
FB_SLOT="$(normalize_slot "$(value "$FASTBOOT_SUMMARY" 'Current slot')")"
FB_UNLOCKED="$(value "$FASTBOOT_SUMMARY" 'Bootloader unlocked')"
FB_USERSPACE="$(value "$FASTBOOT_SUMMARY" 'Userspace fastboot')"

blocked=0
reason=()

if [[ "$ADB_TARGET" != "yes" ]]; then
  reason+=("ADB capture does not positively match ovaltine")
  blocked=1
fi
if [[ "$FB_TARGET" != "yes" ]]; then
  reason+=("fastboot capture does not positively match ovaltine")
  blocked=1
fi
if placeholder "$ADB_BUILD"; then
  reason+=("ADB capture does not provide an exact build ID")
  blocked=1
fi

if ! placeholder "$FB_BUILD" && [[ "$FB_BUILD" != "$ADB_BUILD" ]]; then
  reason+=("ADB and fastboot build IDs disagree")
  blocked=1
fi

if ! placeholder "$ADB_SLOT" && ! placeholder "$FB_SLOT" && [[ "$ADB_SLOT" != "$FB_SLOT" ]]; then
  reason+=("ADB and fastboot slot observations disagree")
  blocked=1
fi

case "$FB_CLASS" in
  CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED|FASTBOOTD_DETECTED_BLOCKED|LOCKED_BOOTLOADER_BLOCKED|BOOTLOADER_STATE_UNKNOWN_BLOCKED)
    ;;
  *)
    reason+=("fastboot capture does not contain a usable bootloader classification")
    blocked=1
    ;;
esac

mkdir -p "$OUTPUT_DIR"
OUT="$OUTPUT_DIR/M1_EXACT_DEVICE_EVIDENCE.txt"
CHECKSUMS="$OUTPUT_DIR/SHA256SUMS"

if [[ "$blocked" -ne 0 ]]; then
  {
    echo "IzzOS M1 exact-device evidence merge"
    echo "Classification: M1_EXACT_DEVICE_EVIDENCE_BLOCKED"
    echo "Target: OnePlus 10T 5G / ovaltine / SM8475"
    echo "ADB classification: ${ADB_CLASS:-unknown}"
    echo "Fastboot classification: ${FB_CLASS:-unknown}"
    echo "Build ID: ${ADB_BUILD:-unknown}"
    echo "ADB slot: ${ADB_SLOT:-unknown}"
    echo "Fastboot slot: ${FB_SLOT:-unknown}"
    for r in "${reason[@]}"; do echo "Blocker: $r"; done
    echo "Device writes: NONE"
    echo "Launch authorization: NO"
  } > "$OUT"
  sha256sum "$OUT" > "$CHECKSUMS"
  cat "$OUT"
  exit 1
fi

CANONICAL_SLOT="$FB_SLOT"
placeholder "$CANONICAL_SLOT" && CANONICAL_SLOT="$ADB_SLOT"
placeholder "$CANONICAL_SLOT" && CANONICAL_SLOT="unknown"

cat > "$OUT" <<EOF
IzzOS M1 exact-device evidence merge
Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
Target: OnePlus 10T 5G / ovaltine / SM8475
Target match: yes
Build ID: $ADB_BUILD
Current slot: $CANONICAL_SLOT
Bootloader unlocked: ${FB_UNLOCKED:-unknown}
Userspace fastboot: ${FB_USERSPACE:-unknown}
ADB classification: $ADB_CLASS
Fastboot classification: $FB_CLASS
ADB evidence SHA256: $(sha256sum "$ADB_SUMMARY" | awk '{print $1}')
Fastboot evidence SHA256: $(sha256sum "$FASTBOOT_SUMMARY" | awk '{print $1}')
Collector mode: READ_ONLY
Device writes: NONE
Launch commands executed: NO
Launch authorization: NO

This file proves only that the supplied ADB-side and fastboot-side captures are internally consistent on target/build/slot fields that are available. It does not prove physical device identity beyond those observations and does not authorize temporary boot, flashing, unlocking, slot changes, or persistent modification.
EOF

sha256sum "$OUT" > "$CHECKSUMS"
cat "$OUT"
