#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <M1_EXACT_DEVICE_EVIDENCE.txt> <output-plan.txt>" >&2
  exit 2
fi

EVIDENCE="$1"
OUTPUT="$2"
[[ -f "$EVIDENCE" ]] || { echo "ERROR: evidence file missing: $EVIDENCE" >&2; exit 2; }

value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$EVIDENCE"
}

CLASSIFICATION="$(value 'Classification')"
TARGET_MATCH="$(value 'Target match')"
BUILD_ID="$(value 'Build ID')"
SLOT="$(value 'Current slot')"
FB_CLASS="$(value 'Fastboot classification')"

placeholder() {
  local v="${1,,}"
  [[ -z "$v" || "$v" == "unknown" || "$v" == "n/a" || "$v" == "na" || "$v" == "none" || "$v" == "unset" || "$v" == "unvalidated" || "$v" == "-" ]]
}

blocked=0
reasons=()
if [[ "$CLASSIFICATION" != "M1_EXACT_DEVICE_EVIDENCE_CONSISTENT" ]]; then
  blocked=1
  reasons+=("canonical exact-device evidence is not consistent")
fi
if [[ "$TARGET_MATCH" != "yes" ]]; then
  blocked=1
  reasons+=("target is not positively matched to ovaltine")
fi
if placeholder "$BUILD_ID"; then
  blocked=1
  reasons+=("exact OxygenOS/build ID is missing")
fi

mkdir -p "$(dirname "$OUTPUT")"

if [[ "$blocked" -ne 0 ]]; then
  {
    echo "IzzOS stock-image request plan"
    echo "Classification: STOCK_IMAGE_REQUEST_BLOCKED"
    echo "Target: OnePlus 10T 5G / ovaltine / SM8475"
    echo "Build ID: ${BUILD_ID:-unknown}"
    echo "Current slot: ${SLOT:-unknown}"
    for r in "${reasons[@]}"; do echo "Blocker: $r"; done
    echo "Extraction authorized: NO"
    echo "Device writes authorized: NO"
  } > "$OUTPUT"
  cat "$OUTPUT"
  exit 1
fi

cat > "$OUTPUT" <<EOF
IzzOS stock-image request plan
Classification: STOCK_IMAGE_REQUEST_PLAN_READY
Target: OnePlus 10T 5G / ovaltine / SM8475
Build ID: $BUILD_ID
Current slot: ${SLOT:-unknown}
Fastboot classification: ${FB_CLASS:-unknown}
Preferred source: exact official OnePlus full/local-install package for this build, or an exact official payload that reproducibly yields the required images
Third-party mirror policy: evidence lead only; do not use unless cryptographic identity/provenance is established

Required first-wave images:
- boot.img | REQUIRED | verify boot header/layout and temporary-route derivation inputs
- vendor_boot.img | REQUIRED | verify vendor boot header/fragments and matching firmware context
- dtbo.img | REQUIRED | verify exact device-tree overlay payload for the same build
- vbmeta.img | REQUIRED | verify AVB metadata and exact build pairing

Conditional images:
- init_boot.img | CONDITIONAL | request only if present/relevant on this exact firmware and confirmed by stock metadata

Deferred by default:
- abl/xbl/uefi or other bootloader partitions | DEFERRED | do not acquire merely because another Qualcomm device used them
- modem, persist, super, userdata, metadata | DEFERRED | unrelated to current non-destructive M1/M2 route decision

For every acquired stock image create provenance with:
- Device model/product
- exact OxygenOS/build ID: $BUILD_ID
- Image role
- exact filename
- byte size
- SHA256
- source
- extraction method/tool context

Required verification sequence after acquisition:
1. create provenance manifests with scripts/create-stock-image-provenance.sh
2. verify each manifest with scripts/verify-stock-image-provenance.sh
3. verify same-build set with scripts/verify-stock-image-set.sh
4. verify the complete content-bound set with scripts/verify-exact-stock-hash-lock.sh and the exact-build lock
5. analyze exact stock boot metadata before route-specific packaging

Extraction authorized: NO
Device writes authorized: NO
Launch authorization: NO
Decision: this plan identifies what to request when the project explicitly opens the stock-image acquisition gate; it does not itself request, extract, download, flash, boot, or modify the device.
EOF

cat "$OUTPUT"
