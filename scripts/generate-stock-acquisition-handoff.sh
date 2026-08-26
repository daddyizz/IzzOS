#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <stock-image-request-plan.txt> <output-handoff.txt>" >&2
  exit 2
fi

PLAN="$1"
OUTPUT="$2"
[[ -f "$PLAN" ]] || { echo "ERROR: request plan missing: $PLAN" >&2; exit 2; }

value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$PLAN"
}

CLASSIFICATION="$(value 'Classification')"
BUILD_ID="$(value 'Build ID')"
TARGET="$(value 'Target')"
EXTRACTION_AUTH="$(value 'Extraction authorized')"

placeholder() {
  local v="${1,,}"
  [[ -z "$v" || "$v" == "unknown" || "$v" == "n/a" || "$v" == "na" || "$v" == "none" || "$v" == "unset" || "$v" == "unvalidated" || "$v" == "-" ]]
}

if [[ "$CLASSIFICATION" != "STOCK_IMAGE_REQUEST_PLAN_READY" ]]; then
  echo "ERROR: stock-image request plan is not ready" >&2
  exit 1
fi
if placeholder "$BUILD_ID"; then
  echo "ERROR: exact build ID missing from request plan" >&2
  exit 1
fi
if [[ "$EXTRACTION_AUTH" != "NO" ]]; then
  echo "ERROR: planner safety invariant violated: Extraction authorized must remain NO" >&2
  exit 1
fi

for role in boot.img vendor_boot.img dtbo.img vbmeta.img; do
  if ! grep -Fq -- "- $role | REQUIRED |" "$PLAN"; then
    echo "ERROR: required first-wave image role missing from plan: $role" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT")"

cat > "$OUTPUT" <<EOF
IzzOS stock-image acquisition handoff
Classification: STOCK_ACQUISITION_HANDOFF_PREPARED
Target: ${TARGET:-OnePlus 10T 5G / ovaltine / SM8475}
Build ID: $BUILD_ID
Extraction authorized: NO
Device writes authorized: NO
Launch authorization: NO

Purpose
-------
This file is a pre-authorized planning artifact only. It does not download, extract, pull, flash, boot, unlock, or modify the phone. Use it only after the project explicitly opens the stock-image acquisition gate for this exact build.

Required first-wave images
--------------------------
1. boot.img
2. vendor_boot.img
3. dtbo.img
4. vbmeta.img

Conditional image
-----------------
- init_boot.img only if exact stock metadata proves it is present/relevant for this build.

Preferred source policy
-----------------------
Use the exact official OnePlus full/local-install package for build $BUILD_ID, or an exact official payload from which these images can be reproducibly extracted. A third-party mirror is only an evidence lead until cryptographic identity/provenance is established.

Per-image provenance command templates
--------------------------------------
Replace <IMAGE_PATH>, <EXACT_OFFICIAL_SOURCE>, and <EXTRACTION_METHOD> only after the acquisition gate is explicitly opened and the exact source has been validated.

boot.img:
  bash scripts/create-stock-image-provenance.sh <IMAGE_PATH>/boot.img 'OnePlus 10T 5G / ovaltine / SM8475' '$BUILD_ID' 'boot' '<EXACT_OFFICIAL_SOURCE>' '<EXTRACTION_METHOD>'

vendor_boot.img:
  bash scripts/create-stock-image-provenance.sh <IMAGE_PATH>/vendor_boot.img 'OnePlus 10T 5G / ovaltine / SM8475' '$BUILD_ID' 'vendor_boot' '<EXACT_OFFICIAL_SOURCE>' '<EXTRACTION_METHOD>'

dtbo.img:
  bash scripts/create-stock-image-provenance.sh <IMAGE_PATH>/dtbo.img 'OnePlus 10T 5G / ovaltine / SM8475' '$BUILD_ID' 'dtbo' '<EXACT_OFFICIAL_SOURCE>' '<EXTRACTION_METHOD>'

vbmeta.img:
  bash scripts/create-stock-image-provenance.sh <IMAGE_PATH>/vbmeta.img 'OnePlus 10T 5G / ovaltine / SM8475' '$BUILD_ID' 'vbmeta' '<EXACT_OFFICIAL_SOURCE>' '<EXTRACTION_METHOD>'

Post-acquisition verification
-----------------------------
1. verify every generated *.provenance.txt with scripts/verify-stock-image-provenance.sh
2. verify the complete same-build set with scripts/verify-stock-image-set.sh
3. verify the complete set against docs/CPH2413_15.0.0.1901_EX01_STOCK_HASHES.txt with scripts/verify-exact-stock-hash-lock.sh
4. analyze exact stock boot metadata before any route-specific packaging
5. preserve original images and provenance manifests unchanged; do not commit proprietary stock images to the public repository

Hard stop
---------
Do not run the command templates above until the project explicitly says the stock-image acquisition gate is open for build $BUILD_ID.
EOF

cat "$OUTPUT"
