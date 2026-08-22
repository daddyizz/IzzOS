#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: $0 <image-file> <device-model-product> <oxygenos-build> <image-role> <image-source> <extraction-method>" >&2
  exit 2
fi

IMAGE="$1"
DEVICE="$2"
BUILD="$3"
ROLE="$4"
SOURCE="$5"
METHOD="$6"

[[ -f "$IMAGE" ]] || { echo "ERROR: image file not found: $IMAGE" >&2; exit 2; }

for value in "$DEVICE" "$BUILD" "$ROLE" "$SOURCE" "$METHOD"; do
  case "${value,,}" in
    ""|unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)
      echo "ERROR: provenance arguments must not be empty/placeholders" >&2
      exit 2
      ;;
  esac
done

NAME="$(basename "$IMAGE")"
SIZE="$(stat -c '%s' "$IMAGE")"
SHA256="$(sha256sum "$IMAGE" | awk '{print $1}')"
OUT="${IMAGE}.provenance.txt"

cat > "$OUT" <<EOF
Device model/product: $DEVICE
OxygenOS build: $BUILD
Image role: $ROLE
Image file: $NAME
Image size bytes: $SIZE
Image SHA256: $SHA256
Image source: $SOURCE
Extraction method: $METHOD
EOF

bash "$(dirname "$0")/verify-stock-image-provenance.sh" "$OUT" >/dev/null

echo "Created: $OUT"
echo "Image SHA256: $SHA256"
echo "Image size bytes: $SIZE"
