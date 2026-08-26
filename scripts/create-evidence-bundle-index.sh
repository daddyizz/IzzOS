#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <output-index> <evidence-file> [evidence-file ...]" >&2
  exit 2
fi

OUT="$1"
shift

: > "$OUT"

for path in "$@"; do
  if [[ ! -f "$path" ]]; then
    echo "ERROR: evidence file not found: $path" >&2
    rm -f "$OUT"
    exit 2
  fi
  sha="$(sha256sum "$path" | awk '{print $1}')"
  size="$(stat -c '%s' "$path")"
  printf '%s  %s  %s\n' "$sha" "$size" "$path" >> "$OUT"
done

echo "classification: EVIDENCE_INDEX_CREATED"
echo "index: $OUT"
echo "files: $#"
