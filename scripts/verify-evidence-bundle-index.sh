#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <EVIDENCE_SHA256SUMS>" >&2
  exit 2
fi

INDEX="$1"
[[ -f "$INDEX" ]] || { echo "ERROR: evidence index not found: $INDEX" >&2; exit 2; }

count=0
while read -r expected_sha expected_size path; do
  [[ -n "${expected_sha:-}" ]] || continue
  count=$((count + 1))

  if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: malformed SHA256 in index for: ${path:-UNKNOWN}" >&2
    exit 1
  fi

  if [[ ! "$expected_size" =~ ^[0-9]+$ ]]; then
    echo "ERROR: malformed size in index for: ${path:-UNKNOWN}" >&2
    exit 1
  fi

  if [[ -z "${path:-}" || ! -f "$path" ]]; then
    echo "ERROR: indexed evidence file missing: ${path:-UNKNOWN}" >&2
    exit 1
  fi

  actual_sha="$(sha256sum "$path" | awk '{print $1}')"
  actual_size="$(stat -c '%s' "$path")"

  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "ERROR: evidence SHA256 mismatch: $path" >&2
    exit 1
  fi

  if [[ "$actual_size" != "$expected_size" ]]; then
    echo "ERROR: evidence size mismatch: $path" >&2
    exit 1
  fi
done < "$INDEX"

if [[ "$count" -eq 0 ]]; then
  echo "ERROR: evidence index is empty" >&2
  exit 1
fi

echo "classification: EVIDENCE_INDEX_VERIFIED"
echo "files: $count"
echo "decision: indexed evidence files are unchanged since the index was created."
