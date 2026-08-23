#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(bash "$ROOT/scripts/model-sm8475-reserved-memory-gaps.sh")"

grep -q '^classification: SOURCE_BACKED_FIXED_CARVEOUT_MODEL_ONLY$' <<<"$OUT"
grep -q '^runtime DRAM span base evidence: 0x80000000$' <<<"$OUT"
grep -q 'reserved 0x80000000-0x85200000' <<<"$OUT"
grep -q 'status=UNVALIDATED_GAP' <<<"$OUT"
grep -q '^decision: .*gaps are not safe FD ranges' <<<"$OUT"

if grep -q 'status=SAFE' <<<"$OUT"; then
  echo "ERROR: research gap model must never classify a range SAFE" >&2
  exit 1
fi

echo "PASS: SM8475 reserved-memory gap model remains conservative"
