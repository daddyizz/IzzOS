#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if OUT="$(bash "$ROOT/scripts/model-sm8475-reserved-memory-gaps.sh" "$TMP/missing-exact-dtb.dtb" 2>&1)"; then
  echo "ERROR: deprecated generic model ran without exact selected-DTB evidence" >&2
  exit 1
fi

grep -q '^classification: GENERIC_SOURCE_MODEL_DEPRECATED$' <<<"$OUT"
grep -q '^reason: exact vendor_boot dtb-1 evidence supersedes the earlier hand-maintained Cape carveout table' <<<"$OUT"
grep -q '^ERROR: exact selected DTB not found:' <<<"$OUT"

echo "PASS: deprecated generic SM8475 model requires exact selected-DTB evidence"
