#!/usr/bin/env bash
set -euo pipefail

DTB="${1:-out/vendor-boot-dtb-set/dtb-1.dtb}"

echo "IzzOS SM8475 reserved-memory model wrapper"
echo "classification: GENERIC_SOURCE_MODEL_DEPRECATED"
echo "reason: exact vendor_boot dtb-1 evidence supersedes the earlier hand-maintained Cape carveout table; the old table contained stale sizes/addresses and must not be used for FD placement."

if [[ ! -f "$DTB" ]]; then
  echo "ERROR: exact selected DTB not found: $DTB" >&2
  exit 2
fi

if command -v py >/dev/null 2>&1; then
  exec py scripts/model_exact_dtb_reserved_gaps.py "$DTB"
elif command -v python3 >/dev/null 2>&1; then
  exec python3 scripts/model_exact_dtb_reserved_gaps.py "$DTB"
else
  echo "ERROR: Python launcher not found. On the current Windows host use 'py'." >&2
  exit 3
fi
