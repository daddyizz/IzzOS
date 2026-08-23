#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/collect-running-kernel-placement-hints.sh"

bash -n "$SCRIPT"

# The remote awk program lives inside a host double-quoted string, so awk field
# references must be escaped from the host shell when set -u is enabled.
grep -Fq 'awk '\''\$3=="_text" || \$3=="_stext" || \$3=="_end" || \$3=="kimage_voffset" {print}'\''' "$SCRIPT"

if grep -Fq 'awk '\''$3==' "$SCRIPT"; then
  echo "ERROR: unescaped awk field reference would be expanded by the host shell" >&2
  exit 1
fi

echo "PASS: running-kernel placement collector awk quoting is host-shell safe"
