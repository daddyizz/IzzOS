#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/collect-running-kernel-placement-hints.sh"

bash -n "$SCRIPT"

# The remote awk program lives inside a host double-quoted string, so awk field
# references must be escaped from the host shell when set -u is enabled.
grep -Fq '\$3==\"_text\"' "$SCRIPT"
grep -Fq '\$3==\"_stext\"' "$SCRIPT"
grep -Fq '\$3==\"_end\"' "$SCRIPT"
grep -Fq '\$3==\"kimage_voffset\"' "$SCRIPT"

if grep -Fq 'awk '\''$3==' "$SCRIPT"; then
  echo "ERROR: unescaped awk field reference would be expanded by the host shell" >&2
  exit 1
fi

echo "PASS: running-kernel placement collector awk quoting is host-shell safe"
