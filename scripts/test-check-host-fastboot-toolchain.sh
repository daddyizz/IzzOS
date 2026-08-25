#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT_DIR/scripts/check-host-fastboot-toolchain.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

make_fastboot() {
  local path="$1" output="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo '$output'
  exit 0
fi
exit 1
EOF
  chmod +x "$path"
}

make_fastboot "$TMP/modern" 'fastboot version 37.0.0-TEST'
make_fastboot "$TMP/legacy" 'fastboot version 34.0.5-TEST'
make_fastboot "$TMP/unversioned" 'legacy fastboot'

FASTBOOT_BIN="$TMP/modern" bash "$CHECKER" > "$TMP/modern.out"
grep -q '^fastboot-version: 37.0.0$' "$TMP/modern.out"
grep -q '^classification: HOST_FASTBOOT_TOOLCHAIN_PASS$' "$TMP/modern.out"
if grep -q "$TMP" "$TMP/modern.out"; then
  echo 'ERROR: toolchain report leaked a local path' >&2
  exit 1
fi

if FASTBOOT_BIN="$TMP/legacy" bash "$CHECKER" > "$TMP/legacy.out" 2>&1; then
  echo 'ERROR: legacy fastboot must be blocked' >&2
  exit 1
fi
grep -q '^classification: HOST_FASTBOOT_TOOLCHAIN_BLOCKED$' "$TMP/legacy.out"

if FASTBOOT_BIN="$TMP/unversioned" bash "$CHECKER" > "$TMP/unversioned.out" 2>&1; then
  echo 'ERROR: unversioned fastboot must be blocked' >&2
  exit 1
fi
grep -q '^fastboot-version: UNKNOWN$' "$TMP/unversioned.out"

if FASTBOOT_BIN="$TMP/missing" bash "$CHECKER" > "$TMP/missing.out" 2>&1; then
  echo 'ERROR: missing explicit fastboot must be blocked' >&2
  exit 1
fi
grep -q '^reason: fastboot not found$' "$TMP/missing.out"

echo 'Host fastboot toolchain tests: PASS'
