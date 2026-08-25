#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PY_TMP="$TMP"
ANALYZER="$ROOT/scripts/analyze-linuxloader-fastboot-strings.py"
if [[ "$PYTHON" == *.exe ]] && command -v cygpath >/dev/null 2>&1; then
  PY_TMP="$(cygpath -w "$TMP")"
  ANALYZER="$(cygpath -w "$ANALYZER")"
fi

"$PYTHON" -c 'import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(b"prefix\0fastboot: boot\0noise\0\0" + "getvar:current-slot".encode("utf-16le") + b"\0\0tail")' "$PY_TMP/fixture.bin"
"$PYTHON" "$ANALYZER" "$PY_TMP/fixture.bin" "$PY_TMP/report.txt" >/dev/null

grep -q '^classification: LINUXLOADER_FASTBOOT_BOOT_STRINGS_ENUMERATED$' "$TMP/report.txt"
grep -q '|ASCII|fastboot: boot$' "$TMP/report.txt"
grep -q '|UTF16LE|getvar:current-slot$' "$TMP/report.txt"
if grep -q '|ASCII|noise$' "$TMP/report.txt"; then
  echo 'ERROR: analyzer emitted an unrelated string' >&2
  exit 1
fi

printf 'completely unrelated fixture' > "$TMP/empty.bin"
"$PYTHON" "$ANALYZER" "$PY_TMP/empty.bin" "$PY_TMP/empty-report.txt" >/dev/null
grep -q '^classification: LINUXLOADER_FASTBOOT_BOOT_STRINGS_NOT_FOUND$' "$TMP/empty-report.txt"

if "$PYTHON" "$ANALYZER" "$PY_TMP/fixture.bin" "$PY_TMP/fixture.bin" >/dev/null 2>&1; then
  echo 'ERROR: analyzer allowed output to overwrite its input' >&2
  exit 1
fi

echo 'LinuxLoader fastboot/boot string analyzer tests: PASS'
