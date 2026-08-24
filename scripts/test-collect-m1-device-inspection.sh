#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR="$ROOT_DIR/scripts/collect-m1-device-inspection.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
MOCK="$TMP/mock-bin"
mkdir -p "$MOCK"

cat > "$MOCK/adb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "devices" ]]; then
  printf 'List of devices attached\nSERIAL123\tdevice\n'
  exit 0
fi
if [[ "${1:-}" == "shell" && "${2:-}" == "getprop" ]]; then
  case "${3:-}" in
    ro.product.model) echo 'OnePlus 10T 5G' ;;
    ro.product.device) echo 'ovaltine' ;;
    ro.product.name) echo 'CPH2415' ;;
    ro.build.version.release) echo '16' ;;
    ro.build.display.id) echo 'CPH2415_16.0.0.TEST' ;;
    ro.boot.slot_suffix) echo '_a' ;;
    ro.boot.dtb_idx) echo '1' ;;
    ro.boot.verifiedbootstate) echo 'orange' ;;
    ro.boot.vbmeta.device_state) echo 'unlocked' ;;
    *) echo '' ;;
  esac
  exit 0
fi
exit 1
EOF
chmod +x "$MOCK/adb"

cat > "$MOCK/fastboot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "devices" ]]; then
  printf 'SERIAL123\tfastboot\n'
  exit 0
fi
if [[ "${1:-}" == "getvar" ]]; then
  key="${2:-}"
  case "$key" in
    product) value='ovaltine' ;;
    current-slot) value='a' ;;
    slot-count) value='2' ;;
    unlocked) value='yes' ;;
    secure) value='yes' ;;
    is-userspace) value='no' ;;
    version-bootloader) value='TEST-ABL' ;;
    *) value='' ;;
  esac
  echo "(bootloader) $key: $value" >&2
  exit 0
fi
exit 1
EOF
chmod +x "$MOCK/fastboot"

OUT1="$TMP/candidate"
PATH="$MOCK:$PATH" bash "$COLLECTOR" "$OUT1" >/dev/null

grep -q '^Classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Target match: yes$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Build ID: CPH2415_16.0.0.TEST$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Current slot: a$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Bootloader unlocked: yes$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Userspace fastboot: no$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^dtb-index: 1$' "$OUT1/ovaltine-inspection.txt"
grep -q '^Device writes: NONE$' "$OUT1/INSPECTION_SUMMARY.txt"
grep -q '^Launch commands executed: NO$' "$OUT1/INSPECTION_SUMMARY.txt"
(cd "$OUT1" && sha256sum -c SHA256SUMS >/dev/null)

rm -f "$MOCK/fastboot"
OUT2="$TMP/adb-only"
PATH="$MOCK:$PATH" bash "$COLLECTOR" "$OUT2" >/dev/null

grep -q '^Classification: NEED_EXACT_FASTBOOT_INSPECTION$' "$OUT2/INSPECTION_SUMMARY.txt"
grep -q '^Target match: yes$' "$OUT2/INSPECTION_SUMMARY.txt"
(cd "$OUT2" && sha256sum -c SHA256SUMS >/dev/null)

if grep -REn '^[[:space:]]*(adb[[:space:]]+reboot|fastboot[[:space:]]+(boot|flash|erase|format|flashing|oem|set_active)|flashall)([[:space:]]|$)' \
  "$ROOT_DIR/scripts/collect-m1-device-inspection.sh" \
  "$ROOT_DIR/scripts/inspect-ovaltine-device.sh"; then
  echo 'ERROR: destructive or launch-shaped device command found in inspection tooling' >&2
  exit 1
fi

echo 'M1 inspection collector tests: PASS'
