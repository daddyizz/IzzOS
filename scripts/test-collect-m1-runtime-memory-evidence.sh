#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/collect-m1-runtime-memory-evidence.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/bin/adb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "devices" ]]; then
  printf 'List of devices attached\nTEST\tdevice\n'
  exit 0
fi

if [[ "${1:-}" == "exec-out" && "${2:-}" == "cat" ]]; then
  case "${3:-}" in
    /proc/device-tree/memory/reg)
      printf '\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00'
      ;;
    /proc/device-tree/reserved-memory/hyp_region@80000000/reg)
      printf '\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x00'
      ;;
    *) exit 1 ;;
  esac
  exit 0
fi

if [[ "${1:-}" == "shell" ]]; then
  shift
  cmd="$*"
  case "$cmd" in
    "getprop ro.product.name") echo CPH2413 ;;
    "getprop ro.product.device") echo OP5552L1 ;;
    "getprop ro.build.display.id") echo 'CPH2413_15.0.0.1901(EX01)' ;;
    "getprop ro.boot.slot_suffix") echo _a ;;
    "test -d '/proc/device-tree'") exit 0 ;;
    "test -d '/sys/firmware/devicetree/base'") exit 1 ;;
    "test -r '/proc/device-tree/memory/reg'") exit 0 ;;
    "test -r '/proc/device-tree/memory@0/reg'") exit 1 ;;
    "cat '/proc/device-tree/memory/reg' >/dev/null 2>&1") exit 0 ;;
    "cat '/proc/device-tree/memory@0/reg' >/dev/null 2>&1") exit 1 ;;
    "test -d '/proc/device-tree/reserved-memory'") exit 0 ;;
    "ls -1 '/proc/device-tree/reserved-memory' 2>/dev/null") printf '#address-cells\nhyp_region@80000000\nranges\n' ;;
    "test -d '/proc/device-tree/reserved-memory/hyp_region@80000000'") exit 0 ;;
    "test -r '/proc/device-tree/reserved-memory/hyp_region@80000000/reg'") exit 0 ;;
    "cat '/proc/device-tree/reserved-memory/hyp_region@80000000/reg' >/dev/null 2>&1") exit 0 ;;
    "test -e '/proc/device-tree/reserved-memory/hyp_region@80000000/no-map'") exit 0 ;;
    "test -e '/proc/device-tree/reserved-memory/hyp_region@80000000/reusable'") exit 1 ;;
    "test -r '/proc/device-tree/chosen/linux,usable-memory-range'") exit 1 ;;
    "cat '/proc/device-tree/chosen/linux,usable-memory-range' >/dev/null 2>&1") exit 1 ;;
    "cat /proc/iomem") echo '80000000-ffffffff : System RAM' ;;
    *grep*'/proc/meminfo'*) echo 'MemTotal:       16000000 kB' ;;
    *) exit 1 ;;
  esac
  exit 0
fi

exit 1
EOF
chmod +x "$TMP/bin/adb"

PATH="$TMP/bin:$PATH" bash "$SCRIPT" "$TMP/evidence.txt" >/dev/null

grep -q '^Target product: CPH2413$' "$TMP/evidence.txt"
grep -q '^Target device: OP5552L1$' "$TMP/evidence.txt"
grep -q '^Memory reg hex: 00000000800000000000000200000000$' "$TMP/evidence.txt"
grep -q '^  hyp_region@80000000 | reg=00000000800000000000000000600000 | no-map=yes | reusable=no$' "$TMP/evidence.txt"
grep -q '^classification: M1_RUNTIME_MEMORY_EVIDENCE_CAPTURED$' "$TMP/evidence.txt"

echo 'PASS: read-only runtime memory evidence collector'
