#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-out/vendor-boot-dtb-set}"
OUT="${2:-out/vendor-boot-dtb-analysis.txt}"
mkdir -p "$(dirname "$OUT")"

if [[ ! -d "$DIR" ]]; then
  echo "ERROR: DTB directory not found: $DIR" >&2
  exit 2
fi

if ! command -v dtc >/dev/null 2>&1; then
  echo "ERROR: dtc not found. Install device-tree-compiler or run this in CI/Linux host." >&2
  exit 3
fi

shopt -s nullglob
DTBS=("$DIR"/dtb-*.dtb)
if (( ${#DTBS[@]} == 0 )); then
  echo "ERROR: no dtb-*.dtb files found in $DIR" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

{
  echo "IzzOS vendor_boot DTB structural analysis"
  echo "Collector mode: READ_ONLY_HOST_SIDE"
  echo "Device writes: NONE"
  echo "DTB count: ${#DTBS[@]}"
  echo

  for f in "${DTBS[@]}"; do
    b="$(basename "$f")"
    idx="${b#dtb-}"; idx="${idx%.dtb}"
    dts="$TMP/$b.dts"
    if ! dtc -I dtb -O dts "$f" -o "$dts" 2>"$TMP/$b.err"; then
      echo "dtb-index: $idx"
      echo "parse: FAILED"
      sed 's/^/  dtc-error: /' "$TMP/$b.err"
      echo
      continue
    fi

    model="$(awk '/^[[:space:]]*model = /{print; exit}' "$dts" | sed -E 's/^[[:space:]]*model = //; s/;$//')"
    compatible="$(awk '/^[[:space:]]*compatible = /{print; exit}' "$dts" | sed -E 's/^[[:space:]]*compatible = //; s/;$//')"
    memory_count="$(grep -Ec '^[[:space:]]*memory(@[0-9a-fA-F]+)?[[:space:]]*\{' "$dts" || true)"
    reserved_count="$(awk '
      /reserved-memory[[:space:]]*\{/ {inrm=1; depth=1; next}
      inrm {
        opens=gsub(/\{/,"{"); closes=gsub(/\}/,"}"); depth+=opens-closes;
        if ($0 ~ /^[[:space:]]*[A-Za-z0-9,._+@-]+[[:space:]]*\{/) count++;
        if (depth<=0) {print count+0; exit}
      }
      END {if (!inrm) print 0}
    ' "$dts" | tail -n1)"
    chosen_present="no"
    grep -Eq '^[[:space:]]*chosen[[:space:]]*\{' "$dts" && chosen_present="yes"
    usable="$(grep -E 'linux,usable-memory-range[[:space:]]*=' "$dts" | head -n1 | sed 's/^[[:space:]]*//')"
    memory_regs="$(awk '
      /^[[:space:]]*memory(@[0-9a-fA-F]+)?[[:space:]]*\{/ {inmem=1; depth=1; next}
      inmem {
        opens=gsub(/\{/,"{"); closes=gsub(/\}/,"}"); depth+=opens-closes;
        if ($0 ~ /^[[:space:]]*reg[[:space:]]*=/) {gsub(/^[[:space:]]+/,""); print}
        if (depth<=0) inmem=0
      }
    ' "$dts" | paste -sd '|' -)"

    echo "dtb-index: $idx"
    echo "sha256: $(sha256sum "$f" | awk '{print $1}')"
    echo "model: ${model:-UNAVAILABLE}"
    echo "compatible: ${compatible:-UNAVAILABLE}"
    echo "memory-node-count: $memory_count"
    echo "memory-reg: ${memory_regs:-UNAVAILABLE}"
    echo "reserved-memory-child-count: ${reserved_count:-0}"
    echo "chosen-present: $chosen_present"
    echo "chosen-usable-memory-range: ${usable:-UNAVAILABLE}"
    echo
  done

  if (( ${#DTBS[@]} >= 2 )); then
    base_dts="$TMP/$(basename "${DTBS[0]}").dts"
    echo "Pairwise structural differences vs dtb-0:"
    for f in "${DTBS[@]:1}"; do
      b="$(basename "$f")"
      dts="$TMP/$b.dts"
      if [[ -f "$base_dts" && -f "$dts" ]]; then
        lines="$(diff -u "$base_dts" "$dts" | grep -E '^[+-][^+-]' | wc -l | tr -d ' ')"
        echo "  $(basename "$f" .dtb) changed-lines-vs-dtb-0: $lines"
      else
        echo "  $(basename "$f" .dtb) changed-lines-vs-dtb-0: UNAVAILABLE"
      fi
    done
  fi
  echo
  echo "classification: VENDOR_BOOT_DTB_SET_STRUCTURALLY_ANALYZED"
  echo "decision: DTB structures were decoded host-side. Device-reported dtb_idx=1 remains an index-selection hint only; memory/compatible differences must be reviewed before any standalone firmware placement decision. No device launch is authorized."
} > "$OUT"

cat "$OUT"
