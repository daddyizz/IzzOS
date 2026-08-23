#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-out/vendor-boot-dtb-set}"
OUT="${2:-out/vendor-boot-dtb-analysis.txt}"
mkdir -p "$(dirname "$OUT")"

if [[ ! -d "$DIR" ]]; then
  echo "ERROR: DTB directory not found: $DIR" >&2
  exit 2
fi

shopt -s nullglob
DTBS=("$DIR"/dtb-*.dtb)
if (( ${#DTBS[@]} == 0 )); then
  echo "ERROR: no dtb-*.dtb files found in $DIR" >&2
  exit 1
fi

be32() {
  local f="$1" off="$2" h
  h="$(dd if="$f" bs=1 skip="$off" count=4 status=none | od -An -tx1 -v | tr -d ' \n')"
  [[ ${#h} -eq 8 ]] || { printf '0'; return; }
  printf '%u' "$((16#$h))"
}

hex_slice() {
  local f="$1" off="$2" len="$3"
  dd if="$f" bs=1 skip="$off" count="$len" status=none | od -An -tx1 -v | tr -d ' \n'
}

ascii_prop() {
  local f="$1" name="$2"
  strings -a "$f" | grep -m1 -F "$name" || true
}

fdt_summary() {
  local f="$1"
  local magic total off_struct off_strings size_strings size_struct
  magic="$(hex_slice "$f" 0 4)"
  total="$(be32 "$f" 4)"
  off_struct="$(be32 "$f" 8)"
  off_strings="$(be32 "$f" 12)"
  size_strings="$(be32 "$f" 32)"
  size_struct="$(be32 "$f" 36)"
  echo "fdt-magic: $magic"
  echo "fdt-total-size: $total"
  echo "fdt-struct-offset: $off_struct"
  echo "fdt-struct-size: $size_struct"
  echo "fdt-strings-offset: $off_strings"
  echo "fdt-strings-size: $size_strings"

  local model compat chosen usable memory_mark reserved_mark
  model="$(strings -a "$f" | grep -m1 -E '^Qualcomm Technologies, Inc\.|^OnePlus|^OPPO|^CPH2413$' || true)"
  compat="$(strings -a "$f" | grep -m1 -E '^qcom,cape$|^qcom,.*cape|^oneplus,|^oplus,' || true)"
  chosen="$(strings -a "$f" | grep -m1 '^chosen$' || true)"
  usable="$(strings -a "$f" | grep -m1 '^linux,usable-memory-range$' || true)"
  memory_mark="$(strings -a "$f" | grep -m1 -E '^memory(@[0-9a-fA-F]+)?$' || true)"
  reserved_mark="$(strings -a "$f" | grep -m1 '^reserved-memory$' || true)"
  echo "model-string-hint: ${model:-UNAVAILABLE}"
  echo "compatible-string-hint: ${compat:-UNAVAILABLE}"
  echo "memory-node-string-hint: ${memory_mark:-UNAVAILABLE}"
  echo "reserved-memory-string-hint: ${reserved_mark:-UNAVAILABLE}"
  echo "chosen-present-hint: $([[ -n "$chosen" ]] && echo yes || echo no)"
  echo "chosen-usable-memory-range-name-hint: ${usable:-UNAVAILABLE}"

  echo "reserved-memory-address-string-hints:"
  strings -a "$f" | grep -E '(^|_)(mem|memory|region)@[0-9a-fA-F]+$|^[A-Za-z0-9,._+-]+@[89a-fA-F][0-9a-fA-F]{7,}$' | head -n 80 | sed 's/^/  /' || true
}

{
  echo "IzzOS vendor_boot DTB structural analysis"
  echo "Collector mode: READ_ONLY_HOST_SIDE"
  echo "Device writes: NONE"
  echo "Parser: PURE_BASH_FDT_HEADER_AND_STRING_HINTS"
  echo "DTB count: ${#DTBS[@]}"
  echo

  for f in "${DTBS[@]}"; do
    b="$(basename "$f")"
    idx="${b#dtb-}"; idx="${idx%.dtb}"
    echo "dtb-index: $idx"
    echo "sha256: $(sha256sum "$f" | awk '{print $1}')"
    fdt_summary "$f"
    echo
  done

  if (( ${#DTBS[@]} >= 2 )); then
    echo "Pairwise binary differences vs dtb-0:"
    base="${DTBS[0]}"
    for f in "${DTBS[@]:1}"; do
      same="no"
      cmp -s "$base" "$f" && same="yes"
      echo "  $(basename "$f" .dtb) identical-to-dtb-0: $same"
      echo "  $(basename "$f" .dtb) size: $(wc -c < "$f" | tr -d ' ')"
    done
  fi
  echo
  echo "classification: VENDOR_BOOT_DTB_SET_STRUCTURALLY_ANALYZED_NO_DTC"
  echo "decision: FDT headers and string-table/structure hints were inspected host-side without dtc. Device-reported dtb_idx=1 remains an index-selection hint only. Exact property values such as root memory/reg still require a full FDT property walker or dtc before any standalone firmware placement decision. No device launch is authorized."
} > "$OUT"

cat "$OUT"
