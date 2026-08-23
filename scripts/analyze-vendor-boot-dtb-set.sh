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

hex_to_ascii() {
  local hex="$1" out="" i pair dec
  for ((i=0; i+1<${#hex}; i+=2)); do
    pair="${hex:i:2}"
    [[ "$pair" == "00" ]] && break
    dec=$((16#$pair))
    if (( dec >= 32 && dec <= 126 )); then
      printf -v out '%s%b' "$out" "\\x$pair"
    else
      out+="?"
    fi
  done
  printf '%s' "$out"
}

hex_string_list() {
  local hex="$1" out="" cur="" i pair dec text
  for ((i=0; i+1<${#hex}; i+=2)); do
    pair="${hex:i:2}"
    if [[ "$pair" == "00" ]]; then
      text="$(hex_to_ascii "$cur")"
      if [[ -n "$text" ]]; then
        [[ -n "$out" ]] && out+="," 
        out+="$text"
      fi
      cur=""
    else
      cur+="$pair"
    fi
  done
  [[ -n "$cur" ]] && { text="$(hex_to_ascii "$cur")"; [[ -n "$out" ]] && out+=","; out+="$text"; }
  printf '%s' "$out"
}

be32_hex() {
  local hex="$1" byte_off="$2" h
  h="${hex:$((byte_off*2)):8}"
  [[ ${#h} -eq 8 ]] || { printf '0'; return; }
  printf '%u' "$((16#$h))"
}

nul_string_at() {
  local hex="$1" byte_off="$2" limit_bytes="${3:-4096}" pos=$((byte_off*2)) out="" pair i
  for ((i=0; i<limit_bytes && pos+i*2+1<${#hex}; i++)); do
    pair="${hex:$((pos+i*2)):2}"
    [[ "$pair" == "00" ]] && break
    out+="$pair"
  done
  hex_to_ascii "$out"
}

align4() { printf '%u' "$(( ($1 + 3) & ~3 ))"; }

fdt_summary() {
  local f="$1" hex magic total off_struct off_strings size_strings size_struct
  hex="$(od -An -tx1 -v "$f" | tr -d ' \n')"
  magic="${hex:0:8}"
  total="$(be32_hex "$hex" 4)"
  off_struct="$(be32_hex "$hex" 8)"
  off_strings="$(be32_hex "$hex" 12)"
  size_strings="$(be32_hex "$hex" 32)"
  size_struct="$(be32_hex "$hex" 36)"

  echo "fdt-magic: $magic"
  echo "fdt-total-size: $total"
  echo "fdt-struct-offset: $off_struct"
  echo "fdt-struct-size: $size_struct"
  echo "fdt-strings-offset: $off_strings"
  echo "fdt-strings-size: $size_strings"

  if [[ "$magic" != "d00dfeed" ]]; then
    echo "parse: INVALID_FDT_MAGIC"
    return
  fi

  local cursor="$off_struct" struct_end=$((off_struct + size_struct)) token len nameoff propname val_off val_hex node
  local -a stack=()
  local path="/" model="" compatible="" chosen="no" usable="" memory_regs="" reserved_count=0
  local root_addr_cells="" root_size_cells="" reserved_addr_cells="" reserved_size_cells=""
  local reserved_entries=""

  while (( cursor + 4 <= struct_end )); do
    token="$(be32_hex "$hex" "$cursor")"
    cursor=$((cursor + 4))
    case "$token" in
      1)
        node="$(nul_string_at "$hex" "$cursor")"
        cursor=$((cursor + ${#node} + 1))
        cursor="$(align4 "$cursor")"
        stack+=("$node")
        path="/"
        local s
        for s in "${stack[@]}"; do
          [[ -n "$s" ]] && path+="$s/"
        done
        [[ "$path" == "//" ]] && path="/"
        [[ "$path" == "/chosen/" ]] && chosen="yes"
        if [[ "$path" == "/reserved-memory/"* && ${#stack[@]} -eq 3 ]]; then
          reserved_count=$((reserved_count + 1))
        fi
        ;;
      2)
        if (( ${#stack[@]} > 0 )); then unset 'stack[${#stack[@]}-1]'; stack=("${stack[@]}"); fi
        path="/"
        local s
        for s in "${stack[@]}"; do [[ -n "$s" ]] && path+="$s/"; done
        ;;
      3)
        len="$(be32_hex "$hex" "$cursor")"
        nameoff="$(be32_hex "$hex" "$((cursor + 4))")"
        cursor=$((cursor + 8))
        propname="$(nul_string_at "$hex" "$((off_strings + nameoff))")"
        val_off="$cursor"
        val_hex="${hex:$((val_off*2)):$((len*2))}"
        cursor=$((cursor + len))
        cursor="$(align4 "$cursor")"

        if [[ "$path" == "/" ]]; then
          case "$propname" in
            model) model="$(hex_string_list "$val_hex")" ;;
            compatible) compatible="$(hex_string_list "$val_hex")" ;;
            '#address-cells') [[ "$len" -eq 4 ]] && root_addr_cells="$(be32_hex "$hex" "$val_off")" ;;
            '#size-cells') [[ "$len" -eq 4 ]] && root_size_cells="$(be32_hex "$hex" "$val_off")" ;;
          esac
        fi
        if [[ "$path" == /memory*/ && "$propname" == "reg" ]]; then
          [[ -n "$memory_regs" ]] && memory_regs+="|"
          memory_regs+="$val_hex"
        fi
        if [[ "$path" == "/chosen/" && "$propname" == "linux,usable-memory-range" ]]; then
          usable="$val_hex"
        fi
        if [[ "$path" == "/reserved-memory/" ]]; then
          case "$propname" in
            '#address-cells') [[ "$len" -eq 4 ]] && reserved_addr_cells="$(be32_hex "$hex" "$val_off")" ;;
            '#size-cells') [[ "$len" -eq 4 ]] && reserved_size_cells="$(be32_hex "$hex" "$val_off")" ;;
          esac
        fi
        if [[ "$path" == "/reserved-memory/"* && ${#stack[@]} -eq 3 && "$propname" == "reg" ]]; then
          node="${stack[2]}"
          reserved_entries+="  $node reg=$val_hex"$'\n'
        fi
        ;;
      4) ;;
      9) break ;;
      *)
        echo "parse-warning: unknown-token=$token at-byte=$((cursor-4))"
        break
        ;;
    esac
  done

  echo "model: ${model:-UNAVAILABLE}"
  echo "compatible: ${compatible:-UNAVAILABLE}"
  echo "root-address-cells: ${root_addr_cells:-UNAVAILABLE}"
  echo "root-size-cells: ${root_size_cells:-UNAVAILABLE}"
  echo "memory-reg-raw-hex: ${memory_regs:-UNAVAILABLE}"
  echo "reserved-memory-address-cells: ${reserved_addr_cells:-UNAVAILABLE}"
  echo "reserved-memory-size-cells: ${reserved_size_cells:-UNAVAILABLE}"
  echo "reserved-memory-child-count: $reserved_count"
  echo "chosen-present: $chosen"
  echo "chosen-usable-memory-range-raw-hex: ${usable:-UNAVAILABLE}"
  echo "reserved-memory-reg-entries:"
  if [[ -n "$reserved_entries" ]]; then printf '%s' "$reserved_entries"; else echo "  UNAVAILABLE"; fi
}

{
  echo "IzzOS vendor_boot DTB structural analysis"
  echo "Collector mode: READ_ONLY_HOST_SIDE"
  echo "Device writes: NONE"
  echo "Parser: PURE_BASH_FDT_PROPERTY_WALKER_OD_ONLY"
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
  echo "classification: VENDOR_BOOT_DTB_SET_PROPERTY_WALKED_NO_DTC"
  echo "decision: exact DTB structure/property blocks were walked host-side using only Bash/od. Raw memory and reserved-memory reg cells are evidence for comparison, but static DTB values may still be firmware-patched at runtime. No FD address or device launch is authorized."
} > "$OUT"

cat "$OUT"
