#!/usr/bin/env bash
set -euo pipefail

IMG="${1:-./output/vendor_boot.img}"
OUT_DIR="${2:-out/vendor-boot-dtb-set}"
mkdir -p "$OUT_DIR"

if [[ ! -f "$IMG" ]]; then
  echo "ERROR: vendor_boot image not found: $IMG" >&2
  exit 2
fi

u32le_at() {
  local off="$1"
  local h
  h="$(dd if="$IMG" bs=1 skip="$off" count=4 status=none | od -An -tx1 -v | tr -d ' \n')"
  [[ ${#h} -eq 8 ]] || { echo "ERROR: short read at offset $off" >&2; exit 1; }
  printf '%u' "$((16#${h:6:2}${h:4:2}${h:2:2}${h:0:2}))"
}

u64le_hex_at() {
  local off="$1"
  local h
  h="$(dd if="$IMG" bs=1 skip="$off" count=8 status=none | od -An -tx1 -v | tr -d ' \n')"
  [[ ${#h} -eq 16 ]] || { echo "ERROR: short read at offset $off" >&2; exit 1; }
  printf '0x%s%s%s%s%s%s%s%s' "${h:14:2}" "${h:12:2}" "${h:10:2}" "${h:8:2}" "${h:6:2}" "${h:4:2}" "${h:2:2}" "${h:0:2}"
}

be32_at_file() {
  local file="$1" off="$2"
  local h
  h="$(dd if="$file" bs=1 skip="$off" count=4 status=none | od -An -tx1 -v | tr -d ' \n')"
  [[ ${#h} -eq 8 ]] || { printf '0'; return; }
  printf '%u' "$((16#$h))"
}

align_up() {
  local n="$1" a="$2"
  printf '%u' "$(( (n + a - 1) / a * a ))"
}

magic="$(dd if="$IMG" bs=1 count=8 status=none 2>/dev/null)"
if [[ "$magic" != "VNDRBOOT" ]]; then
  echo "ERROR: not an Android vendor_boot image (magic=$magic)" >&2
  exit 1
fi

header_version="$(u32le_at 8)"
page_size="$(u32le_at 12)"
kernel_addr="$(u32le_at 16)"
ramdisk_addr="$(u32le_at 20)"
ramdisk_size="$(u32le_at 24)"
header_size="$(u32le_at 2096)"
dtb_size="$(u32le_at 2100)"
dtb_addr="$(u64le_hex_at 2104)"

if [[ "$header_version" -ne 4 ]]; then
  echo "ERROR: expected vendor_boot header v4, got $header_version" >&2
  exit 1
fi
if [[ "$page_size" -le 0 || "$header_size" -le 0 || "$dtb_size" -le 0 ]]; then
  echo "ERROR: invalid vendor_boot geometry" >&2
  exit 1
fi

header_pages="$(align_up "$header_size" "$page_size")"
ramdisk_pages="$(align_up "$ramdisk_size" "$page_size")"
dtb_offset=$((header_pages + ramdisk_pages))

rm -f "$OUT_DIR"/dtb-*.dtb "$OUT_DIR"/vendor_boot.dtb "$OUT_DIR"/MANIFEST.txt "$OUT_DIR"/SUMMARY.txt

dd if="$IMG" of="$OUT_DIR/vendor_boot.dtb" bs=1 skip="$dtb_offset" count="$dtb_size" status=none

payload_size="$(wc -c < "$OUT_DIR/vendor_boot.dtb" | tr -d ' ')"
if [[ "$payload_size" -ne "$dtb_size" ]]; then
  echo "ERROR: extracted DTB payload size mismatch: got=$payload_size expected=$dtb_size" >&2
  exit 1
fi

# Keep the loop in the current shell. A pipeline such as `while ...; done | tee`
# would execute the loop in a subshell on Bash and lose the final idx value.
cursor=0
idx=0
: > "$OUT_DIR/MANIFEST.txt"
while (( cursor + 8 <= dtb_size )); do
  blob="$OUT_DIR/vendor_boot.dtb"
  m="$(dd if="$blob" bs=1 skip="$cursor" count=4 status=none | od -An -tx1 -v | tr -d ' \n')"
  if [[ "$m" != "d00dfeed" ]]; then
    break
  fi
  total="$(be32_at_file "$blob" "$((cursor + 4))")"
  if (( total < 40 || cursor + total > dtb_size )); then
    echo "ERROR: invalid FDT totalsize at blob index $idx: offset=$cursor total=$total" >&2
    exit 1
  fi
  out="$OUT_DIR/dtb-$idx.dtb"
  dd if="$blob" of="$out" bs=1 skip="$cursor" count="$total" status=none
  sha="$(sha256sum "$out" | awk '{print $1}')"
  printf 'dtb-index: %d offset=0x%X size=%d sha256=%s\n' "$idx" "$cursor" "$total" "$sha" >> "$OUT_DIR/MANIFEST.txt"
  cursor=$((cursor + total))
  idx=$((idx + 1))
done

{
  echo "IzzOS exact vendor_boot DTB set"
  echo "Collector mode: READ_ONLY_HOST_SIDE"
  echo "Device writes: NONE"
  echo "Vendor boot image: $IMG"
  echo "Vendor boot header version: $header_version"
  echo "Page size: $page_size"
  printf 'Kernel address field: 0x%08X\n' "$kernel_addr"
  printf 'Ramdisk address field: 0x%08X\n' "$ramdisk_addr"
  echo "Vendor ramdisk total size: $ramdisk_size"
  echo "Header size: $header_size"
  echo "DTB payload offset: $dtb_offset"
  echo "DTB payload size: $dtb_size"
  echo "DTB address field: $dtb_addr"
  echo "DTB blob count: $idx"
  if (( idx >= 2 )); then
    echo "classification: VENDOR_BOOT_MULTI_DTB_SET_EXTRACTED"
    echo "decision: exact vendor_boot DTB payload contains multiple concatenated FDT blobs. Use the device-reported ro.boot.dtb_idx only as an index-selection hint; each selected blob still requires independent structural and memory-layout analysis. No firmware load address or device launch is authorized."
  elif (( idx == 1 )); then
    echo "classification: VENDOR_BOOT_SINGLE_DTB_EXTRACTED"
    echo "decision: one exact vendor_boot FDT blob was extracted. It still requires independent structural and memory-layout analysis before any firmware placement decision."
  else
    echo "classification: VENDOR_BOOT_DTB_FORMAT_UNRESOLVED"
    echo "decision: the DTB payload did not parse as a simple concatenation of FDT blobs. Keep standalone firmware placement blocked."
  fi
} > "$OUT_DIR/SUMMARY.txt"

cat "$OUT_DIR/MANIFEST.txt"
cat "$OUT_DIR/SUMMARY.txt"
