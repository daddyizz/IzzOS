#!/usr/bin/env bash
set -euo pipefail

DRAM_SPAN_BASE=$((0x80000000))
LIMIT=$((0x100000000))

fmt() {
  printf '0x%08X' "$1"
}

# Fixed source-backed regions from cape-reserved-memory.dtsi.
# Dynamic CMA/shared pools without a fixed reg are intentionally omitted.
regions=(
  "hyp_mem 0x80000000 0x00600000"
  "xbl_dtlog_mem 0x80600000 0x00040000"
  "xbl_ramdump_mem 0x80640000 0x001C0000"
  "aop_image_mem 0x80800000 0x00060000"
  "aop_cmd_db_mem 0x80860000 0x00020000"
  "aop_config_mem 0x80880000 0x00020000"
  "tme_crash_dump_mem 0x808A0000 0x00040000"
  "tme_log_mem 0x808E0000 0x00004000"
  "uefi_log_mem 0x808E4000 0x00010000"
  "smem_mem 0x80900000 0x00200000"
  "cpucp_fw_mem 0x80B00000 0x00100000"
  "cdsp_secure_heap_mem 0x80C00000 0x04600000"
  "video_mem 0x85700000 0x00700000"
  "adsp_mem 0x85E00000 0x02100000"
  "slpi_mem 0x88000000 0x01900000"
  "cdsp_mem 0x89900000 0x02000000"
  "ipa_fw_mem 0x8B900000 0x00010000"
  "ipa_gsi_mem 0x8B910000 0x0000A000"
  "gpu_microcode_mem 0x8B91A000 0x00002000"
  "spss_region_mem 0x8BA00000 0x00180000"
  "spu_tz_shared_mem 0x8BB80000 0x00060000"
  "spu_modem_shared_mem 0x8BBE0000 0x00020000"
  "mpss_mem 0x8BC00000 0x13200000"
  "cvp_mem 0x9EE00000 0x00700000"
  "camera_mem 0x9F500000 0x00800000"
  "xbl_sc_mem 0xA6E00000 0x00040000"
  "global_sync_mem 0xA6F00000 0x00100000"
  "qheebsp_reserved_mem 0xE0000000 0x00600000"
  "cpusys_vm_mem 0xE0600000 0x00400000"
  "hyp_reserved_mem 0xE0A00000 0x00100000"
  "trust_ui_vm_mem 0xE0B00000 0x04AF3000"
  "trust_ui_vm_qrtr 0xE55F3000 0x00009000"
  "trust_ui_vm_vblk0_ring 0xE55FC000 0x00004000"
  "trust_ui_vm_swiotlb 0xE5600000 0x00100000"
  "tz_stat_mem 0xE8800000 0x00100000"
  "tags_mem 0xE8900000 0x01200000"
  "qtee_mem 0xE9B00000 0x00500000"
  "trusted_apps_mem 0xEA000000 0x03900000"
  "trusted_apps_ext_mem 0xED900000 0x03B00000"
)

# Sort by base, then merge overlapping/adjacent ranges. Keep names for diagnostics.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
for row in "${regions[@]}"; do
  read -r name base size <<<"$row"
  b=$((base))
  s=$((size))
  e=$((b + s))
  printf '%u %u %s\n' "$b" "$e" "$name" >> "$tmp"
done

mapfile -t sorted < <(sort -n -k1,1 -k2,2 "$tmp")

merged=()
cur_start=''
cur_end=''
cur_names=''
for row in "${sorted[@]}"; do
  read -r start end name <<<"$row"
  if [[ -z "$cur_start" ]]; then
    cur_start="$start"; cur_end="$end"; cur_names="$name"
  elif (( start > cur_end )); then
    merged+=("$cur_start $cur_end $cur_names")
    cur_start="$start"; cur_end="$end"; cur_names="$name"
  else
    (( end > cur_end )) && cur_end="$end"
    cur_names+="${cur_names:+,}$name"
  fi
done
[[ -n "$cur_start" ]] && merged+=("$cur_start $cur_end $cur_names")

echo "IzzOS SM8475 fixed reserved-memory model"
echo "classification: SOURCE_BACKED_FIXED_CARVEOUT_MODEL_ONLY"
echo "runtime DRAM span base evidence: $(fmt "$DRAM_SPAN_BASE")"
echo "dynamic/firmware-patched regions: NOT FULLY MODELED"
echo "candidate gaps below 4 GiB:"

cursor="$DRAM_SPAN_BASE"
for row in "${merged[@]}"; do
  read -r start end names <<<"$row"
  (( end <= DRAM_SPAN_BASE )) && continue
  (( start >= LIMIT )) && continue
  (( start < DRAM_SPAN_BASE )) && start="$DRAM_SPAN_BASE"
  (( end > LIMIT )) && end="$LIMIT"
  if (( start > cursor )); then
    printf '  %s-%s size=0x%X status=UNVALIDATED_GAP\n' "$(fmt "$cursor")" "$(fmt "$start")" "$((start-cursor))"
  fi
  printf '  reserved %s-%s size=0x%X names=%s\n' "$(fmt "$start")" "$(fmt "$end")" "$((end-start))" "$names"
  (( end > cursor )) && cursor="$end"
done

if (( cursor < LIMIT )); then
  printf '  %s-0x100000000 size=0x%X status=UNVALIDATED_GAP\n' "$(fmt "$cursor")" "$((LIMIT-cursor))"
fi

echo "decision: fixed source carve-outs can exclude known ranges, but gaps are not safe FD ranges until runtime/dynamic allocations, bootloader placement, DTB, framebuffer, kernel loading behavior and exact-device entry assumptions are independently reconciled."
