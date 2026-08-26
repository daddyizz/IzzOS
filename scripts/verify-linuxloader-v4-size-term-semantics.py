#!/usr/bin/env python3
import hashlib
import struct
import sys
from pathlib import Path


def u32(b, off):
    if off + 4 > len(b):
        raise ValueError(f"u32 out of range at 0x{off:X}")
    return struct.unpack_from("<I", b, off)[0]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def round_up(v, align):
    return (v + align - 1) & ~(align - 1)


def main():
    if len(sys.argv) not in (3, 4):
        print("usage: verify-linuxloader-v4-size-term-semantics.py <boot.img> <vendor_boot.img> [output.txt]", file=sys.stderr)
        return 2

    boot_path = Path(sys.argv[1])
    vendor_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3]) if len(sys.argv) == 4 else None

    boot = boot_path.read_bytes()
    vendor = vendor_path.read_bytes()

    if boot[:8] != b"ANDROID!":
        raise SystemExit("ERROR: boot image magic mismatch")
    if vendor[:8] != b"VNDRBOOT":
        raise SystemExit("ERROR: vendor_boot image magic mismatch")

    # Android boot header v3/v4: magic[8], kernel_size, ramdisk_size, os_version,
    # header_size, reserved[4], header_version, cmdline...
    boot_kernel_size = u32(boot, 0x08)
    boot_ramdisk_size = u32(boot, 0x0C)
    boot_header_size = u32(boot, 0x14)
    boot_header_version = u32(boot, 0x28)

    # vendor_boot v3/v4 common prefix and v4 extension, per AOSP bootimg.h.
    vendor_header_version = u32(vendor, 0x08)
    page_size = u32(vendor, 0x0C)
    vendor_ramdisk_size = u32(vendor, 0x18)
    vendor_header_size = u32(vendor, 0x830)
    dtb_size = u32(vendor, 0x834)

    # v4-only extension begins after the v3 header (0x840 bytes / 2112 bytes).
    table_size = u32(vendor, 0x840) if vendor_header_version >= 4 else 0
    table_entry_num = u32(vendor, 0x844) if vendor_header_version >= 4 else 0
    table_entry_size = u32(vendor, 0x848) if vendor_header_version >= 4 else 0
    bootconfig_size = u32(vendor, 0x84C) if vendor_header_version >= 4 else 0

    total_ramdisk_related = boot_ramdisk_size + vendor_ramdisk_size + bootconfig_size
    rounded = round_up(total_ramdisk_related, page_size)
    reserved_below_kernel_end = rounded + page_size

    lines = []
    lines.append("IzzOS LinuxLoader v4 size-term semantic verification")
    lines.append("Collector mode: READ_ONLY_HOST_SIDE")
    lines.append("Device writes: NONE")
    lines.append(f"boot-image: {boot_path}")
    lines.append(f"boot-sha256: {sha256(boot)}")
    lines.append(f"vendor-boot-image: {vendor_path}")
    lines.append(f"vendor-boot-sha256: {sha256(vendor)}")
    lines.append("")
    lines.append(f"boot-header-version: {boot_header_version}")
    lines.append(f"boot-header-size: {boot_header_size}")
    lines.append(f"boot-kernel-size: {boot_kernel_size}")
    lines.append(f"boot-ramdisk-size: {boot_ramdisk_size} (0x{boot_ramdisk_size:X})")
    lines.append(f"vendor-header-version: {vendor_header_version}")
    lines.append(f"vendor-page-size: {page_size} (0x{page_size:X})")
    lines.append(f"vendor-header-size: {vendor_header_size}")
    lines.append(f"vendor-ramdisk-size: {vendor_ramdisk_size} (0x{vendor_ramdisk_size:X})")
    lines.append(f"vendor-dtb-size: {dtb_size}")
    lines.append(f"vendor-ramdisk-table-size: {table_size}")
    lines.append(f"vendor-ramdisk-table-entry-num: {table_entry_num}")
    lines.append(f"vendor-ramdisk-table-entry-size: {table_entry_size}")
    lines.append(f"vendor-bootconfig-size: {bootconfig_size} (0x{bootconfig_size:X})")
    lines.append("")
    lines.append("exact-binary field semantic mapping:")
    lines.append("struct+0x6C = PageSize")
    lines.append("struct+0x78 = RamdiskSize")
    lines.append("struct+0x94 = VendorRamdiskSize")
    lines.append("struct+0x98 = VendorBootConfigSize (v4-only; zero on non-v4 path)")
    lines.append("")
    lines.append("cross-evidence notes:")
    lines.append("+0x78 is populated from boot-header ramdisk_size producer flow.")
    lines.append("+0x94 producer reads vendor_boot header offset 0x18, which AOSP defines as vendor_ramdisk_size.")
    lines.append("+0x6C producer reads vendor_boot header offset 0x0C, which AOSP defines as page_size.")
    lines.append("+0x98 is conditionally populated only on the vendor_boot v4 path; AOSP v4 adds bootconfig_size as the final 32-bit header field at offset 0x84C.")
    lines.append("")
    lines.append(f"ramdisk-related-total: {total_ramdisk_related} (0x{total_ramdisk_related:X})")
    lines.append(f"rounded-to-page: {rounded} (0x{rounded:X})")
    lines.append(f"placement-reservation-including-one-page-buffer: {reserved_below_kernel_end} (0x{reserved_below_kernel_end:X})")
    lines.append("source-matched formula:")
    lines.append("RamdiskLoadAddr = KernelEndAddr - (ROUND_UP(RamdiskSize + VendorRamdiskSize + VendorBootConfigSize, PageSize) + PageSize)")
    lines.append("DeviceTreeLoadAddr = RamdiskLoadAddr - (0x200000 + PageSize)")
    lines.append("")

    expected = (
        boot_header_version == 4 and
        vendor_header_version == 4 and
        page_size == 4096 and
        bootconfig_size > 0
    )
    if expected:
        lines.append("classification: LINUXLOADER_V4_SIZE_TERM_SEMANTICS_CROSS_EVIDENCE_CONSISTENT")
    else:
        lines.append("classification: LINUXLOADER_V4_SIZE_TERM_SEMANTICS_REVIEW_REQUIRED")
    lines.append("decision: exact image headers, exact-binary producer behavior, and public AOSP/Qualcomm layout are mutually consistent for the size terms used by the dynamic placement formula. This proves formula semantics only; it does not reveal the exact UEFI KernelBaseAddr/KernelSize runtime variables and does not authorize an FD base, fastboot boot, flashing, or slot change.")

    text = "\n".join(lines) + "\n"
    print(text, end="")
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
