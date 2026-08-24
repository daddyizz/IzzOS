#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

CONTRACT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-layout-contract.txt")
FD = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/ovaltine-standalone/Ovaltine.fd")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-fd-capacity.txt")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def grab(text, label):
    match = re.search(rf"(?m)^{re.escape(label)}:\s*(0x[0-9A-Fa-f]+)\s*$", text)
    if not match:
        raise SystemExit(f"ERROR: missing {label} in M7 layout contract")
    return int(match.group(1), 16)


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


if not CONTRACT.is_file():
    raise SystemExit(f"ERROR: M7 layout contract not found: {CONTRACT}")
if not FD.is_file():
    raise SystemExit(f"ERROR: standalone FD artifact not found: {FD}")

contract = CONTRACT.read_text(errors="replace")
contract_pass = bool(
    re.search(r"(?m)^classification:\s*M7_LAYOUT_REGION_CONTRACT_PASS\s*$", contract)
)
kbase = grab(contract, "proven-kernel-region-base")
kend = grab(contract, "proven-kernel-region-end")
dtb = grab(contract, "proven-stock-dtb-load")
ramdisk = grab(contract, "proven-stock-ramdisk-load")
page_size = grab(contract, "proven-stock-page-size")

fd_size = FD.stat().st_size
fd_hash = sha256(FD)
capacity = dtb - kbase if dtb >= kbase else 0
aligned_fd_size = (
    (fd_size + page_size - 1) & ~(page_size - 1)
    if page_size > 0 and not page_size & (page_size - 1)
    else 0
)

checks = [
    ("m7-layout-region-contract-pass", contract_pass),
    ("stock-layout-order-is-valid", kbase < dtb < ramdisk < kend),
    ("stock-page-size-is-power-of-two", 4096 <= page_size <= 65536 and not page_size & (page_size - 1)),
    ("fd-artifact-is-not-empty", fd_size > 0),
    ("fd-size-is-stock-page-aligned", fd_size > 0 and fd_size % page_size == 0 if page_size else False),
    ("fd-aligned-size-fits-before-stock-dtb-bound", aligned_fd_size > 0 and aligned_fd_size <= capacity),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 standalone FD capacity contract",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "Launch commands executed: NO",
    "",
    f"layout-contract: {CONTRACT}",
    f"fd-artifact: {FD}",
    f"fd-sha256: {fd_hash}",
    f"fd-size-bytes: {fd_size}",
    f"fd-size-hex: 0x{fd_size:X}",
    f"fd-aligned-size: 0x{aligned_fd_size:X}",
    "",
    f"stock-kernel-region-base: 0x{kbase:08X}",
    f"stock-dtb-load-bound: 0x{dtb:08X}",
    f"stock-ramdisk-load: 0x{ramdisk:08X}",
    f"stock-kernel-region-end: 0x{kend:08X}",
    f"stock-page-size: 0x{page_size:X}",
    f"maximum-pre-dtb-capacity: 0x{capacity:X}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "fd-base-policy: NOT_YET_PROVEN",
    "android-container-policy: NOT_YET_PROVEN",
    "entry-policy: NOT_YET_PROVEN",
    "gic-timer-policy: NOT_YET_PROVEN",
    "storage-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines
        + [
            "classification: M7_FD_CAPACITY_CONTRACT_FAIL",
            "decision: the supplied FD artifact is empty, misaligned, oversized, or not bound to a passing M7 region contract; do not construct a launch container.",
        ],
        1,
    )

emit(
    lines
    + [
        "classification: M7_FD_CAPACITY_CONTRACT_PASS",
        "decision: the actual FD artifact size and stock-page alignment fit within the exact pre-DTB capacity bound. This does not select an FD base, prove an Android container/entry contract, initialize GIC/timers, or authorize a device launch.",
    ]
)
