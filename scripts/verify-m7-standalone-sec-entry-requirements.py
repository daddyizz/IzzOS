#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ENTRY = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-aarch64-entry-contract.txt")
PLACEMENT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-linuxloader-placement-evidence.txt")
SELECTED_DTB = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-selected-dtb.txt")
GIC_TIMER = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("out/m7-gic-timer-dtb.txt")
OUT = Path(sys.argv[5]) if len(sys.argv) > 5 else Path("out/m7-standalone-sec-entry-requirements.txt")

TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
LINUX_BOOT_REFERENCE = "https://www.kernel.org/doc/html/latest/arch/arm64/booting.html"
EDK2_PREPI_REFERENCE = "https://github.com/tianocore/edk2-platforms/blob/master/Platform/ARM/JunoPkg/ArmJuno.fdf"


def field(text, label):
    match = re.search(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def valid_hash(value):
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{64}", value))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def valid_hex(value):
    return bool(value and re.fullmatch(r"0x[0-9A-Fa-f]+", value))


def emit(lines, exit_code=0):
    text = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(text, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (ENTRY, PLACEMENT, SELECTED_DTB, GIC_TIMER):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 SEC-entry evidence input not found: {required}")

entry = ENTRY.read_text(errors="replace")
placement = PLACEMENT.read_text(errors="replace")
selected_dtb = SELECTED_DTB.read_text(errors="replace")
gic_timer = GIC_TIMER.read_text(errors="replace")

entry_boot_hash = field(entry, "actual-boot-sha256")
placement_boot_hash = field(placement, "boot-sha256")
selected_hash = field(selected_dtb, "selected-dtb-sha256")
gic_bound_hash = field(gic_timer, "bound-selected-dtb-sha256")
gic_actual_hash = field(gic_timer, "actual-selected-dtb-sha256")
linuxloader_hash = field(placement, "linuxloader-sha256")
stock_dtb_address = field(entry, "stock-dtb-load-address")

checks = [
    ("stock-aarch64-entry-contract-pass", field(entry, "classification") == "M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED"),
    ("linuxloader-placement-evidence-pass", field(placement, "classification") == "M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND"),
    ("selected-dtb-binding-pass", field(selected_dtb, "classification") == "M7_EXACT_SELECTED_DTB_BOUND"),
    ("gic-timer-dtb-evidence-pass", field(gic_timer, "classification") == "M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED"),
    ("placement-targets-exact-device-build", field(placement, "exact-device-build") == TARGET_BUILD),
    ("entry-and-placement-boot-hashes-match", equal_hash(entry_boot_hash, placement_boot_hash)),
    ("placement-carries-exact-linuxloader-hash", valid_hash(linuxloader_hash)),
    ("entry-carries-stock-dtb-address", valid_hex(stock_dtb_address)),
    ("selected-and-gic-bound-dtb-hashes-match", equal_hash(selected_hash, gic_bound_hash)),
    ("selected-and-gic-actual-dtb-hashes-match", equal_hash(selected_hash, gic_actual_hash)),
    ("linux-x0-x3-contract-is-explicit", field(entry, "source-linux-entry-register-contract") == "x0=DTB_PHYSICAL_ADDRESS,x1=0,x2=0,x3=0"),
    ("linux-security-state-contract-is-explicit", field(entry, "source-linux-entry-security-contract") == "NON_SECURE"),
    ("linux-exception-level-contract-is-explicit", field(entry, "source-linux-entry-el-contract") == "EL2_RECOMMENDED_OR_EL1"),
    ("linux-interrupt-mask-contract-is-explicit", field(entry, "source-linux-entry-interrupt-contract") == "PSTATE_DAIF_ALL_MASKED"),
    ("linux-mmu-contract-is-explicit", field(entry, "source-linux-entry-mmu-contract") == "OFF"),
    ("linux-timer-contract-is-explicit", field(entry, "source-linux-entry-timer-contract") == "CNTFRQ_AND_CNTVOFF_PREINITIALIZED"),
    ("qualcomm-entry-el-remains-uncaptured", field(entry, "observed-qualcomm-entry-el") == "NOT_CAPTURED"),
    ("qualcomm-system-register-state-remains-uncaptured", field(entry, "observed-qualcomm-system-register-state") == "NOT_CAPTURED"),
    ("standalone-sec-equivalence-remains-unproven", field(entry, "standalone-sec-entry-equivalence") == "NOT_PROVEN" and field(placement, "standalone-sec-entry-equivalence") == "NOT_PROVEN"),
    ("fd-kernel-substitution-remains-unproven", field(placement, "fd-kernel-substitution-equivalence") == "NOT_PROVEN"),
    ("final-destination-remains-unobserved", field(placement, "final-physical-destination") == "NOT_RUNTIME_OBSERVED"),
    ("runtime-controller-ownership-remains-unproven", field(gic_timer, "runtime-controller-ownership") == "NOT_YET_PROVEN"),
    ("gic-exception-level-remains-unproven", field(gic_timer, "exception-level-contract") == "NOT_YET_PROVEN"),
    ("all-prerequisite-reports-deny-launch", all(field(report, "launch-authorization") == "NO" for report in (entry, placement, selected_dtb, gic_timer))),
]
failed = [name for name, passed in checks if not passed]

lines = [
    "IzzOS Milestone 7 standalone SEC entry requirement binding",
    "Collector mode: READ_ONLY_HOST_SIDE",
    "Device writes: NONE",
    "MMIO reads/writes executed: NO",
    "Container construction executed: NO",
    "Launch commands executed: NO",
    "",
    f"exact-device-build: {TARGET_BUILD}",
    f"stock-entry-report: {ENTRY}",
    f"linuxloader-placement-report: {PLACEMENT}",
    f"selected-dtb-report: {SELECTED_DTB}",
    f"gic-timer-report: {GIC_TIMER}",
    f"boot-sha256: {entry_boot_hash or 'MISSING'}",
    f"linuxloader-sha256: {linuxloader_hash or 'MISSING'}",
    f"selected-dtb-sha256: {selected_hash or 'MISSING'}",
    f"stock-dtb-load-address: {stock_dtb_address or 'MISSING'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"source-linux-entry-reference: {LINUX_BOOT_REFERENCE}",
    "source-linux-register-contract: x0=DTB_PHYSICAL_ADDRESS,x1=0,x2=0,x3=0",
    "source-linux-security-contract: NON_SECURE",
    "source-linux-el-contract: EL2_RECOMMENDED_OR_EL1",
    "source-linux-interrupt-contract: PSTATE_DAIF_ALL_MASKED",
    "source-linux-mmu-contract: OFF",
    "source-linux-instruction-cache-contract: MAY_BE_ON_OR_OFF_NO_STALE_IMAGE_ENTRIES",
    "source-linux-loaded-image-cache-contract: CLEAN_TO_POC",
    "source-linux-timer-contract: CNTFRQ_AND_CNTVOFF_PREINITIALIZED",
    "",
    f"source-edk2-prepi-reference: {EDK2_PREPI_REFERENCE}",
    "edk2-prepi-entry-form: FV_PATCHED_TO_SEC_OR_PREPI_ENTRYPOINT",
    "edk2-entry-wrapper-required: YES",
    "required-wrapper-currentel-capture: YES",
    "required-wrapper-sctlr-state-capture: YES",
    "required-wrapper-daif-state-capture: YES",
    "required-wrapper-timer-state-capture: YES",
    "required-wrapper-dtb-register-preservation: YES",
    "required-wrapper-stack-and-temporary-ram-bootstrap: YES",
    "required-wrapper-image-coherency-normalization: YES",
    "",
    "observed-qualcomm-entry-el: NOT_CAPTURED",
    "observed-qualcomm-system-register-state: NOT_CAPTURED",
    "observed-final-physical-destination: NOT_CAPTURED",
    "standalone-sec-entry-equivalence: NOT_PROVEN",
    "direct-fd-as-linux-image: FORBIDDEN",
    "dsc-fdf-promotion-authorization: NO",
    "container-build-authorization: NO",
    "kernel-replacement-authorization: NO",
    "mmio-initialization-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BLOCKED",
            "decision: the exact stock-entry, placement, DTB, and platform reports do not form a consistent non-authorizing prerequisite set. Do not design SEC/PrePi source, promote DSC/FDF files, substitute an FD, initialize MMIO, or launch the device.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND",
        "decision: the exact Linux-style handoff and static platform evidence are bound into a standalone SEC/PrePi requirement manifest. This identifies the wrapper observations and normalization work still required; it does not prove Qualcomm-to-EDK2 entry equivalence or authorize DSC/FDF promotion, container construction, MMIO initialization, or launch.",
    ]
)
