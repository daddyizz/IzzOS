#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path


if len(sys.argv) != 5:
    raise SystemExit(
        "Usage: report-m7-device-promotion-readiness.py "
        "<m7-host-readiness.txt> <m1-exact-device-evidence.txt> "
        "<m2-recovery-evidence.txt> <output.txt>"
    )

HOST = Path(sys.argv[1])
DEVICE = Path(sys.argv[2])
RECOVERY = Path(sys.argv[3])
OUT = Path(sys.argv[4])


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def values(text, label):
    return [match.strip() for match in re.findall(rf"(?mi)^{re.escape(label)}:\s*(.+?)\s*$", text)]


def field(text, label):
    found = values(text, label)
    return found[0] if len(found) == 1 else None


def normalized(value):
    return (value or "").strip().lower()


def normalized_slot(value):
    return normalized(value).removeprefix("_")


def meaningful(value):
    return normalized(value) not in {"", "unknown", "n/a", "na", "none", "todo", "tbd", "unset", "unvalidated", "-"}


def is_sha256(value):
    return bool(re.fullmatch(r"[0-9A-Fa-f]{64}", value or ""))


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [("host-readiness", HOST), ("exact-device", DEVICE), ("recovery", RECOVERY)]
if OUT.resolve() in {path.resolve() for _, path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an input evidence file")

texts = {}
hashes = {}
checks = []
for key, path in inputs:
    present = path.is_file()
    texts[key] = path.read_text(errors="replace") if present else ""
    hashes[key] = sha256(path) if present else None
    checks.append((f"{key}-present", present))

host = texts["host-readiness"]
device = texts["exact-device"]
recovery = texts["recovery"]

checks.extend([
    ("host-classification-is-exact", field(host, "classification") == "M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED"),
    ("host-device-commands-remain-none", field(host, "device-commands") == "NONE"),
    ("host-persistent-writes-remain-forbidden", field(host, "persistent-writes") == "FORBIDDEN"),
    ("host-slot-changes-remain-forbidden", field(host, "slot-changes") == "FORBIDDEN"),
    ("host-launch-remains-unauthorized", field(host, "launch-authorization") == "NO"),
    ("device-classification-is-exact", field(device, "Classification") == "M1_EXACT_DEVICE_EVIDENCE_CONSISTENT"),
    ("device-target-is-exact", field(device, "Target") == "OnePlus 10T 5G / ovaltine / SM8475"),
    ("device-target-match-is-positive", normalized(field(device, "Target match")) == "yes"),
    ("device-build-is-exact", bool(re.fullmatch(r"CPH2413_.+", field(device, "Build ID") or ""))),
    ("device-slot-is-a-or-b", normalized_slot(field(device, "Current slot")) in {"a", "b"}),
    ("device-bootloader-is-unlocked", normalized(field(device, "Bootloader unlocked")) == "yes"),
    ("device-fastboot-is-not-userspace", normalized(field(device, "Userspace fastboot")) == "no"),
    ("device-adb-class-is-stage-a-inspection", field(device, "ADB classification") == "NEED_EXACT_FASTBOOT_INSPECTION"),
    ("device-fastboot-class-is-classic-candidate", field(device, "Fastboot classification") == "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED"),
    ("device-fastboot-target-is-bound", normalized(field(device, "Fastboot target observation")) in {"yes", "platform-compatible"}),
    ("device-adb-source-hash-is-valid", is_sha256(field(device, "ADB evidence SHA256"))),
    ("device-fastboot-source-hash-is-valid", is_sha256(field(device, "Fastboot evidence SHA256"))),
    ("device-collector-is-read-only", field(device, "Collector mode") == "READ_ONLY"),
    ("device-writes-remain-none", field(device, "Device writes") == "NONE"),
    ("device-launch-commands-remain-none", field(device, "Launch commands executed") == "NO"),
    ("device-launch-remains-unauthorized", field(device, "Launch authorization") == "NO"),
])

device_build = field(device, "Build ID")
device_slot = normalized_slot(field(device, "Current slot"))
recovery_model = normalized(field(recovery, "Device model/product"))
recovery_build = field(recovery, "OxygenOS build")
recovery_slot = normalized_slot(field(recovery, "Current slot"))
verified_emergency = {
    "self_service_hard_recovery_verified",
    "authorized_service_hard_recovery_verified",
}

checks.extend([
    ("recovery-target-is-exact", "oneplus 10t" in recovery_model and "ovaltine" in recovery_model),
    ("recovery-build-matches-device", bool(device_build) and recovery_build == device_build),
    ("recovery-slot-matches-device", bool(device_slot) and recovery_slot == device_slot),
    ("recovery-slot-count-is-two", field(recovery, "Slot count") == "2"),
    ("recovery-bootloader-is-unlocked", normalized(field(recovery, "Bootloader unlocked")) == "yes"),
    ("recovery-fastboot-is-classic", normalized(field(recovery, "Fastboot mode")) == "classic bootloader fastboot"),
    ("recovery-stock-source-is-recorded", meaningful(field(recovery, "Stock image source"))),
    ("recovery-stock-boot-is-verified", normalized(field(recovery, "Stock boot image verified")) == "yes"),
    ("recovery-stock-vendor-boot-is-verified", normalized(field(recovery, "Stock vendor_boot verified")) == "yes"),
    ("recovery-stock-dtbo-is-verified", normalized(field(recovery, "Stock dtbo verified")) == "yes"),
    ("recovery-stock-vbmeta-is-verified", normalized(field(recovery, "Stock vbmeta verified")) == "yes"),
    ("recovery-stock-recovery-is-verified", normalized(field(recovery, "Stock recovery image verified")) == "yes"),
    ("recovery-emergency-route-is-verified", normalized(field(recovery, "Emergency recovery status")) in verified_emergency),
    ("recovery-temporary-route-candidate-is-recorded", meaningful(field(recovery, "Temporary route candidate"))),
    ("recovery-persistent-write-is-not-required", normalized(field(recovery, "Persistent write required")) == "no"),
    ("recovery-slot-change-is-not-required", normalized(field(recovery, "Slot change required")) == "no"),
    ("recovery-procedure-reference-is-recorded", meaningful(field(recovery, "Recovery procedure reference"))),
])

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 device-promotion evidence audit",
    "Auditor mode: OFFLINE_EVIDENCE_BINDING_ONLY",
    "Device commands executed by auditor: NONE",
    "Device writes executed by auditor: NONE",
    "Launch commands executed by auditor: NONE",
    "",
    *[
        f"input: key={key} file={path} sha256={hashes[key] or 'MISSING'}"
        for key, path in inputs
    ],
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "product-roadmap-milestone: M1_NON_DESTRUCTIVE_UEFI_DIAGNOSTIC_PAYLOAD",
    "internal-engineering-stage: M7_STANDALONE_LAYOUT_AND_ENTRY_EVIDENCE",
    "independent-observation-authenticity: HASH_BOUND_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "sec-prepi-wrapper-execution: NOT_PROVEN",
    "dsc-fdf-promotion-authorization: NO",
    "android-container-construction-authorization: NO",
    "device-commands: NONE",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M7_DEVICE_PROMOTION_EVIDENCE_INCOMPLETE",
        "decision: host readiness, exact-device evidence and verified recovery evidence are not yet a consistent hash-bound chain. Keep SEC/PrePi promotion, container construction and device launch blocked.",
    ], 1)

emit(lines + [
    "remaining-blocker: INDEPENDENT_CAPTURE_AUTHENTICITY_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "remaining-blocker: SEC_PREPI_WRAPPER_EXECUTION_NOT_PROVEN",
    "classification: M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED",
    "decision: the host, exact-device and recovery inputs are internally consistent and their exact bytes are SHA-256 bound by this report. This does not authenticate who collected them, prove SEC/PrePi execution, authorize DSC/FDF promotion, construct an Android container, or authorize any device command.",
])
