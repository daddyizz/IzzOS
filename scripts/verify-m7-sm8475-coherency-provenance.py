#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path

ASSERTION = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/m7-coherency-secondary-state.txt")
RAW = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out/m7-sm8475-coherency-provenance-raw.txt")
OUT = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/m7-sm8475-coherency-provenance.txt")

SCHEMA = "IZZOS_M7_SM8475_COHERENCY_PROVENANCE_V1"
SOURCE_REPOSITORY = "https://github.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475"
SOURCE_BRANCH = "oneplus/sm8475_s_12.1_oneplus_10t_5g"
SOURCE_COMMIT = "a24e032ef338174bfa835bed0f8e2ad3620f4ffc"
CAPE_PATH = "kernel_platform/qcom/proprietary/devicetree/qcom/cape.dtsi"
CAPE_BLOB = "9534c9c207dd293f7771ff072dbe9f350b448996"
PSCI_PATH = "kernel_platform/qcom/proprietary/devicetree/bindings/arm/psci.txt"
PSCI_BLOB = "a2c4f1d524929bb788360542690061ade0c4f543"


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


def equal_hash(left, right):
    return bool(left and re.fullmatch(r"[0-9A-Fa-f]{64}", left) and left.lower() == right.lower())


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered)
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


for required in (ASSERTION, RAW):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 provenance input not found: {required}")

assertion = ASSERTION.read_text(errors="replace")
raw = RAW.read_text(errors="replace")
assertion_hash = sha256(ASSERTION)
raw_hash = sha256(RAW)

required_manifest_fields = {
    "coherency-provenance-schema": SCHEMA,
    "target-platform": "ONEPLUS_10T_CPH2413_SM8475_CAPE",
    "official-source-repository": SOURCE_REPOSITORY,
    "official-source-branch": SOURCE_BRANCH,
    "official-source-commit": SOURCE_COMMIT,
    "cape-dtsi-path": CAPE_PATH,
    "cape-dtsi-blob-sha1": CAPE_BLOB,
    "psci-binding-path": PSCI_PATH,
    "psci-binding-blob-sha1": PSCI_BLOB,
    "source-fetch-policy": "IMMUTABLE_COMMIT_AND_BLOB_IDENTITY_ONLY",
    "cape-enabled-cpu-count": "8",
    "cape-cpu-enable-method": "PSCI",
    "cape-psci-compatible": "arm,psci-1.0",
    "cape-psci-conduit": "SMC",
    "secondary-cpu-control-owner": "EL3_PSCI_PLATFORM_FIRMWARE",
    "public-source-coherency-register": "NOT_PUBLISHED",
    "public-source-coherency-mask": "NOT_PUBLISHED",
    "public-source-coherency-sequence": "NOT_PUBLISHED",
    "cpuectlr-smpen-assumption": "FORBIDDEN_WITHOUT_EXACT_SM8475_SOURCE",
    "mmio-address-assumption": "FORBIDDEN",
    "source-boundary": "PSCI_OWNERSHIP_PROVEN_INTERNAL_COHERENCY_MECHANISM_NOT_PUBLISHED",
    "observation-authenticity": "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "capture-route-authorization": "NOT_PROVEN",
    "device-writes": "NONE",
    "persistent-writes": "NONE",
    "slot-changes": "NONE",
    "launch-authorization": "NO",
}

checks = [
    ("assertion-schema-gate-passed", field(assertion, "classification") == "M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS"),
    ("assertion-left-coherency-unproven", field(assertion, "coherency-proof") == "NOT_YET_PROVEN"),
    ("assertion-left-mechanism-unvalidated", field(assertion, "implementation-defined-coherency-mechanism") == "NOT_INDEPENDENTLY_VALIDATED"),
    ("assertion-remains-self-reported", field(assertion, "observation-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("assertion-capture-route-remains-unproven", field(assertion, "capture-route-authorization") == "NOT_PROVEN"),
    ("assertion-denies-wrapper-implementation", field(assertion, "sec-wrapper-implementation-authorization") == "NO"),
    ("assertion-denies-mmio-initialization", field(assertion, "mmio-initialization-authorization") == "NO"),
    ("assertion-denies-launch", field(assertion, "launch-authorization") == "NO"),
    ("manifest-binds-exact-assertion-report", equal_hash(field(raw, "coherency-assertion-report-sha256"), assertion_hash)),
]

for label, expected in required_manifest_fields.items():
    checks.append((f"manifest-{label}-is-exact", field(raw, label) == expected))

checks.extend(
    [
        ("manifest-labels-are-unambiguous", all(len(values(raw, label)) == 1 for label in ["coherency-assertion-report-sha256", *required_manifest_fields])),
        ("source-commit-is-a-git-sha1", bool(re.fullmatch(r"[0-9a-f]{40}", field(raw, "official-source-commit") or ""))),
        ("cape-blob-is-a-git-sha1", bool(re.fullmatch(r"[0-9a-f]{40}", field(raw, "cape-dtsi-blob-sha1") or ""))),
        ("psci-binding-blob-is-a-git-sha1", bool(re.fullmatch(r"[0-9a-f]{40}", field(raw, "psci-binding-blob-sha1") or ""))),
    ]
)

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 SM8475 coherency provenance boundary gate",
    "Collector mode: HOST_SIDE_IMMUTABLE_SOURCE_PROVENANCE_VALIDATION",
    "Network requests executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"coherency-assertion-report: {ASSERTION}",
    f"coherency-assertion-report-sha256: {assertion_hash}",
    f"coherency-provenance-manifest: {RAW}",
    f"coherency-provenance-manifest-sha256: {raw_hash}",
    f"official-source-commit: {field(raw, 'official-source-commit') or 'UNAVAILABLE'}",
    f"cape-dtsi-blob-sha1: {field(raw, 'cape-dtsi-blob-sha1') or 'UNAVAILABLE'}",
    f"psci-binding-blob-sha1: {field(raw, 'psci-binding-blob-sha1') or 'UNAVAILABLE'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "public-source-boundary: PSCI_SMC_FIRMWARE_OWNERSHIP_PROVEN_EXACT_COHERENCY_IMPLEMENTATION_UNAVAILABLE",
    "secondary-cpu-enable-interface: PSCI_VIA_SMC",
    "coherency-mechanism-implementation: NOT_PUBLICLY_PROVEN",
    "coherency-register-authorization: NO",
    "cpuectlr-smpen-authorization: NO",
    "mmio-initialization-authorization: NO",
    "sec-wrapper-implementation-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "fastboot-boot-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(
        lines + [
            "classification: M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_BLOCKED",
            "decision: the assertion binding, immutable OnePlus source identity, PSCI/SMC ownership boundary, or no-overclaim safety policy is invalid. Do not infer a Qualcomm coherency register, mask, sequence, MMIO address, wrapper implementation, DSC/FDF promotion, or launch authorization.",
        ],
        1,
    )

emit(
    lines + [
        "classification: M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS",
        "decision: immutable OnePlus Cape source provenance establishes eight PSCI-enabled CPUs and an SMC firmware interface for CPU power control. It does not publish the internal Qualcomm coherency register, mask, or sequence; CPUECTLR/SMPEN, MMIO initialization, wrapper implementation, DSC/FDF promotion, and launch remain unauthorized.",
    ]
)
