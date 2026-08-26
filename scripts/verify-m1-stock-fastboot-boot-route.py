#!/usr/bin/env python3
"""Bind an exact-stock, non-persistent fastboot boot route observation."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


if len(sys.argv) != 9:
    raise SystemExit(
        "Usage: verify-m1-stock-fastboot-boot-route.py "
        "<route-report> <owner-risk-record> <preflight-dir> <postboot-dir> "
        "<stock-provenance> <stock-boot-image> <exact-stock-hash-lock> <output>"
    )

REPORT, RISK, PRE_DIR, POST_DIR, PROVENANCE, IMAGE, HASH_LOCK, OUT = map(
    Path, sys.argv[1:]
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def values(text: str, label: str) -> list[str]:
    return [
        match.strip()
        for match in re.findall(rf"(?mi)^{re.escape(label)}:\s*(.*?)\s*$", text)
    ]


def field(text: str, label: str) -> str | None:
    found = values(text, label)
    return found[0] if len(found) == 1 else None


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def emit(checks: list[tuple[str, bool]], classification: str, decision: str, code: int) -> None:
    failed = [name for name, passed in checks if not passed]
    lines = [
        "IzzOS M1 exact-stock fastboot boot route verifier",
        "Verifier mode: OFFLINE_CONTENT_BOUND_EVIDENCE_ONLY",
        "Device commands executed by verifier: NONE",
        "Device writes executed by verifier: NONE",
        "",
        "checks:",
        *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
        "",
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        f"classification: {classification}",
        f"decision: {decision}",
    ]
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(code)


required_paths = [REPORT, RISK, PROVENANCE, IMAGE, HASH_LOCK]
required_bundle_files = {
    "ovaltine-inspection.txt",
    "ovaltine-inspection-analysis.txt",
    "INSPECTION_SUMMARY.txt",
}
checks: list[tuple[str, bool]] = [
    (f"required-file-{path.name}-present", path.is_file()) for path in required_paths
]
checks.extend([
    ("preflight-directory-present", PRE_DIR.is_dir()),
    ("postboot-directory-present", POST_DIR.is_dir()),
])

if not all(path.is_file() for path in required_paths) or not PRE_DIR.is_dir() or not POST_DIR.is_dir():
    emit(
        checks,
        "M1_STOCK_FASTBOOT_BOOT_ROUTE_EVIDENCE_BLOCKED",
        "one or more required inputs are absent; keep custom container construction and device launch blocked.",
        1,
    )


def verify_bundle(directory: Path, prefix: str) -> tuple[Path, str, str, str]:
    manifest = directory / "SHA256SUMS"
    raw = directory / "ovaltine-inspection.txt"
    analysis = directory / "ovaltine-inspection-analysis.txt"
    summary = directory / "INSPECTION_SUMMARY.txt"
    checks.append((f"{prefix}-checksum-manifest-present", manifest.is_file()))
    seen: set[str] = set()
    valid = manifest.is_file()
    if manifest.is_file():
        for line in read(manifest).splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", line)
            if not match:
                valid = False
                continue
            expected, name = match.groups()
            candidate = directory / name
            if name in seen or name not in required_bundle_files or not candidate.is_file():
                valid = False
                continue
            seen.add(name)
            if sha256(candidate) != expected:
                valid = False
    valid = valid and seen == required_bundle_files
    checks.append((f"{prefix}-bundle-checksums-valid", valid))
    return manifest, read(raw) if raw.is_file() else "", read(analysis) if analysis.is_file() else "", read(summary) if summary.is_file() else ""


pre_manifest, pre_raw, pre_analysis, pre_summary = verify_bundle(PRE_DIR, "preflight")
post_manifest, post_raw, post_analysis, post_summary = verify_bundle(POST_DIR, "postboot")

report = read(REPORT)
risk = read(RISK)
provenance = read(PROVENANCE)
lock = read(HASH_LOCK)
image_hash = sha256(IMAGE)
image_size = IMAGE.stat().st_size

report_labels = [
    "recorded-date",
    "target-model",
    "target-product-android",
    "target-product-fastboot",
    "target-build",
    "pre-route-slot",
    "post-route-slot-suffix",
    "owner-risk-record-sha256",
    "preflight-checksum-manifest-sha256",
    "postboot-checksum-manifest-sha256",
    "stock-provenance-record-sha256",
    "exact-stock-boot-image-sha256",
    "exact-stock-boot-image-size-bytes",
    "classification",
]
checks.extend(
    (f"report-field-{label}-unique", len(values(report, label)) == 1)
    for label in report_labels
)

checks.extend([
    ("report-schema-exact", report.splitlines()[0:1] == ["IZZOS_M1_EXACT_STOCK_FASTBOOT_BOOT_ROUTE_V1"]),
    ("risk-schema-exact", risk.splitlines()[0:1] == ["IZZOS_M1_OWNER_RISK_ACCEPTANCE_V1"]),
    ("target-model-exact", field(report, "target-model") == "CPH2413"),
    ("target-android-product-exact", field(report, "target-product-android") == "CPH2413"),
    ("target-fastboot-product-exact", field(report, "target-product-fastboot") == "taro"),
    ("target-build-exact", field(report, "target-build") == "CPH2413_15.0.0.1901(EX01)"),
    ("route-is-classic-fastboot", field(report, "fastboot-userspace") == "no"),
    ("bootloader-was-unlocked", field(report, "bootloader-unlocked") == "yes"),
    ("bootloader-was-secure", field(report, "bootloader-secure") == "yes"),
    ("host-fastboot-version-current", field(report, "host-fastboot-version") == "37.0.0"),
    ("owner-risk-record-hash-bound", field(report, "owner-risk-record-sha256") == sha256(RISK)),
    ("preflight-manifest-hash-bound", field(report, "preflight-checksum-manifest-sha256") == sha256(pre_manifest) if pre_manifest.is_file() else False),
    ("postboot-manifest-hash-bound", field(report, "postboot-checksum-manifest-sha256") == sha256(post_manifest) if post_manifest.is_file() else False),
    ("stock-provenance-hash-bound", field(report, "stock-provenance-record-sha256") == sha256(PROVENANCE)),
    ("stock-image-hash-bound", field(report, "exact-stock-boot-image-sha256") == image_hash),
    ("stock-image-size-bound", field(report, "exact-stock-boot-image-size-bytes") == str(image_size)),
    ("risk-scope-exact", field(risk, "scope") == "ONE_NON_PERSISTENT_EXACT_STOCK_BOOT_ROUTE_PROBE"),
    ("risk-classification-exact", field(risk, "classification") == "OWNER_ACCEPTED_ASSISTED_RECOVERY_RISK_FOR_ONE_STOCK_ROUTE_PROBE"),
    ("risk-image-hash-bound", field(risk, "exact-stock-boot-sha256") == image_hash),
    ("risk-forbids-persistent-writes", field(risk, "persistent-writes") == "FORBIDDEN"),
    ("risk-forbids-slot-changes", field(risk, "slot-changes") == "FORBIDDEN"),
    ("risk-does-not-authorize-diagnostic", field(risk, "diagnostic-payload-launch") == "NOT_AUTHORIZED_BY_THIS_RECORD"),
    ("provenance-role-is-boot", field(provenance, "Image role") == "boot"),
    ("provenance-file-is-boot", field(provenance, "Image file") == "boot.img"),
    ("provenance-build-exact", field(provenance, "OxygenOS build") == "CPH2413_15.0.0.1901(EX01)"),
    ("provenance-image-hash-bound", field(provenance, "Image SHA256") == image_hash),
    ("provenance-image-size-bound", field(provenance, "Image size bytes") == str(image_size)),
    ("hash-lock-schema-exact", field(lock, "Schema") == "IZZOS_EXACT_STOCK_HASH_LOCK_V1"),
    ("hash-lock-build-exact", field(lock, "Build ID") == "CPH2413_15.0.0.1901(EX01)"),
    ("hash-lock-boot-record-exact", f"Image record: boot|boot.img|{image_size}|{image_hash}|required" in lock.splitlines()),
    ("preflight-fastboot-device-count-one", "[FASTBOOT] connected devices: 1" in pre_raw),
    ("preflight-product-taro", field(pre_raw, "product") == "taro"),
    ("preflight-slot-a", field(pre_raw, "current-slot") == "a"),
    ("preflight-slot-count-two", field(pre_raw, "slot-count") == "2"),
    ("preflight-unlocked", field(pre_raw, "unlocked") == "yes"),
    ("preflight-secure", field(pre_raw, "secure") == "yes"),
    ("preflight-classic-fastboot", field(pre_raw, "is-userspace") == "no"),
    ("preflight-classification-candidate", field(pre_analysis, "classification") == "CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED"),
    ("postboot-adb-device-count-one", "[ADB] authorized devices: 1" in post_raw),
    ("postboot-model-exact", field(post_raw, "model") == "CPH2413"),
    ("postboot-product-exact", field(post_raw, "product") == "CPH2413"),
    ("postboot-build-exact", field(post_raw, "build-id") == "CPH2413_15.0.0.1901(EX01)"),
    ("postboot-slot-a", field(post_raw, "slot-suffix") == "_a"),
    ("postboot-verified-boot-orange", field(post_raw, "verified-boot-state") == "orange"),
    ("postboot-vbmeta-unlocked", field(post_raw, "vbmeta-device-state") == "unlocked"),
    ("postboot-classification-exact", field(post_analysis, "classification") == "NEED_EXACT_FASTBOOT_INSPECTION"),
    ("report-pre-slot-matches-preflight", field(report, "pre-route-slot") == field(pre_raw, "current-slot")),
    ("report-post-slot-matches-postboot", field(report, "post-route-slot-suffix") == field(post_raw, "slot-suffix")),
    ("route-command-scope-exact", field(report, "command-scope") == "ONE_NON_PERSISTENT_FASTBOOT_BOOT_EXACT_STOCK_IMAGE"),
    ("download-result-okay", field(report, "download-result") == "OKAY"),
    ("boot-result-okay", field(report, "boot-result") == "OKAY"),
    ("android-returned", field(report, "android-returned") == "yes"),
    ("post-route-build-match", field(report, "post-route-build-match") == "yes"),
    ("post-route-slot-match", field(report, "post-route-slot-match") == "yes"),
    ("no-persistent-write-command", field(report, "persistent-write-command-executed") == "no"),
    ("no-slot-change-command", field(report, "slot-change-command-executed") == "no"),
    ("no-flash-erase-format-unlock", field(report, "flash-erase-format-unlock-command-executed") == "no"),
    ("stock-handler-runtime-confirmed", field(report, "stock-fastboot-boot-handler-runtime-confirmed") == "yes"),
    ("custom-container-remains-unvalidated", field(report, "custom-container-validated") == "no"),
    ("diagnostic-remains-unexecuted", field(report, "diagnostic-payload-executed") == "no"),
    ("milestone-launch-remains-unauthorized", field(report, "milestone-launch-authorized") == "no"),
    ("report-classification-exact", field(report, "classification") == "EXACT_STOCK_FASTBOOT_BOOT_ROUTE_ACCEPTED_CUSTOM_CONTAINER_REQUIRED"),
])

if not all(passed for _, passed in checks):
    emit(
        checks,
        "M1_STOCK_FASTBOOT_BOOT_ROUTE_EVIDENCE_BLOCKED",
        "the route observation is missing, tampered, inconsistent, or overclaims custom execution; keep container construction and device launch blocked.",
        1,
    )

emit(
    checks,
    "M1_EXACT_STOCK_FASTBOOT_BOOT_ROUTE_EVIDENCE_BOUND",
    "the exact stock image was accepted by classic fastboot and returned to the same Android build and slot. This binds only stock-route availability; an independently verified custom container and separate diagnostic launch authorization are still required.",
    0,
)
