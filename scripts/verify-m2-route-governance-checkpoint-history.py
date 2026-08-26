#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 6:
    raise SystemExit(
        "Usage: verify-m2-route-governance-checkpoint-history.py "
        "<m15-continuity-report.txt> <head-checkpoint.txt> "
        "<head-checkpoint-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

M15_REPORT = Path(sys.argv[1])
CHECKPOINT = Path(sys.argv[2])
CHECKPOINT_SIGNATURE = Path(sys.argv[3])
VERIFICATION_TEXT = sys.argv[4]
OUT = Path(sys.argv[5])
ROOT = Path(__file__).resolve().parent.parent
ANCHOR = ROOT / "config" / "m2-route-governance-checkpoint-history-test-anchor.txt"
HEAD_KEY = ROOT / "config" / "m2-route-governance-root-next-test-public.pem"

ANCHOR_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_CHECKPOINT_HISTORY_ANCHOR_V1"
CHECKPOINT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ANTI_ROLLBACK_CHECKPOINT_V1"
SCOPE = "M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

ANCHOR_FIELDS = [
    "checkpoint-history-anchor-schema", "checkpoint-history-id", "predecessor-anchor-id",
    "predecessor-anchor-material", "predecessor-checkpoint-sha256",
    "published-head-checkpoint-sha256", "published-head-root-key-id",
    "published-head-root-public-key-sha256", "published-head-minimum-governance-epoch",
    "published-head-minimum-governance-sequence", "history-entry-count",
    "publication-environment", "fork-policy", "governance-scope", "persistent-writes",
    "slot-changes", "route-specific-packaging-authorization", "payload-launch-authorization",
]
CHECKPOINT_FIELDS = [
    "route-governance-root-anti-rollback-checkpoint-schema", "checkpoint-id",
    "root-transition-sha256", "previous-checkpoint-sha256",
    "active-governance-root-key-id", "active-governance-root-public-key-sha256",
    "active-governance-root-manifest-sha256", "minimum-governance-epoch",
    "minimum-governance-sequence", "published-at-utc", "valid-until-utc",
    "publication-state", "emergency-recovery-policy", "governance-scope",
    "persistent-writes", "slot-changes", "route-specific-packaging-authorization",
    "payload-launch-authorization",
]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def values(text, label):
    return [match.strip() for match in re.findall(rf"(?m)^{re.escape(label)}:\s*(.+?)\s*$", text)]


def field(text, label):
    found = values(text, label)
    return found[0] if len(found) == 1 else None


def number(text, label):
    value = field(text, label)
    return int(value) if value and re.fullmatch(r"[0-9]+", value) else None


def valid_hash(value):
    return bool(value and re.fullmatch(HASH, value) and not re.fullmatch(r"0{64}", value))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def parse_utc(value):
    if not value or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def canonical_bytes(text, labels):
    if any(field(text, label) is None for label in labels):
        return None
    return "".join(f"{label}: {field(text, label)}\n" for label in labels).encode("utf-8")


def openssl_run(arguments):
    executable = shutil.which(os.environ.get("OPENSSL", "openssl"))
    if not executable:
        return False, "OpenSSL executable not found"
    try:
        completed = subprocess.run(
            [executable, *arguments], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def is_ed25519(path):
    passed, detail = openssl_run(["pkey", "-pubin", "-in", str(path), "-text_pub", "-noout"])
    return passed and "ED25519" in detail.upper()


def verify_signature(key, record, signature):
    return openssl_run([
        "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
        "-in", str(record), "-sigfile", str(signature),
    ])[0]


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [M15_REPORT, CHECKPOINT, CHECKPOINT_SIGNATURE, ANCHOR, HEAD_KEY]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M16 checkpoint-history input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a history input, repository anchor, key or signature")

anchor_bytes = ANCHOR.read_bytes()
anchor_text = anchor_bytes.decode(errors="replace")
report_text = M15_REPORT.read_text(errors="replace")
checkpoint_bytes = CHECKPOINT.read_bytes()
checkpoint_text = checkpoint_bytes.decode(errors="replace")

anchor_hash = sha256(ANCHOR)
report_hash = sha256(M15_REPORT)
checkpoint_hash = sha256(CHECKPOINT)
head_key_hash = sha256(HEAD_KEY)
predecessor_material = field(anchor_text, "predecessor-anchor-material") or ""
predecessor_material_hash = hashlib.sha256(predecessor_material.encode("utf-8")).hexdigest()

anchor_epoch = number(anchor_text, "published-head-minimum-governance-epoch")
anchor_sequence = number(anchor_text, "published-head-minimum-governance-sequence")
checkpoint_epoch = number(checkpoint_text, "minimum-governance-epoch")
checkpoint_sequence = number(checkpoint_text, "minimum-governance-sequence")
report_epoch = number(report_text, "next-governance-epoch")
report_sequence = number(report_text, "next-governance-sequence")
published_at = parse_utc(field(checkpoint_text, "published-at-utc"))
valid_until = parse_utc(field(checkpoint_text, "valid-until-utc"))
report_time = parse_utc(field(report_text, "verification-timestamp-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
checkpoint_signature_ok = CHECKPOINT_SIGNATURE.stat().st_size == 64 and verify_signature(
    HEAD_KEY, CHECKPOINT, CHECKPOINT_SIGNATURE
)

checks = [
    ("repository-history-anchor-is-canonical", all(len(values(anchor_text, label)) == 1 for label in ANCHOR_FIELDS) and canonical_bytes(anchor_text, ANCHOR_FIELDS) == anchor_bytes),
    ("repository-history-anchor-schema-id-and-environment-are-exact", field(anchor_text, "checkpoint-history-anchor-schema") == ANCHOR_SCHEMA and bool(re.fullmatch(TOKEN, field(anchor_text, "checkpoint-history-id") or "")) and field(anchor_text, "publication-environment") == "HOST_TEST_ONLY_NOT_PRODUCTION"),
    ("predecessor-anchor-material-is-content-bound", field(anchor_text, "predecessor-anchor-id") == predecessor_material and equal_hash(field(anchor_text, "predecessor-checkpoint-sha256"), predecessor_material_hash)),
    ("history-head-is-fixed-to-repository-replacement-key", is_ed25519(HEAD_KEY) and equal_hash(field(anchor_text, "published-head-root-public-key-sha256"), head_key_hash) and field(anchor_text, "published-head-root-key-id") == "izzos-m2-route-governance-host-test-02"),
    ("history-entry-count-and-fork-policy-are-exact", number(anchor_text, "history-entry-count") == 2 and field(anchor_text, "fork-policy") == "REJECT_ALTERNATE_HEAD_AT_OR_BELOW_PUBLISHED_EPOCH_SEQUENCE"),
    ("history-anchor-remains-non-authorizing", field(anchor_text, "governance-scope") == SCOPE and field(anchor_text, "persistent-writes") == "FORBIDDEN" and field(anchor_text, "slot-changes") == "FORBIDDEN" and field(anchor_text, "route-specific-packaging-authorization") == "NO" and field(anchor_text, "payload-launch-authorization") == "NO"),
    ("upstream-m15-continuity-report-passes-but-remains-test-only", field(report_text, "classification") == "M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED" and field(report_text, "continuity-environment") == "HOST_TEST_ONLY_NOT_PRODUCTION" and field(report_text, "checkpoint-signature-verification") == "PASS"),
    ("upstream-m15-report-remains-non-authorizing", field(report_text, "route-specific-packaging-authorization") == "NO" and field(report_text, "payload-launch-authorization") == "NO" and field(report_text, "persistent-writes") == "FORBIDDEN" and field(report_text, "slot-changes") == "FORBIDDEN"),
    ("head-checkpoint-fields-are-present-once-and-canonical", all(len(values(checkpoint_text, label)) == 1 for label in CHECKPOINT_FIELDS) and canonical_bytes(checkpoint_text, CHECKPOINT_FIELDS) == checkpoint_bytes),
    ("head-checkpoint-schema-and-hashes-are-valid", field(checkpoint_text, "route-governance-root-anti-rollback-checkpoint-schema") == CHECKPOINT_SCHEMA and bool(re.fullmatch(TOKEN, field(checkpoint_text, "checkpoint-id") or "")) and valid_hash(field(checkpoint_text, "root-transition-sha256")) and valid_hash(field(checkpoint_text, "active-governance-root-manifest-sha256"))),
    ("head-checkpoint-is-exact-repository-published-head", equal_hash(field(anchor_text, "published-head-checkpoint-sha256"), checkpoint_hash) and equal_hash(field(report_text, "anti-rollback-checkpoint-sha256"), checkpoint_hash)),
    ("head-checkpoint-links-exact-predecessor-anchor", equal_hash(field(checkpoint_text, "previous-checkpoint-sha256"), predecessor_material_hash) and equal_hash(field(checkpoint_text, "previous-checkpoint-sha256"), field(anchor_text, "predecessor-checkpoint-sha256"))),
    ("head-checkpoint-root-and-signature-are-exact", field(checkpoint_text, "active-governance-root-key-id") == field(anchor_text, "published-head-root-key-id") and equal_hash(field(checkpoint_text, "active-governance-root-public-key-sha256"), head_key_hash) and equal_hash(field(report_text, "replacement-governance-root-public-key-sha256"), head_key_hash) and checkpoint_signature_ok),
    ("head-epoch-and-sequence-match-published-monotonic-minimum", anchor_epoch == checkpoint_epoch == report_epoch == 2 and anchor_sequence == checkpoint_sequence == report_sequence == 1),
    ("head-publication-window-and-order-pass", all(value is not None for value in (published_at, report_time, verification_time, valid_until)) and published_at <= report_time <= verification_time <= valid_until),
    ("head-checkpoint-publication-and-recovery-policy-are-exact", field(checkpoint_text, "publication-state") == "HOST_TEST_REPOSITORY_CHECKPOINT_ONLY" and field(checkpoint_text, "emergency-recovery-policy") == "EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED"),
    ("head-checkpoint-remains-non-authorizing", field(checkpoint_text, "governance-scope") == SCOPE and field(checkpoint_text, "persistent-writes") == "FORBIDDEN" and field(checkpoint_text, "slot-changes") == "FORBIDDEN" and field(checkpoint_text, "route-specific-packaging-authorization") == "NO" and field(checkpoint_text, "payload-launch-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS internal M16 governance checkpoint-history gate",
    "Verifier mode: HOST_TEST_REPOSITORY_HEAD_AND_PREDECESSOR_BINDING_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"repository-history-anchor-sha256: {anchor_hash}",
    f"upstream-m15-continuity-report-sha256: {report_hash}",
    f"published-head-checkpoint-sha256: {checkpoint_hash}",
    f"published-head-root-public-key-sha256: {head_key_hash}",
    f"published-head-minimum-governance-epoch: {checkpoint_epoch if checkpoint_epoch is not None else 'MISSING'}",
    f"published-head-minimum-governance-sequence: {checkpoint_sequence if checkpoint_sequence is not None else 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"head-checkpoint-signature-verification: {'PASS' if checkpoint_signature_ok else 'FAIL'}",
    "history-environment: HOST_TEST_ONLY_NOT_PRODUCTION",
    "physical-device-truth: NOT_MEASURED_BY_HISTORY_VERIFIER",
    "route-specific-packaging-authorization: NO",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M2_ROUTE_GOVERNANCE_CHECKPOINT_HISTORY_BLOCKED",
        "decision: reject the claimed head because its repository anchor, predecessor link, fixed key, signature, monotonic position, publication window or no-launch policy failed.",
    ], 1)

emit(lines + [
    "remaining-blocker: PRODUCTION_APPEND_ONLY_CHECKPOINT_PUBLICATION_REQUIRED",
    "remaining-blocker: PRODUCTION_GOVERNANCE_ROOT_AND_INDEPENDENT_CUSTODY_REQUIRED",
    "remaining-blocker: GENUINE_EXACT_DEVICE_ROUTE_ATTESTATION_REQUIRED",
    "classification: M2_ROUTE_GOVERNANCE_CHECKPOINT_HISTORY_HOST_TEST_PASS_PRODUCTION_PUBLICATION_REQUIRED",
    "decision: the exact host-test predecessor material, signed M15 checkpoint and repository-published head form one fork-detecting monotonic history. This validates host mechanics only and authorizes no device action.",
])
