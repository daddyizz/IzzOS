#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 15:
    raise SystemExit(
        "Usage: verify-m2-route-governance-root-continuity.py "
        "<m14-enrollment-report.txt> <current-root-manifest.txt> <current-root-public-key.pem> "
        "<replacement-root-manifest.txt> <replacement-root-public-key.pem> "
        "<root-transition.txt> <custodian-1-signature.bin> <custodian-2-signature.bin> "
        "<custodian-3-signature.bin> <replacement-root-signature.bin> "
        "<anti-rollback-checkpoint.txt> <checkpoint-signature.bin> "
        "<verification-timestamp-utc> <output.txt>"
    )

M14_REPORT = Path(sys.argv[1])
CURRENT_MANIFEST = Path(sys.argv[2])
CURRENT_KEY = Path(sys.argv[3])
REPLACEMENT_MANIFEST = Path(sys.argv[4])
REPLACEMENT_KEY = Path(sys.argv[5])
TRANSITION = Path(sys.argv[6])
CUSTODIAN_SIGNATURES = [Path(sys.argv[7]), Path(sys.argv[8]), Path(sys.argv[9])]
REPLACEMENT_SIGNATURE = Path(sys.argv[10])
CHECKPOINT = Path(sys.argv[11])
CHECKPOINT_SIGNATURE = Path(sys.argv[12])
VERIFICATION_TEXT = sys.argv[13]
OUT = Path(sys.argv[14])
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ENROLLMENT = REPOSITORY_ROOT / "config" / "m2-route-governance-root-enrollment.txt"
ENROLLED_CURRENT_KEY = REPOSITORY_ROOT / "config" / "m2-route-governance-root-test-public.pem"
ENROLLED_NEXT_KEY = REPOSITORY_ROOT / "config" / "m2-route-governance-root-next-test-public.pem"
CUSTODIAN_KEYS = [
    REPOSITORY_ROOT / "config" / "m2-route-governance-recovery-custodian-1-test-public.pem",
    REPOSITORY_ROOT / "config" / "m2-route-governance-recovery-custodian-2-test-public.pem",
    REPOSITORY_ROOT / "config" / "m2-route-governance-recovery-custodian-3-test-public.pem",
]

ROOT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1"
TRANSITION_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_TRANSITION_V1"
CHECKPOINT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ANTI_ROLLBACK_CHECKPOINT_V1"
SCOPE = "M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

ROOT_FIELDS = [
    "route-governance-root-schema", "governance-root-key-id", "governance-root-role",
    "signature-algorithm", "public-key-sha256", "valid-from-utc", "valid-until-utc",
    "key-revocation-status", "trust-anchor-state", "governance-scope", "key-custody",
    "persistent-writes", "slot-changes", "route-specific-packaging-authorization",
    "payload-launch-authorization",
]
TRANSITION_FIELDS = [
    "route-governance-root-transition-schema", "transition-id",
    "source-enrollment-report-sha256", "repository-enrollment-record-sha256",
    "previous-governance-root-key-id", "previous-governance-root-public-key-sha256",
    "previous-governance-root-manifest-sha256", "previous-governance-root-status",
    "replacement-governance-root-key-id", "replacement-governance-root-public-key-sha256",
    "replacement-governance-root-manifest-sha256", "previous-governance-epoch",
    "previous-governance-sequence", "next-governance-epoch", "next-governance-sequence",
    "transition-mode", "rotation-policy", "emergency-recovery-policy",
    "recovery-custodian-1-public-key-sha256", "recovery-custodian-2-public-key-sha256",
    "recovery-custodian-3-public-key-sha256", "effective-at-utc",
    "governance-scope", "persistent-writes", "slot-changes",
    "route-specific-packaging-authorization", "payload-launch-authorization",
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


inputs = [M14_REPORT, CURRENT_MANIFEST, CURRENT_KEY, REPLACEMENT_MANIFEST,
          REPLACEMENT_KEY, TRANSITION, *CUSTODIAN_SIGNATURES, REPLACEMENT_SIGNATURE,
          CHECKPOINT, CHECKPOINT_SIGNATURE, ENROLLMENT, ENROLLED_CURRENT_KEY,
          ENROLLED_NEXT_KEY, *CUSTODIAN_KEYS]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M15 root-continuity input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a continuity input, key or signature")

m14_text = M14_REPORT.read_text(errors="replace")
current_bytes = CURRENT_MANIFEST.read_bytes()
current_text = current_bytes.decode(errors="replace")
replacement_bytes = REPLACEMENT_MANIFEST.read_bytes()
replacement_text = replacement_bytes.decode(errors="replace")
transition_bytes = TRANSITION.read_bytes()
transition_text = transition_bytes.decode(errors="replace")
checkpoint_bytes = CHECKPOINT.read_bytes()
checkpoint_text = checkpoint_bytes.decode(errors="replace")

m14_hash = sha256(M14_REPORT)
enrollment_hash = sha256(ENROLLMENT)
current_manifest_hash = sha256(CURRENT_MANIFEST)
current_key_hash = sha256(CURRENT_KEY)
replacement_manifest_hash = sha256(REPLACEMENT_MANIFEST)
replacement_key_hash = sha256(REPLACEMENT_KEY)
transition_hash = sha256(TRANSITION)
checkpoint_hash = sha256(CHECKPOINT)
current_enrolled_hash = sha256(ENROLLED_CURRENT_KEY)
next_enrolled_hash = sha256(ENROLLED_NEXT_KEY)

previous_epoch = number(transition_text, "previous-governance-epoch")
previous_sequence = number(transition_text, "previous-governance-sequence")
next_epoch = number(transition_text, "next-governance-epoch")
next_sequence = number(transition_text, "next-governance-sequence")
minimum_epoch = number(checkpoint_text, "minimum-governance-epoch")
minimum_sequence = number(checkpoint_text, "minimum-governance-sequence")
effective_at = parse_utc(field(transition_text, "effective-at-utc"))
published_at = parse_utc(field(checkpoint_text, "published-at-utc"))
checkpoint_until = parse_utc(field(checkpoint_text, "valid-until-utc"))
current_from = parse_utc(field(current_text, "valid-from-utc"))
current_until = parse_utc(field(current_text, "valid-until-utc"))
replacement_from = parse_utc(field(replacement_text, "valid-from-utc"))
replacement_until = parse_utc(field(replacement_text, "valid-until-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)

custodian_key_hashes = [sha256(path) for path in CUSTODIAN_KEYS]
custodian_signature_results = [
    signature.stat().st_size == 64 and verify_signature(key, TRANSITION, signature)
    for key, signature in zip(CUSTODIAN_KEYS, CUSTODIAN_SIGNATURES)
]
custodian_signature_count = sum(custodian_signature_results)
replacement_signature_ok = verify_signature(REPLACEMENT_KEY, TRANSITION, REPLACEMENT_SIGNATURE)
checkpoint_signature_ok = verify_signature(REPLACEMENT_KEY, CHECKPOINT, CHECKPOINT_SIGNATURE)

checks = [
    ("upstream-m14-enrollment-contract-passes-but-remains-test-only", field(m14_text, "classification") == "M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_PASS_PRODUCTION_ROOT_REQUIRED" and field(m14_text, "repository-enrollment-environment") == "HOST_TEST_ONLY_NOT_PRODUCTION"),
    ("upstream-m14-report-remains-non-authorizing", field(m14_text, "route-specific-packaging-authorization") == "NO" and field(m14_text, "payload-launch-authorization") == "NO" and field(m14_text, "persistent-writes") == "FORBIDDEN" and field(m14_text, "slot-changes") == "FORBIDDEN"),
    ("current-root-manifest-is-canonical-and-exact", all(len(values(current_text, label)) == 1 for label in ROOT_FIELDS) and canonical_bytes(current_text, ROOT_FIELDS) == current_bytes and field(current_text, "route-governance-root-schema") == ROOT_SCHEMA and field(current_text, "governance-root-role") == "M2_ROUTE_ATTESTER_GOVERNANCE_ROOT" and field(current_text, "signature-algorithm") == "ED25519" and field(current_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(current_text, "trust-anchor-state") == "CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT" and field(current_text, "governance-scope") == SCOPE and field(current_text, "key-custody") == "EXTERNAL_TO_ROUTE_ATTESTER"),
    ("current-root-is-exact-repository-enrolled-key", is_ed25519(CURRENT_KEY) and equal_hash(field(current_text, "public-key-sha256"), current_key_hash) and current_key_hash == current_enrolled_hash and CURRENT_KEY.read_bytes() == ENROLLED_CURRENT_KEY.read_bytes()),
    ("upstream-m14-report-binds-current-root-and-enrollment", equal_hash(field(m14_text, "governance-root-manifest-sha256"), current_manifest_hash) and equal_hash(field(m14_text, "governance-root-public-key-sha256"), current_key_hash) and equal_hash(field(m14_text, "repository-enrollment-record-sha256"), enrollment_hash) and equal_hash(field(m14_text, "repository-enrolled-public-key-sha256"), current_key_hash)),
    ("replacement-root-manifest-is-canonical-and-exact", all(len(values(replacement_text, label)) == 1 for label in ROOT_FIELDS) and canonical_bytes(replacement_text, ROOT_FIELDS) == replacement_bytes and field(replacement_text, "route-governance-root-schema") == ROOT_SCHEMA and field(replacement_text, "governance-root-role") == "M2_ROUTE_ATTESTER_GOVERNANCE_ROOT" and field(replacement_text, "signature-algorithm") == "ED25519" and field(replacement_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(replacement_text, "trust-anchor-state") == "SCHEDULED_REPLACEMENT_PENDING_REPOSITORY_PUBLICATION" and field(replacement_text, "governance-scope") == SCOPE and field(replacement_text, "key-custody") == "OFFLINE_EXTERNAL_TO_REPOSITORY_ATTESTER_AND_LAUNCH_OPERATOR"),
    ("replacement-root-is-exact-repository-next-test-key", is_ed25519(REPLACEMENT_KEY) and equal_hash(field(replacement_text, "public-key-sha256"), replacement_key_hash) and replacement_key_hash == next_enrolled_hash and REPLACEMENT_KEY.read_bytes() == ENROLLED_NEXT_KEY.read_bytes()),
    ("both-root-manifests-remain-non-authorizing", all(field(text, "persistent-writes") == "FORBIDDEN" and field(text, "slot-changes") == "FORBIDDEN" and field(text, "route-specific-packaging-authorization") == "NO" and field(text, "payload-launch-authorization") == "NO" for text in (current_text, replacement_text))),
    ("transition-fields-are-present-once-and-canonical", all(len(values(transition_text, label)) == 1 for label in TRANSITION_FIELDS) and canonical_bytes(transition_text, TRANSITION_FIELDS) == transition_bytes),
    ("transition-schema-id-and-source-bindings-are-exact", field(transition_text, "route-governance-root-transition-schema") == TRANSITION_SCHEMA and bool(re.fullmatch(TOKEN, field(transition_text, "transition-id") or "")) and equal_hash(field(transition_text, "source-enrollment-report-sha256"), m14_hash) and equal_hash(field(transition_text, "repository-enrollment-record-sha256"), enrollment_hash)),
    ("transition-binds-and-revokes-previous-root", field(transition_text, "previous-governance-root-key-id") == field(current_text, "governance-root-key-id") and equal_hash(field(transition_text, "previous-governance-root-public-key-sha256"), current_key_hash) and equal_hash(field(transition_text, "previous-governance-root-manifest-sha256"), current_manifest_hash) and field(transition_text, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_TRANSITION"),
    ("transition-binds-exact-replacement-root", field(transition_text, "replacement-governance-root-key-id") == field(replacement_text, "governance-root-key-id") and equal_hash(field(transition_text, "replacement-governance-root-public-key-sha256"), replacement_key_hash) and equal_hash(field(transition_text, "replacement-governance-root-manifest-sha256"), replacement_manifest_hash)),
    ("transition-epoch-and-sequence-advance-monotonically", previous_epoch is not None and previous_sequence is not None and previous_epoch > 0 and previous_sequence > 0 and next_epoch == previous_epoch + 1 and next_sequence == 1),
    ("transition-mode-rotation-and-recovery-policies-are-exact", field(transition_text, "transition-mode") == "EMERGENCY_RECOVERY_2_OF_3" and field(transition_text, "rotation-policy") == "CURRENT_ROOT_SIGNATURE_WAIVED_AFTER_DECLARED_COMPROMISE" and field(transition_text, "emergency-recovery-policy") == "EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED"),
    ("transition-pins-three-distinct-repository-custodian-keys", len(set(custodian_key_hashes)) == 3 and all(is_ed25519(key) for key in CUSTODIAN_KEYS) and all(equal_hash(field(transition_text, f"recovery-custodian-{index}-public-key-sha256"), custodian_key_hashes[index - 1]) for index in range(1, 4))),
    ("transition-scope-and-policy-remain-non-authorizing", field(transition_text, "governance-scope") == SCOPE and field(transition_text, "persistent-writes") == "FORBIDDEN" and field(transition_text, "slot-changes") == "FORBIDDEN" and field(transition_text, "route-specific-packaging-authorization") == "NO" and field(transition_text, "payload-launch-authorization") == "NO"),
    ("transition-has-valid-two-of-three-recovery-custodian-quorum", custodian_signature_count >= 2),
    ("transition-replacement-root-possession-signature-is-valid", REPLACEMENT_SIGNATURE.stat().st_size == 64 and replacement_signature_ok),
    ("checkpoint-fields-are-present-once-and-canonical", all(len(values(checkpoint_text, label)) == 1 for label in CHECKPOINT_FIELDS) and canonical_bytes(checkpoint_text, CHECKPOINT_FIELDS) == checkpoint_bytes),
    ("checkpoint-schema-id-transition-and-history-are-exact", field(checkpoint_text, "route-governance-root-anti-rollback-checkpoint-schema") == CHECKPOINT_SCHEMA and bool(re.fullmatch(TOKEN, field(checkpoint_text, "checkpoint-id") or "")) and equal_hash(field(checkpoint_text, "root-transition-sha256"), transition_hash) and valid_hash(field(checkpoint_text, "previous-checkpoint-sha256"))),
    ("checkpoint-pins-replacement-root-and-monotonic-minimum", field(checkpoint_text, "active-governance-root-key-id") == field(replacement_text, "governance-root-key-id") and equal_hash(field(checkpoint_text, "active-governance-root-public-key-sha256"), replacement_key_hash) and equal_hash(field(checkpoint_text, "active-governance-root-manifest-sha256"), replacement_manifest_hash) and minimum_epoch == next_epoch and minimum_sequence == next_sequence),
    ("checkpoint-publication-recovery-scope-and-policy-are-exact", field(checkpoint_text, "publication-state") == "HOST_TEST_REPOSITORY_CHECKPOINT_ONLY" and field(checkpoint_text, "emergency-recovery-policy") == "EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED" and field(checkpoint_text, "governance-scope") == SCOPE and field(checkpoint_text, "persistent-writes") == "FORBIDDEN" and field(checkpoint_text, "slot-changes") == "FORBIDDEN" and field(checkpoint_text, "route-specific-packaging-authorization") == "NO" and field(checkpoint_text, "payload-launch-authorization") == "NO"),
    ("checkpoint-replacement-root-signature-is-valid", CHECKPOINT_SIGNATURE.stat().st_size == 64 and checkpoint_signature_ok),
    ("transition-publication-and-validity-order-passes", all(value is not None for value in (effective_at, published_at, checkpoint_until, current_from, current_until, replacement_from, replacement_until, verification_time)) and current_from <= effective_at <= current_until and replacement_from <= effective_at <= published_at <= verification_time <= checkpoint_until <= replacement_until),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS internal M15 governance-root continuity and anti-rollback gate",
    "Verifier mode: HOST_TEST_2_OF_3_RECOVERY_AND_CHECKPOINT_SIGNATURES_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"upstream-m14-enrollment-report-sha256: {m14_hash}",
    f"repository-enrollment-record-sha256: {enrollment_hash}",
    f"current-governance-root-manifest-sha256: {current_manifest_hash}",
    f"current-governance-root-public-key-sha256: {current_key_hash}",
    f"replacement-governance-root-manifest-sha256: {replacement_manifest_hash}",
    f"replacement-governance-root-public-key-sha256: {replacement_key_hash}",
    f"root-transition-sha256: {transition_hash}",
    f"anti-rollback-checkpoint-sha256: {checkpoint_hash}",
    f"next-governance-epoch: {next_epoch if next_epoch is not None else 'MISSING'}",
    f"next-governance-sequence: {next_sequence if next_sequence is not None else 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"recovery-custodian-valid-signature-count: {custodian_signature_count}",
    f"recovery-custodian-1-signature-verification: {'PASS' if custodian_signature_results[0] else 'FAIL'}",
    f"recovery-custodian-2-signature-verification: {'PASS' if custodian_signature_results[1] else 'FAIL'}",
    f"recovery-custodian-3-signature-verification: {'PASS' if custodian_signature_results[2] else 'FAIL'}",
    f"replacement-root-possession-signature-verification: {'PASS' if replacement_signature_ok else 'FAIL'}",
    f"checkpoint-signature-verification: {'PASS' if checkpoint_signature_ok else 'FAIL'}",
    "continuity-environment: HOST_TEST_ONLY_NOT_PRODUCTION",
    "physical-device-truth: NOT_MEASURED_BY_CONTINUITY_VERIFIER",
    "route-specific-packaging-authorization: NO",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_BLOCKED",
        "decision: reject the root transition/checkpoint because repository pins, dual signatures, revocation continuity, monotonic state, recovery policy, validity or no-write/no-launch policy failed.",
    ], 1)

emit(lines + [
    "remaining-blocker: PRODUCTION_GOVERNANCE_ROOT_AND_INDEPENDENT_CUSTODY_REQUIRED",
    "remaining-blocker: GENUINE_EXACT_DEVICE_ROUTE_ATTESTATION_REQUIRED",
    "remaining-blocker: EXACT_STOCK_ACCEPTANCE_AND_TEMPORARY_EXECUTION_REQUIRED",
    "classification: M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED",
    "decision: two of three fixed host-test recovery custodians signed an exact monotonic transition, the replacement root proved possession and signed its anti-rollback checkpoint, and the old root was declared revoked. This validates continuity mechanics only and authorizes no device action.",
])
