#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 18:
    raise SystemExit(
        "Usage: verify-m7-checkpoint-publication-root-recovery.py "
        "<key-governance-verification.txt> <anti-rollback-checkpoint.txt> "
        "<governance-root-manifest.txt> <governance-root-public-key.pem> "
        "<publication-recovery-policy.txt> "
        "<witness-1-public-key.pem> <witness-1-signature.bin> "
        "<witness-2-public-key.pem> <witness-2-signature.bin> "
        "<witness-3-public-key.pem> <witness-3-signature.bin> "
        "<recovery-custodian-1-public-key.pem> "
        "<recovery-custodian-2-public-key.pem> "
        "<recovery-custodian-3-public-key.pem> "
        "<governance-root-policy-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

GOVERNANCE = Path(sys.argv[1])
CHECKPOINT = Path(sys.argv[2])
ROOT_MANIFEST = Path(sys.argv[3])
ROOT_KEY = Path(sys.argv[4])
POLICY = Path(sys.argv[5])
WITNESS_KEYS = [Path(sys.argv[6]), Path(sys.argv[8]), Path(sys.argv[10])]
WITNESS_SIGNATURES = [Path(sys.argv[7]), Path(sys.argv[9]), Path(sys.argv[11])]
RECOVERY_KEYS = [Path(sys.argv[12]), Path(sys.argv[13]), Path(sys.argv[14])]
ROOT_SIGNATURE = Path(sys.argv[15])
VERIFICATION_TEXT = sys.argv[16]
OUT = Path(sys.argv[17])

GOVERNANCE_CLASSIFICATION = "M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED"
CHECKPOINT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
POLICY_SCHEMA = "IZZOS_M7_CHECKPOINT_PUBLICATION_AND_ROOT_RECOVERY_POLICY_V1"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"
MAX_PUBLICATION_WINDOW_SECONDS = 15 * 60

ROOT_FIELDS = [
    "key-governance-root-schema",
    "governance-root-key-id",
    "governance-root-role",
    "signature-algorithm",
    "public-key-sha256",
    "valid-from-utc",
    "valid-until-utc",
    "key-revocation-status",
    "trust-anchor-source",
    "governance-scope",
    "key-custody",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
]

POLICY_FIELDS = [
    "checkpoint-publication-recovery-policy-schema",
    "policy-id",
    "governance-verification-report-sha256",
    "anti-rollback-checkpoint-sha256",
    "checkpoint-id",
    "governance-epoch",
    "governance-sequence",
    "policy-issued-at-utc",
    "checkpoint-published-at-utc",
    "publication-valid-until-utc",
    "publication-window-max-seconds",
    "publication-record-source",
    "publication-signature-algorithm",
    "publication-quorum-threshold",
    "publication-witness-1-id",
    "publication-witness-1-public-key-sha256",
    "publication-witness-2-id",
    "publication-witness-2-public-key-sha256",
    "publication-witness-3-id",
    "publication-witness-3-public-key-sha256",
    "governance-root-key-id",
    "governance-root-public-key-sha256",
    "governance-root-approval-policy",
    "root-recovery-mode",
    "root-recovery-threshold",
    "recovery-custodian-1-id",
    "recovery-custodian-1-public-key-sha256",
    "recovery-custodian-2-id",
    "recovery-custodian-2-public-key-sha256",
    "recovery-custodian-3-id",
    "recovery-custodian-3-public-key-sha256",
    "recovery-event-requirements",
    "compromise-response",
    "unseen-newer-checkpoint-discovery",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "wrapper-execution-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
]


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


def decimal_value(text, label):
    value = field(text, label)
    return int(value, 10) if value and re.fullmatch(r"[0-9]+", value) else None


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


def openssl_run(executable, arguments):
    if not executable:
        return False, "OpenSSL executable not found"
    try:
        completed = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def is_ed25519(executable, key):
    passed, detail = openssl_run(
        executable,
        ["pkey", "-pubin", "-in", str(key), "-text_pub", "-noout"],
    )
    return passed and "ED25519" in detail.upper()


def verify_signature(executable, key, record, signature):
    if signature.stat().st_size != 64:
        return False
    return openssl_run(
        executable,
        [
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(key),
            "-rawin",
            "-in",
            str(record),
            "-sigfile",
            str(signature),
        ],
    )[0]


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [
    GOVERNANCE,
    CHECKPOINT,
    ROOT_MANIFEST,
    ROOT_KEY,
    POLICY,
    *WITNESS_KEYS,
    *WITNESS_SIGNATURES,
    *RECOVERY_KEYS,
    ROOT_SIGNATURE,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 checkpoint-publication input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an input, key, policy or signature")

governance = GOVERNANCE.read_text(errors="replace")
checkpoint = CHECKPOINT.read_text(errors="replace")
root_manifest_bytes = ROOT_MANIFEST.read_bytes()
root_manifest = root_manifest_bytes.decode(errors="replace")
policy_bytes = POLICY.read_bytes()
policy = policy_bytes.decode(errors="replace")

governance_hash = sha256(GOVERNANCE)
checkpoint_hash = sha256(CHECKPOINT)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
policy_hash = sha256(POLICY)
witness_key_hashes = [sha256(path) for path in WITNESS_KEYS]
recovery_key_hashes = [sha256(path) for path in RECOVERY_KEYS]

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
root_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
witness_key_types = [is_ed25519(openssl_path, key) for key in WITNESS_KEYS]
recovery_key_types = [is_ed25519(openssl_path, key) for key in RECOVERY_KEYS]
root_signature_valid = verify_signature(openssl_path, ROOT_KEY, POLICY, ROOT_SIGNATURE)
witness_signature_valid = [
    verify_signature(openssl_path, key, POLICY, signature)
    for key, signature in zip(WITNESS_KEYS, WITNESS_SIGNATURES)
]

epoch = decimal_value(policy, "governance-epoch")
sequence = decimal_value(policy, "governance-sequence")
checkpoint_epoch = decimal_value(checkpoint, "minimum-accepted-governance-epoch")
checkpoint_sequence = decimal_value(checkpoint, "minimum-accepted-governance-sequence")
report_epoch = decimal_value(governance, "governance-epoch")
report_sequence = decimal_value(governance, "governance-sequence")
publication_threshold = decimal_value(policy, "publication-quorum-threshold")
recovery_threshold = decimal_value(policy, "root-recovery-threshold")
window_limit = decimal_value(policy, "publication-window-max-seconds")

root_valid_from = parse_utc(field(root_manifest, "valid-from-utc"))
root_valid_until = parse_utc(field(root_manifest, "valid-until-utc"))
report_verification_time = parse_utc(field(governance, "verification-timestamp-utc"))
checkpoint_updated_at = parse_utc(field(checkpoint, "checkpoint-updated-at-utc"))
issued_at = parse_utc(field(policy, "policy-issued-at-utc"))
published_at = parse_utc(field(policy, "checkpoint-published-at-utc"))
valid_until = parse_utc(field(policy, "publication-valid-until-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
publication_window = (
    (valid_until - published_at).total_seconds()
    if valid_until and published_at
    else None
)

witness_ids = [field(policy, f"publication-witness-{index}-id") for index in range(1, 4)]
witness_pins = [
    field(policy, f"publication-witness-{index}-public-key-sha256")
    for index in range(1, 4)
]
recovery_ids = [field(policy, f"recovery-custodian-{index}-id") for index in range(1, 4)]
recovery_pins = [
    field(policy, f"recovery-custodian-{index}-public-key-sha256")
    for index in range(1, 4)
]
all_key_hashes = [root_key_hash, *witness_key_hashes, *recovery_key_hashes]
valid_witness_count = sum(witness_signature_valid)

checks = [
    ("upstream-key-governance-classification-passes", field(governance, "classification") == GOVERNANCE_CLASSIFICATION),
    ("upstream-governance-pins-exact-checkpoint", field(governance, "anti-rollback-state") == "EXACT_SUPPLIED_REPOSITORY_CHECKPOINT_MATCH" and equal_hash(field(governance, "anti-rollback-checkpoint-sha256"), checkpoint_hash)),
    ("upstream-governance-remains-non-authorizing", field(governance, "wrapper-execution-authorization") == "NO" and field(governance, "launch-authorization") == "NO" and field(governance, "persistent-writes") == "FORBIDDEN"),
    ("checkpoint-schema-id-and-state-are-valid", field(checkpoint, "anti-rollback-checkpoint-schema") == CHECKPOINT_SCHEMA and bool(re.fullmatch(TOKEN, field(checkpoint, "checkpoint-id") or "")) and checkpoint_epoch is not None and checkpoint_sequence is not None and checkpoint_epoch > 0 and checkpoint_sequence > 0),
    ("root-manifest-fields-are-present-once", all(len(values(root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("root-manifest-is-canonical", canonical_bytes(root_manifest, ROOT_FIELDS) == root_manifest_bytes),
    ("root-manifest-schema-role-and-scope-are-exact", field(root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and field(root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(root_manifest, "signature-algorithm") == "ED25519" and field(root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY"),
    ("root-key-id-and-pin-match-upstream", bool(re.fullmatch(TOKEN, field(root_manifest, "governance-root-key-id") or "")) and equal_hash(field(root_manifest, "public-key-sha256"), root_key_hash) and equal_hash(field(governance, "governance-root-public-key-sha256"), root_key_hash) and root_is_ed25519),
    ("root-manifest-is-current-not-revoked-and-non-authorizing", field(root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_manifest, "persistent-writes") == "FORBIDDEN" and field(root_manifest, "slot-changes") == "FORBIDDEN" and field(root_manifest, "payload-launch-authorization") == "NO"),
    ("policy-fields-are-present-once", all(len(values(policy, label)) == 1 for label in POLICY_FIELDS)),
    ("policy-is-canonical", canonical_bytes(policy, POLICY_FIELDS) == policy_bytes),
    ("policy-schema-id-and-source-are-exact", field(policy, "checkpoint-publication-recovery-policy-schema") == POLICY_SCHEMA and bool(re.fullmatch(TOKEN, field(policy, "policy-id") or "")) and field(policy, "publication-record-source") == "REPOSITORY_REVIEWED_AND_INDEPENDENT_WITNESS_QUORUM" and field(policy, "publication-signature-algorithm") == "ED25519"),
    ("policy-binds-exact-governance-report-and-checkpoint", equal_hash(field(policy, "governance-verification-report-sha256"), governance_hash) and equal_hash(field(policy, "anti-rollback-checkpoint-sha256"), checkpoint_hash) and field(policy, "checkpoint-id") == field(checkpoint, "checkpoint-id")),
    ("policy-epoch-and-sequence-match-report-and-checkpoint", epoch == checkpoint_epoch == report_epoch and sequence == checkpoint_sequence == report_sequence and epoch is not None and sequence is not None),
    ("publication-window-is-fresh-bounded-and-ordered", all(value is not None for value in (checkpoint_updated_at, report_verification_time, issued_at, published_at, valid_until, verification_time)) and checkpoint_updated_at <= report_verification_time <= issued_at <= published_at <= verification_time <= valid_until and publication_window is not None and 0 < publication_window <= MAX_PUBLICATION_WINDOW_SECONDS and window_limit == MAX_PUBLICATION_WINDOW_SECONDS),
    ("root-key-validity-covers-policy-and-verification", all(value is not None for value in (root_valid_from, root_valid_until, issued_at, verification_time)) and root_valid_from <= issued_at <= verification_time <= root_valid_until),
    ("governance-root-approval-policy-and-signature-pass", field(policy, "governance-root-key-id") == field(root_manifest, "governance-root-key-id") and equal_hash(field(policy, "governance-root-public-key-sha256"), root_key_hash) and field(policy, "governance-root-approval-policy") == "REQUIRED_DETACHED_ED25519" and ROOT_SIGNATURE.stat().st_size == 64 and root_signature_valid),
    ("publication-witness-identities-and-key-pins-are-exact", all(identifier and re.fullmatch(TOKEN, identifier) for identifier in witness_ids) and len(set(witness_ids)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(witness_pins, witness_key_hashes)) and all(witness_key_types)),
    ("publication-quorum-is-two-of-three-and-passes", publication_threshold == 2 and valid_witness_count >= 2),
    ("root-recovery-policy-is-bounded-two-of-three", field(policy, "root-recovery-mode") == "PREAUTHORIZED_2_OF_3_CUSTODIAN_ROOT_REPLACEMENT" and recovery_threshold == 2 and field(policy, "recovery-event-requirements") == "NEW_ROOT_MANIFEST_PLUS_2_OF_3_DETACHED_ED25519" and field(policy, "compromise-response") == "REVOKE_PREVIOUS_ROOT_BEFORE_REPLACEMENT_ACTIVATION"),
    ("recovery-custodian-identities-and-key-pins-are-exact", all(identifier and re.fullmatch(TOKEN, identifier) for identifier in recovery_ids) and len(set(recovery_ids)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(recovery_pins, recovery_key_hashes)) and all(recovery_key_types)),
    ("all-governance-witness-and-recovery-keys-are-distinct", len(set(all_key_hashes)) == len(all_key_hashes)),
    ("policy-admits-unseen-newer-checkpoint-limit", field(policy, "unseen-newer-checkpoint-discovery") == "NOT_PROVEN_BY_THIS_SUPPLIED_QUORUM"),
    ("policy-forbids-write-slot-wrapper-promotion-container-and-launch", field(policy, "persistent-writes") == "FORBIDDEN" and field(policy, "slot-changes") == "FORBIDDEN" and field(policy, "payload-launch-authorization") == "NO" and field(policy, "wrapper-execution-authorization") == "NO" and field(policy, "dsc-fdf-promotion-authorization") == "NO" and field(policy, "container-build-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 checkpoint publication quorum and governance-root recovery policy gate",
    "Verifier mode: HOST_SIDE_ROOT_SIGNED_POLICY_AND_2_OF_3_PUBLICATION_WITNESSES_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"key-governance-verification-sha256: {governance_hash}",
    f"anti-rollback-checkpoint-sha256: {checkpoint_hash}",
    f"governance-root-manifest-sha256: {root_manifest_hash}",
    f"governance-root-public-key-sha256: {root_key_hash}",
    f"publication-recovery-policy-sha256: {policy_hash}",
    f"governance-epoch: {epoch if epoch is not None else 'MISSING'}",
    f"governance-sequence: {sequence if sequence is not None else 'MISSING'}",
    f"publication-quorum-required: {publication_threshold if publication_threshold is not None else 'MISSING'}",
    f"publication-witness-signatures-valid: {valid_witness_count}",
    f"root-recovery-threshold: {recovery_threshold if recovery_threshold is not None else 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"governance-root-policy-signature: {'PASS' if root_signature_valid else 'FAIL'}",
    f"publication-witness-1-signature: {'PASS' if witness_signature_valid[0] else 'FAIL'}",
    f"publication-witness-2-signature: {'PASS' if witness_signature_valid[1] else 'FAIL'}",
    f"publication-witness-3-signature: {'PASS' if witness_signature_valid[2] else 'FAIL'}",
    "root-recovery-event-authorized: NO",
    "replacement-governance-root-activated: NO",
    "wrapper-execution-authorization: NO",
    "dsc-fdf-promotion-authorization: NO",
    "container-build-authorization: NO",
    "device-commands: NONE",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
    "launch-authorization: NO",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M7_CHECKPOINT_PUBLICATION_ROOT_RECOVERY_BLOCKED",
        "decision: the exact checkpoint/report binding, bounded freshness window, governance-root approval, two-of-three publication quorum, recovery-custodian pins or no-write/no-launch policy failed. Reject this supplied publication state and do not authorize a device command.",
    ], 1)

emit(lines + [
    "publication-quorum-state: EXACT_ROOT_APPROVED_POLICY_WITH_2_OF_3_OR_GREATER_WITNESS_SIGNATURES",
    "root-recovery-policy-state: PREAUTHORIZED_POLICY_ONLY_NO_RECOVERY_EVENT",
    "remaining-blocker: UNSEEN_NEWER_CHECKPOINT_CANNOT_BE_DISCOVERED_FROM_SUPPLIED_FILES",
    "remaining-blocker: WITNESS_AND_RECOVERY_PRIVATE_KEY_CUSTODY_REMAINS_EXTERNAL",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_CHECKPOINT_PUBLICATION_QUORUM_ROOT_RECOVERY_POLICY_PASS_EXTERNAL_DISTRIBUTION_REQUIRED",
    "decision: the currently pinned governance root approved the exact checkpoint publication and recovery policy, at least two of three distinct witnesses signed the same fresh canonical bytes, and three distinct recovery-custodian public keys are pinned under a two-of-three future replacement policy. This does not prove private-key possession, discover an unseen newer checkpoint, execute root recovery or authorize any device action.",
])
