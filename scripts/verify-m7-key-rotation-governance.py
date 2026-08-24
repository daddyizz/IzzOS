#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 14:
    raise SystemExit(
        "Usage: verify-m7-key-rotation-governance.py "
        "<authority-attestation-report.txt> <active-key-manifest.txt> "
        "<active-public-key.pem> <previous-public-key.pem> <previous-governance-state> "
        "<governance-root-manifest.txt> <governance-root-public-key.pem> "
        "<key-rotation-record.txt> <previous-key-signature.bin> "
        "<governance-root-signature.bin> <anti-rollback-checkpoint.txt> "
        "<verification-timestamp-utc> <output.txt>"
    )

ATTESTATION = Path(sys.argv[1])
ACTIVE_MANIFEST = Path(sys.argv[2])
ACTIVE_KEY = Path(sys.argv[3])
PREVIOUS_KEY = Path(sys.argv[4])
PREVIOUS_STATE = Path(sys.argv[5])
ROOT_MANIFEST = Path(sys.argv[6])
ROOT_KEY = Path(sys.argv[7])
ROTATION = Path(sys.argv[8])
PREVIOUS_SIGNATURE = Path(sys.argv[9])
ROOT_SIGNATURE = Path(sys.argv[10])
CHECKPOINT = Path(sys.argv[11])
VERIFICATION_TEXT = sys.argv[12]
OUT = Path(sys.argv[13])

ACTIVE_SCHEMA = "IZZOS_M7_TRUSTED_AUTHORITY_KEY_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
ROTATION_SCHEMA = "IZZOS_M7_AUTHORITY_KEY_ROTATION_RECORD_V1"
CHECKPOINT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1"
ATTESTATION_SCOPE = "M7_BOUND_TOKEN_CONSUMPTION_AND_WRAPPER_EVIDENCE_RESULT_ONLY"
GOVERNANCE_SCOPE = "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY"
SCHEDULED_MODE = "DUAL_CONTROL_SCHEDULED_HANDOVER"
EMERGENCY_MODE = "ROOT_AUTHORIZED_COMPROMISE_REVOCATION"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

ACTIVE_FIELDS = [
    "trusted-authority-key-schema",
    "authority-key-id",
    "authority-role",
    "signature-algorithm",
    "public-key-sha256",
    "valid-from-utc",
    "valid-until-utc",
    "key-revocation-status",
    "trust-anchor-source",
    "attestation-scope",
    "key-custody",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
]

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

ROTATION_FIELDS = [
    "key-rotation-record-schema",
    "governance-root-key-id",
    "governance-epoch",
    "governance-sequence",
    "previous-governance-state-sha256",
    "previous-authority-key-id",
    "previous-authority-public-key-sha256",
    "previous-authority-key-status",
    "active-authority-key-id",
    "active-authority-public-key-sha256",
    "active-authority-key-manifest-sha256",
    "rotation-mode",
    "rotation-reason",
    "issued-at-utc",
    "effective-at-utc",
    "previous-key-handover-signature-policy",
    "governance-root-approval-signature-policy",
    "rotation-scope",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
]

CHECKPOINT_FIELDS = [
    "anti-rollback-checkpoint-schema",
    "checkpoint-id",
    "minimum-accepted-governance-epoch",
    "minimum-accepted-governance-sequence",
    "latest-key-rotation-record-sha256",
    "previous-governance-state-sha256",
    "active-authority-key-id",
    "active-authority-public-key-sha256",
    "governance-root-key-id",
    "checkpoint-updated-at-utc",
    "checkpoint-source",
    "rollback-policy",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
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
    detail = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, detail


def verify_signature(executable, key, record, signature):
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


def is_ed25519(executable, key):
    passed, detail = openssl_run(
        executable,
        ["pkey", "-pubin", "-in", str(key), "-text_pub", "-noout"],
    )
    return passed and "ED25519" in detail.upper()


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [
    ATTESTATION,
    ACTIVE_MANIFEST,
    ACTIVE_KEY,
    PREVIOUS_KEY,
    PREVIOUS_STATE,
    ROOT_MANIFEST,
    ROOT_KEY,
    ROTATION,
    PREVIOUS_SIGNATURE,
    ROOT_SIGNATURE,
    CHECKPOINT,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 key-governance input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a governance input, key or signature")

attestation = ATTESTATION.read_text(errors="replace")
active_manifest_bytes = ACTIVE_MANIFEST.read_bytes()
active_manifest = active_manifest_bytes.decode(errors="replace")
root_manifest_bytes = ROOT_MANIFEST.read_bytes()
root_manifest = root_manifest_bytes.decode(errors="replace")
rotation_bytes = ROTATION.read_bytes()
rotation = rotation_bytes.decode(errors="replace")
checkpoint_bytes = CHECKPOINT.read_bytes()
checkpoint = checkpoint_bytes.decode(errors="replace")

attestation_hash = sha256(ATTESTATION)
active_manifest_hash = sha256(ACTIVE_MANIFEST)
active_key_hash = sha256(ACTIVE_KEY)
previous_key_hash = sha256(PREVIOUS_KEY)
previous_state_hash = sha256(PREVIOUS_STATE)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
rotation_hash = sha256(ROTATION)
previous_signature_hash = sha256(PREVIOUS_SIGNATURE)
root_signature_hash = sha256(ROOT_SIGNATURE)
checkpoint_hash = sha256(CHECKPOINT)

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
active_key_is_ed25519 = is_ed25519(openssl_path, ACTIVE_KEY)
previous_key_is_ed25519 = is_ed25519(openssl_path, PREVIOUS_KEY)
root_key_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
previous_signature_valid = verify_signature(openssl_path, PREVIOUS_KEY, ROTATION, PREVIOUS_SIGNATURE)
root_signature_valid = verify_signature(openssl_path, ROOT_KEY, ROTATION, ROOT_SIGNATURE)

mode = field(rotation, "rotation-mode")
reason = field(rotation, "rotation-reason")
previous_signature_size = PREVIOUS_SIGNATURE.stat().st_size
root_signature_size = ROOT_SIGNATURE.stat().st_size
scheduled_handover = (
    mode == SCHEDULED_MODE
    and reason in {"SCHEDULED_KEY_ROTATION", "CUSTODY_TRANSFER"}
    and field(rotation, "previous-key-handover-signature-policy") == "REQUIRED_DETACHED_ED25519"
    and previous_signature_size == 64
    and previous_signature_valid
)
emergency_revocation = (
    mode == EMERGENCY_MODE
    and reason == "COMPROMISE_RECOVERY"
    and field(rotation, "previous-key-handover-signature-policy") == "FORBIDDEN_COMPROMISED_KEY"
    and previous_signature_size == 0
)
previous_signature_policy_pass = scheduled_handover or emergency_revocation

active_valid_from = parse_utc(field(active_manifest, "valid-from-utc"))
active_valid_until = parse_utc(field(active_manifest, "valid-until-utc"))
root_valid_from = parse_utc(field(root_manifest, "valid-from-utc"))
root_valid_until = parse_utc(field(root_manifest, "valid-until-utc"))
issued_at = parse_utc(field(rotation, "issued-at-utc"))
effective_at = parse_utc(field(rotation, "effective-at-utc"))
attested_at = parse_utc(field(attestation, "attested-at-utc"))
checkpoint_updated_at = parse_utc(field(checkpoint, "checkpoint-updated-at-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)

active_lifetime = (active_valid_until - active_valid_from).total_seconds() if active_valid_from and active_valid_until else None
root_lifetime = (root_valid_until - root_valid_from).total_seconds() if root_valid_from and root_valid_until else None
epoch = decimal_value(rotation, "governance-epoch")
sequence = decimal_value(rotation, "governance-sequence")
checkpoint_epoch = decimal_value(checkpoint, "minimum-accepted-governance-epoch")
checkpoint_sequence = decimal_value(checkpoint, "minimum-accepted-governance-sequence")

checks = [
    ("upstream-authority-attestation-classification-passes", field(attestation, "classification") == "M7_AUTHORITY_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED"),
    ("upstream-attestation-is-verified-to-pinned-key", field(attestation, "signature-verification") == "PASS" and field(attestation, "attestation-endorsement") == "CRYPTOGRAPHICALLY_VERIFIED_TO_REPOSITORY_PINNED_KEY"),
    ("upstream-attestation-remains-non-authorizing", field(attestation, "wrapper-execution-authorization") == "NO" and field(attestation, "launch-authorization") == "NO"),
    ("active-key-fields-are-present-once", all(len(values(active_manifest, label)) == 1 for label in ACTIVE_FIELDS)),
    ("active-key-manifest-is-canonical", canonical_bytes(active_manifest, ACTIVE_FIELDS) == active_manifest_bytes),
    ("active-key-schema-role-and-scope-are-exact", field(active_manifest, "trusted-authority-key-schema") == ACTIVE_SCHEMA and field(active_manifest, "authority-role") == "M7_INDEPENDENT_CAPTURE_AND_EXECUTION_ATTESTER" and field(active_manifest, "signature-algorithm") == "ED25519" and field(active_manifest, "attestation-scope") == ATTESTATION_SCOPE),
    ("active-key-id-and-public-key-pin-are-exact", bool(re.fullmatch(TOKEN, field(active_manifest, "authority-key-id") or "")) and equal_hash(field(active_manifest, "public-key-sha256"), active_key_hash) and active_key_is_ed25519),
    ("active-key-is-current-and-bounded", field(active_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and active_lifetime is not None and 0 < active_lifetime <= 366 * 24 * 60 * 60),
    ("active-key-manifest-denies-write-slot-and-launch", field(active_manifest, "persistent-writes") == "FORBIDDEN" and field(active_manifest, "slot-changes") == "FORBIDDEN" and field(active_manifest, "payload-launch-authorization") == "NO"),
    ("governance-root-fields-are-present-once", all(len(values(root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("governance-root-manifest-is-canonical", canonical_bytes(root_manifest, ROOT_FIELDS) == root_manifest_bytes),
    ("governance-root-schema-role-and-scope-are-exact", field(root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and field(root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(root_manifest, "signature-algorithm") == "ED25519" and field(root_manifest, "governance-scope") == GOVERNANCE_SCOPE),
    ("governance-root-id-and-public-key-pin-are-exact", bool(re.fullmatch(TOKEN, field(root_manifest, "governance-root-key-id") or "")) and equal_hash(field(root_manifest, "public-key-sha256"), root_key_hash) and root_key_is_ed25519),
    ("governance-root-is-current-and-bounded", field(root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and root_lifetime is not None and 0 < root_lifetime <= 5 * 366 * 24 * 60 * 60),
    ("governance-root-source-and-custody-are-explicit", field(root_manifest, "trust-anchor-source") == "REPOSITORY_REVIEWED_SHA256_PIN" and field(root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER"),
    ("governance-root-manifest-denies-write-slot-and-launch", field(root_manifest, "persistent-writes") == "FORBIDDEN" and field(root_manifest, "slot-changes") == "FORBIDDEN" and field(root_manifest, "payload-launch-authorization") == "NO"),
    ("rotation-record-fields-are-present-once", all(len(values(rotation, label)) == 1 for label in ROTATION_FIELDS)),
    ("rotation-record-is-canonical", canonical_bytes(rotation, ROTATION_FIELDS) == rotation_bytes),
    ("rotation-record-schema-root-and-scope-are-exact", field(rotation, "key-rotation-record-schema") == ROTATION_SCHEMA and field(rotation, "governance-root-key-id") == field(root_manifest, "governance-root-key-id") and field(rotation, "rotation-scope") == GOVERNANCE_SCOPE),
    ("rotation-epoch-and-sequence-are-positive", epoch is not None and sequence is not None and epoch > 0 and sequence > 0),
    ("rotation-binds-exact-nonempty-previous-state", PREVIOUS_STATE.stat().st_size > 0 and equal_hash(field(rotation, "previous-governance-state-sha256"), previous_state_hash)),
    ("rotation-revokes-exact-distinct-previous-key", bool(re.fullmatch(TOKEN, field(rotation, "previous-authority-key-id") or "")) and equal_hash(field(rotation, "previous-authority-public-key-sha256"), previous_key_hash) and field(rotation, "previous-authority-key-status") == "REVOKED_EFFECTIVE_AT_ROTATION" and previous_key_is_ed25519 and previous_key_hash not in {active_key_hash, root_key_hash}),
    ("rotation-activates-exact-manifest-and-key", field(rotation, "active-authority-key-id") == field(active_manifest, "authority-key-id") and equal_hash(field(rotation, "active-authority-public-key-sha256"), active_key_hash) and equal_hash(field(rotation, "active-authority-key-manifest-sha256"), active_manifest_hash)),
    ("rotation-previous-key-signature-policy-passes", previous_signature_policy_pass),
    ("rotation-root-signature-policy-and-signature-pass", field(rotation, "governance-root-approval-signature-policy") == "REQUIRED_DETACHED_ED25519" and root_signature_size == 64 and root_signature_valid),
    ("rotation-forbids-write-slot-promotion-container-and-launch", field(rotation, "persistent-writes") == "FORBIDDEN" and field(rotation, "slot-changes") == "FORBIDDEN" and field(rotation, "payload-launch-authorization") == "NO" and field(rotation, "dsc-fdf-promotion-authorization") == "NO" and field(rotation, "container-build-authorization") == "NO"),
    ("checkpoint-fields-are-present-once", all(len(values(checkpoint, label)) == 1 for label in CHECKPOINT_FIELDS)),
    ("checkpoint-is-canonical", canonical_bytes(checkpoint, CHECKPOINT_FIELDS) == checkpoint_bytes),
    ("checkpoint-schema-source-and-policy-are-exact", field(checkpoint, "anti-rollback-checkpoint-schema") == CHECKPOINT_SCHEMA and bool(re.fullmatch(TOKEN, field(checkpoint, "checkpoint-id") or "")) and field(checkpoint, "checkpoint-source") == "REPOSITORY_REVIEWED_MONOTONIC_PIN" and field(checkpoint, "rollback-policy") == "REJECT_ANY_NONMATCHING_OR_LOWER_STATE"),
    ("checkpoint-pins-exact-latest-rotation", equal_hash(field(checkpoint, "latest-key-rotation-record-sha256"), rotation_hash) and equal_hash(field(checkpoint, "previous-governance-state-sha256"), field(rotation, "previous-governance-state-sha256"))),
    ("checkpoint-minimum-epoch-and-sequence-match-rotation", checkpoint_epoch == epoch and checkpoint_sequence == sequence and epoch is not None and sequence is not None),
    ("checkpoint-pins-active-key-and-root", field(checkpoint, "active-authority-key-id") == field(active_manifest, "authority-key-id") and equal_hash(field(checkpoint, "active-authority-public-key-sha256"), active_key_hash) and field(checkpoint, "governance-root-key-id") == field(root_manifest, "governance-root-key-id")),
    ("checkpoint-denies-write-slot-and-launch", field(checkpoint, "persistent-writes") == "FORBIDDEN" and field(checkpoint, "slot-changes") == "FORBIDDEN" and field(checkpoint, "payload-launch-authorization") == "NO"),
    ("attestation-is-bound-to-active-key-and-manifest", field(attestation, "authority-key-id") == field(active_manifest, "authority-key-id") and equal_hash(field(attestation, "authority-public-key-sha256"), active_key_hash) and equal_hash(field(attestation, "trusted-key-manifest-sha256"), active_manifest_hash)),
    ("governance-times-are-ordered", all(value is not None for value in (issued_at, effective_at, attested_at, checkpoint_updated_at, verification_time)) and issued_at <= effective_at <= attested_at <= checkpoint_updated_at <= verification_time),
    ("active-key-is-valid-for-attestation-and-verification", all(value is not None for value in (active_valid_from, active_valid_until, attested_at, verification_time)) and active_valid_from <= attested_at <= verification_time <= active_valid_until),
    ("root-key-is-valid-for-rotation-and-verification", all(value is not None for value in (root_valid_from, root_valid_until, issued_at, verification_time)) and root_valid_from <= issued_at <= verification_time <= root_valid_until),
]

failed = [name for name, passed in checks if not passed]
previous_signature_state = (
    "VERIFIED_DUAL_CONTROL_HANDOVER"
    if scheduled_handover
    else "WAIVED_BY_ROOT_COMPROMISE_REVOCATION"
    if emergency_revocation
    else "INVALID"
)
revoked_previous_key_state = (
    "DUAL_SIGNED_SCHEDULED_HANDOVER"
    if scheduled_handover and root_signature_valid
    else "ROOT_SIGNED_COMPROMISE_REVOCATION"
    if emergency_revocation and root_signature_valid
    else "NOT_VERIFIED"
)
checkpoint_exact_match = (
    canonical_bytes(checkpoint, CHECKPOINT_FIELDS) == checkpoint_bytes
    and equal_hash(field(checkpoint, "latest-key-rotation-record-sha256"), rotation_hash)
    and checkpoint_epoch == epoch
    and checkpoint_sequence == sequence
    and field(checkpoint, "active-authority-key-id") == field(active_manifest, "authority-key-id")
    and equal_hash(field(checkpoint, "active-authority-public-key-sha256"), active_key_hash)
    and field(checkpoint, "governance-root-key-id") == field(root_manifest, "governance-root-key-id")
)
lines = [
    "IzzOS Milestone 7 authority-key revocation, rotation and anti-rollback governance gate",
    "Verifier mode: HOST_SIDE_DUAL_SIGNATURE_ROTATION_AND_EXACT_CHECKPOINT_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"authority-attestation-report-sha256: {attestation_hash}",
    f"active-key-manifest-sha256: {active_manifest_hash}",
    f"active-authority-public-key-sha256: {active_key_hash}",
    f"previous-authority-public-key-sha256: {previous_key_hash}",
    f"previous-governance-state-sha256: {previous_state_hash}",
    f"governance-root-manifest-sha256: {root_manifest_hash}",
    f"governance-root-public-key-sha256: {root_key_hash}",
    f"key-rotation-record-sha256: {rotation_hash}",
    f"previous-key-signature-sha256: {previous_signature_hash}",
    f"governance-root-signature-sha256: {root_signature_hash}",
    f"anti-rollback-checkpoint-sha256: {checkpoint_hash}",
    f"governance-epoch: {epoch if epoch is not None else 'MISSING'}",
    f"governance-sequence: {sequence if sequence is not None else 'MISSING'}",
    f"rotation-mode: {mode or 'MISSING'}",
    f"previous-key-signature-state: {previous_signature_state}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"revoked-previous-key-state: {revoked_previous_key_state}",
    "anti-rollback-state: EXACT_SUPPLIED_REPOSITORY_CHECKPOINT_MATCH" if checkpoint_exact_match else "anti-rollback-state: NOT_VERIFIED",
    "attestation-active-key-binding: PASS" if field(attestation, "authority-key-id") == field(active_manifest, "authority-key-id") and equal_hash(field(attestation, "authority-public-key-sha256"), active_key_hash) else "attestation-active-key-binding: FAIL",
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
        "classification: M7_KEY_ROTATION_GOVERNANCE_BLOCKED",
        "decision: the active/root key pins, rotation signatures, revoked previous key, monotonic epoch/sequence checkpoint, attestation binding, validity times or no-write/no-launch policy failed. Reject the key state and do not authorize a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: REPOSITORY_CHECKPOINT_FRESHNESS_AND_DISTRIBUTION_NOT_PROVEN_BY_VERIFIER",
    "remaining-blocker: GOVERNANCE_ROOT_CUSTODY_AND_RECOVERY_PROCEDURE_EXTERNAL",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED",
    "decision: the exact active attestation key is linked to the signed rotation, the previous key is revoked by either dual-control handover or root-authorized compromise recovery, and the supplied repository checkpoint pins the exact epoch, sequence and record bytes. This host-only result cannot prove that no newer checkpoint exists or govern offline root custody, and it does not authorize execution, promotion, container construction or launch.",
])
