#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 20:
    raise SystemExit(
        "Usage: verify-m7-governance-root-recovery-event.py "
        "<checkpoint-publication-verification.txt> <publication-recovery-policy.txt> "
        "<previous-checkpoint.txt> <previous-root-manifest.txt> <previous-root-public-key.pem> "
        "<replacement-root-manifest.txt> <replacement-root-public-key.pem> <recovery-event.txt> "
        "<custodian-1-public-key.pem> <custodian-1-signature.bin> "
        "<custodian-2-public-key.pem> <custodian-2-signature.bin> "
        "<custodian-3-public-key.pem> <custodian-3-signature.bin> "
        "<replacement-root-event-signature.bin> <recovered-checkpoint.txt> "
        "<replacement-root-checkpoint-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

PUBLICATION_REPORT = Path(sys.argv[1])
POLICY = Path(sys.argv[2])
PREVIOUS_CHECKPOINT = Path(sys.argv[3])
PREVIOUS_ROOT_MANIFEST = Path(sys.argv[4])
PREVIOUS_ROOT_KEY = Path(sys.argv[5])
REPLACEMENT_ROOT_MANIFEST = Path(sys.argv[6])
REPLACEMENT_ROOT_KEY = Path(sys.argv[7])
RECOVERY_EVENT = Path(sys.argv[8])
CUSTODIAN_KEYS = [Path(sys.argv[9]), Path(sys.argv[11]), Path(sys.argv[13])]
CUSTODIAN_SIGNATURES = [Path(sys.argv[10]), Path(sys.argv[12]), Path(sys.argv[14])]
REPLACEMENT_EVENT_SIGNATURE = Path(sys.argv[15])
RECOVERED_CHECKPOINT = Path(sys.argv[16])
REPLACEMENT_CHECKPOINT_SIGNATURE = Path(sys.argv[17])
VERIFICATION_TEXT = sys.argv[18]
OUT = Path(sys.argv[19])

UPSTREAM_CLASSIFICATION = "M7_CHECKPOINT_PUBLICATION_QUORUM_ROOT_RECOVERY_POLICY_PASS_EXTERNAL_DISTRIBUTION_REQUIRED"
POLICY_SCHEMA = "IZZOS_M7_CHECKPOINT_PUBLICATION_AND_ROOT_RECOVERY_POLICY_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
EVENT_SCHEMA = "IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_EVENT_V1"
CHECKPOINT_SCHEMA = "IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

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

EVENT_FIELDS = [
    "governance-root-recovery-event-schema",
    "recovery-event-id",
    "source-publication-policy-sha256",
    "source-publication-verification-sha256",
    "previous-anti-rollback-checkpoint-sha256",
    "previous-governance-epoch",
    "previous-governance-sequence",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
    "previous-governance-root-key-id",
    "previous-governance-root-public-key-sha256",
    "previous-governance-root-status",
    "replacement-governance-root-key-id",
    "replacement-governance-root-public-key-sha256",
    "replacement-governance-root-manifest-sha256",
    "recovery-mode",
    "recovery-reason",
    "declared-at-utc",
    "effective-at-utc",
    "custodian-signature-policy",
    "replacement-root-possession-proof",
    "recovery-scope",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "wrapper-execution-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
]

CHECKPOINT_FIELDS = [
    "governance-root-recovery-checkpoint-schema",
    "checkpoint-id",
    "recovery-event-sha256",
    "previous-anti-rollback-checkpoint-sha256",
    "minimum-governance-epoch",
    "minimum-governance-sequence",
    "active-governance-root-key-id",
    "active-governance-root-public-key-sha256",
    "active-governance-root-manifest-sha256",
    "previous-governance-root-key-id",
    "previous-governance-root-status",
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
    PUBLICATION_REPORT,
    POLICY,
    PREVIOUS_CHECKPOINT,
    PREVIOUS_ROOT_MANIFEST,
    PREVIOUS_ROOT_KEY,
    REPLACEMENT_ROOT_MANIFEST,
    REPLACEMENT_ROOT_KEY,
    RECOVERY_EVENT,
    *CUSTODIAN_KEYS,
    *CUSTODIAN_SIGNATURES,
    REPLACEMENT_EVENT_SIGNATURE,
    RECOVERED_CHECKPOINT,
    REPLACEMENT_CHECKPOINT_SIGNATURE,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 governance-root recovery input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a recovery input, key or signature")

publication_report = PUBLICATION_REPORT.read_text(errors="replace")
policy = POLICY.read_text(errors="replace")
previous_checkpoint = PREVIOUS_CHECKPOINT.read_text(errors="replace")
previous_root_manifest_bytes = PREVIOUS_ROOT_MANIFEST.read_bytes()
previous_root_manifest = previous_root_manifest_bytes.decode(errors="replace")
replacement_root_manifest_bytes = REPLACEMENT_ROOT_MANIFEST.read_bytes()
replacement_root_manifest = replacement_root_manifest_bytes.decode(errors="replace")
event_bytes = RECOVERY_EVENT.read_bytes()
event = event_bytes.decode(errors="replace")
recovered_checkpoint_bytes = RECOVERED_CHECKPOINT.read_bytes()
recovered_checkpoint = recovered_checkpoint_bytes.decode(errors="replace")

publication_report_hash = sha256(PUBLICATION_REPORT)
policy_hash = sha256(POLICY)
previous_checkpoint_hash = sha256(PREVIOUS_CHECKPOINT)
previous_root_manifest_hash = sha256(PREVIOUS_ROOT_MANIFEST)
previous_root_key_hash = sha256(PREVIOUS_ROOT_KEY)
replacement_root_manifest_hash = sha256(REPLACEMENT_ROOT_MANIFEST)
replacement_root_key_hash = sha256(REPLACEMENT_ROOT_KEY)
event_hash = sha256(RECOVERY_EVENT)
recovered_checkpoint_hash = sha256(RECOVERED_CHECKPOINT)
custodian_key_hashes = [sha256(path) for path in CUSTODIAN_KEYS]

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
previous_root_is_ed25519 = is_ed25519(openssl_path, PREVIOUS_ROOT_KEY)
replacement_root_is_ed25519 = is_ed25519(openssl_path, REPLACEMENT_ROOT_KEY)
custodian_key_types = [is_ed25519(openssl_path, key) for key in CUSTODIAN_KEYS]
custodian_signature_valid = [
    verify_signature(openssl_path, key, RECOVERY_EVENT, signature)
    for key, signature in zip(CUSTODIAN_KEYS, CUSTODIAN_SIGNATURES)
]
replacement_event_signature_valid = verify_signature(
    openssl_path, REPLACEMENT_ROOT_KEY, RECOVERY_EVENT, REPLACEMENT_EVENT_SIGNATURE
)
replacement_checkpoint_signature_valid = verify_signature(
    openssl_path,
    REPLACEMENT_ROOT_KEY,
    RECOVERED_CHECKPOINT,
    REPLACEMENT_CHECKPOINT_SIGNATURE,
)

policy_epoch = decimal_value(policy, "governance-epoch")
policy_sequence = decimal_value(policy, "governance-sequence")
report_epoch = decimal_value(publication_report, "governance-epoch")
report_sequence = decimal_value(publication_report, "governance-sequence")
event_previous_epoch = decimal_value(event, "previous-governance-epoch")
event_previous_sequence = decimal_value(event, "previous-governance-sequence")
event_recovered_epoch = decimal_value(event, "recovered-governance-epoch")
event_recovered_sequence = decimal_value(event, "recovered-governance-sequence")
checkpoint_epoch = decimal_value(recovered_checkpoint, "minimum-governance-epoch")
checkpoint_sequence = decimal_value(recovered_checkpoint, "minimum-governance-sequence")
recovery_threshold = decimal_value(policy, "root-recovery-threshold")
valid_custodian_count = sum(custodian_signature_valid)

policy_custodian_ids = [field(policy, f"recovery-custodian-{index}-id") for index in range(1, 4)]
policy_custodian_pins = [
    field(policy, f"recovery-custodian-{index}-public-key-sha256")
    for index in range(1, 4)
]

previous_root_valid_from = parse_utc(field(previous_root_manifest, "valid-from-utc"))
previous_root_valid_until = parse_utc(field(previous_root_manifest, "valid-until-utc"))
replacement_root_valid_from = parse_utc(field(replacement_root_manifest, "valid-from-utc"))
replacement_root_valid_until = parse_utc(field(replacement_root_manifest, "valid-until-utc"))
publication_verified_at = parse_utc(field(publication_report, "verification-timestamp-utc"))
declared_at = parse_utc(field(event, "declared-at-utc"))
effective_at = parse_utc(field(event, "effective-at-utc"))
checkpoint_updated_at = parse_utc(field(recovered_checkpoint, "checkpoint-updated-at-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
replacement_lifetime = (
    (replacement_root_valid_until - replacement_root_valid_from).total_seconds()
    if replacement_root_valid_until and replacement_root_valid_from
    else None
)

previous_root_id = field(previous_root_manifest, "governance-root-key-id")
replacement_root_id = field(replacement_root_manifest, "governance-root-key-id")

checks = [
    ("upstream-publication-and-recovery-policy-classification-passes", field(publication_report, "classification") == UPSTREAM_CLASSIFICATION),
    ("upstream-report-binds-exact-policy-checkpoint-and-previous-root", equal_hash(field(publication_report, "publication-recovery-policy-sha256"), policy_hash) and equal_hash(field(publication_report, "anti-rollback-checkpoint-sha256"), previous_checkpoint_hash) and equal_hash(field(publication_report, "governance-root-manifest-sha256"), previous_root_manifest_hash) and equal_hash(field(publication_report, "governance-root-public-key-sha256"), previous_root_key_hash)),
    ("upstream-root-and-publication-quorum-states-pass", field(publication_report, "governance-root-policy-signature") == "PASS" and field(publication_report, "publication-quorum-state") == "EXACT_ROOT_APPROVED_POLICY_WITH_2_OF_3_OR_GREATER_WITNESS_SIGNATURES" and field(publication_report, "root-recovery-policy-state") == "PREAUTHORIZED_POLICY_ONLY_NO_RECOVERY_EVENT"),
    ("upstream-report-remains-non-authorizing", field(publication_report, "root-recovery-event-authorized") == "NO" and field(publication_report, "replacement-governance-root-activated") == "NO" and field(publication_report, "wrapper-execution-authorization") == "NO" and field(publication_report, "persistent-writes") == "FORBIDDEN" and field(publication_report, "launch-authorization") == "NO"),
    ("policy-schema-root-and-recovery-mode-are-exact", field(policy, "checkpoint-publication-recovery-policy-schema") == POLICY_SCHEMA and field(policy, "governance-root-key-id") == previous_root_id and equal_hash(field(policy, "governance-root-public-key-sha256"), previous_root_key_hash) and field(policy, "root-recovery-mode") == "PREAUTHORIZED_2_OF_3_CUSTODIAN_ROOT_REPLACEMENT"),
    ("policy-epoch-and-sequence-match-upstream", policy_epoch == report_epoch and policy_sequence == report_sequence and policy_epoch is not None and policy_sequence is not None),
    ("policy-pins-distinct-two-of-three-custodian-keys", recovery_threshold == 2 and field(policy, "recovery-event-requirements") == "NEW_ROOT_MANIFEST_PLUS_2_OF_3_DETACHED_ED25519" and field(policy, "compromise-response") == "REVOKE_PREVIOUS_ROOT_BEFORE_REPLACEMENT_ACTIVATION" and all(identifier and re.fullmatch(TOKEN, identifier) for identifier in policy_custodian_ids) and len(set(policy_custodian_ids)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(policy_custodian_pins, custodian_key_hashes)) and all(custodian_key_types) and len(set(custodian_key_hashes)) == 3),
    ("previous-root-manifest-fields-are-present-once", all(len(values(previous_root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("previous-root-manifest-is-canonical", canonical_bytes(previous_root_manifest, ROOT_FIELDS) == previous_root_manifest_bytes),
    ("previous-root-manifest-and-key-match-policy", field(previous_root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and field(previous_root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(previous_root_manifest, "signature-algorithm") == "ED25519" and field(previous_root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY" and field(previous_root_manifest, "trust-anchor-source") == "REPOSITORY_REVIEWED_SHA256_PIN" and field(previous_root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER" and field(previous_root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(previous_root_manifest, "persistent-writes") == "FORBIDDEN" and field(previous_root_manifest, "slot-changes") == "FORBIDDEN" and field(previous_root_manifest, "payload-launch-authorization") == "NO" and equal_hash(field(previous_root_manifest, "public-key-sha256"), previous_root_key_hash) and previous_root_is_ed25519),
    ("previous-root-was-valid-when-recovery-was-declared", all(value is not None for value in (previous_root_valid_from, previous_root_valid_until, declared_at)) and previous_root_valid_from <= declared_at <= previous_root_valid_until),
    ("replacement-root-manifest-fields-are-present-once", all(len(values(replacement_root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("replacement-root-manifest-is-canonical", canonical_bytes(replacement_root_manifest, ROOT_FIELDS) == replacement_root_manifest_bytes),
    ("replacement-root-schema-role-scope-and-source-are-exact", field(replacement_root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and field(replacement_root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(replacement_root_manifest, "signature-algorithm") == "ED25519" and field(replacement_root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY" and field(replacement_root_manifest, "trust-anchor-source") == "RECOVERY_QUORUM_ACTIVATED_SHA256_PIN" and field(replacement_root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER"),
    ("replacement-root-id-and-key-are-new-exact-and-bounded", bool(re.fullmatch(TOKEN, replacement_root_id or "")) and replacement_root_id != previous_root_id and equal_hash(field(replacement_root_manifest, "public-key-sha256"), replacement_root_key_hash) and replacement_root_is_ed25519 and replacement_root_key_hash not in {previous_root_key_hash, *custodian_key_hashes} and replacement_lifetime is not None and 0 < replacement_lifetime <= 5 * 366 * 24 * 60 * 60),
    ("replacement-root-manifest-is-active-and-non-authorizing", field(replacement_root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(replacement_root_manifest, "persistent-writes") == "FORBIDDEN" and field(replacement_root_manifest, "slot-changes") == "FORBIDDEN" and field(replacement_root_manifest, "payload-launch-authorization") == "NO"),
    ("recovery-event-fields-are-present-once", all(len(values(event, label)) == 1 for label in EVENT_FIELDS)),
    ("recovery-event-is-canonical", canonical_bytes(event, EVENT_FIELDS) == event_bytes),
    ("recovery-event-schema-id-and-source-bindings-are-exact", field(event, "governance-root-recovery-event-schema") == EVENT_SCHEMA and bool(re.fullmatch(TOKEN, field(event, "recovery-event-id") or "")) and equal_hash(field(event, "source-publication-policy-sha256"), policy_hash) and equal_hash(field(event, "source-publication-verification-sha256"), publication_report_hash) and equal_hash(field(event, "previous-anti-rollback-checkpoint-sha256"), previous_checkpoint_hash)),
    ("recovery-event-monotonically-advances-one-epoch", event_previous_epoch == policy_epoch == report_epoch and event_previous_sequence == policy_sequence == report_sequence and event_recovered_epoch is not None and event_previous_epoch is not None and event_recovered_epoch == event_previous_epoch + 1 and event_recovered_sequence == 1),
    ("recovery-event-revokes-exact-previous-root", field(event, "previous-governance-root-key-id") == previous_root_id and equal_hash(field(event, "previous-governance-root-public-key-sha256"), previous_root_key_hash) and field(event, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY"),
    ("recovery-event-activates-exact-replacement-root", field(event, "replacement-governance-root-key-id") == replacement_root_id and equal_hash(field(event, "replacement-governance-root-public-key-sha256"), replacement_root_key_hash) and equal_hash(field(event, "replacement-governance-root-manifest-sha256"), replacement_root_manifest_hash)),
    ("recovery-event-mode-reason-scope-and-policies-are-exact", field(event, "recovery-mode") == "TWO_OF_THREE_CUSTODIAN_ROOT_REPLACEMENT" and field(event, "recovery-reason") in {"ROOT_KEY_COMPROMISE", "ROOT_KEY_LOSS", "ROOT_CUSTODY_FAILURE"} and field(event, "custodian-signature-policy") == "REQUIRED_2_OF_3_DETACHED_ED25519" and field(event, "replacement-root-possession-proof") == "REQUIRED_DETACHED_ED25519" and field(event, "recovery-scope") == "M7_GOVERNANCE_ROOT_REPLACEMENT_ONLY"),
    ("recovery-event-custodian-quorum-passes", valid_custodian_count >= 2),
    ("replacement-root-possession-signature-passes", REPLACEMENT_EVENT_SIGNATURE.stat().st_size == 64 and replacement_event_signature_valid),
    ("recovery-event-forbids-write-slot-wrapper-promotion-container-and-launch", field(event, "persistent-writes") == "FORBIDDEN" and field(event, "slot-changes") == "FORBIDDEN" and field(event, "payload-launch-authorization") == "NO" and field(event, "wrapper-execution-authorization") == "NO" and field(event, "dsc-fdf-promotion-authorization") == "NO" and field(event, "container-build-authorization") == "NO"),
    ("recovered-checkpoint-fields-are-present-once", all(len(values(recovered_checkpoint, label)) == 1 for label in CHECKPOINT_FIELDS)),
    ("recovered-checkpoint-is-canonical", canonical_bytes(recovered_checkpoint, CHECKPOINT_FIELDS) == recovered_checkpoint_bytes),
    ("recovered-checkpoint-schema-id-and-event-bindings-are-exact", field(recovered_checkpoint, "governance-root-recovery-checkpoint-schema") == CHECKPOINT_SCHEMA and bool(re.fullmatch(TOKEN, field(recovered_checkpoint, "checkpoint-id") or "")) and equal_hash(field(recovered_checkpoint, "recovery-event-sha256"), event_hash) and equal_hash(field(recovered_checkpoint, "previous-anti-rollback-checkpoint-sha256"), previous_checkpoint_hash)),
    ("recovered-checkpoint-pins-new-epoch-root-and-revoked-old-root", checkpoint_epoch == event_recovered_epoch and checkpoint_sequence == event_recovered_sequence and field(recovered_checkpoint, "active-governance-root-key-id") == replacement_root_id and equal_hash(field(recovered_checkpoint, "active-governance-root-public-key-sha256"), replacement_root_key_hash) and equal_hash(field(recovered_checkpoint, "active-governance-root-manifest-sha256"), replacement_root_manifest_hash) and field(recovered_checkpoint, "previous-governance-root-key-id") == previous_root_id and field(recovered_checkpoint, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY"),
    ("recovered-checkpoint-source-policy-and-signature-pass", field(recovered_checkpoint, "checkpoint-source") == "RECOVERY_QUORUM_AND_REPLACEMENT_ROOT_SIGNED_PIN" and field(recovered_checkpoint, "rollback-policy") == "REJECT_PRE_RECOVERY_ROOT_AND_LOWER_EPOCH" and REPLACEMENT_CHECKPOINT_SIGNATURE.stat().st_size == 64 and replacement_checkpoint_signature_valid),
    ("recovered-checkpoint-denies-write-slot-and-launch", field(recovered_checkpoint, "persistent-writes") == "FORBIDDEN" and field(recovered_checkpoint, "slot-changes") == "FORBIDDEN" and field(recovered_checkpoint, "payload-launch-authorization") == "NO"),
    ("recovery-times-are-ordered-and-replacement-root-is-current", all(value is not None for value in (publication_verified_at, declared_at, effective_at, checkpoint_updated_at, verification_time, replacement_root_valid_from, replacement_root_valid_until)) and publication_verified_at <= declared_at <= effective_at <= checkpoint_updated_at <= verification_time and replacement_root_valid_from <= declared_at <= verification_time <= replacement_root_valid_until),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 governance-root recovery event gate",
    "Verifier mode: HOST_SIDE_2_OF_3_CUSTODIAN_RECOVERY_AND_REPLACEMENT_ROOT_PROOF_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"checkpoint-publication-verification-sha256: {publication_report_hash}",
    f"source-publication-policy-sha256: {policy_hash}",
    f"previous-anti-rollback-checkpoint-sha256: {previous_checkpoint_hash}",
    f"previous-governance-root-manifest-sha256: {previous_root_manifest_hash}",
    f"previous-governance-root-public-key-sha256: {previous_root_key_hash}",
    f"replacement-governance-root-manifest-sha256: {replacement_root_manifest_hash}",
    f"replacement-governance-root-public-key-sha256: {replacement_root_key_hash}",
    f"governance-root-recovery-event-sha256: {event_hash}",
    f"recovered-checkpoint-sha256: {recovered_checkpoint_hash}",
    f"previous-governance-epoch: {event_previous_epoch if event_previous_epoch is not None else 'MISSING'}",
    f"previous-governance-sequence: {event_previous_sequence if event_previous_sequence is not None else 'MISSING'}",
    f"recovered-governance-epoch: {event_recovered_epoch if event_recovered_epoch is not None else 'MISSING'}",
    f"recovered-governance-sequence: {event_recovered_sequence if event_recovered_sequence is not None else 'MISSING'}",
    f"custodian-signatures-valid: {valid_custodian_count}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"custodian-1-signature: {'PASS' if custodian_signature_valid[0] else 'FAIL'}",
    f"custodian-2-signature: {'PASS' if custodian_signature_valid[1] else 'FAIL'}",
    f"custodian-3-signature: {'PASS' if custodian_signature_valid[2] else 'FAIL'}",
    f"replacement-root-event-possession-signature: {'PASS' if replacement_event_signature_valid else 'FAIL'}",
    f"replacement-root-checkpoint-signature: {'PASS' if replacement_checkpoint_signature_valid else 'FAIL'}",
    "previous-governance-root-state: REVOKED" if field(event, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY" else "previous-governance-root-state: NOT_VERIFIED",
    "replacement-governance-root-state: CRYPTOGRAPHICALLY_BOUND_PENDING_REPUBLICATION" if not failed else "replacement-governance-root-state: NOT_VERIFIED",
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
        "classification: M7_GOVERNANCE_ROOT_RECOVERY_EVENT_BLOCKED",
        "decision: the prior policy/checkpoint binding, old-root revocation, monotonic epoch transition, two-of-three custodian quorum, replacement-root possession proof, recovered checkpoint or no-write/no-launch policy failed. Reject the replacement root and do not authorize a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: RECOVERED_CHECKPOINT_REPUBLICATION_AND_FRESH_WITNESS_QUORUM_REQUIRED",
    "remaining-blocker: RECOVERY_CUSTODIAN_AND_REPLACEMENT_ROOT_CUSTODY_REMAINS_EXTERNAL",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_GOVERNANCE_ROOT_RECOVERY_EVENT_PASS_REPUBLICATION_REQUIRED",
    "decision: the supplied prior recovery policy authorized the exact three custodian keys, at least two signed the canonical recovery event, the previous root is revoked, the replacement root proved possession, and its signed checkpoint advances exactly one governance epoch. The recovered checkpoint must still be independently republished before it can replace distributed trust state; no device action is authorized.",
])
