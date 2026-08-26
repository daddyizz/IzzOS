#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 16:
    raise SystemExit(
        "Usage: verify-m7-recovered-checkpoint-republication.py "
        "<root-recovery-verification.txt> <recovery-event.txt> <recovered-checkpoint.txt> "
        "<replacement-root-manifest.txt> <replacement-root-public-key.pem> "
        "<republication-record.txt> "
        "<witness-1-public-key.pem> <witness-1-signature.bin> "
        "<witness-2-public-key.pem> <witness-2-signature.bin> "
        "<witness-3-public-key.pem> <witness-3-signature.bin> "
        "<replacement-root-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

RECOVERY_REPORT = Path(sys.argv[1])
RECOVERY_EVENT = Path(sys.argv[2])
RECOVERED_CHECKPOINT = Path(sys.argv[3])
ROOT_MANIFEST = Path(sys.argv[4])
ROOT_KEY = Path(sys.argv[5])
REPUBLICATION = Path(sys.argv[6])
WITNESS_KEYS = [Path(sys.argv[7]), Path(sys.argv[9]), Path(sys.argv[11])]
WITNESS_SIGNATURES = [Path(sys.argv[8]), Path(sys.argv[10]), Path(sys.argv[12])]
ROOT_SIGNATURE = Path(sys.argv[13])
VERIFICATION_TEXT = sys.argv[14]
OUT = Path(sys.argv[15])

UPSTREAM_CLASSIFICATION = "M7_GOVERNANCE_ROOT_RECOVERY_EVENT_PASS_REPUBLICATION_REQUIRED"
EVENT_SCHEMA = "IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_EVENT_V1"
CHECKPOINT_SCHEMA = "IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
REPUBLICATION_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_REPUBLICATION_V1"
MAX_PUBLICATION_WINDOW_SECONDS = 15 * 60
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

REPUBLICATION_FIELDS = [
    "recovered-checkpoint-republication-schema",
    "republication-id",
    "root-recovery-verification-sha256",
    "governance-root-recovery-event-sha256",
    "recovered-checkpoint-sha256",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
    "active-governance-root-key-id",
    "active-governance-root-public-key-sha256",
    "active-governance-root-manifest-sha256",
    "previous-governance-root-status",
    "republication-issued-at-utc",
    "republication-published-at-utc",
    "republication-valid-until-utc",
    "republication-window-max-seconds",
    "republication-source",
    "signature-algorithm",
    "witness-quorum-threshold",
    "republication-witness-1-id",
    "republication-witness-1-public-key-sha256",
    "republication-witness-2-id",
    "republication-witness-2-public-key-sha256",
    "republication-witness-3-id",
    "republication-witness-3-public-key-sha256",
    "replacement-root-approval-policy",
    "continuity-policy",
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
    RECOVERY_REPORT,
    RECOVERY_EVENT,
    RECOVERED_CHECKPOINT,
    ROOT_MANIFEST,
    ROOT_KEY,
    REPUBLICATION,
    *WITNESS_KEYS,
    *WITNESS_SIGNATURES,
    ROOT_SIGNATURE,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 recovered-checkpoint republication input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a republication input, key or signature")

recovery_report = RECOVERY_REPORT.read_text(errors="replace")
event = RECOVERY_EVENT.read_text(errors="replace")
checkpoint = RECOVERED_CHECKPOINT.read_text(errors="replace")
root_manifest_bytes = ROOT_MANIFEST.read_bytes()
root_manifest = root_manifest_bytes.decode(errors="replace")
republication_bytes = REPUBLICATION.read_bytes()
republication = republication_bytes.decode(errors="replace")

recovery_report_hash = sha256(RECOVERY_REPORT)
event_hash = sha256(RECOVERY_EVENT)
checkpoint_hash = sha256(RECOVERED_CHECKPOINT)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
republication_hash = sha256(REPUBLICATION)
witness_key_hashes = [sha256(path) for path in WITNESS_KEYS]

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
root_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
witness_key_types = [is_ed25519(openssl_path, key) for key in WITNESS_KEYS]
root_signature_valid = verify_signature(openssl_path, ROOT_KEY, REPUBLICATION, ROOT_SIGNATURE)
witness_signature_valid = [
    verify_signature(openssl_path, key, REPUBLICATION, signature)
    for key, signature in zip(WITNESS_KEYS, WITNESS_SIGNATURES)
]

report_epoch = decimal_value(recovery_report, "recovered-governance-epoch")
report_sequence = decimal_value(recovery_report, "recovered-governance-sequence")
event_epoch = decimal_value(event, "recovered-governance-epoch")
event_sequence = decimal_value(event, "recovered-governance-sequence")
checkpoint_epoch = decimal_value(checkpoint, "minimum-governance-epoch")
checkpoint_sequence = decimal_value(checkpoint, "minimum-governance-sequence")
republication_epoch = decimal_value(republication, "recovered-governance-epoch")
republication_sequence = decimal_value(republication, "recovered-governance-sequence")
quorum_threshold = decimal_value(republication, "witness-quorum-threshold")
window_limit = decimal_value(republication, "republication-window-max-seconds")
valid_witness_count = sum(witness_signature_valid)

witness_ids = [field(republication, f"republication-witness-{index}-id") for index in range(1, 4)]
witness_pins = [
    field(republication, f"republication-witness-{index}-public-key-sha256")
    for index in range(1, 4)
]

root_valid_from = parse_utc(field(root_manifest, "valid-from-utc"))
root_valid_until = parse_utc(field(root_manifest, "valid-until-utc"))
checkpoint_updated_at = parse_utc(field(checkpoint, "checkpoint-updated-at-utc"))
recovery_verified_at = parse_utc(field(recovery_report, "verification-timestamp-utc"))
issued_at = parse_utc(field(republication, "republication-issued-at-utc"))
published_at = parse_utc(field(republication, "republication-published-at-utc"))
valid_until = parse_utc(field(republication, "republication-valid-until-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
recovery_to_publication = (
    (published_at - recovery_verified_at).total_seconds()
    if published_at and recovery_verified_at
    else None
)
record_lifetime = (
    (valid_until - issued_at).total_seconds()
    if valid_until and issued_at
    else None
)

root_id = field(root_manifest, "governance-root-key-id")

checks = [
    ("upstream-root-recovery-event-classification-passes", field(recovery_report, "classification") == UPSTREAM_CLASSIFICATION),
    ("upstream-report-binds-exact-event-checkpoint-manifest-and-root-key", equal_hash(field(recovery_report, "governance-root-recovery-event-sha256"), event_hash) and equal_hash(field(recovery_report, "recovered-checkpoint-sha256"), checkpoint_hash) and equal_hash(field(recovery_report, "replacement-governance-root-manifest-sha256"), root_manifest_hash) and equal_hash(field(recovery_report, "replacement-governance-root-public-key-sha256"), root_key_hash)),
    ("upstream-recovery-states-pass-and-remain-non-authorizing", field(recovery_report, "previous-governance-root-state") == "REVOKED" and field(recovery_report, "replacement-governance-root-state") == "CRYPTOGRAPHICALLY_BOUND_PENDING_REPUBLICATION" and field(recovery_report, "wrapper-execution-authorization") == "NO" and field(recovery_report, "persistent-writes") == "FORBIDDEN" and field(recovery_report, "launch-authorization") == "NO"),
    ("recovery-event-schema-root-revocation-and-replacement-bindings-are-exact", field(event, "governance-root-recovery-event-schema") == EVENT_SCHEMA and field(event, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY" and field(event, "replacement-governance-root-key-id") == root_id and equal_hash(field(event, "replacement-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(event, "replacement-governance-root-manifest-sha256"), root_manifest_hash)),
    ("recovered-checkpoint-schema-event-root-and-revocation-bindings-are-exact", field(checkpoint, "governance-root-recovery-checkpoint-schema") == CHECKPOINT_SCHEMA and equal_hash(field(checkpoint, "recovery-event-sha256"), event_hash) and field(checkpoint, "active-governance-root-key-id") == root_id and equal_hash(field(checkpoint, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(checkpoint, "active-governance-root-manifest-sha256"), root_manifest_hash) and field(checkpoint, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY"),
    ("all-recovery-epoch-and-sequence-bindings-match", report_epoch == event_epoch == checkpoint_epoch == republication_epoch and report_sequence == event_sequence == checkpoint_sequence == republication_sequence and report_epoch is not None and report_sequence is not None and report_epoch > 0 and report_sequence > 0),
    ("recovered-checkpoint-remains-non-authorizing", field(checkpoint, "persistent-writes") == "FORBIDDEN" and field(checkpoint, "slot-changes") == "FORBIDDEN" and field(checkpoint, "payload-launch-authorization") == "NO"),
    ("replacement-root-manifest-fields-are-present-once", all(len(values(root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("replacement-root-manifest-is-canonical", canonical_bytes(root_manifest, ROOT_FIELDS) == root_manifest_bytes),
    ("replacement-root-manifest-key-role-scope-source-and-state-are-exact", field(root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and bool(re.fullmatch(TOKEN, root_id or "")) and field(root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(root_manifest, "signature-algorithm") == "ED25519" and equal_hash(field(root_manifest, "public-key-sha256"), root_key_hash) and root_is_ed25519 and field(root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_manifest, "trust-anchor-source") == "RECOVERY_QUORUM_ACTIVATED_SHA256_PIN" and field(root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY" and field(root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER"),
    ("replacement-root-manifest-remains-non-authorizing", field(root_manifest, "persistent-writes") == "FORBIDDEN" and field(root_manifest, "slot-changes") == "FORBIDDEN" and field(root_manifest, "payload-launch-authorization") == "NO"),
    ("republication-fields-are-present-once", all(len(values(republication, label)) == 1 for label in REPUBLICATION_FIELDS)),
    ("republication-is-canonical", canonical_bytes(republication, REPUBLICATION_FIELDS) == republication_bytes),
    ("republication-schema-id-source-and-signature-policy-are-exact", field(republication, "recovered-checkpoint-republication-schema") == REPUBLICATION_SCHEMA and bool(re.fullmatch(TOKEN, field(republication, "republication-id") or "")) and field(republication, "republication-source") == "RECOVERY_ROOT_SIGNED_AND_INDEPENDENT_WITNESS_QUORUM" and field(republication, "signature-algorithm") == "ED25519" and field(republication, "replacement-root-approval-policy") == "REQUIRED_DETACHED_ED25519"),
    ("republication-binds-exact-recovery-report-event-and-checkpoint", equal_hash(field(republication, "root-recovery-verification-sha256"), recovery_report_hash) and equal_hash(field(republication, "governance-root-recovery-event-sha256"), event_hash) and equal_hash(field(republication, "recovered-checkpoint-sha256"), checkpoint_hash)),
    ("republication-binds-exact-active-root-and-revoked-previous-root", field(republication, "active-governance-root-key-id") == root_id and equal_hash(field(republication, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(republication, "active-governance-root-manifest-sha256"), root_manifest_hash) and field(republication, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY"),
    ("republication-times-are-fresh-bounded-and-ordered", all(value is not None for value in (checkpoint_updated_at, recovery_verified_at, issued_at, published_at, valid_until, verification_time, root_valid_from, root_valid_until)) and checkpoint_updated_at <= recovery_verified_at <= issued_at <= published_at <= verification_time <= valid_until and root_valid_from <= issued_at <= verification_time <= root_valid_until and recovery_to_publication is not None and 0 <= recovery_to_publication <= MAX_PUBLICATION_WINDOW_SECONDS and record_lifetime is not None and 0 < record_lifetime <= MAX_PUBLICATION_WINDOW_SECONDS and window_limit == MAX_PUBLICATION_WINDOW_SECONDS),
    ("replacement-root-approval-signature-passes", ROOT_SIGNATURE.stat().st_size == 64 and root_signature_valid),
    ("republication-witness-identities-and-key-pins-are-exact-and-distinct", all(identifier and re.fullmatch(TOKEN, identifier) for identifier in witness_ids) and len(set(witness_ids)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(witness_pins, witness_key_hashes)) and all(witness_key_types) and len(set([root_key_hash, *witness_key_hashes])) == 4),
    ("republication-witness-quorum-is-two-of-three-and-passes", quorum_threshold == 2 and valid_witness_count >= 2),
    ("republication-continuity-and-unseen-newer-limit-are-explicit", field(republication, "continuity-policy") == "REJECT_PRE_RECOVERY_ROOT_AND_ALL_LOWER_EPOCHS" and field(republication, "unseen-newer-checkpoint-discovery") == "NOT_PROVEN_BY_THIS_SUPPLIED_QUORUM"),
    ("republication-forbids-write-slot-wrapper-promotion-container-and-launch", field(republication, "persistent-writes") == "FORBIDDEN" and field(republication, "slot-changes") == "FORBIDDEN" and field(republication, "payload-launch-authorization") == "NO" and field(republication, "wrapper-execution-authorization") == "NO" and field(republication, "dsc-fdf-promotion-authorization") == "NO" and field(republication, "container-build-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 recovered-checkpoint republication quorum gate",
    "Verifier mode: HOST_SIDE_REPLACEMENT_ROOT_AND_2_OF_3_REPUBLICATION_WITNESSES_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"root-recovery-verification-sha256: {recovery_report_hash}",
    f"governance-root-recovery-event-sha256: {event_hash}",
    f"recovered-checkpoint-sha256: {checkpoint_hash}",
    f"replacement-governance-root-manifest-sha256: {root_manifest_hash}",
    f"replacement-governance-root-public-key-sha256: {root_key_hash}",
    f"republication-record-sha256: {republication_hash}",
    f"recovered-governance-epoch: {republication_epoch if republication_epoch is not None else 'MISSING'}",
    f"recovered-governance-sequence: {republication_sequence if republication_sequence is not None else 'MISSING'}",
    f"republication-witness-signatures-valid: {valid_witness_count}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"replacement-root-republication-signature: {'PASS' if root_signature_valid else 'FAIL'}",
    f"republication-witness-1-signature: {'PASS' if witness_signature_valid[0] else 'FAIL'}",
    f"republication-witness-2-signature: {'PASS' if witness_signature_valid[1] else 'FAIL'}",
    f"republication-witness-3-signature: {'PASS' if witness_signature_valid[2] else 'FAIL'}",
    "previous-governance-root-state: REVOKED",
    "replacement-governance-root-state: REPUBLISHED_TO_FRESH_SUPPLIED_WITNESS_QUORUM" if not failed else "replacement-governance-root-state: NOT_VERIFIED",
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
        "classification: M7_RECOVERED_CHECKPOINT_REPUBLICATION_BLOCKED",
        "decision: the recovery-chain binding, replacement-root approval, short publication window, two-of-three witness quorum, root-revocation continuity or no-write/no-launch policy failed. Reject this supplied republication and do not authorize a device command.",
    ], 1)

emit(lines + [
    "republication-quorum-state: EXACT_REPLACEMENT_ROOT_APPROVED_RECORD_WITH_2_OF_3_OR_GREATER_WITNESS_SIGNATURES",
    "remaining-blocker: UNSEEN_NEWER_CHECKPOINT_CANNOT_BE_DISCOVERED_FROM_SUPPLIED_FILES",
    "remaining-blocker: EXTERNAL_REPOSITORY_AND_WITNESS_DISTRIBUTION_REMAINS_OPERATIONAL",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_RECOVERED_CHECKPOINT_REPUBLICATION_QUORUM_PASS_EXTERNAL_DISTRIBUTION_REQUIRED",
    "decision: the recovered checkpoint, event, epoch, replacement root and revoked previous-root state are bound to one canonical short-lived record signed by the replacement root and at least two of three distinct witnesses. This proves only the supplied quorum and cannot discover an unseen newer checkpoint or authorize a device action.",
])
