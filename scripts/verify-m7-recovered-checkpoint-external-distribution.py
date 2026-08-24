#!/usr/bin/env python3
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


if len(sys.argv) != 19:
    raise SystemExit(
        "Usage: verify-m7-recovered-checkpoint-external-distribution.py "
        "<republication-verification.txt> <republication-record.txt> "
        "<recovered-checkpoint.txt> <replacement-root-manifest.txt> "
        "<replacement-root-public-key.pem> <distribution-policy.txt> "
        "<replacement-root-policy-signature.bin> "
        "<channel-1-public-key.pem> <channel-1-receipt.txt> <channel-1-signature.bin> "
        "<channel-2-public-key.pem> <channel-2-receipt.txt> <channel-2-signature.bin> "
        "<channel-3-public-key.pem> <channel-3-receipt.txt> <channel-3-signature.bin> "
        "<verification-timestamp-utc> <output.txt>"
    )

REPUBLICATION_REPORT = Path(sys.argv[1])
REPUBLICATION = Path(sys.argv[2])
RECOVERED_CHECKPOINT = Path(sys.argv[3])
ROOT_MANIFEST = Path(sys.argv[4])
ROOT_KEY = Path(sys.argv[5])
POLICY = Path(sys.argv[6])
ROOT_POLICY_SIGNATURE = Path(sys.argv[7])
CHANNEL_KEYS = [Path(sys.argv[8]), Path(sys.argv[11]), Path(sys.argv[14])]
RECEIPTS = [Path(sys.argv[9]), Path(sys.argv[12]), Path(sys.argv[15])]
RECEIPT_SIGNATURES = [Path(sys.argv[10]), Path(sys.argv[13]), Path(sys.argv[16])]
VERIFICATION_TEXT = sys.argv[17]
OUT = Path(sys.argv[18])

UPSTREAM_CLASSIFICATION = (
    "M7_RECOVERED_CHECKPOINT_REPUBLICATION_QUORUM_PASS_EXTERNAL_DISTRIBUTION_REQUIRED"
)
REPUBLICATION_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_REPUBLICATION_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
POLICY_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_POLICY_V1"
RECEIPT_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_RECEIPT_V1"
MAX_RECEIPT_LAG_SECONDS = 60 * 60
MAX_RECEIPT_AGE_SECONDS = 60 * 60
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

POLICY_FIELDS = [
    "external-distribution-policy-schema",
    "distribution-policy-id",
    "republication-verification-sha256",
    "republication-record-sha256",
    "recovered-checkpoint-sha256",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
    "active-governance-root-key-id",
    "active-governance-root-public-key-sha256",
    "active-governance-root-manifest-sha256",
    "distribution-policy-issued-at-utc",
    "distribution-receipt-max-lag-seconds",
    "distribution-receipt-max-age-seconds",
    "required-independent-channel-count",
    "signature-algorithm",
    "distribution-channel-1-id",
    "distribution-channel-1-operator-id",
    "distribution-channel-1-origin",
    "distribution-channel-1-public-key-sha256",
    "distribution-channel-2-id",
    "distribution-channel-2-operator-id",
    "distribution-channel-2-origin",
    "distribution-channel-2-public-key-sha256",
    "distribution-channel-3-id",
    "distribution-channel-3-operator-id",
    "distribution-channel-3-origin",
    "distribution-channel-3-public-key-sha256",
    "channel-independence-policy",
    "continuous-monitoring-state",
    "unseen-newer-checkpoint-discovery",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "wrapper-execution-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
]

RECEIPT_FIELDS = [
    "external-distribution-receipt-schema",
    "distribution-policy-sha256",
    "distribution-channel-id",
    "distribution-operator-id",
    "distribution-origin",
    "distribution-public-key-sha256",
    "republication-verification-sha256",
    "republication-record-sha256",
    "recovered-checkpoint-sha256",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
    "observed-at-utc",
    "checkpoint-content-available",
    "transport-policy",
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


def origin_host(value):
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or parsed.path in ("", "/")
    ):
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "localhost" or "." not in hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    return hostname


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [
    REPUBLICATION_REPORT,
    REPUBLICATION,
    RECOVERED_CHECKPOINT,
    ROOT_MANIFEST,
    ROOT_KEY,
    POLICY,
    ROOT_POLICY_SIGNATURE,
    *CHANNEL_KEYS,
    *RECEIPTS,
    *RECEIPT_SIGNATURES,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 external-distribution input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an external-distribution input, key or signature")

report = REPUBLICATION_REPORT.read_text(errors="replace")
republication = REPUBLICATION.read_text(errors="replace")
checkpoint = RECOVERED_CHECKPOINT.read_text(errors="replace")
root_manifest_bytes = ROOT_MANIFEST.read_bytes()
root_manifest = root_manifest_bytes.decode(errors="replace")
policy_bytes = POLICY.read_bytes()
policy = policy_bytes.decode(errors="replace")
receipt_bytes = [path.read_bytes() for path in RECEIPTS]
receipts = [data.decode(errors="replace") for data in receipt_bytes]

report_hash = sha256(REPUBLICATION_REPORT)
republication_hash = sha256(REPUBLICATION)
checkpoint_hash = sha256(RECOVERED_CHECKPOINT)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
policy_hash = sha256(POLICY)
channel_key_hashes = [sha256(path) for path in CHANNEL_KEYS]
receipt_hashes = [sha256(path) for path in RECEIPTS]

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
root_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
channel_key_types = [is_ed25519(openssl_path, key) for key in CHANNEL_KEYS]
root_signature_valid = verify_signature(openssl_path, ROOT_KEY, POLICY, ROOT_POLICY_SIGNATURE)
receipt_signatures_valid = [
    verify_signature(openssl_path, key, receipt, signature)
    for key, receipt, signature in zip(CHANNEL_KEYS, RECEIPTS, RECEIPT_SIGNATURES)
]

report_epoch = decimal_value(report, "recovered-governance-epoch")
report_sequence = decimal_value(report, "recovered-governance-sequence")
record_epoch = decimal_value(republication, "recovered-governance-epoch")
record_sequence = decimal_value(republication, "recovered-governance-sequence")
checkpoint_epoch = decimal_value(checkpoint, "minimum-governance-epoch")
checkpoint_sequence = decimal_value(checkpoint, "minimum-governance-sequence")
policy_epoch = decimal_value(policy, "recovered-governance-epoch")
policy_sequence = decimal_value(policy, "recovered-governance-sequence")
receipt_epochs = [decimal_value(receipt, "recovered-governance-epoch") for receipt in receipts]
receipt_sequences = [decimal_value(receipt, "recovered-governance-sequence") for receipt in receipts]

root_id = field(root_manifest, "governance-root-key-id")
channel_ids = [field(policy, f"distribution-channel-{index}-id") for index in range(1, 4)]
operator_ids = [field(policy, f"distribution-channel-{index}-operator-id") for index in range(1, 4)]
origins = [field(policy, f"distribution-channel-{index}-origin") for index in range(1, 4)]
origin_hosts = [origin_host(origin) for origin in origins]
channel_pins = [
    field(policy, f"distribution-channel-{index}-public-key-sha256")
    for index in range(1, 4)
]

root_valid_from = parse_utc(field(root_manifest, "valid-from-utc"))
root_valid_until = parse_utc(field(root_manifest, "valid-until-utc"))
republication_published_at = parse_utc(field(republication, "republication-published-at-utc"))
upstream_verified_at = parse_utc(field(report, "verification-timestamp-utc"))
policy_issued_at = parse_utc(field(policy, "distribution-policy-issued-at-utc"))
observed_times = [parse_utc(field(receipt, "observed-at-utc")) for receipt in receipts]
verification_time = parse_utc(VERIFICATION_TEXT)

lag_limit = decimal_value(policy, "distribution-receipt-max-lag-seconds")
age_limit = decimal_value(policy, "distribution-receipt-max-age-seconds")
required_channels = decimal_value(policy, "required-independent-channel-count")
time_values_present = all(
    value is not None
    for value in [
        root_valid_from,
        root_valid_until,
        republication_published_at,
        upstream_verified_at,
        policy_issued_at,
        verification_time,
        *observed_times,
    ]
)
time_windows_pass = False
if time_values_present:
    time_windows_pass = (
        republication_published_at <= upstream_verified_at <= policy_issued_at
        and root_valid_from <= policy_issued_at <= verification_time <= root_valid_until
        and all(
            policy_issued_at <= observed <= verification_time
            and 0 <= (observed - republication_published_at).total_seconds() <= MAX_RECEIPT_LAG_SECONDS
            and 0 <= (verification_time - observed).total_seconds() <= MAX_RECEIPT_AGE_SECONDS
            for observed in observed_times
        )
        and lag_limit == MAX_RECEIPT_LAG_SECONDS
        and age_limit == MAX_RECEIPT_AGE_SECONDS
    )

receipt_bindings_pass = all(
    field(receipt, "external-distribution-receipt-schema") == RECEIPT_SCHEMA
    and equal_hash(field(receipt, "distribution-policy-sha256"), policy_hash)
    and field(receipt, "distribution-channel-id") == channel_id
    and field(receipt, "distribution-operator-id") == operator_id
    and field(receipt, "distribution-origin") == origin
    and equal_hash(field(receipt, "distribution-public-key-sha256"), channel_key_hash)
    and equal_hash(field(receipt, "republication-verification-sha256"), report_hash)
    and equal_hash(field(receipt, "republication-record-sha256"), republication_hash)
    and equal_hash(field(receipt, "recovered-checkpoint-sha256"), checkpoint_hash)
    and receipt_epoch == policy_epoch
    and receipt_sequence == policy_sequence
    and field(receipt, "checkpoint-content-available") == "YES_EXACT_SHA256"
    and field(receipt, "transport-policy") == "HTTPS_TLS_REQUIRED"
    for receipt, channel_id, operator_id, origin, channel_key_hash, receipt_epoch, receipt_sequence
    in zip(
        receipts,
        channel_ids,
        operator_ids,
        origins,
        channel_key_hashes,
        receipt_epochs,
        receipt_sequences,
    )
)

checks = [
    ("upstream-republication-classification-passes", field(report, "classification") == UPSTREAM_CLASSIFICATION),
    ("upstream-report-binds-exact-republication-checkpoint-manifest-and-root-key", equal_hash(field(report, "republication-record-sha256"), republication_hash) and equal_hash(field(report, "recovered-checkpoint-sha256"), checkpoint_hash) and equal_hash(field(report, "replacement-governance-root-manifest-sha256"), root_manifest_hash) and equal_hash(field(report, "replacement-governance-root-public-key-sha256"), root_key_hash)),
    ("upstream-republication-state-passes-and-remains-non-authorizing", field(report, "replacement-governance-root-state") == "REPUBLISHED_TO_FRESH_SUPPLIED_WITNESS_QUORUM" and field(report, "wrapper-execution-authorization") == "NO" and field(report, "persistent-writes") == "FORBIDDEN" and field(report, "launch-authorization") == "NO"),
    ("republication-record-remains-exact-revoked-root-and-non-authorizing", field(republication, "recovered-checkpoint-republication-schema") == REPUBLICATION_SCHEMA and equal_hash(field(republication, "recovered-checkpoint-sha256"), checkpoint_hash) and field(republication, "active-governance-root-key-id") == root_id and equal_hash(field(republication, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(republication, "active-governance-root-manifest-sha256"), root_manifest_hash) and field(republication, "previous-governance-root-status") == "REVOKED_EFFECTIVE_AT_RECOVERY" and field(republication, "persistent-writes") == "FORBIDDEN" and field(republication, "slot-changes") == "FORBIDDEN" and field(republication, "payload-launch-authorization") == "NO"),
    ("all-recovery-epoch-and-sequence-bindings-match", report_epoch == record_epoch == checkpoint_epoch == policy_epoch and report_sequence == record_sequence == checkpoint_sequence == policy_sequence and all(epoch == policy_epoch for epoch in receipt_epochs) and all(sequence == policy_sequence for sequence in receipt_sequences) and policy_epoch is not None and policy_sequence is not None and policy_epoch > 0 and policy_sequence > 0),
    ("replacement-root-manifest-fields-are-present-once", all(len(values(root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("replacement-root-manifest-is-canonical", canonical_bytes(root_manifest, ROOT_FIELDS) == root_manifest_bytes),
    ("replacement-root-manifest-key-role-scope-source-and-state-are-exact", field(root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and bool(re.fullmatch(TOKEN, root_id or "")) and field(root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(root_manifest, "signature-algorithm") == "ED25519" and equal_hash(field(root_manifest, "public-key-sha256"), root_key_hash) and root_is_ed25519 and field(root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_manifest, "trust-anchor-source") == "RECOVERY_QUORUM_ACTIVATED_SHA256_PIN" and field(root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY" and field(root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER"),
    ("replacement-root-manifest-remains-non-authorizing", field(root_manifest, "persistent-writes") == "FORBIDDEN" and field(root_manifest, "slot-changes") == "FORBIDDEN" and field(root_manifest, "payload-launch-authorization") == "NO"),
    ("distribution-policy-fields-are-present-once", all(len(values(policy, label)) == 1 for label in POLICY_FIELDS)),
    ("distribution-policy-is-canonical", canonical_bytes(policy, POLICY_FIELDS) == policy_bytes),
    ("distribution-policy-schema-id-root-and-input-bindings-are-exact", field(policy, "external-distribution-policy-schema") == POLICY_SCHEMA and bool(re.fullmatch(TOKEN, field(policy, "distribution-policy-id") or "")) and equal_hash(field(policy, "republication-verification-sha256"), report_hash) and equal_hash(field(policy, "republication-record-sha256"), republication_hash) and equal_hash(field(policy, "recovered-checkpoint-sha256"), checkpoint_hash) and field(policy, "active-governance-root-key-id") == root_id and equal_hash(field(policy, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(policy, "active-governance-root-manifest-sha256"), root_manifest_hash) and field(policy, "signature-algorithm") == "ED25519"),
    ("distribution-policy-has-three-distinct-pinned-https-channels", required_channels == 3 and all(value and re.fullmatch(TOKEN, value) for value in channel_ids) and all(value and re.fullmatch(TOKEN, value) for value in operator_ids) and len(set(channel_ids)) == 3 and len(set(operator_ids)) == 3 and all(origin_hosts) and len(set(origin_hosts)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(channel_pins, channel_key_hashes)) and all(channel_key_types) and len(set([root_key_hash, *channel_key_hashes])) == 4),
    ("distribution-policy-replacement-root-signature-passes", ROOT_POLICY_SIGNATURE.stat().st_size == 64 and root_signature_valid),
    ("distribution-receipt-fields-are-present-once", all(all(len(values(receipt, label)) == 1 for label in RECEIPT_FIELDS) for receipt in receipts)),
    ("distribution-receipts-are-canonical", all(canonical_bytes(receipt, RECEIPT_FIELDS) == data for receipt, data in zip(receipts, receipt_bytes))),
    ("distribution-receipts-bind-exact-policy-channels-and-checkpoint", receipt_bindings_pass),
    ("distribution-receipts-are-fresh-bounded-and-ordered", time_windows_pass),
    ("all-three-independent-distribution-receipt-signatures-pass", all(receipt_signatures_valid)),
    ("distribution-continuity-and-monitoring-limit-are-explicit", field(policy, "channel-independence-policy") == "DISTINCT_OPERATOR_ID_ORIGIN_HOST_AND_ED25519_KEY_REQUIRED" and field(policy, "continuous-monitoring-state") == "NOT_PROVEN_BY_ONE_SHOT_RECEIPTS" and field(policy, "unseen-newer-checkpoint-discovery") == "NOT_PROVEN_BY_SUPPLIED_DISTRIBUTION_RECEIPTS"),
    ("policy-and-receipts-forbid-write-slot-wrapper-promotion-container-and-launch", field(policy, "persistent-writes") == "FORBIDDEN" and field(policy, "slot-changes") == "FORBIDDEN" and field(policy, "payload-launch-authorization") == "NO" and field(policy, "wrapper-execution-authorization") == "NO" and field(policy, "dsc-fdf-promotion-authorization") == "NO" and field(policy, "container-build-authorization") == "NO" and all(field(receipt, "persistent-writes") == "FORBIDDEN" and field(receipt, "slot-changes") == "FORBIDDEN" and field(receipt, "payload-launch-authorization") == "NO" for receipt in receipts)),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 recovered-checkpoint external-distribution gate",
    "Verifier mode: HOST_SIDE_REPLACEMENT_ROOT_POLICY_AND_3_OF_3_DISTRIBUTION_RECEIPTS_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Network requests executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"republication-verification-sha256: {report_hash}",
    f"republication-record-sha256: {republication_hash}",
    f"recovered-checkpoint-sha256: {checkpoint_hash}",
    f"replacement-governance-root-manifest-sha256: {root_manifest_hash}",
    f"replacement-governance-root-public-key-sha256: {root_key_hash}",
    f"distribution-policy-sha256: {policy_hash}",
    f"distribution-receipt-1-sha256: {receipt_hashes[0]}",
    f"distribution-receipt-2-sha256: {receipt_hashes[1]}",
    f"distribution-receipt-3-sha256: {receipt_hashes[2]}",
    f"recovered-governance-epoch: {policy_epoch if policy_epoch is not None else 'MISSING'}",
    f"recovered-governance-sequence: {policy_sequence if policy_sequence is not None else 'MISSING'}",
    f"distribution-receipt-signatures-valid: {sum(receipt_signatures_valid)}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"replacement-root-distribution-policy-signature: {'PASS' if root_signature_valid else 'FAIL'}",
    f"distribution-channel-1-receipt-signature: {'PASS' if receipt_signatures_valid[0] else 'FAIL'}",
    f"distribution-channel-2-receipt-signature: {'PASS' if receipt_signatures_valid[1] else 'FAIL'}",
    f"distribution-channel-3-receipt-signature: {'PASS' if receipt_signatures_valid[2] else 'FAIL'}",
    "previous-governance-root-state: REVOKED",
    "replacement-governance-root-state: EXTERNALLY_DISTRIBUTED_TO_3_OF_3_SUPPLIED_INDEPENDENT_CHANNELS" if not failed else "replacement-governance-root-state: NOT_VERIFIED",
    "continuous-monitoring-state: NOT_PROVEN_BY_ONE_SHOT_RECEIPTS",
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
        "classification: M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_BLOCKED",
        "decision: the recovery-chain binding, replacement-root policy approval, three-channel independence, exact receipt signatures, freshness or no-write/no-launch policy failed. Reject this supplied distribution evidence and do not authorize a device command.",
    ], 1)

emit(lines + [
    "external-distribution-state: EXACT_RECOVERED_CHECKPOINT_OBSERVED_BY_3_OF_3_SUPPLIED_INDEPENDENT_CHANNELS",
    "remaining-blocker: CONTINUOUS_MULTI_CHANNEL_MONITORING_NOT_PROVEN_BY_ONE_SHOT_RECEIPTS",
    "remaining-blocker: UNSEEN_NEWER_CHECKPOINT_CANNOT_BE_DISCOVERED_FROM_SUPPLIED_FILES",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_PASS_CONTINUOUS_MONITORING_REQUIRED",
    "decision: the exact recovered checkpoint and republication were observed within the bounded window by three distinct replacement-root-pinned HTTPS operators whose detached signatures cover canonical receipts. This proves only the supplied observations; it does not prove continuous availability, discover an unseen newer checkpoint or authorize a device action.",
])
