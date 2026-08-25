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
        "Usage: verify-m7-recovered-checkpoint-bounded-monitoring.py "
        "<external-distribution-verification.txt> <external-distribution-policy.txt> "
        "<recovered-checkpoint.txt> <replacement-root-manifest.txt> "
        "<replacement-root-public-key.pem> <monitoring-mandate.txt> "
        "<replacement-root-mandate-signature.bin> "
        "<channel-1-public-key.pem> <channel-1-journal.txt> <channel-1-signature.bin> "
        "<channel-2-public-key.pem> <channel-2-journal.txt> <channel-2-signature.bin> "
        "<channel-3-public-key.pem> <channel-3-journal.txt> <channel-3-signature.bin> "
        "<verification-timestamp-utc> <output.txt>"
    )

EXTERNAL_REPORT = Path(sys.argv[1])
DISTRIBUTION_POLICY = Path(sys.argv[2])
RECOVERED_CHECKPOINT = Path(sys.argv[3])
ROOT_MANIFEST = Path(sys.argv[4])
ROOT_KEY = Path(sys.argv[5])
MANDATE = Path(sys.argv[6])
ROOT_MANDATE_SIGNATURE = Path(sys.argv[7])
CHANNEL_KEYS = [Path(sys.argv[8]), Path(sys.argv[11]), Path(sys.argv[14])]
JOURNALS = [Path(sys.argv[9]), Path(sys.argv[12]), Path(sys.argv[15])]
JOURNAL_SIGNATURES = [Path(sys.argv[10]), Path(sys.argv[13]), Path(sys.argv[16])]
VERIFICATION_TEXT = sys.argv[17]
OUT = Path(sys.argv[18])

UPSTREAM_CLASSIFICATION = (
    "M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_PASS_CONTINUOUS_MONITORING_REQUIRED"
)
POLICY_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_POLICY_V1"
ROOT_SCHEMA = "IZZOS_M7_KEY_GOVERNANCE_ROOT_V1"
MANDATE_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_MANDATE_V1"
JOURNAL_SCHEMA = "IZZOS_M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_JOURNAL_V1"
OBSERVATION_ROUNDS = 4
MAX_OBSERVATION_GAP_SECONDS = 15 * 60
MIN_MONITORING_WINDOW_SECONDS = 45 * 60
MAX_MONITORING_WINDOW_SECONDS = 45 * 60
MAX_FINAL_OBSERVATION_AGE_SECONDS = 5 * 60
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

MANDATE_FIELDS = [
    "bounded-monitoring-mandate-schema",
    "monitoring-id",
    "external-distribution-verification-sha256",
    "external-distribution-policy-sha256",
    "recovered-checkpoint-sha256",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
    "active-governance-root-key-id",
    "active-governance-root-public-key-sha256",
    "active-governance-root-manifest-sha256",
    "monitoring-window-start-utc",
    "monitoring-window-end-utc",
    "minimum-observation-rounds",
    "maximum-observation-gap-seconds",
    "required-independent-channel-count",
    "signature-algorithm",
]
for channel in range(1, 4):
    MANDATE_FIELDS.extend([
        f"monitoring-channel-{channel}-id",
        f"monitoring-channel-{channel}-operator-id",
        f"monitoring-channel-{channel}-origin",
        f"monitoring-channel-{channel}-public-key-sha256",
    ])
MANDATE_FIELDS.extend([
    "channel-independence-policy",
    "bounded-monitoring-scope",
    "long-term-availability-state",
    "unseen-newer-checkpoint-discovery",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "wrapper-execution-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
])

JOURNAL_FIELDS = [
    "bounded-monitoring-journal-schema",
    "monitoring-mandate-sha256",
    "monitoring-channel-id",
    "monitoring-operator-id",
    "monitoring-origin",
    "monitoring-public-key-sha256",
    "external-distribution-verification-sha256",
    "external-distribution-policy-sha256",
    "recovered-checkpoint-sha256",
    "recovered-governance-epoch",
    "recovered-governance-sequence",
]
for observation in range(1, OBSERVATION_ROUNDS + 1):
    JOURNAL_FIELDS.extend([
        f"observation-{observation}-at-utc",
        f"observation-{observation}-checkpoint-sha256",
        f"observation-{observation}-availability",
    ])
JOURNAL_FIELDS.extend([
    "monitoring-result",
    "transport-policy",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
])


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
        return hostname


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [
    EXTERNAL_REPORT,
    DISTRIBUTION_POLICY,
    RECOVERED_CHECKPOINT,
    ROOT_MANIFEST,
    ROOT_KEY,
    MANDATE,
    ROOT_MANDATE_SIGNATURE,
    *CHANNEL_KEYS,
    *JOURNALS,
    *JOURNAL_SIGNATURES,
]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 bounded-monitoring input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a bounded-monitoring input, key or signature")

report = EXTERNAL_REPORT.read_text(errors="replace")
policy = DISTRIBUTION_POLICY.read_text(errors="replace")
checkpoint = RECOVERED_CHECKPOINT.read_text(errors="replace")
root_manifest_bytes = ROOT_MANIFEST.read_bytes()
root_manifest = root_manifest_bytes.decode(errors="replace")
mandate_bytes = MANDATE.read_bytes()
mandate = mandate_bytes.decode(errors="replace")
journal_bytes = [path.read_bytes() for path in JOURNALS]
journals = [data.decode(errors="replace") for data in journal_bytes]

report_hash = sha256(EXTERNAL_REPORT)
policy_hash = sha256(DISTRIBUTION_POLICY)
checkpoint_hash = sha256(RECOVERED_CHECKPOINT)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
mandate_hash = sha256(MANDATE)
channel_key_hashes = [sha256(path) for path in CHANNEL_KEYS]
journal_hashes = [sha256(path) for path in JOURNALS]

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
root_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
channel_key_types = [is_ed25519(openssl_path, key) for key in CHANNEL_KEYS]
root_signature_valid = verify_signature(openssl_path, ROOT_KEY, MANDATE, ROOT_MANDATE_SIGNATURE)
journal_signatures_valid = [
    verify_signature(openssl_path, key, journal, signature)
    for key, journal, signature in zip(CHANNEL_KEYS, JOURNALS, JOURNAL_SIGNATURES)
]

report_epoch = decimal_value(report, "recovered-governance-epoch")
report_sequence = decimal_value(report, "recovered-governance-sequence")
policy_epoch = decimal_value(policy, "recovered-governance-epoch")
policy_sequence = decimal_value(policy, "recovered-governance-sequence")
checkpoint_epoch = decimal_value(checkpoint, "minimum-governance-epoch")
checkpoint_sequence = decimal_value(checkpoint, "minimum-governance-sequence")
mandate_epoch = decimal_value(mandate, "recovered-governance-epoch")
mandate_sequence = decimal_value(mandate, "recovered-governance-sequence")
journal_epochs = [decimal_value(journal, "recovered-governance-epoch") for journal in journals]
journal_sequences = [decimal_value(journal, "recovered-governance-sequence") for journal in journals]

root_id = field(root_manifest, "governance-root-key-id")
channel_ids = [field(mandate, f"monitoring-channel-{index}-id") for index in range(1, 4)]
operator_ids = [field(mandate, f"monitoring-channel-{index}-operator-id") for index in range(1, 4)]
origins = [field(mandate, f"monitoring-channel-{index}-origin") for index in range(1, 4)]
origin_hosts = [origin_host(origin) for origin in origins]
channel_pins = [field(mandate, f"monitoring-channel-{index}-public-key-sha256") for index in range(1, 4)]

root_valid_from = parse_utc(field(root_manifest, "valid-from-utc"))
root_valid_until = parse_utc(field(root_manifest, "valid-until-utc"))
upstream_verified_at = parse_utc(field(report, "verification-timestamp-utc"))
window_start = parse_utc(field(mandate, "monitoring-window-start-utc"))
window_end = parse_utc(field(mandate, "monitoring-window-end-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
observation_times = [
    [parse_utc(field(journal, f"observation-{index}-at-utc")) for index in range(1, OBSERVATION_ROUNDS + 1)]
    for journal in journals
]

round_count = decimal_value(mandate, "minimum-observation-rounds")
gap_limit = decimal_value(mandate, "maximum-observation-gap-seconds")
required_channels = decimal_value(mandate, "required-independent-channel-count")
time_values_present = all(
    value is not None
    for value in [
        root_valid_from,
        root_valid_until,
        upstream_verified_at,
        window_start,
        window_end,
        verification_time,
        *[value for channel_times in observation_times for value in channel_times],
    ]
)
monitoring_times_pass = False
if time_values_present:
    window_seconds = (window_end - window_start).total_seconds()
    reference_rounds = observation_times[0]
    monitoring_times_pass = (
        upstream_verified_at <= window_start < window_end <= verification_time
        and root_valid_from <= window_start <= verification_time <= root_valid_until
        and MIN_MONITORING_WINDOW_SECONDS <= window_seconds <= MAX_MONITORING_WINDOW_SECONDS
        and 0 <= (verification_time - window_end).total_seconds() <= MAX_FINAL_OBSERVATION_AGE_SECONDS
        and all(channel_times == reference_rounds for channel_times in observation_times[1:])
        and reference_rounds[0] == window_start
        and reference_rounds[-1] == window_end
        and all(
            0 < (current - previous).total_seconds() <= MAX_OBSERVATION_GAP_SECONDS
            for previous, current in zip(reference_rounds, reference_rounds[1:])
        )
        and round_count == OBSERVATION_ROUNDS
        and gap_limit == MAX_OBSERVATION_GAP_SECONDS
    )

policy_channel_bindings_pass = all(
    field(policy, f"distribution-channel-{index}-id") == channel_ids[index - 1]
    and field(policy, f"distribution-channel-{index}-operator-id") == operator_ids[index - 1]
    and field(policy, f"distribution-channel-{index}-origin") == origins[index - 1]
    and equal_hash(
        field(policy, f"distribution-channel-{index}-public-key-sha256"),
        channel_key_hashes[index - 1],
    )
    for index in range(1, 4)
)

journal_bindings_pass = all(
    field(journal, "bounded-monitoring-journal-schema") == JOURNAL_SCHEMA
    and equal_hash(field(journal, "monitoring-mandate-sha256"), mandate_hash)
    and field(journal, "monitoring-channel-id") == channel_id
    and field(journal, "monitoring-operator-id") == operator_id
    and field(journal, "monitoring-origin") == origin
    and equal_hash(field(journal, "monitoring-public-key-sha256"), channel_key_hash)
    and equal_hash(field(journal, "external-distribution-verification-sha256"), report_hash)
    and equal_hash(field(journal, "external-distribution-policy-sha256"), policy_hash)
    and equal_hash(field(journal, "recovered-checkpoint-sha256"), checkpoint_hash)
    and journal_epoch == mandate_epoch
    and journal_sequence == mandate_sequence
    and all(
        equal_hash(field(journal, f"observation-{index}-checkpoint-sha256"), checkpoint_hash)
        and field(journal, f"observation-{index}-availability") == "YES_EXACT_SHA256"
        for index in range(1, OBSERVATION_ROUNDS + 1)
    )
    and field(journal, "monitoring-result") == "ALL_REQUIRED_OBSERVATIONS_AVAILABLE"
    and field(journal, "transport-policy") == "HTTPS_TLS_REQUIRED"
    for journal, channel_id, operator_id, origin, channel_key_hash, journal_epoch, journal_sequence
    in zip(
        journals,
        channel_ids,
        operator_ids,
        origins,
        channel_key_hashes,
        journal_epochs,
        journal_sequences,
    )
)

checks = [
    ("upstream-external-distribution-classification-passes", field(report, "classification") == UPSTREAM_CLASSIFICATION),
    ("upstream-report-binds-exact-policy-checkpoint-manifest-and-root-key", equal_hash(field(report, "distribution-policy-sha256"), policy_hash) and equal_hash(field(report, "recovered-checkpoint-sha256"), checkpoint_hash) and equal_hash(field(report, "replacement-governance-root-manifest-sha256"), root_manifest_hash) and equal_hash(field(report, "replacement-governance-root-public-key-sha256"), root_key_hash)),
    ("upstream-distribution-state-passes-and-remains-non-authorizing", field(report, "replacement-governance-root-state") == "EXTERNALLY_DISTRIBUTED_TO_3_OF_3_SUPPLIED_INDEPENDENT_CHANNELS" and field(report, "continuous-monitoring-state") == "NOT_PROVEN_BY_ONE_SHOT_RECEIPTS" and field(report, "wrapper-execution-authorization") == "NO" and field(report, "persistent-writes") == "FORBIDDEN" and field(report, "launch-authorization") == "NO"),
    ("distribution-policy-schema-input-root-and-channel-bindings-remain-exact", field(policy, "external-distribution-policy-schema") == POLICY_SCHEMA and equal_hash(field(policy, "recovered-checkpoint-sha256"), checkpoint_hash) and field(policy, "active-governance-root-key-id") == root_id and equal_hash(field(policy, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(policy, "active-governance-root-manifest-sha256"), root_manifest_hash) and policy_channel_bindings_pass),
    ("all-recovery-epoch-and-sequence-bindings-match", report_epoch == policy_epoch == checkpoint_epoch == mandate_epoch and report_sequence == policy_sequence == checkpoint_sequence == mandate_sequence and all(epoch == mandate_epoch for epoch in journal_epochs) and all(sequence == mandate_sequence for sequence in journal_sequences) and mandate_epoch is not None and mandate_sequence is not None and mandate_epoch > 0 and mandate_sequence > 0),
    ("replacement-root-manifest-fields-are-present-once", all(len(values(root_manifest, label)) == 1 for label in ROOT_FIELDS)),
    ("replacement-root-manifest-is-canonical", canonical_bytes(root_manifest, ROOT_FIELDS) == root_manifest_bytes),
    ("replacement-root-manifest-key-role-scope-source-and-state-are-exact", field(root_manifest, "key-governance-root-schema") == ROOT_SCHEMA and bool(re.fullmatch(TOKEN, root_id or "")) and field(root_manifest, "governance-root-role") == "M7_OFFLINE_KEY_GOVERNANCE_ROOT" and field(root_manifest, "signature-algorithm") == "ED25519" and equal_hash(field(root_manifest, "public-key-sha256"), root_key_hash) and root_is_ed25519 and field(root_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_manifest, "trust-anchor-source") == "RECOVERY_QUORUM_ACTIVATED_SHA256_PIN" and field(root_manifest, "governance-scope") == "M7_AUTHORITY_KEY_ROTATION_AND_REVOCATION_ONLY" and field(root_manifest, "key-custody") == "OFFLINE_EXTERNAL_TO_VERIFIER"),
    ("replacement-root-manifest-remains-non-authorizing", field(root_manifest, "persistent-writes") == "FORBIDDEN" and field(root_manifest, "slot-changes") == "FORBIDDEN" and field(root_manifest, "payload-launch-authorization") == "NO"),
    ("bounded-monitoring-mandate-fields-are-present-once", all(len(values(mandate, label)) == 1 for label in MANDATE_FIELDS)),
    ("bounded-monitoring-mandate-is-canonical", canonical_bytes(mandate, MANDATE_FIELDS) == mandate_bytes),
    ("bounded-monitoring-mandate-schema-id-root-and-input-bindings-are-exact", field(mandate, "bounded-monitoring-mandate-schema") == MANDATE_SCHEMA and bool(re.fullmatch(TOKEN, field(mandate, "monitoring-id") or "")) and equal_hash(field(mandate, "external-distribution-verification-sha256"), report_hash) and equal_hash(field(mandate, "external-distribution-policy-sha256"), policy_hash) and equal_hash(field(mandate, "recovered-checkpoint-sha256"), checkpoint_hash) and field(mandate, "active-governance-root-key-id") == root_id and equal_hash(field(mandate, "active-governance-root-public-key-sha256"), root_key_hash) and equal_hash(field(mandate, "active-governance-root-manifest-sha256"), root_manifest_hash) and field(mandate, "signature-algorithm") == "ED25519"),
    ("bounded-monitoring-mandate-has-three-distinct-pinned-channels", required_channels == 3 and all(value and re.fullmatch(TOKEN, value) for value in channel_ids) and all(value and re.fullmatch(TOKEN, value) for value in operator_ids) and len(set(channel_ids)) == 3 and len(set(operator_ids)) == 3 and all(origin_hosts) and len(set(origin_hosts)) == 3 and all(equal_hash(pin, actual) for pin, actual in zip(channel_pins, channel_key_hashes)) and all(channel_key_types) and len(set([root_key_hash, *channel_key_hashes])) == 4),
    ("bounded-monitoring-mandate-replacement-root-signature-passes", ROOT_MANDATE_SIGNATURE.stat().st_size == 64 and root_signature_valid),
    ("bounded-monitoring-journal-fields-are-present-once", all(all(len(values(journal, label)) == 1 for label in JOURNAL_FIELDS) for journal in journals)),
    ("bounded-monitoring-journals-are-canonical", all(canonical_bytes(journal, JOURNAL_FIELDS) == data for journal, data in zip(journals, journal_bytes))),
    ("bounded-monitoring-journals-bind-exact-mandate-channels-and-checkpoint", journal_bindings_pass),
    ("bounded-monitoring-rounds-are-synchronized-fresh-and-gap-bounded", monitoring_times_pass),
    ("all-three-bounded-monitoring-journal-signatures-pass", all(journal_signatures_valid)),
    ("bounded-monitoring-scope-and-long-term-limit-are-explicit", field(mandate, "channel-independence-policy") == "DISTINCT_OPERATOR_ORIGIN_AND_ED25519_KEY_REQUIRED" and field(mandate, "bounded-monitoring-scope") == "FOUR_SYNCHRONIZED_ROUNDS_ACROSS_THREE_CHANNELS_ONLY" and field(mandate, "long-term-availability-state") == "NOT_PROVEN_BEYOND_BOUNDED_WINDOW" and field(mandate, "unseen-newer-checkpoint-discovery") == "NOT_PROVEN_OUTSIDE_MONITORED_CHANNELS"),
    ("mandate-and-journals-forbid-write-slot-wrapper-promotion-container-and-launch", field(mandate, "persistent-writes") == "FORBIDDEN" and field(mandate, "slot-changes") == "FORBIDDEN" and field(mandate, "payload-launch-authorization") == "NO" and field(mandate, "wrapper-execution-authorization") == "NO" and field(mandate, "dsc-fdf-promotion-authorization") == "NO" and field(mandate, "container-build-authorization") == "NO" and all(field(journal, "persistent-writes") == "FORBIDDEN" and field(journal, "slot-changes") == "FORBIDDEN" and field(journal, "payload-launch-authorization") == "NO" for journal in journals)),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 recovered-checkpoint bounded-monitoring gate",
    "Verifier mode: HOST_SIDE_REPLACEMENT_ROOT_MANDATE_AND_3_CHANNEL_4_ROUND_JOURNALS_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Network requests executed by verifier: NONE",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"external-distribution-verification-sha256: {report_hash}",
    f"external-distribution-policy-sha256: {policy_hash}",
    f"recovered-checkpoint-sha256: {checkpoint_hash}",
    f"replacement-governance-root-manifest-sha256: {root_manifest_hash}",
    f"replacement-governance-root-public-key-sha256: {root_key_hash}",
    f"bounded-monitoring-mandate-sha256: {mandate_hash}",
    f"bounded-monitoring-journal-1-sha256: {journal_hashes[0]}",
    f"bounded-monitoring-journal-2-sha256: {journal_hashes[1]}",
    f"bounded-monitoring-journal-3-sha256: {journal_hashes[2]}",
    f"recovered-governance-epoch: {mandate_epoch if mandate_epoch is not None else 'MISSING'}",
    f"recovered-governance-sequence: {mandate_sequence if mandate_sequence is not None else 'MISSING'}",
    f"bounded-monitoring-journal-signatures-valid: {sum(journal_signatures_valid)}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    f"replacement-root-monitoring-mandate-signature: {'PASS' if root_signature_valid else 'FAIL'}",
    f"monitoring-channel-1-journal-signature: {'PASS' if journal_signatures_valid[0] else 'FAIL'}",
    f"monitoring-channel-2-journal-signature: {'PASS' if journal_signatures_valid[1] else 'FAIL'}",
    f"monitoring-channel-3-journal-signature: {'PASS' if journal_signatures_valid[2] else 'FAIL'}",
    "bounded-monitoring-state: THREE_CHANNELS_FOUR_SYNCHRONIZED_ROUNDS_VERIFIED" if not failed else "bounded-monitoring-state: NOT_VERIFIED",
    "long-term-availability-state: NOT_PROVEN_BEYOND_BOUNDED_WINDOW",
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
        "classification: M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_BLOCKED",
        "decision: the upstream distribution binding, root-signed mandate, synchronized three-channel observation window, signatures, freshness or no-write/no-launch policy failed. Reject this monitoring evidence and do not authorize a device command.",
    ], 1)

emit(lines + [
    "internal-m7-host-security-chain: COMPLETE_FOR_SUPPLIED_BOUNDED_EVIDENCE",
    "remaining-blocker: LONG_TERM_AVAILABILITY_REQUIRES_OPERATIONAL_MONITORING",
    "remaining-blocker: PHYSICAL_DEVICE_EXECUTION_EVIDENCE_REMAINS_REQUIRED_FOR_PRODUCT_M1",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_RECOVERED_CHECKPOINT_BOUNDED_MONITORING_PASS_INTERNAL_HOST_SECURITY_CHAIN_COMPLETE",
    "decision: four synchronized observations across all three distinct root-pinned channels bind the exact recovered checkpoint throughout the supplied bounded window. Together with the preceding host gates this closes the internal M7 host security-chain implementation, but it does not prove indefinite availability, discover an unseen checkpoint outside the monitored channels, complete product M1 or authorize a device action.",
])
