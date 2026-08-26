#!/usr/bin/env python3
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 9:
    raise SystemExit(
        "Usage: verify-m7-token-consumption-execution-result.py "
        "<authorization-readiness-report.txt> <authorization-request.txt> "
        "<pre-use-ledger.txt> <post-use-ledger.txt> <consumption-receipt.txt> "
        "<execution-evidence-artifact> <execution-result.txt> <output.txt>"
    )

READINESS = Path(sys.argv[1])
REQUEST = Path(sys.argv[2])
PRE_LEDGER = Path(sys.argv[3])
POST_LEDGER = Path(sys.argv[4])
RECEIPT = Path(sys.argv[5])
EVIDENCE_ARTIFACT = Path(sys.argv[6])
RESULT = Path(sys.argv[7])
OUT = Path(sys.argv[8])

REQUEST_SCHEMA = "IZZOS_M7_ONE_SHOT_EXECUTION_AUTHORIZATION_REQUEST_V1"
LEDGER_SCHEMA = "IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1"
RECEIPT_SCHEMA = "IZZOS_M7_ATOMIC_TOKEN_CONSUMPTION_RECEIPT_V1"
RESULT_SCHEMA = "IZZOS_M7_BOUND_WRAPPER_EXECUTION_RESULT_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

RECEIPT_FIELDS = [
    "token-consumption-receipt-schema",
    "authorization-readiness-report-sha256",
    "authorization-request-sha256",
    "pre-use-ledger-sha256",
    "post-use-ledger-sha256",
    "authorization-token-sha256",
    "consumption-id",
    "consumed-at-utc",
    "consumption-operation-assertion",
    "token-precondition",
    "token-postcondition",
    "invocation-budget-before",
    "invocation-budget-after",
    "ledger-write-scope",
    "execution-evidence-artifact-sha256",
    "atomicity-authenticity",
    "device-storage-writes",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
]

RESULT_FIELDS = [
    "wrapper-execution-result-schema",
    "token-consumption-receipt-sha256",
    "authorization-readiness-report-sha256",
    "authorization-request-sha256",
    "authorization-token-sha256",
    "execution-evidence-artifact-sha256",
    "exact-device-build",
    "capture-id",
    "execution-id",
    "execution-started-at-utc",
    "execution-completed-at-utc",
    "wrapper-invocation-count",
    "wrapper-transfer-count",
    "wrapper-return-count",
    "execution-outcome",
    "execution-authenticity",
    "runtime-ownership-snapshot-status",
    "smc-calls",
    "mmio-writes",
    "device-storage-writes",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
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


def valid_hash(value):
    return bool(value and re.fullmatch(HASH, value) and not re.fullmatch(r"0{64}", value))


def equal_hash(left, right):
    return valid_hash(left) and valid_hash(right) and left.lower() == right.lower()


def decimal_value(text, label):
    value = field(text, label)
    return int(value, 10) if value and re.fullmatch(r"[0-9]+", value) else None


def parse_utc(value):
    if not value or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def ledger_is_valid(text):
    entries = values(text, "used-token-sha256")
    allowed_lines = [
        line == f"used-token-ledger-schema: {LEDGER_SCHEMA}"
        or bool(re.fullmatch(rf"used-token-sha256: {HASH}", line))
        for line in text.splitlines()
    ]
    return (
        bool(allowed_lines)
        and all(allowed_lines)
        and len(values(text, "used-token-ledger-schema")) == 1
        and field(text, "used-token-ledger-schema") == LEDGER_SCHEMA
        and all(valid_hash(entry) for entry in entries)
        and len({entry.lower() for entry in entries}) == len(entries)
    )


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [READINESS, REQUEST, PRE_LEDGER, POST_LEDGER, RECEIPT, EVIDENCE_ARTIFACT, RESULT]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 token-consumption/result input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a receipt, result, ledger or bound input")

readiness = READINESS.read_text(errors="replace")
request = REQUEST.read_text(errors="replace")
pre_ledger_bytes = PRE_LEDGER.read_bytes()
post_ledger_bytes = POST_LEDGER.read_bytes()
pre_ledger = pre_ledger_bytes.decode(errors="replace")
post_ledger = post_ledger_bytes.decode(errors="replace")
receipt = RECEIPT.read_text(errors="replace")
result = RESULT.read_text(errors="replace")

readiness_hash = sha256(READINESS)
request_hash = sha256(REQUEST)
pre_ledger_hash = sha256(PRE_LEDGER)
post_ledger_hash = sha256(POST_LEDGER)
receipt_hash = sha256(RECEIPT)
evidence_hash = sha256(EVIDENCE_ARTIFACT)
result_hash = sha256(RESULT)

authorization_token = field(request, "authorization-token-sha256")
pre_tokens = values(pre_ledger, "used-token-sha256")
post_tokens = values(post_ledger, "used-token-sha256")
token_lower = authorization_token.lower() if valid_hash(authorization_token) else None
expected_post_ledger_bytes = (
    pre_ledger_bytes + f"used-token-sha256: {token_lower}\n".encode()
    if token_lower is not None and pre_ledger_bytes.endswith(b"\n")
    else None
)
exact_single_append = expected_post_ledger_bytes is not None and post_ledger_bytes == expected_post_ledger_bytes

evaluation_time = parse_utc(field(readiness, "evaluation-timestamp-utc"))
expires_time = parse_utc(field(request, "expires-at-utc"))
consumed_time = parse_utc(field(receipt, "consumed-at-utc"))
started_time = parse_utc(field(result, "execution-started-at-utc"))
completed_time = parse_utc(field(result, "execution-completed-at-utc"))
execution_duration = (
    (completed_time - started_time).total_seconds()
    if started_time and completed_time
    else None
)

checks = [
    ("authorization-readiness-classification-passes", field(readiness, "classification") == "M7_FRESH_ONE_SHOT_EXECUTION_TOKEN_READY_ATOMIC_CONSUMPTION_REQUIRED"),
    ("authorization-readiness-binds-request", equal_hash(field(readiness, "authorization-request-sha256"), request_hash)),
    ("authorization-readiness-binds-pre-use-ledger", equal_hash(field(readiness, "used-token-ledger-sha256"), pre_ledger_hash)),
    ("authorization-readiness-binds-token", equal_hash(field(readiness, "authorization-token-sha256"), authorization_token) and equal_hash(field(readiness, "expected-authorization-token-sha256"), authorization_token)),
    ("authorization-readiness-remains-non-authorizing", field(readiness, "authorization-token-state") == "UNUSED_IN_SUPPLIED_LEDGER" and field(readiness, "atomic-token-consumption") == "REQUIRED_EXTERNAL" and field(readiness, "wrapper-execution-authorization") == "NO" and field(readiness, "launch-authorization") == "NO"),
    ("authorization-request-retains-one-use-safe-scope", field(request, "one-shot-authorization-schema") == REQUEST_SCHEMA and decimal_value(request, "authorization-use-count") == 1 and field(request, "requested-wrapper-execution-scope") == "EXACTLY_ONCE_FOR_BOUND_EVIDENCE_CAPTURE_ONLY" and field(request, "atomic-token-consumption") == "REQUIRED_BEFORE_WRAPPER_INVOCATION"),
    ("authorization-request-targets-exact-capture", field(request, "exact-device-build") == TARGET_BUILD and bool(re.fullmatch(TOKEN, field(request, "capture-id") or ""))),
    ("authorization-request-forbids-write-promotion-container-and-launch", field(request, "device-writes") == "NONE" and field(request, "persistent-writes") == "FORBIDDEN" and field(request, "slot-changes") == "FORBIDDEN" and field(request, "payload-launch-authorization") == "NO" and field(request, "dsc-fdf-promotion-authorization") == "NO" and field(request, "container-build-authorization") == "NO"),
    ("pre-use-ledger-is-valid-and-token-absent", ledger_is_valid(pre_ledger) and token_lower is not None and token_lower not in {entry.lower() for entry in pre_tokens}),
    ("post-use-ledger-is-valid-and-token-present-once", ledger_is_valid(post_ledger) and token_lower is not None and sum(entry.lower() == token_lower for entry in post_tokens) == 1),
    ("post-use-ledger-is-exact-single-token-append", exact_single_append),
    ("consumption-receipt-fields-are-present-once", all(len(values(receipt, label)) == 1 for label in RECEIPT_FIELDS)),
    ("consumption-receipt-schema-is-exact", field(receipt, "token-consumption-receipt-schema") == RECEIPT_SCHEMA),
    ("consumption-receipt-binds-readiness-request-and-ledgers", equal_hash(field(receipt, "authorization-readiness-report-sha256"), readiness_hash) and equal_hash(field(receipt, "authorization-request-sha256"), request_hash) and equal_hash(field(receipt, "pre-use-ledger-sha256"), pre_ledger_hash) and equal_hash(field(receipt, "post-use-ledger-sha256"), post_ledger_hash)),
    ("consumption-receipt-binds-token-and-evidence-artifact", equal_hash(field(receipt, "authorization-token-sha256"), authorization_token) and equal_hash(field(receipt, "execution-evidence-artifact-sha256"), evidence_hash) and EVIDENCE_ARTIFACT.stat().st_size > 0),
    ("consumption-receipt-identity-is-specific", bool(re.fullmatch(TOKEN, field(receipt, "consumption-id") or ""))),
    ("consumption-receipt-asserts-one-compare-and-append", field(receipt, "consumption-operation-assertion") == "ATOMIC_COMPARE_TOKEN_ABSENT_AND_APPEND_ONCE" and field(receipt, "token-precondition") == "ABSENT" and field(receipt, "token-postcondition") == "PRESENT_EXACTLY_ONCE" and decimal_value(receipt, "invocation-budget-before") == 1 and decimal_value(receipt, "invocation-budget-after") == 0),
    ("consumption-receipt-limits-write-scope-and-remains-self-reported", field(receipt, "ledger-write-scope") == "EXACT_POST_USE_LEDGER_APPEND_ONLY" and field(receipt, "atomicity-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"),
    ("consumption-receipt-forbids-device-write-and-launch", field(receipt, "device-storage-writes") == "NONE" and field(receipt, "persistent-writes") == "FORBIDDEN" and field(receipt, "slot-changes") == "FORBIDDEN" and field(receipt, "payload-launch-authorization") == "NO"),
    ("consumption-time-is-inside-readiness-window", all(value is not None for value in (evaluation_time, consumed_time, expires_time)) and evaluation_time <= consumed_time <= expires_time),
    ("execution-result-fields-are-present-once", all(len(values(result, label)) == 1 for label in RESULT_FIELDS)),
    ("execution-result-schema-is-exact", field(result, "wrapper-execution-result-schema") == RESULT_SCHEMA),
    ("execution-result-binds-receipt-readiness-request-and-token", equal_hash(field(result, "token-consumption-receipt-sha256"), receipt_hash) and equal_hash(field(result, "authorization-readiness-report-sha256"), readiness_hash) and equal_hash(field(result, "authorization-request-sha256"), request_hash) and equal_hash(field(result, "authorization-token-sha256"), authorization_token)),
    ("execution-result-binds-evidence-artifact", equal_hash(field(result, "execution-evidence-artifact-sha256"), evidence_hash)),
    ("execution-result-targets-exact-capture", field(result, "exact-device-build") == TARGET_BUILD and field(result, "capture-id") == field(request, "capture-id") and bool(re.fullmatch(TOKEN, field(result, "execution-id") or ""))),
    ("execution-result-has-one-non-returning-transfer", decimal_value(result, "wrapper-invocation-count") == 1 and decimal_value(result, "wrapper-transfer-count") == 1 and decimal_value(result, "wrapper-return-count") == 0 and field(result, "execution-outcome") == "BOUND_EVIDENCE_CAPTURE_ASSERTED_COMPLETE"),
    ("execution-result-remains-self-reported-and-snapshot-bound", field(result, "execution-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED" and field(result, "runtime-ownership-snapshot-status") == "EXACT_AUTHORIZED_SNAPSHOT_ASSERTED_UNCHANGED"),
    ("execution-result-time-follows-consumption-and-finishes-inside-window", all(value is not None for value in (consumed_time, started_time, completed_time, expires_time)) and consumed_time <= started_time <= completed_time <= expires_time),
    ("execution-result-duration-is-bounded", execution_duration is not None and 0 <= execution_duration <= 300),
    ("execution-result-forbids-smc-mmio-device-write-and-launch", field(result, "smc-calls") == "NONE" and field(result, "mmio-writes") == "NONE" and field(result, "device-storage-writes") == "NONE" and field(result, "persistent-writes") == "FORBIDDEN" and field(result, "slot-changes") == "FORBIDDEN" and field(result, "payload-launch-authorization") == "NO" and field(result, "dsc-fdf-promotion-authorization") == "NO" and field(result, "container-build-authorization") == "NO"),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 token-consumption receipt and execution-result binding gate",
    "Verifier mode: HOST_SIDE_LEDGER_TRANSITION_AND_RESULT_BYTE_BINDING_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "Token ledger writes executed by verifier: NONE",
    "",
    f"authorization-readiness-report-sha256: {readiness_hash}",
    f"authorization-request-sha256: {request_hash}",
    f"pre-use-ledger-sha256: {pre_ledger_hash}",
    f"post-use-ledger-sha256: {post_ledger_hash}",
    f"token-consumption-receipt-sha256: {receipt_hash}",
    f"execution-evidence-artifact-sha256: {evidence_hash}",
    f"execution-evidence-artifact-size: {EVIDENCE_ARTIFACT.stat().st_size}",
    f"execution-result-sha256: {result_hash}",
    f"authorization-token-sha256: {authorization_token or 'MISSING'}",
    f"exact-device-build: {field(result, 'exact-device-build') or 'MISSING'}",
    f"capture-id: {field(result, 'capture-id') or 'MISSING'}",
    f"consumption-id: {field(receipt, 'consumption-id') or 'MISSING'}",
    f"execution-id: {field(result, 'execution-id') or 'MISSING'}",
    f"consumed-at-utc: {field(receipt, 'consumed-at-utc') or 'MISSING'}",
    f"execution-started-at-utc: {field(result, 'execution-started-at-utc') or 'MISSING'}",
    f"execution-completed-at-utc: {field(result, 'execution-completed-at-utc') or 'MISSING'}",
    f"execution-duration-seconds: {int(execution_duration) if execution_duration is not None else 'UNAVAILABLE'}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "token-consumption-transition: EXACT_SINGLE_APPEND_IN_SUPPLIED_LEDGER_BYTES" if exact_single_append else "token-consumption-transition: NOT_VERIFIED",
    "atomicity-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "execution-result-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "wrapper-execution-proof: NOT_INDEPENDENTLY_ATTESTED",
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
        "classification: M7_TOKEN_CONSUMPTION_EXECUTION_RESULT_BLOCKED",
        "decision: the readiness chain, exact ledger transition, consumption receipt, time window, evidence artifact or execution result is incomplete, contradictory, unsafe or not hash-bound. Do not infer atomic consumption or wrapper execution and do not run a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: TOKEN_CONSUMPTION_ATOMICITY_NOT_INDEPENDENTLY_ATTESTED",
    "remaining-blocker: WRAPPER_EXECUTION_AND_RESULT_NOT_INDEPENDENTLY_ATTESTED",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_TOKEN_CONSUMPTION_RESULT_SCHEMA_PASS_ATOMICITY_AUTHENTICITY_REQUIRED",
    "decision: the supplied ledger bytes show one exact token append, the receipt binds that transition and the evidence artifact, and the self-reported result binds the same request, token, receipt and time window. This host-only schema result does not prove an atomic external operation, prove device execution, retroactively authorize a wrapper, promote DSC/FDF files, build a container or authorize launch.",
])
