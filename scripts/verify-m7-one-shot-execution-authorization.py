#!/usr/bin/env python3
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 8:
    raise SystemExit(
        "Usage: verify-m7-one-shot-execution-authorization.py "
        "<runtime-ownership-report.txt> <wrapper-execution-report.txt> "
        "<device-promotion-readiness.txt> <authorization-request.txt> "
        "<used-token-ledger.txt> <evaluation-timestamp-utc> <output.txt>"
    )

OWNERSHIP = Path(sys.argv[1])
WRAPPER = Path(sys.argv[2])
DEVICE_PROMOTION = Path(sys.argv[3])
REQUEST = Path(sys.argv[4])
LEDGER = Path(sys.argv[5])
EVALUATION_TEXT = sys.argv[6]
OUT = Path(sys.argv[7])

SCHEMA = "IZZOS_M7_ONE_SHOT_EXECUTION_AUTHORIZATION_REQUEST_V1"
LEDGER_SCHEMA = "IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
MAX_FRESHNESS_SECONDS = 300
TOKEN = r"[A-Za-z0-9_.-]+"
HASH = r"[0-9A-Fa-f]{64}"

REQUEST_FIELDS = [
    "one-shot-authorization-schema",
    "runtime-ownership-report-sha256",
    "runtime-ownership-snapshot-sha256",
    "wrapper-execution-report-sha256",
    "device-promotion-readiness-sha256",
    "exact-device-build",
    "capture-id",
    "capture-timestamp-utc",
    "authorized-at-utc",
    "expires-at-utc",
    "authorization-nonce",
    "authorization-token-sha256",
    "authorization-use-count",
    "requested-wrapper-execution-scope",
    "authorization-authority-authenticity",
    "atomic-token-consumption",
    "device-writes",
    "persistent-writes",
    "slot-changes",
    "payload-launch-authorization",
    "dsc-fdf-promotion-authorization",
    "container-build-authorization",
]
TOKEN_BINDING_FIELDS = [field for field in REQUEST_FIELDS if field != "authorization-token-sha256"]


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


def parse_utc(value):
    if not value or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def decimal_value(text, label):
    value = field(text, label)
    return int(value, 10) if value and re.fullmatch(r"[0-9]+", value) else None


def token_digest(request):
    if any(field(request, label) is None for label in TOKEN_BINDING_FIELDS):
        return None
    canonical = "".join(f"{label}={field(request, label)}\n" for label in TOKEN_BINDING_FIELDS)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [OWNERSHIP, WRAPPER, DEVICE_PROMOTION, REQUEST, LEDGER]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 one-shot authorization input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an authorization input or token ledger")

ownership = OWNERSHIP.read_text(errors="replace")
wrapper = WRAPPER.read_text(errors="replace")
device_promotion = DEVICE_PROMOTION.read_text(errors="replace")
request = REQUEST.read_text(errors="replace")
ledger = LEDGER.read_text(errors="replace")

ownership_hash = sha256(OWNERSHIP)
wrapper_hash = sha256(WRAPPER)
device_promotion_hash = sha256(DEVICE_PROMOTION)
request_hash = sha256(REQUEST)
ledger_hash = sha256(LEDGER)

capture_time = parse_utc(field(request, "capture-timestamp-utc"))
authorized_time = parse_utc(field(request, "authorized-at-utc"))
expires_time = parse_utc(field(request, "expires-at-utc"))
evaluation_time = parse_utc(EVALUATION_TEXT)
capture_age = (evaluation_time - capture_time).total_seconds() if capture_time and evaluation_time else None
authorization_window = (expires_time - authorized_time).total_seconds() if authorized_time and expires_time else None

declared_token = field(request, "authorization-token-sha256")
expected_token = token_digest(request)
used_tokens = values(ledger, "used-token-sha256")

checks = [
    ("upstream-runtime-ownership-classification-passes", field(ownership, "classification") == "M7_RUNTIME_DESTINATION_OWNERSHIP_SCHEMA_PASS_AUTHENTICITY_FRESHNESS_REQUIRED"),
    ("upstream-wrapper-assertion-classification-passes", field(wrapper, "classification") == "M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED"),
    ("upstream-device-promotion-classification-passes", field(device_promotion, "classification") == "M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED"),
    ("upstream-ownership-binds-wrapper-report", equal_hash(field(ownership, "wrapper-execution-report-sha256"), wrapper_hash)),
    ("upstream-wrapper-binds-device-promotion-report", equal_hash(field(wrapper, "device-promotion-readiness-sha256"), device_promotion_hash)),
    ("upstream-reports-target-exact-build", field(ownership, "exact-device-build") == TARGET_BUILD and field(wrapper, "exact-device-build") == TARGET_BUILD),
    ("upstream-ownership-is-one-self-reported-instant", field(ownership, "ownership-evidence-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED" and field(ownership, "ownership-snapshot-lifetime") == "EXACT_CAPTURE_INSTANT_ONLY"),
    ("upstream-reports-deny-promotion-container-and-launch", field(ownership, "dsc-fdf-promotion-authorization") == "NO" and field(ownership, "container-build-authorization") == "NO" and field(ownership, "launch-authorization") == "NO" and field(wrapper, "dsc-fdf-promotion-authorization") == "NO" and field(wrapper, "container-build-authorization") == "NO" and field(wrapper, "launch-authorization") == "NO" and field(device_promotion, "dsc-fdf-promotion-authorization") == "NO" and field(device_promotion, "android-container-construction-authorization") == "NO" and field(device_promotion, "launch-authorization") == "NO"),
    ("authorization-request-fields-are-present-once", all(len(values(request, label)) == 1 for label in REQUEST_FIELDS)),
    ("authorization-request-schema-is-exact", field(request, "one-shot-authorization-schema") == SCHEMA),
    ("authorization-request-binds-runtime-ownership-report", equal_hash(field(request, "runtime-ownership-report-sha256"), ownership_hash)),
    ("authorization-request-binds-runtime-ownership-snapshot", equal_hash(field(request, "runtime-ownership-snapshot-sha256"), field(ownership, "runtime-ownership-snapshot-sha256"))),
    ("authorization-request-binds-wrapper-report", equal_hash(field(request, "wrapper-execution-report-sha256"), wrapper_hash)),
    ("authorization-request-binds-device-promotion-report", equal_hash(field(request, "device-promotion-readiness-sha256"), device_promotion_hash)),
    ("authorization-request-binds-exact-capture", field(request, "exact-device-build") == TARGET_BUILD and field(request, "capture-id") == field(ownership, "capture-id") and bool(re.fullmatch(TOKEN, field(request, "capture-id") or "")) and field(request, "capture-timestamp-utc") == field(ownership, "capture-timestamp-utc")),
    ("authorization-times-are-valid-utc", all(value is not None for value in (capture_time, authorized_time, expires_time, evaluation_time))),
    ("ownership-snapshot-is-not-future-or-stale", capture_age is not None and 0 <= capture_age <= MAX_FRESHNESS_SECONDS),
    ("authorization-start-follows-capture-and-precedes-evaluation", capture_time is not None and authorized_time is not None and evaluation_time is not None and capture_time <= authorized_time <= evaluation_time),
    ("authorization-window-is-positive-and-bounded", authorization_window is not None and 0 < authorization_window <= MAX_FRESHNESS_SECONDS),
    ("evaluation-is-inside-authorization-window", authorized_time is not None and evaluation_time is not None and expires_time is not None and authorized_time <= evaluation_time <= expires_time),
    ("authorization-nonce-is-specific", bool(re.fullmatch(HASH, field(request, "authorization-nonce") or "")) and not re.fullmatch(r"0{64}", field(request, "authorization-nonce") or "")),
    ("authorization-use-count-is-exactly-one", decimal_value(request, "authorization-use-count") == 1),
    ("authorization-scope-is-one-bound-evidence-capture", field(request, "requested-wrapper-execution-scope") == "EXACTLY_ONCE_FOR_BOUND_EVIDENCE_CAPTURE_ONLY"),
    ("authority-authenticity-remains-declared-not-attested", field(request, "authorization-authority-authenticity") == "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED"),
    ("atomic-token-consumption-is-required-externally", field(request, "atomic-token-consumption") == "REQUIRED_BEFORE_WRAPPER_INVOCATION"),
    ("authorization-request-forbids-write-promotion-container-and-launch", field(request, "device-writes") == "NONE" and field(request, "persistent-writes") == "FORBIDDEN" and field(request, "slot-changes") == "FORBIDDEN" and field(request, "payload-launch-authorization") == "NO" and field(request, "dsc-fdf-promotion-authorization") == "NO" and field(request, "container-build-authorization") == "NO"),
    ("authorization-token-digest-is-canonical", expected_token is not None and equal_hash(declared_token, expected_token)),
    ("used-token-ledger-schema-is-present-once", len(values(ledger, "used-token-ledger-schema")) == 1 and field(ledger, "used-token-ledger-schema") == LEDGER_SCHEMA),
    ("used-token-ledger-entries-are-valid-and-unique", all(valid_hash(value) for value in used_tokens) and len({value.lower() for value in used_tokens}) == len(used_tokens)),
    ("authorization-token-is-unused-in-supplied-ledger", valid_hash(declared_token) and declared_token.lower() not in {value.lower() for value in used_tokens}),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 fresh one-shot execution-authorization readiness gate",
    "Verifier mode: HOST_SIDE_FRESHNESS_BINDING_AND_REPLAY_CHECK_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "Token ledger writes executed by verifier: NONE",
    "",
    f"runtime-ownership-report-sha256: {ownership_hash}",
    f"wrapper-execution-report-sha256: {wrapper_hash}",
    f"device-promotion-readiness-sha256: {device_promotion_hash}",
    f"authorization-request-sha256: {request_hash}",
    f"used-token-ledger-sha256: {ledger_hash}",
    f"authorization-token-sha256: {declared_token or 'MISSING'}",
    f"expected-authorization-token-sha256: {expected_token or 'UNAVAILABLE'}",
    f"capture-id: {field(request, 'capture-id') or 'MISSING'}",
    f"capture-timestamp-utc: {field(request, 'capture-timestamp-utc') or 'MISSING'}",
    f"authorized-at-utc: {field(request, 'authorized-at-utc') or 'MISSING'}",
    f"expires-at-utc: {field(request, 'expires-at-utc') or 'MISSING'}",
    f"evaluation-timestamp-utc: {EVALUATION_TEXT}",
    f"capture-age-seconds: {int(capture_age) if capture_age is not None else 'UNAVAILABLE'}",
    f"authorization-window-seconds: {int(authorization_window) if authorization_window is not None else 'UNAVAILABLE'}",
    f"used-token-count: {len(used_tokens)}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "ownership-evidence-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "authorization-authority-authenticity: DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED",
    "authorization-token-state: UNUSED_IN_SUPPLIED_LEDGER" if valid_hash(declared_token) and declared_token.lower() not in {value.lower() for value in used_tokens} else "authorization-token-state: INVALID_OR_ALREADY_USED",
    "atomic-token-consumption: REQUIRED_EXTERNAL",
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
        "classification: M7_ONE_SHOT_EXECUTION_AUTHORIZATION_READINESS_BLOCKED",
        "decision: the bound snapshot, upstream reports, freshness window, canonical token, single-use policy or supplied replay ledger failed. Do not invoke a wrapper, promote DSC/FDF files, build a container or run a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: INDEPENDENT_CAPTURE_AND_AUTHORITY_AUTHENTICATION_REQUIRED",
    "remaining-blocker: TOKEN_MUST_BE_ATOMICALLY_RECORDED_AS_USED_BEFORE_ANY_SEPARATELY_AUTHORIZED_INVOCATION",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_FRESH_ONE_SHOT_EXECUTION_TOKEN_READY_ATOMIC_CONSUMPTION_REQUIRED",
    "decision: the exact runtime-ownership snapshot is fresh at the supplied evaluation time, the request is byte-bound to the upstream chain, and its canonical token is absent from the supplied ledger. This host-only result is readiness evidence, not execution authorization: an independent authority must authenticate the evidence and atomically consume the token before any separately authorized wrapper invocation.",
])
