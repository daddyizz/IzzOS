#!/usr/bin/env python3
import hashlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 6:
    raise SystemExit(
        "Usage: verify-m2-route-governance-root-enrollment.py "
        "<m13-governance-report.txt> <governance-root-manifest.txt> "
        "<governance-root-public-key.pem> <verification-timestamp-utc> <output.txt>"
    )

M13_REPORT = Path(sys.argv[1])
ROOT_MANIFEST = Path(sys.argv[2])
ROOT_KEY = Path(sys.argv[3])
VERIFICATION_TEXT = sys.argv[4]
OUT = Path(sys.argv[5])
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ENROLLMENT = REPOSITORY_ROOT / "config" / "m2-route-governance-root-enrollment.txt"
ENROLLED_KEY = REPOSITORY_ROOT / "config" / "m2-route-governance-root-test-public.pem"

ROOT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1"
ENROLLMENT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ENROLLMENT_V1"
GOVERNANCE_SCOPE = "M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

ROOT_FIELDS = [
    "route-governance-root-schema", "governance-root-key-id", "governance-root-role",
    "signature-algorithm", "public-key-sha256", "valid-from-utc", "valid-until-utc",
    "key-revocation-status", "trust-anchor-state", "governance-scope", "key-custody",
    "persistent-writes", "slot-changes", "route-specific-packaging-authorization",
    "payload-launch-authorization",
]
ENROLLMENT_FIELDS = [
    "route-governance-root-enrollment-schema", "enrollment-id", "governance-root-key-id",
    "governance-root-public-key-path", "governance-root-public-key-sha256",
    "enrollment-environment", "repository-review-policy", "root-custody-policy",
    "scheduled-rotation-policy", "emergency-recovery-policy", "effective-from-utc",
    "valid-until-utc", "governance-scope", "persistent-writes", "slot-changes",
    "route-specific-packaging-authorization", "payload-launch-authorization",
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
    executable = shutil.which("openssl")
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


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [M13_REPORT, ROOT_MANIFEST, ROOT_KEY, ENROLLMENT, ENROLLED_KEY]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M14 root-enrollment input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an enrollment input or key")

m13_text = M13_REPORT.read_text(errors="replace")
root_bytes = ROOT_MANIFEST.read_bytes()
root_text = root_bytes.decode(errors="replace")
enrollment_bytes = ENROLLMENT.read_bytes()
enrollment_text = enrollment_bytes.decode(errors="replace")

m13_hash = sha256(M13_REPORT)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
enrollment_hash = sha256(ENROLLMENT)
enrolled_key_hash = sha256(ENROLLED_KEY)
effective_from = parse_utc(field(enrollment_text, "effective-from-utc"))
valid_until = parse_utc(field(enrollment_text, "valid-until-utc"))
root_from = parse_utc(field(root_text, "valid-from-utc"))
root_until = parse_utc(field(root_text, "valid-until-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)

checks = [
    ("upstream-m13-governance-signature-gate-passes", field(m13_text, "classification") == "M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED" and field(m13_text, "policy-signature-verification") == "PASS" and field(m13_text, "registry-signature-verification") == "PASS" and field(m13_text, "governance-root-trust") == "CALLER_PINNED_ROOT_NOT_REPOSITORY_ENROLLED"),
    ("upstream-m13-report-remains-non-authorizing", field(m13_text, "route-specific-packaging-authorization") == "NO" and field(m13_text, "payload-launch-authorization") == "NO" and field(m13_text, "persistent-writes") == "FORBIDDEN" and field(m13_text, "slot-changes") == "FORBIDDEN"),
    ("root-manifest-fields-are-present-once-and-canonical", all(len(values(root_text, label)) == 1 for label in ROOT_FIELDS) and canonical_bytes(root_text, ROOT_FIELDS) == root_bytes),
    ("root-manifest-schema-role-scope-and-state-are-exact", field(root_text, "route-governance-root-schema") == ROOT_SCHEMA and field(root_text, "governance-root-role") == "M2_ROUTE_ATTESTER_GOVERNANCE_ROOT" and field(root_text, "signature-algorithm") == "ED25519" and field(root_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_text, "trust-anchor-state") == "CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT" and field(root_text, "governance-scope") == GOVERNANCE_SCOPE and field(root_text, "key-custody") == "EXTERNAL_TO_ROUTE_ATTESTER"),
    ("root-manifest-remains-non-authorizing", field(root_text, "persistent-writes") == "FORBIDDEN" and field(root_text, "slot-changes") == "FORBIDDEN" and field(root_text, "route-specific-packaging-authorization") == "NO" and field(root_text, "payload-launch-authorization") == "NO"),
    ("root-key-is-ed25519-and-manifest-pinned", is_ed25519(ROOT_KEY) and equal_hash(field(root_text, "public-key-sha256"), root_key_hash)),
    ("upstream-m13-report-binds-exact-root-manifest-and-key", equal_hash(field(m13_text, "governance-root-manifest-sha256"), root_manifest_hash) and equal_hash(field(m13_text, "governance-root-public-key-sha256"), root_key_hash)),
    ("repository-enrollment-fields-are-present-once-and-canonical", all(len(values(enrollment_text, label)) == 1 for label in ENROLLMENT_FIELDS) and canonical_bytes(enrollment_text, ENROLLMENT_FIELDS) == enrollment_bytes),
    ("repository-enrollment-schema-id-root-and-path-are-exact", field(enrollment_text, "route-governance-root-enrollment-schema") == ENROLLMENT_SCHEMA and bool(re.fullmatch(TOKEN, field(enrollment_text, "enrollment-id") or "")) and field(enrollment_text, "governance-root-key-id") == field(root_text, "governance-root-key-id") and field(enrollment_text, "governance-root-public-key-path") == "config/m2-route-governance-root-test-public.pem"),
    ("repository-enrollment-enforces-exact-public-key-bytes", equal_hash(field(enrollment_text, "governance-root-public-key-sha256"), enrolled_key_hash) and root_key_hash == enrolled_key_hash and ROOT_KEY.read_bytes() == ENROLLED_KEY.read_bytes()),
    ("repository-enrollment-is-explicitly-host-test-only", field(enrollment_text, "enrollment-environment") == "HOST_TEST_ONLY_NOT_PRODUCTION"),
    ("repository-review-custody-rotation-and-recovery-policies-are-exact", field(enrollment_text, "repository-review-policy") == "TWO_PERSON_REVIEW_REQUIRED_FOR_PRODUCTION_REPLACEMENT" and field(enrollment_text, "root-custody-policy") == "OFFLINE_EXTERNAL_TO_REPOSITORY_ATTESTER_AND_LAUNCH_OPERATOR" and field(enrollment_text, "scheduled-rotation-policy") == "DUAL_CONTROL_CURRENT_AND_REPLACEMENT_ROOT_REQUIRED" and field(enrollment_text, "emergency-recovery-policy") == "EXTERNAL_2_OF_3_CUSTODIAN_QUORUM_REQUIRED"),
    ("repository-enrollment-scope-and-policy-remain-non-authorizing", field(enrollment_text, "governance-scope") == GOVERNANCE_SCOPE and field(enrollment_text, "persistent-writes") == "FORBIDDEN" and field(enrollment_text, "slot-changes") == "FORBIDDEN" and field(enrollment_text, "route-specific-packaging-authorization") == "NO" and field(enrollment_text, "payload-launch-authorization") == "NO"),
    ("enrollment-root-and-verification-validity-order-passes", all(value is not None for value in (effective_from, valid_until, root_from, root_until, verification_time)) and root_from <= effective_from <= verification_time <= valid_until <= root_until),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS internal M14 repository governance-root enrollment contract gate",
    "Verifier mode: FIXED_REPOSITORY_HOST_TEST_ROOT_SHA256_PIN_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"upstream-m13-governance-report-sha256: {m13_hash}",
    f"governance-root-manifest-sha256: {root_manifest_hash}",
    f"governance-root-public-key-sha256: {root_key_hash}",
    f"repository-enrollment-record-sha256: {enrollment_hash}",
    f"repository-enrolled-public-key-sha256: {enrolled_key_hash}",
    f"repository-enrollment-id: {field(enrollment_text, 'enrollment-id') or 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "repository-enrollment-environment: HOST_TEST_ONLY_NOT_PRODUCTION",
    "physical-device-truth: NOT_MEASURED_BY_ENROLLMENT_VERIFIER",
    "route-specific-packaging-authorization: NO",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_BLOCKED",
        "decision: reject the supplied M13/root chain because it does not match the exact fixed repository host-test enrollment contract or its no-write/no-launch policy.",
    ], 1)

emit(lines + [
    "remaining-blocker: PRODUCTION_GOVERNANCE_ROOT_AND_INDEPENDENT_CUSTODY_REQUIRED",
    "remaining-blocker: MONOTONIC_ROOT_TRANSITION_AND_RECOVERY_PUBLICATION_REQUIRED",
    "remaining-blocker: EXACT_DEVICE_PHYSICAL_ROUTE_EVIDENCE_REQUIRED",
    "classification: M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_PASS_PRODUCTION_ROOT_REQUIRED",
    "decision: the exact M13 root matches the fixed repository host-test enrollment record and public-key bytes. This validates repository enforcement mechanics only; the test root is not a production authority and no device action is authorized.",
])
