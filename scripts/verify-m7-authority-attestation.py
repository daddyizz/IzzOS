#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 8:
    raise SystemExit(
        "Usage: verify-m7-authority-attestation.py "
        "<token-consumption-result-report.txt> <trusted-key-manifest.txt> "
        "<authority-public-key.pem> <signed-attestation-envelope.txt> "
        "<detached-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

RESULT_REPORT = Path(sys.argv[1])
KEY_MANIFEST = Path(sys.argv[2])
PUBLIC_KEY = Path(sys.argv[3])
ENVELOPE = Path(sys.argv[4])
SIGNATURE = Path(sys.argv[5])
VERIFICATION_TEXT = sys.argv[6]
OUT = Path(sys.argv[7])

KEY_SCHEMA = "IZZOS_M7_TRUSTED_AUTHORITY_KEY_V1"
ENVELOPE_SCHEMA = "IZZOS_M7_AUTHORITY_ATTESTATION_ENVELOPE_V1"
TARGET_BUILD = "CPH2413_15.0.0.1901(EX01)"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

KEY_FIELDS = [
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

ENVELOPE_FIELDS = [
    "attestation-envelope-schema",
    "authority-key-id",
    "signature-algorithm",
    "token-consumption-execution-result-report-sha256",
    "authorization-token-sha256",
    "token-consumption-receipt-sha256",
    "execution-evidence-artifact-sha256",
    "exact-device-build",
    "capture-id",
    "attestation-id",
    "attested-at-utc",
    "attestation-scope",
    "capture-authenticity",
    "token-consumption-atomicity",
    "wrapper-execution-authenticity",
    "device-route-authenticity",
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


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [RESULT_REPORT, KEY_MANIFEST, PUBLIC_KEY, ENVELOPE, SIGNATURE]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 authority-attestation input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an attestation, key, signature or bound report")

result_report = RESULT_REPORT.read_text(errors="replace")
key_manifest_bytes = KEY_MANIFEST.read_bytes()
key_manifest = key_manifest_bytes.decode(errors="replace")
envelope_bytes = ENVELOPE.read_bytes()
envelope = envelope_bytes.decode(errors="replace")

result_report_hash = sha256(RESULT_REPORT)
key_manifest_hash = sha256(KEY_MANIFEST)
public_key_hash = sha256(PUBLIC_KEY)
envelope_hash = sha256(ENVELOPE)
signature_hash = sha256(SIGNATURE)
signature_size = SIGNATURE.stat().st_size

valid_from = parse_utc(field(key_manifest, "valid-from-utc"))
valid_until = parse_utc(field(key_manifest, "valid-until-utc"))
attested_at = parse_utc(field(envelope, "attested-at-utc"))
execution_completed = parse_utc(field(result_report, "execution-completed-at-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
key_lifetime = (valid_until - valid_from).total_seconds() if valid_from and valid_until else None

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
key_ok, key_detail = openssl_run(
    openssl_path,
    ["pkey", "-pubin", "-in", str(PUBLIC_KEY), "-text_pub", "-noout"],
)
signature_ok, signature_detail = openssl_run(
    openssl_path,
    [
        "pkeyutl",
        "-verify",
        "-pubin",
        "-inkey",
        str(PUBLIC_KEY),
        "-rawin",
        "-in",
        str(ENVELOPE),
        "-sigfile",
        str(SIGNATURE),
    ],
)
key_is_ed25519 = key_ok and "ED25519" in key_detail.upper()
public_key_is_pinned = equal_hash(field(key_manifest, "public-key-sha256"), public_key_hash)
pinned_signature_ok = signature_ok and key_is_ed25519 and public_key_is_pinned

checks = [
    ("upstream-token-consumption-result-classification-passes", field(result_report, "classification") == "M7_TOKEN_CONSUMPTION_RESULT_SCHEMA_PASS_ATOMICITY_AUTHENTICITY_REQUIRED"),
    ("upstream-result-remains-self-reported-and-non-authorizing", field(result_report, "atomicity-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED" and field(result_report, "execution-result-authenticity") == "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED" and field(result_report, "wrapper-execution-proof") == "NOT_INDEPENDENTLY_ATTESTED" and field(result_report, "wrapper-execution-authorization") == "NO" and field(result_report, "launch-authorization") == "NO"),
    ("upstream-result-targets-exact-capture", field(result_report, "exact-device-build") == TARGET_BUILD and bool(re.fullmatch(TOKEN, field(result_report, "capture-id") or ""))),
    ("upstream-result-hashes-are-specific", all(valid_hash(field(result_report, label)) for label in ("authorization-token-sha256", "token-consumption-receipt-sha256", "execution-evidence-artifact-sha256"))),
    ("trusted-key-fields-are-present-once", all(len(values(key_manifest, label)) == 1 for label in KEY_FIELDS)),
    ("trusted-key-manifest-is-canonical", canonical_bytes(key_manifest, KEY_FIELDS) == key_manifest_bytes),
    ("trusted-key-schema-role-and-scope-are-exact", field(key_manifest, "trusted-authority-key-schema") == KEY_SCHEMA and field(key_manifest, "authority-role") == "M7_INDEPENDENT_CAPTURE_AND_EXECUTION_ATTESTER" and field(key_manifest, "attestation-scope") == "M7_BOUND_TOKEN_CONSUMPTION_AND_WRAPPER_EVIDENCE_RESULT_ONLY"),
    ("trusted-key-id-is-specific", bool(re.fullmatch(TOKEN, field(key_manifest, "authority-key-id") or ""))),
    ("trusted-key-algorithm-is-ed25519", field(key_manifest, "signature-algorithm") == "ED25519" and key_is_ed25519),
    ("trusted-key-manifest-pins-exact-public-key", public_key_is_pinned),
    ("trusted-key-validity-is-bounded", key_lifetime is not None and 0 < key_lifetime <= 366 * 24 * 60 * 60),
    ("trusted-key-is-valid-at-attestation-and-verification", all(value is not None for value in (valid_from, valid_until, attested_at, verification_time)) and valid_from <= attested_at <= verification_time <= valid_until),
    ("trusted-key-is-not-declared-revoked", field(key_manifest, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION"),
    ("trusted-key-source-and-custody-are-explicit", field(key_manifest, "trust-anchor-source") == "REPOSITORY_REVIEWED_SHA256_PIN" and field(key_manifest, "key-custody") == "EXTERNAL_TO_VERIFIER"),
    ("trusted-key-manifest-denies-write-slot-and-launch", field(key_manifest, "persistent-writes") == "FORBIDDEN" and field(key_manifest, "slot-changes") == "FORBIDDEN" and field(key_manifest, "payload-launch-authorization") == "NO"),
    ("attestation-envelope-fields-are-present-once", all(len(values(envelope, label)) == 1 for label in ENVELOPE_FIELDS)),
    ("attestation-envelope-is-canonical", canonical_bytes(envelope, ENVELOPE_FIELDS) == envelope_bytes),
    ("attestation-envelope-schema-key-and-scope-are-exact", field(envelope, "attestation-envelope-schema") == ENVELOPE_SCHEMA and field(envelope, "authority-key-id") == field(key_manifest, "authority-key-id") and field(envelope, "signature-algorithm") == "ED25519" and field(envelope, "attestation-scope") == field(key_manifest, "attestation-scope")),
    ("attestation-envelope-binds-upstream-result", equal_hash(field(envelope, "token-consumption-execution-result-report-sha256"), result_report_hash)),
    ("attestation-envelope-binds-token-receipt-and-evidence", equal_hash(field(envelope, "authorization-token-sha256"), field(result_report, "authorization-token-sha256")) and equal_hash(field(envelope, "token-consumption-receipt-sha256"), field(result_report, "token-consumption-receipt-sha256")) and equal_hash(field(envelope, "execution-evidence-artifact-sha256"), field(result_report, "execution-evidence-artifact-sha256"))),
    ("attestation-envelope-targets-exact-capture", field(envelope, "exact-device-build") == TARGET_BUILD and field(envelope, "capture-id") == field(result_report, "capture-id") and bool(re.fullmatch(TOKEN, field(envelope, "attestation-id") or ""))),
    ("attestation-follows-bound-execution-result", execution_completed is not None and attested_at is not None and execution_completed <= attested_at),
    ("attestation-endorses-exact-independent-claims", field(envelope, "capture-authenticity") == "INDEPENDENTLY_ATTESTED_BY_PINNED_KEY" and field(envelope, "token-consumption-atomicity") == "INDEPENDENTLY_ATTESTED_BY_PINNED_KEY" and field(envelope, "wrapper-execution-authenticity") == "INDEPENDENTLY_ATTESTED_BY_PINNED_KEY" and field(envelope, "device-route-authenticity") == "INDEPENDENTLY_ATTESTED_BY_PINNED_KEY"),
    ("attestation-forbids-smc-mmio-device-write-and-launch", field(envelope, "smc-calls") == "NONE" and field(envelope, "mmio-writes") == "NONE" and field(envelope, "device-storage-writes") == "NONE" and field(envelope, "persistent-writes") == "FORBIDDEN" and field(envelope, "slot-changes") == "FORBIDDEN" and field(envelope, "payload-launch-authorization") == "NO" and field(envelope, "dsc-fdf-promotion-authorization") == "NO" and field(envelope, "container-build-authorization") == "NO"),
    ("detached-signature-size-is-ed25519", signature_size == 64),
    ("detached-signature-verifies-with-pinned-ed25519-key", pinned_signature_ok),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS Milestone 7 independent authority-attestation signature gate",
    "Verifier mode: HOST_SIDE_ED25519_SIGNATURE_AND_REPOSITORY_KEY_PIN_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"token-consumption-execution-result-report-sha256: {result_report_hash}",
    f"trusted-key-manifest-sha256: {key_manifest_hash}",
    f"authority-public-key-sha256: {public_key_hash}",
    f"signed-attestation-envelope-sha256: {envelope_hash}",
    f"detached-signature-sha256: {signature_hash}",
    f"detached-signature-size: {signature_size}",
    f"authority-key-id: {field(key_manifest, 'authority-key-id') or 'MISSING'}",
    f"attestation-id: {field(envelope, 'attestation-id') or 'MISSING'}",
    f"exact-device-build: {field(envelope, 'exact-device-build') or 'MISSING'}",
    f"capture-id: {field(envelope, 'capture-id') or 'MISSING'}",
    f"attested-at-utc: {field(envelope, 'attested-at-utc') or 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "signature-verification: PASS" if signature_ok and key_is_ed25519 else "signature-verification: FAIL",
    "attestation-endorsement: CRYPTOGRAPHICALLY_VERIFIED_TO_REPOSITORY_PINNED_KEY" if pinned_signature_ok else "attestation-endorsement: NOT_VERIFIED_TO_REPOSITORY_PINNED_KEY",
    "physical-device-truth: ATTESTER_ENDORSEMENT_NOT_MEASURED_BY_VERIFIER",
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
        "classification: M7_AUTHORITY_ATTESTATION_SIGNATURE_BLOCKED",
        "decision: the pinned key, canonical signed envelope, validity period, detached Ed25519 signature, upstream byte binding or no-write/no-launch policy failed. Do not treat the attestation as authentic and do not authorize a device command.",
    ], 1)

emit(lines + [
    "remaining-blocker: TRUSTED_KEY_CUSTODY_REVOCATION_AND_ROTATION_GOVERNANCE_REQUIRED",
    "remaining-blocker: SIGNED_ATTESTER_ENDORSEMENT_DOES_NOT_ITSELF_PROVE_PHYSICAL_DEVICE_TRUTH",
    "remaining-blocker: DEVICE_EXECUTION_ROUTE_REMAINS_UNAUTHORIZED",
    "classification: M7_AUTHORITY_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED",
    "decision: OpenSSL verified the exact canonical envelope against the exact repository-pinned Ed25519 public key, and the signed claims bind the upstream token-consumption/result report. This proves the key endorsed those bytes; it does not establish key custody or revocation governance, independently measure the phone, retroactively authorize execution, promote DSC/FDF files, build a container or authorize launch.",
])
