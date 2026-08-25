#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 9:
    raise SystemExit(
        "Usage: verify-m2-route-attestation.py "
        "<m2-manifest.txt> <route-evidence.txt> <trusted-key-manifest.txt> "
        "<authority-public-key.pem> <signed-envelope.txt> <detached-signature.bin> "
        "<verification-timestamp-utc> <output.txt>"
    )

M2_MANIFEST = Path(sys.argv[1])
ROUTE_EVIDENCE = Path(sys.argv[2])
KEY_MANIFEST = Path(sys.argv[3])
PUBLIC_KEY = Path(sys.argv[4])
ENVELOPE = Path(sys.argv[5])
SIGNATURE = Path(sys.argv[6])
VERIFICATION_TEXT = sys.argv[7]
OUT = Path(sys.argv[8])

KEY_SCHEMA = "IZZOS_M2_ROUTE_ATTESTER_KEY_V1"
ENVELOPE_SCHEMA = "IZZOS_M2_ROUTE_ATTESTATION_ENVELOPE_V1"
KEY_SCOPE = "M2_CONTENT_BOUND_TEMPORARY_ROUTE_EVIDENCE_ONLY"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

KEY_FIELDS = [
    "trusted-route-attester-key-schema",
    "authority-key-id",
    "authority-role",
    "signature-algorithm",
    "public-key-sha256",
    "valid-from-utc",
    "valid-until-utc",
    "key-revocation-status",
    "trust-anchor-state",
    "attestation-scope",
    "key-custody",
    "persistent-writes",
    "slot-changes",
    "route-specific-packaging-authorization",
    "payload-launch-authorization",
]

ENVELOPE_FIELDS = [
    "route-attestation-envelope-schema",
    "authority-key-id",
    "signature-algorithm",
    "m2-manifest-sha256",
    "content-bound-route-evidence-sha256",
    "exact-device-build",
    "selected-launch-route",
    "observation-id",
    "attestation-id",
    "observation-completed-at-utc",
    "attested-at-utc",
    "attestation-scope",
    "route-evidence-authenticity",
    "device-execution-observed",
    "diagnostic-payload-reached",
    "controlled-result-recorded",
    "stock-boot-restored",
    "persistent-writes-observed",
    "slot-change-observed",
    "user-data-mutation-observed",
    "route-specific-packaging-authorization",
    "payload-launch-authorization",
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


def run_tool(executable, arguments, timeout=20):
    if not executable:
        return False, "executable not found"
    try:
        completed = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
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


inputs = [M2_MANIFEST, ROUTE_EVIDENCE, KEY_MANIFEST, PUBLIC_KEY, ENVELOPE, SIGNATURE]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M2 route-attestation input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite an attestation input")

manifest_text = M2_MANIFEST.read_text(errors="replace")
route_text = ROUTE_EVIDENCE.read_text(errors="replace")
key_bytes = KEY_MANIFEST.read_bytes()
key_text = key_bytes.decode(errors="replace")
envelope_bytes = ENVELOPE.read_bytes()
envelope_text = envelope_bytes.decode(errors="replace")

manifest_hash = sha256(M2_MANIFEST)
route_hash = sha256(ROUTE_EVIDENCE)
key_manifest_hash = sha256(KEY_MANIFEST)
public_key_hash = sha256(PUBLIC_KEY)
envelope_hash = sha256(ENVELOPE)
signature_hash = sha256(SIGNATURE)
signature_size = SIGNATURE.stat().st_size

manifest_build = field(manifest_text, "Firmware ID")
manifest_route = field(manifest_text, "Selected launch route")
route_build = field(route_text, "Firmware ID")
route_name = field(route_text, "Selected launch route")

valid_from = parse_utc(field(key_text, "valid-from-utc"))
valid_until = parse_utc(field(key_text, "valid-until-utc"))
observed_at = parse_utc(field(envelope_text, "observation-completed-at-utc"))
attested_at = parse_utc(field(envelope_text, "attested-at-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)
key_lifetime = (valid_until - valid_from).total_seconds() if valid_from and valid_until else None

bash_name = os.environ.get("BASH", "bash")
bash_path = shutil.which(bash_name)
route_verifier = Path(__file__).with_name("verify-m2-route-evidence.sh")
route_gate_ok, route_gate_detail = run_tool(
    bash_path,
    [str(route_verifier), str(M2_MANIFEST), str(ROUTE_EVIDENCE)],
    timeout=120,
)
route_gate_classified = route_gate_ok and "classification: TEMPORARY_ROUTE_EVIDENCE_CONTENT_BOUND" in route_gate_detail

openssl_name = os.environ.get("OPENSSL", "openssl")
openssl_path = shutil.which(openssl_name)
key_ok, key_detail = run_tool(
    openssl_path,
    ["pkey", "-pubin", "-in", str(PUBLIC_KEY), "-text_pub", "-noout"],
)
signature_ok, signature_detail = run_tool(
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
public_key_is_pinned = equal_hash(field(key_text, "public-key-sha256"), public_key_hash)
pinned_signature_ok = signature_ok and key_is_ed25519 and public_key_is_pinned

checks = [
    ("upstream-content-bound-route-evidence-passes", route_gate_classified),
    ("manifest-and-route-evidence-target-one-exact-route", bool(manifest_build) and manifest_build == route_build and bool(manifest_route) and manifest_route == route_name),
    ("manifest-route-is-validated-but-remains-non-writing", field(manifest_text, "Route decision") == "TEMPORARY_ROUTE_VALIDATED" and field(manifest_text, "Persistent writes") == "FORBIDDEN" and field(manifest_text, "Slot changes") == "FORBIDDEN"),
    ("trusted-key-fields-are-present-once", all(len(values(key_text, label)) == 1 for label in KEY_FIELDS)),
    ("trusted-key-manifest-is-canonical", canonical_bytes(key_text, KEY_FIELDS) == key_bytes),
    ("trusted-key-schema-role-and-scope-are-exact", field(key_text, "trusted-route-attester-key-schema") == KEY_SCHEMA and field(key_text, "authority-role") == "M2_INDEPENDENT_TEMPORARY_ROUTE_ATTESTER" and field(key_text, "attestation-scope") == KEY_SCOPE),
    ("trusted-key-id-is-specific", bool(re.fullmatch(TOKEN, field(key_text, "authority-key-id") or ""))),
    ("trusted-key-algorithm-is-ed25519", field(key_text, "signature-algorithm") == "ED25519" and key_is_ed25519),
    ("trusted-key-manifest-pins-exact-public-key", public_key_is_pinned),
    ("trusted-key-validity-is-bounded", key_lifetime is not None and 0 < key_lifetime <= 366 * 24 * 60 * 60),
    ("trusted-key-is-valid-at-observation-attestation-and-verification", all(value is not None for value in (valid_from, valid_until, observed_at, attested_at, verification_time)) and valid_from <= observed_at <= attested_at <= verification_time <= valid_until),
    ("trusted-key-is-not-declared-revoked", field(key_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION"),
    ("trusted-key-governance-is-explicitly-pending", field(key_text, "trust-anchor-state") == "CALLER_SUPPLIED_PIN_PENDING_GOVERNANCE" and field(key_text, "key-custody") == "EXTERNAL_TO_VERIFIER"),
    ("trusted-key-manifest-denies-write-slot-packaging-and-launch", field(key_text, "persistent-writes") == "FORBIDDEN" and field(key_text, "slot-changes") == "FORBIDDEN" and field(key_text, "route-specific-packaging-authorization") == "NO" and field(key_text, "payload-launch-authorization") == "NO"),
    ("attestation-envelope-fields-are-present-once", all(len(values(envelope_text, label)) == 1 for label in ENVELOPE_FIELDS)),
    ("attestation-envelope-is-canonical", canonical_bytes(envelope_text, ENVELOPE_FIELDS) == envelope_bytes),
    ("attestation-envelope-schema-key-and-scope-are-exact", field(envelope_text, "route-attestation-envelope-schema") == ENVELOPE_SCHEMA and field(envelope_text, "authority-key-id") == field(key_text, "authority-key-id") and field(envelope_text, "signature-algorithm") == "ED25519" and field(envelope_text, "attestation-scope") == KEY_SCOPE),
    ("attestation-envelope-binds-exact-manifest-and-route-evidence", equal_hash(field(envelope_text, "m2-manifest-sha256"), manifest_hash) and equal_hash(field(envelope_text, "content-bound-route-evidence-sha256"), route_hash)),
    ("attestation-envelope-targets-exact-build-and-route", field(envelope_text, "exact-device-build") == manifest_build and field(envelope_text, "selected-launch-route") == manifest_route),
    ("attestation-identifiers-are-specific", bool(re.fullmatch(TOKEN, field(envelope_text, "observation-id") or "")) and bool(re.fullmatch(TOKEN, field(envelope_text, "attestation-id") or ""))),
    ("attestation-endorses-route-evidence-authenticity", field(envelope_text, "route-evidence-authenticity") == "INDEPENDENTLY_ATTESTED_BY_PINNED_KEY"),
    ("attestation-endorses-positive-observations", all(field(envelope_text, label) == "YES" for label in ("device-execution-observed", "diagnostic-payload-reached", "controlled-result-recorded", "stock-boot-restored"))),
    ("attestation-endorses-no-mutation-observations", all(field(envelope_text, label) == "NO" for label in ("persistent-writes-observed", "slot-change-observed", "user-data-mutation-observed"))),
    ("attestation-denies-packaging-and-launch-authorization", field(envelope_text, "route-specific-packaging-authorization") == "NO" and field(envelope_text, "payload-launch-authorization") == "NO"),
    ("detached-signature-size-is-ed25519", signature_size == 64),
    ("detached-signature-verifies-with-pinned-ed25519-key", pinned_signature_ok),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS internal M12 independent temporary-route attestation signature gate",
    "Verifier mode: HOST_SIDE_ED25519_SIGNATURE_AND_CALLER_KEY_PIN_ONLY",
    "OpenSSL executable: FOUND" if openssl_path else "OpenSSL executable: NOT_FOUND",
    "Bash route-evidence verifier: FOUND" if bash_path else "Bash route-evidence verifier: NOT_FOUND",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"m2-manifest-sha256: {manifest_hash}",
    f"content-bound-route-evidence-sha256: {route_hash}",
    f"trusted-key-manifest-sha256: {key_manifest_hash}",
    f"authority-public-key-sha256: {public_key_hash}",
    f"signed-attestation-envelope-sha256: {envelope_hash}",
    f"detached-signature-sha256: {signature_hash}",
    f"detached-signature-size: {signature_size}",
    f"authority-key-id: {field(key_text, 'authority-key-id') or 'MISSING'}",
    f"attestation-id: {field(envelope_text, 'attestation-id') or 'MISSING'}",
    f"exact-device-build: {field(envelope_text, 'exact-device-build') or 'MISSING'}",
    f"selected-launch-route: {field(envelope_text, 'selected-launch-route') or 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "signature-verification: PASS" if signature_ok and key_is_ed25519 else "signature-verification: FAIL",
    "attestation-endorsement: CRYPTOGRAPHICALLY_VERIFIED_TO_CALLER_PINNED_KEY" if pinned_signature_ok else "attestation-endorsement: NOT_VERIFIED_TO_CALLER_PINNED_KEY",
    "physical-device-truth: ATTESTER_ENDORSEMENT_NOT_MEASURED_BY_VERIFIER",
    "route-specific-packaging-authorization: NO",
    "payload-launch-authorization: NO",
    "device-commands: NONE",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M2_ROUTE_ATTESTATION_SIGNATURE_BLOCKED",
        "decision: the canonical envelope, content binding, pinned Ed25519 key, signature, validity interval or no-write/no-launch policy failed. Do not trust the route attestation or authorize packaging/launch.",
    ], 1)

emit(lines + [
    "remaining-blocker: ROUTE_ATTESTER_KEY_CUSTODY_REVOCATION_AND_ROTATION_GOVERNANCE_REQUIRED",
    "remaining-blocker: SIGNED_ATTESTER_ENDORSEMENT_DOES_NOT_ITSELF_PROVE_PHYSICAL_DEVICE_TRUTH",
    "remaining-blocker: ROUTE_SPECIFIC_PACKAGING_REMAINS_UNAUTHORIZED",
    "remaining-blocker: DEVICE_LAUNCH_REMAINS_UNAUTHORIZED",
    "classification: M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED",
    "decision: OpenSSL verified the exact canonical envelope against the caller-pinned Ed25519 public key, and the signed bytes bind the M2 manifest plus M11 content-bound route evidence. This proves that key endorsed those bytes; it does not establish key governance, independently measure the phone, authorize route-specific packaging or authorize launch.",
])
