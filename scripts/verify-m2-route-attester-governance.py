#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


if len(sys.argv) != 12:
    raise SystemExit(
        "Usage: verify-m2-route-attester-governance.py "
        "<route-attestation-report.txt> <active-key-manifest.txt> <active-public-key.pem> "
        "<governance-root-manifest.txt> <governance-root-public-key.pem> "
        "<governance-policy.txt> <policy-signature.bin> <revocation-registry.txt> "
        "<registry-signature.bin> <verification-timestamp-utc> <output.txt>"
    )

ATTESTATION = Path(sys.argv[1])
ACTIVE_MANIFEST = Path(sys.argv[2])
ACTIVE_KEY = Path(sys.argv[3])
ROOT_MANIFEST = Path(sys.argv[4])
ROOT_KEY = Path(sys.argv[5])
POLICY = Path(sys.argv[6])
POLICY_SIGNATURE = Path(sys.argv[7])
REGISTRY = Path(sys.argv[8])
REGISTRY_SIGNATURE = Path(sys.argv[9])
VERIFICATION_TEXT = sys.argv[10]
OUT = Path(sys.argv[11])

ACTIVE_SCHEMA = "IZZOS_M2_ROUTE_ATTESTER_KEY_V1"
ROOT_SCHEMA = "IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1"
POLICY_SCHEMA = "IZZOS_M2_ROUTE_ATTESTER_GOVERNANCE_POLICY_V1"
REGISTRY_SCHEMA = "IZZOS_M2_ROUTE_ATTESTER_REVOCATION_REGISTRY_V1"
ATTESTATION_SCOPE = "M2_CONTENT_BOUND_TEMPORARY_ROUTE_EVIDENCE_ONLY"
GOVERNANCE_SCOPE = "M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY"
HASH = r"[0-9A-Fa-f]{64}"
TOKEN = r"[A-Za-z0-9_.-]+"

ACTIVE_FIELDS = [
    "trusted-route-attester-key-schema", "authority-key-id", "authority-role",
    "signature-algorithm", "public-key-sha256", "valid-from-utc", "valid-until-utc",
    "key-revocation-status", "trust-anchor-state", "attestation-scope", "key-custody",
    "persistent-writes", "slot-changes", "route-specific-packaging-authorization",
    "payload-launch-authorization",
]
ROOT_FIELDS = [
    "route-governance-root-schema", "governance-root-key-id", "governance-root-role",
    "signature-algorithm", "public-key-sha256", "valid-from-utc", "valid-until-utc",
    "key-revocation-status", "trust-anchor-state", "governance-scope", "key-custody",
    "persistent-writes", "slot-changes", "route-specific-packaging-authorization",
    "payload-launch-authorization",
]
POLICY_FIELDS = [
    "route-attester-governance-policy-schema", "governance-root-key-id",
    "governance-epoch", "governance-sequence", "previous-governance-policy-sha256",
    "upstream-route-attestation-report-sha256", "active-authority-key-id",
    "active-authority-public-key-sha256", "active-authority-key-manifest-sha256",
    "revocation-registry-sha256", "custody-separation", "scheduled-rotation-policy",
    "emergency-revocation-policy", "issued-at-utc", "effective-at-utc",
    "governance-scope", "persistent-writes", "slot-changes",
    "route-specific-packaging-authorization", "payload-launch-authorization",
]
REGISTRY_FIELDS = [
    "route-attester-revocation-registry-schema", "governance-root-key-id",
    "governance-epoch", "governance-sequence", "active-authority-key-id",
    "active-authority-public-key-sha256", "active-authority-key-status",
    "replacement-authority-key-id", "latest-revocation-event-id", "generated-at-utc",
    "valid-until-utc", "registry-scope", "persistent-writes", "slot-changes",
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


def number(text, label):
    value = field(text, label)
    return int(value) if value and re.fullmatch(r"[0-9]+", value) else None


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
            [executable, *arguments], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def verify_signature(executable, key, record, signature):
    return openssl_run(executable, [
        "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
        "-in", str(record), "-sigfile", str(signature),
    ])[0]


def is_ed25519(executable, key):
    passed, detail = openssl_run(
        executable, ["pkey", "-pubin", "-in", str(key), "-text_pub", "-noout"]
    )
    return passed and "ED25519" in detail.upper()


def emit(lines, exit_code=0):
    rendered = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, newline="\n")
    print(rendered, end="")
    if exit_code:
        raise SystemExit(exit_code)


inputs = [ATTESTATION, ACTIVE_MANIFEST, ACTIVE_KEY, ROOT_MANIFEST, ROOT_KEY,
          POLICY, POLICY_SIGNATURE, REGISTRY, REGISTRY_SIGNATURE]
for required in inputs:
    if not required.is_file():
        raise SystemExit(f"ERROR: required M2 route-attester governance input not found: {required}")
if OUT.resolve() in {path.resolve() for path in inputs}:
    raise SystemExit("ERROR: output must not overwrite a governance input, key or signature")

attestation_text = ATTESTATION.read_text(errors="replace")
active_bytes = ACTIVE_MANIFEST.read_bytes()
active_text = active_bytes.decode(errors="replace")
root_bytes = ROOT_MANIFEST.read_bytes()
root_text = root_bytes.decode(errors="replace")
policy_bytes = POLICY.read_bytes()
policy_text = policy_bytes.decode(errors="replace")
registry_bytes = REGISTRY.read_bytes()
registry_text = registry_bytes.decode(errors="replace")

attestation_hash = sha256(ATTESTATION)
active_manifest_hash = sha256(ACTIVE_MANIFEST)
active_key_hash = sha256(ACTIVE_KEY)
root_manifest_hash = sha256(ROOT_MANIFEST)
root_key_hash = sha256(ROOT_KEY)
policy_hash = sha256(POLICY)
registry_hash = sha256(REGISTRY)
policy_signature_hash = sha256(POLICY_SIGNATURE)
registry_signature_hash = sha256(REGISTRY_SIGNATURE)

active_from = parse_utc(field(active_text, "valid-from-utc"))
active_until = parse_utc(field(active_text, "valid-until-utc"))
root_from = parse_utc(field(root_text, "valid-from-utc"))
root_until = parse_utc(field(root_text, "valid-until-utc"))
issued_at = parse_utc(field(policy_text, "issued-at-utc"))
effective_at = parse_utc(field(policy_text, "effective-at-utc"))
registry_generated = parse_utc(field(registry_text, "generated-at-utc"))
registry_until = parse_utc(field(registry_text, "valid-until-utc"))
verification_time = parse_utc(VERIFICATION_TEXT)

epoch = number(policy_text, "governance-epoch")
sequence = number(policy_text, "governance-sequence")
registry_epoch = number(registry_text, "governance-epoch")
registry_sequence = number(registry_text, "governance-sequence")

openssl_path = shutil.which(os.environ.get("OPENSSL", "openssl"))
root_is_ed25519 = is_ed25519(openssl_path, ROOT_KEY)
active_is_ed25519 = is_ed25519(openssl_path, ACTIVE_KEY)
root_key_pinned = equal_hash(field(root_text, "public-key-sha256"), root_key_hash)
active_key_pinned = equal_hash(field(active_text, "public-key-sha256"), active_key_hash)
policy_signature_ok = verify_signature(openssl_path, ROOT_KEY, POLICY, POLICY_SIGNATURE)
registry_signature_ok = verify_signature(openssl_path, ROOT_KEY, REGISTRY, REGISTRY_SIGNATURE)

checks = [
    ("upstream-m12-signature-report-passes-but-requires-governance", field(attestation_text, "classification") == "M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED" and field(attestation_text, "signature-verification") == "PASS" and field(attestation_text, "attestation-endorsement") == "CRYPTOGRAPHICALLY_VERIFIED_TO_CALLER_PINNED_KEY"),
    ("upstream-report-remains-non-authorizing", field(attestation_text, "route-specific-packaging-authorization") == "NO" and field(attestation_text, "payload-launch-authorization") == "NO"),
    ("active-key-fields-are-present-once-and-canonical", all(len(values(active_text, label)) == 1 for label in ACTIVE_FIELDS) and canonical_bytes(active_text, ACTIVE_FIELDS) == active_bytes),
    ("active-key-schema-role-scope-and-pin-pass", field(active_text, "trusted-route-attester-key-schema") == ACTIVE_SCHEMA and field(active_text, "authority-role") == "M2_INDEPENDENT_TEMPORARY_ROUTE_ATTESTER" and field(active_text, "attestation-scope") == ATTESTATION_SCOPE and field(active_text, "signature-algorithm") == "ED25519" and active_is_ed25519 and active_key_pinned),
    ("active-key-is-bound-to-upstream-report", field(active_text, "authority-key-id") == field(attestation_text, "authority-key-id") and equal_hash(field(attestation_text, "trusted-key-manifest-sha256"), active_manifest_hash) and equal_hash(field(attestation_text, "authority-public-key-sha256"), active_key_hash)),
    ("active-key-pending-trust-state-and-custody-are-exact", field(active_text, "trust-anchor-state") == "CALLER_SUPPLIED_PIN_PENDING_GOVERNANCE" and field(active_text, "key-custody") == "EXTERNAL_TO_VERIFIER"),
    ("active-key-remains-not-revoked-and-non-authorizing", field(active_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(active_text, "persistent-writes") == "FORBIDDEN" and field(active_text, "slot-changes") == "FORBIDDEN" and field(active_text, "route-specific-packaging-authorization") == "NO" and field(active_text, "payload-launch-authorization") == "NO"),
    ("root-fields-are-present-once-and-canonical", all(len(values(root_text, label)) == 1 for label in ROOT_FIELDS) and canonical_bytes(root_text, ROOT_FIELDS) == root_bytes),
    ("root-schema-role-scope-and-pin-pass", field(root_text, "route-governance-root-schema") == ROOT_SCHEMA and field(root_text, "governance-root-role") == "M2_ROUTE_ATTESTER_GOVERNANCE_ROOT" and field(root_text, "governance-scope") == GOVERNANCE_SCOPE and field(root_text, "signature-algorithm") == "ED25519" and root_is_ed25519 and root_key_pinned),
    ("root-is-unrevoked-separated-and-explicitly-pending-enrollment", field(root_text, "key-revocation-status") == "NOT_REVOKED_AT_VERIFICATION" and field(root_text, "trust-anchor-state") == "CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT" and field(root_text, "key-custody") == "EXTERNAL_TO_ROUTE_ATTESTER"),
    ("root-remains-non-authorizing", field(root_text, "persistent-writes") == "FORBIDDEN" and field(root_text, "slot-changes") == "FORBIDDEN" and field(root_text, "route-specific-packaging-authorization") == "NO" and field(root_text, "payload-launch-authorization") == "NO"),
    ("policy-fields-are-present-once-and-canonical", all(len(values(policy_text, label)) == 1 for label in POLICY_FIELDS) and canonical_bytes(policy_text, POLICY_FIELDS) == policy_bytes),
    ("policy-schema-root-epoch-sequence-and-history-pass", field(policy_text, "route-attester-governance-policy-schema") == POLICY_SCHEMA and field(policy_text, "governance-root-key-id") == field(root_text, "governance-root-key-id") and epoch is not None and epoch > 0 and sequence is not None and sequence > 0 and valid_hash(field(policy_text, "previous-governance-policy-sha256"))),
    ("policy-binds-upstream-active-key-and-registry", equal_hash(field(policy_text, "upstream-route-attestation-report-sha256"), attestation_hash) and field(policy_text, "active-authority-key-id") == field(active_text, "authority-key-id") and equal_hash(field(policy_text, "active-authority-public-key-sha256"), active_key_hash) and equal_hash(field(policy_text, "active-authority-key-manifest-sha256"), active_manifest_hash) and equal_hash(field(policy_text, "revocation-registry-sha256"), registry_hash)),
    ("policy-custody-rotation-revocation-and-scope-are-exact", field(policy_text, "custody-separation") == "GOVERNANCE_ROOT_EXTERNAL_TO_ROUTE_ATTESTER_AND_LAUNCH_OPERATOR" and field(policy_text, "scheduled-rotation-policy") == "DUAL_CONTROL_ROOT_SIGNED_REPLACEMENT_REQUIRED" and field(policy_text, "emergency-revocation-policy") == "ROOT_SIGNED_IMMEDIATE_REVOCATION_REQUIRED" and field(policy_text, "governance-scope") == GOVERNANCE_SCOPE),
    ("policy-remains-non-authorizing", field(policy_text, "persistent-writes") == "FORBIDDEN" and field(policy_text, "slot-changes") == "FORBIDDEN" and field(policy_text, "route-specific-packaging-authorization") == "NO" and field(policy_text, "payload-launch-authorization") == "NO"),
    ("registry-fields-are-present-once-and-canonical", all(len(values(registry_text, label)) == 1 for label in REGISTRY_FIELDS) and canonical_bytes(registry_text, REGISTRY_FIELDS) == registry_bytes),
    ("registry-schema-root-epoch-and-sequence-match-policy", field(registry_text, "route-attester-revocation-registry-schema") == REGISTRY_SCHEMA and field(registry_text, "governance-root-key-id") == field(root_text, "governance-root-key-id") and registry_epoch == epoch and registry_sequence == sequence),
    ("registry-active-key-is-exact-and-not-revoked", field(registry_text, "active-authority-key-id") == field(active_text, "authority-key-id") and equal_hash(field(registry_text, "active-authority-public-key-sha256"), active_key_hash) and field(registry_text, "active-authority-key-status") == "ACTIVE_NOT_REVOKED" and field(registry_text, "replacement-authority-key-id") == "NONE" and field(registry_text, "latest-revocation-event-id") == "NONE"),
    ("registry-scope-and-policy-remain-non-authorizing", field(registry_text, "registry-scope") == GOVERNANCE_SCOPE and field(registry_text, "persistent-writes") == "FORBIDDEN" and field(registry_text, "slot-changes") == "FORBIDDEN" and field(registry_text, "route-specific-packaging-authorization") == "NO" and field(registry_text, "payload-launch-authorization") == "NO"),
    ("governance-timestamps-and-validity-order-pass", all(value is not None for value in (active_from, active_until, root_from, root_until, issued_at, effective_at, registry_generated, registry_until, verification_time)) and active_from <= issued_at <= effective_at <= registry_generated <= verification_time <= registry_until <= active_until and root_from <= issued_at <= verification_time <= root_until),
    ("policy-signature-is-detached-ed25519-and-valid", POLICY_SIGNATURE.stat().st_size == 64 and policy_signature_ok),
    ("registry-signature-is-detached-ed25519-and-valid", REGISTRY_SIGNATURE.stat().st_size == 64 and registry_signature_ok),
]

failed = [name for name, passed in checks if not passed]
lines = [
    "IzzOS internal M13 route-attester key-governance signature gate",
    "Verifier mode: HOST_SIDE_DUAL_RECORD_ED25519_ROOT_SIGNATURE_ONLY",
    "Device commands executed by verifier: NONE",
    "Device writes executed by verifier: NONE",
    "Launch commands executed by verifier: NONE",
    "",
    f"upstream-route-attestation-report-sha256: {attestation_hash}",
    f"active-authority-key-manifest-sha256: {active_manifest_hash}",
    f"active-authority-public-key-sha256: {active_key_hash}",
    f"governance-root-manifest-sha256: {root_manifest_hash}",
    f"governance-root-public-key-sha256: {root_key_hash}",
    f"governance-policy-sha256: {policy_hash}",
    f"revocation-registry-sha256: {registry_hash}",
    f"policy-signature-sha256: {policy_signature_hash}",
    f"registry-signature-sha256: {registry_signature_hash}",
    f"governance-epoch: {epoch if epoch is not None else 'MISSING'}",
    f"governance-sequence: {sequence if sequence is not None else 'MISSING'}",
    f"verification-timestamp-utc: {VERIFICATION_TEXT}",
    "",
    "checks:",
    *[f'{name}: {"PASS" if passed else "FAIL"}' for name, passed in checks],
    "",
    "policy-signature-verification: PASS" if policy_signature_ok else "policy-signature-verification: FAIL",
    "registry-signature-verification: PASS" if registry_signature_ok else "registry-signature-verification: FAIL",
    "governance-root-trust: CALLER_PINNED_ROOT_NOT_REPOSITORY_ENROLLED",
    "physical-device-truth: NOT_MEASURED_BY_GOVERNANCE_VERIFIER",
    "route-specific-packaging-authorization: NO",
    "payload-launch-authorization: NO",
    "persistent-writes: FORBIDDEN",
    "slot-changes: FORBIDDEN",
]

if failed:
    emit(lines + [
        f"failed-check-count: {len(failed)}",
        *[f"failed-check: {name}" for name in failed],
        "classification: M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_BLOCKED",
        "decision: the upstream binding, active/root key pin, signed governance policy, signed revocation registry, epoch/sequence, custody, validity or no-write/no-launch policy failed.",
    ], 1)

emit(lines + [
    "remaining-blocker: GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_AND_INDEPENDENT_CUSTODY_REQUIRED",
    "remaining-blocker: EXACT_DEVICE_ROUTE_ATTESTATION_AND_STOCK_ACCEPTANCE_REMAIN_REQUIRED",
    "remaining-blocker: ROUTE_SPECIFIC_PACKAGING_REMAINS_UNAUTHORIZED",
    "remaining-blocker: DEVICE_LAUNCH_REMAINS_UNAUTHORIZED",
    "classification: M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED",
    "decision: the caller-pinned Ed25519 governance root signed the exact policy and revocation snapshot binding the M12 report and active attester key. This validates governance mechanics but does not enroll the root, prove physical device truth, authorize packaging or authorize launch.",
])
