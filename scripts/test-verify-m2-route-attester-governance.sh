#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m2-route-attester-governance.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/active-private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/active-private.pem" -pubout -out "$TMP/active-public.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/root-private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/root-private.pem" -pubout -out "$TMP/root-public.pem" 2>/dev/null
ACTIVE_SHA="$(sha256sum "$TMP/active-public.pem" | awk '{print $1}')"
ROOT_SHA="$(sha256sum "$TMP/root-public.pem" | awk '{print $1}')"
PREVIOUS_SHA="$(printf 'm13-previous-governance-state' | sha256sum | awk '{print $1}')"

cat > "$TMP/active-manifest.txt" <<EOF
trusted-route-attester-key-schema: IZZOS_M2_ROUTE_ATTESTER_KEY_V1
authority-key-id: izzos-m2-route-attester-test-01
authority-role: M2_INDEPENDENT_TEMPORARY_ROUTE_ATTESTER
signature-algorithm: ED25519
public-key-sha256: $ACTIVE_SHA
valid-from-utc: 2026-01-01T00:00:00Z
valid-until-utc: 2027-01-01T00:00:00Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-state: CALLER_SUPPLIED_PIN_PENDING_GOVERNANCE
attestation-scope: M2_CONTENT_BOUND_TEMPORARY_ROUTE_EVIDENCE_ONLY
key-custody: EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
ACTIVE_MANIFEST_SHA="$(sha256sum "$TMP/active-manifest.txt" | awk '{print $1}')"

cat > "$TMP/attestation-report.txt" <<EOF
trusted-key-manifest-sha256: $ACTIVE_MANIFEST_SHA
authority-public-key-sha256: $ACTIVE_SHA
authority-key-id: izzos-m2-route-attester-test-01
signature-verification: PASS
attestation-endorsement: CRYPTOGRAPHICALLY_VERIFIED_TO_CALLER_PINNED_KEY
physical-device-truth: ATTESTER_ENDORSEMENT_NOT_MEASURED_BY_VERIFIER
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
classification: M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED
EOF
ATTESTATION_SHA="$(sha256sum "$TMP/attestation-report.txt" | awk '{print $1}')"

write_root_manifest() {
  local output="$1" revoked="${2:-NOT_REVOKED_AT_VERIFICATION}" valid_until="${3:-2027-01-01T00:00:00Z}"
  cat > "$output" <<EOF
route-governance-root-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1
governance-root-key-id: izzos-m2-route-governance-root-test-01
governance-root-role: M2_ROUTE_ATTESTER_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $ROOT_SHA
valid-from-utc: 2026-01-01T00:00:00Z
valid-until-utc: $valid_until
key-revocation-status: $revoked
trust-anchor-state: CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
key-custody: EXTERNAL_TO_ROUTE_ATTESTER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_registry() {
  local output="$1" status="${2:-ACTIVE_NOT_REVOKED}" sequence="${3:-1}" generated="${4:-2026-08-25T00:01:02Z}"
  cat > "$output" <<EOF
route-attester-revocation-registry-schema: IZZOS_M2_ROUTE_ATTESTER_REVOCATION_REGISTRY_V1
governance-root-key-id: izzos-m2-route-governance-root-test-01
governance-epoch: 1
governance-sequence: $sequence
active-authority-key-id: izzos-m2-route-attester-test-01
active-authority-public-key-sha256: $ACTIVE_SHA
active-authority-key-status: $status
replacement-authority-key-id: NONE
latest-revocation-event-id: NONE
generated-at-utc: $generated
valid-until-utc: 2026-12-31T00:00:00Z
registry-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_policy() {
  local output="$1" registry="$2" launch="${3:-NO}" sequence="${4:-1}"
  local registry_sha
  registry_sha="$(sha256sum "$registry" | awk '{print $1}')"
  cat > "$output" <<EOF
route-attester-governance-policy-schema: IZZOS_M2_ROUTE_ATTESTER_GOVERNANCE_POLICY_V1
governance-root-key-id: izzos-m2-route-governance-root-test-01
governance-epoch: 1
governance-sequence: $sequence
previous-governance-policy-sha256: $PREVIOUS_SHA
upstream-route-attestation-report-sha256: $ATTESTATION_SHA
active-authority-key-id: izzos-m2-route-attester-test-01
active-authority-public-key-sha256: $ACTIVE_SHA
active-authority-key-manifest-sha256: $ACTIVE_MANIFEST_SHA
revocation-registry-sha256: $registry_sha
custody-separation: GOVERNANCE_ROOT_EXTERNAL_TO_ROUTE_ATTESTER_AND_LAUNCH_OPERATOR
scheduled-rotation-policy: DUAL_CONTROL_ROOT_SIGNED_REPLACEMENT_REQUIRED
emergency-revocation-policy: ROOT_SIGNED_IMMEDIATE_REVOCATION_REQUIRED
issued-at-utc: 2026-08-25T00:01:00Z
effective-at-utc: 2026-08-25T00:01:01Z
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
EOF
}

sign_record() {
  "$OPENSSL" pkeyutl -sign -inkey "$TMP/root-private.pem" -rawin -in "$1" -out "$2" 2>/dev/null
}

run_verify() {
  local output="$1" root_manifest="${2:-$TMP/root-manifest.txt}" policy="${3:-$TMP/policy.txt}" policy_signature="${4:-$TMP/policy-signature.bin}" registry="${5:-$TMP/registry.txt}" registry_signature="${6:-$TMP/registry-signature.bin}" verification="${7:-2026-08-25T00:01:03Z}" active_manifest="${8:-$TMP/active-manifest.txt}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/attestation-report.txt" "$active_manifest" "$TMP/active-public.pem" \
    "$root_manifest" "$TMP/root-public.pem" "$policy" "$policy_signature" \
    "$registry" "$registry_signature" "$verification" "$output"
}

write_root_manifest "$TMP/root-manifest.txt"
write_registry "$TMP/registry.txt"
write_policy "$TMP/policy.txt" "$TMP/registry.txt"
sign_record "$TMP/policy.txt" "$TMP/policy-signature.bin"
sign_record "$TMP/registry.txt" "$TMP/registry-signature.bin"

if ! run_verify "$TMP/pass.txt" >/dev/null; then
  cat "$TMP/pass.txt" >&2
  exit 1
fi
grep -q '^policy-signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^registry-signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^route-specific-packaging-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED$' "$TMP/pass.txt"

sed 's/governance-sequence: 1/governance-sequence: 2/' "$TMP/policy.txt" > "$TMP/tampered-policy.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/root-manifest.txt" "$TMP/tampered-policy.txt" "$TMP/policy-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted changed signed policy' >&2
  exit 1
fi

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/rogue-private.pem" 2>/dev/null
"$OPENSSL" pkeyutl -sign -inkey "$TMP/rogue-private.pem" -rawin -in "$TMP/registry.txt" -out "$TMP/rogue-registry-signature.bin" 2>/dev/null
if run_verify "$TMP/rogue-out.txt" "$TMP/root-manifest.txt" "$TMP/policy.txt" "$TMP/policy-signature.bin" "$TMP/registry.txt" "$TMP/rogue-registry-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted rogue registry signature' >&2
  exit 1
fi

write_registry "$TMP/revoked-registry.txt" REVOKED
write_policy "$TMP/revoked-policy.txt" "$TMP/revoked-registry.txt"
sign_record "$TMP/revoked-policy.txt" "$TMP/revoked-policy-signature.bin"
sign_record "$TMP/revoked-registry.txt" "$TMP/revoked-registry-signature.bin"
if run_verify "$TMP/revoked-out.txt" "$TMP/root-manifest.txt" "$TMP/revoked-policy.txt" "$TMP/revoked-policy-signature.bin" "$TMP/revoked-registry.txt" "$TMP/revoked-registry-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted revoked active attester key' >&2
  exit 1
fi

write_registry "$TMP/stale-registry.txt" ACTIVE_NOT_REVOKED 1 2026-08-25T00:00:59Z
write_policy "$TMP/stale-policy.txt" "$TMP/stale-registry.txt"
sign_record "$TMP/stale-policy.txt" "$TMP/stale-policy-signature.bin"
sign_record "$TMP/stale-registry.txt" "$TMP/stale-registry-signature.bin"
if run_verify "$TMP/stale-out.txt" "$TMP/root-manifest.txt" "$TMP/stale-policy.txt" "$TMP/stale-policy-signature.bin" "$TMP/stale-registry.txt" "$TMP/stale-registry-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted registry older than policy effective time' >&2
  exit 1
fi

write_policy "$TMP/unsafe-policy.txt" "$TMP/registry.txt" YES
sign_record "$TMP/unsafe-policy.txt" "$TMP/unsafe-policy-signature.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/root-manifest.txt" "$TMP/unsafe-policy.txt" "$TMP/unsafe-policy-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted launch authorization' >&2
  exit 1
fi

write_root_manifest "$TMP/expired-root.txt" NOT_REVOKED_AT_VERIFICATION 2026-08-25T00:01:02Z
if run_verify "$TMP/expired-out.txt" "$TMP/expired-root.txt" "$TMP/policy.txt" "$TMP/policy-signature.bin" "$TMP/registry.txt" "$TMP/registry-signature.bin" 2026-08-25T00:01:03Z >/dev/null 2>&1; then
  echo 'ERROR: governance gate accepted expired governance root' >&2
  exit 1
fi

echo 'M2 route-attester governance tests: PASS'
