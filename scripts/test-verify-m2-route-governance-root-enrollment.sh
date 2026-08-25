#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m2-route-governance-root-enrollment.py"
ENROLLED_KEY="$ROOT/config/m2-route-governance-root-test-public.pem"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ROOT_SHA="$(sha256sum "$ENROLLED_KEY" | awk '{print $1}')"

write_root_manifest() {
  local output="$1" key_sha="${2:-$ROOT_SHA}" key_id="${3:-izzos-m2-route-governance-host-test-01}"
  cat > "$output" <<EOF
route-governance-root-schema: IZZOS_M2_ROUTE_GOVERNANCE_ROOT_V1
governance-root-key-id: $key_id
governance-root-role: M2_ROUTE_ATTESTER_GOVERNANCE_ROOT
signature-algorithm: ED25519
public-key-sha256: $key_sha
valid-from-utc: 2025-01-01T00:00:00Z
valid-until-utc: 2028-01-01T00:00:00Z
key-revocation-status: NOT_REVOKED_AT_VERIFICATION
trust-anchor-state: CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT
governance-scope: M2_ROUTE_ATTESTER_KEY_GOVERNANCE_ONLY
key-custody: EXTERNAL_TO_ROUTE_ATTESTER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_m13_report() {
  local output="$1" manifest="$2" key="$3" launch="${4:-NO}"
  local manifest_sha key_sha
  manifest_sha="$(sha256sum "$manifest" | awk '{print $1}')"
  key_sha="$(sha256sum "$key" | awk '{print $1}')"
  cat > "$output" <<EOF
governance-root-manifest-sha256: $manifest_sha
governance-root-public-key-sha256: $key_sha
governance-policy-sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
revocation-registry-sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
policy-signature-verification: PASS
registry-signature-verification: PASS
governance-root-trust: CALLER_PINNED_ROOT_NOT_REPOSITORY_ENROLLED
physical-device-truth: NOT_MEASURED_BY_GOVERNANCE_VERIFIER
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
classification: M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED
EOF
}

run_verify() {
  local output="$1" report="${2:-$TMP/m13-report.txt}" manifest="${3:-$TMP/root-manifest.txt}" key="${4:-$ENROLLED_KEY}" verification="${5:-2026-08-25T00:02:00Z}"
  "$PYTHON" "$VERIFY" "$report" "$manifest" "$key" "$verification" "$output"
}

write_root_manifest "$TMP/root-manifest.txt"
write_m13_report "$TMP/m13-report.txt" "$TMP/root-manifest.txt" "$ENROLLED_KEY"

if ! run_verify "$TMP/pass.txt" >/dev/null; then
  cat "$TMP/pass.txt" >&2
  exit 1
fi
grep -q '^repository-enrollment-environment: HOST_TEST_ONLY_NOT_PRODUCTION$' "$TMP/pass.txt"
grep -q '^route-specific-packaging-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_PASS_PRODUCTION_ROOT_REQUIRED$' "$TMP/pass.txt"

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/rogue-private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/rogue-private.pem" -pubout -out "$TMP/rogue-public.pem" 2>/dev/null
ROGUE_SHA="$(sha256sum "$TMP/rogue-public.pem" | awk '{print $1}')"
write_root_manifest "$TMP/rogue-manifest.txt" "$ROGUE_SHA"
write_m13_report "$TMP/rogue-report.txt" "$TMP/rogue-manifest.txt" "$TMP/rogue-public.pem"
if run_verify "$TMP/rogue-out.txt" "$TMP/rogue-report.txt" "$TMP/rogue-manifest.txt" "$TMP/rogue-public.pem" >/dev/null 2>&1; then
  echo 'ERROR: M14 enrollment gate accepted a non-enrolled root key' >&2
  exit 1
fi

write_root_manifest "$TMP/wrong-id-manifest.txt" "$ROOT_SHA" izzos-m2-route-governance-wrong-01
write_m13_report "$TMP/wrong-id-report.txt" "$TMP/wrong-id-manifest.txt" "$ENROLLED_KEY"
if run_verify "$TMP/wrong-id-out.txt" "$TMP/wrong-id-report.txt" "$TMP/wrong-id-manifest.txt" >/dev/null 2>&1; then
  echo 'ERROR: M14 enrollment gate accepted a mismatched root identity' >&2
  exit 1
fi

write_m13_report "$TMP/unsafe-report.txt" "$TMP/root-manifest.txt" "$ENROLLED_KEY" YES
if run_verify "$TMP/unsafe-out.txt" "$TMP/unsafe-report.txt" >/dev/null 2>&1; then
  echo 'ERROR: M14 enrollment gate accepted launch authorization' >&2
  exit 1
fi

cp "$TMP/root-manifest.txt" "$TMP/duplicate-manifest.txt"
printf 'governance-root-key-id: duplicate\n' >> "$TMP/duplicate-manifest.txt"
write_m13_report "$TMP/duplicate-report.txt" "$TMP/duplicate-manifest.txt" "$ENROLLED_KEY"
if run_verify "$TMP/duplicate-out.txt" "$TMP/duplicate-report.txt" "$TMP/duplicate-manifest.txt" >/dev/null 2>&1; then
  echo 'ERROR: M14 enrollment gate accepted duplicate manifest fields' >&2
  exit 1
fi

if run_verify "$TMP/expired-out.txt" "$TMP/m13-report.txt" "$TMP/root-manifest.txt" "$ENROLLED_KEY" 2027-01-01T00:00:01Z >/dev/null 2>&1; then
  echo 'ERROR: M14 enrollment gate accepted verification after enrollment expiry' >&2
  exit 1
fi

echo 'M2 repository governance-root enrollment contract tests: PASS'
