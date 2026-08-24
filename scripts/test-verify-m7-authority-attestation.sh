#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-authority-attestation.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/private.pem" -pubout -out "$TMP/public.pem" 2>/dev/null
PUBLIC_SHA="$(sha256sum "$TMP/public.pem" | awk '{print $1}')"
TOKEN_SHA="$(printf 'm7-attestation-token' | sha256sum | awk '{print $1}')"
RECEIPT_SHA="$(printf 'm7-attestation-receipt' | sha256sum | awk '{print $1}')"
EVIDENCE_SHA="$(printf 'm7-attestation-evidence' | sha256sum | awk '{print $1}')"

cat > "$TMP/result-report.txt" <<EOF
authorization-token-sha256: $TOKEN_SHA
token-consumption-receipt-sha256: $RECEIPT_SHA
execution-evidence-artifact-sha256: $EVIDENCE_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
capture-id: CPH2413-EX01-runtime-ownership-test
execution-completed-at-utc: 2026-08-25T00:01:03Z
atomicity-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
execution-result-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
wrapper-execution-proof: NOT_INDEPENDENTLY_ATTESTED
wrapper-execution-authorization: NO
launch-authorization: NO
classification: M7_TOKEN_CONSUMPTION_RESULT_SCHEMA_PASS_ATOMICITY_AUTHENTICITY_REQUIRED
EOF
RESULT_SHA="$(sha256sum "$TMP/result-report.txt" | awk '{print $1}')"

write_manifest() {
  local output="$1" public_sha="${2:-$PUBLIC_SHA}" revoked="${3:-NOT_REVOKED_AT_VERIFICATION}" valid_until="${4:-2027-01-01T00:00:00Z}"
  cat > "$output" <<EOF
trusted-authority-key-schema: IZZOS_M7_TRUSTED_AUTHORITY_KEY_V1
authority-key-id: izzos-m7-attester-test-01
authority-role: M7_INDEPENDENT_CAPTURE_AND_EXECUTION_ATTESTER
signature-algorithm: ED25519
public-key-sha256: $public_sha
valid-from-utc: 2026-01-01T00:00:00Z
valid-until-utc: $valid_until
key-revocation-status: $revoked
trust-anchor-source: REPOSITORY_REVIEWED_SHA256_PIN
attestation-scope: M7_BOUND_TOKEN_CONSUMPTION_AND_WRAPPER_EVIDENCE_RESULT_ONLY
key-custody: EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
}

write_envelope() {
  local output="$1" result_sha="${2:-$RESULT_SHA}" attested="${3:-2026-08-25T00:01:04Z}" launch="${4:-NO}"
  cat > "$output" <<EOF
attestation-envelope-schema: IZZOS_M7_AUTHORITY_ATTESTATION_ENVELOPE_V1
authority-key-id: izzos-m7-attester-test-01
signature-algorithm: ED25519
token-consumption-execution-result-report-sha256: $result_sha
authorization-token-sha256: $TOKEN_SHA
token-consumption-receipt-sha256: $RECEIPT_SHA
execution-evidence-artifact-sha256: $EVIDENCE_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
capture-id: CPH2413-EX01-runtime-ownership-test
attestation-id: CPH2413-EX01-attestation-test
attested-at-utc: $attested
attestation-scope: M7_BOUND_TOKEN_CONSUMPTION_AND_WRAPPER_EVIDENCE_RESULT_ONLY
capture-authenticity: INDEPENDENTLY_ATTESTED_BY_PINNED_KEY
token-consumption-atomicity: INDEPENDENTLY_ATTESTED_BY_PINNED_KEY
wrapper-execution-authenticity: INDEPENDENTLY_ATTESTED_BY_PINNED_KEY
device-route-authenticity: INDEPENDENTLY_ATTESTED_BY_PINNED_KEY
smc-calls: NONE
mmio-writes: NONE
device-storage-writes: NONE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: $launch
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

sign_envelope() {
  local envelope="$1" signature="$2" private_key="${3:-$TMP/private.pem}"
  "$OPENSSL" pkeyutl -sign -inkey "$private_key" -rawin -in "$envelope" -out "$signature" 2>/dev/null
}

write_manifest "$TMP/manifest.txt"
write_envelope "$TMP/envelope.txt"
sign_envelope "$TMP/envelope.txt" "$TMP/signature.bin"

run_verify() {
  local output="$1" result="${2:-$TMP/result-report.txt}" manifest="${3:-$TMP/manifest.txt}" public_key="${4:-$TMP/public.pem}" envelope="${5:-$TMP/envelope.txt}" signature="${6:-$TMP/signature.bin}" verification="${7:-2026-08-25T00:01:05Z}"
  OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" "$result" "$manifest" "$public_key" "$envelope" "$signature" "$verification" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^trusted-key-manifest-pins-exact-public-key: PASS$' "$TMP/pass.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: PASS$' "$TMP/pass.txt"
grep -q '^signature-verification: PASS$' "$TMP/pass.txt"
grep -q '^wrapper-execution-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_AUTHORITY_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED$' "$TMP/pass.txt"

sed 's/attestation-id: CPH2413-EX01-attestation-test/attestation-id: CPH2413-EX01-attestation-changed/' "$TMP/envelope.txt" > "$TMP/tampered-envelope.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/public.pem" "$TMP/tampered-envelope.txt" "$TMP/signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted changed signed bytes' >&2
  exit 1
fi
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: FAIL$' "$TMP/tampered-out.txt"

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/other-private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/other-private.pem" -pubout -out "$TMP/other-public.pem" 2>/dev/null
sign_envelope "$TMP/envelope.txt" "$TMP/untrusted-signature.bin" "$TMP/other-private.pem"
if run_verify "$TMP/untrusted-key-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/other-public.pem" "$TMP/envelope.txt" "$TMP/untrusted-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted an unpinned public key' >&2
  exit 1
fi
grep -q '^trusted-key-manifest-pins-exact-public-key: FAIL$' "$TMP/untrusted-key-out.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: FAIL$' "$TMP/untrusted-key-out.txt"
grep -q '^signature-verification: PASS$' "$TMP/untrusted-key-out.txt"
grep -q '^attestation-endorsement: NOT_VERIFIED_TO_REPOSITORY_PINNED_KEY$' "$TMP/untrusted-key-out.txt"

write_manifest "$TMP/expired-manifest.txt" "$PUBLIC_SHA" NOT_REVOKED_AT_VERIFICATION 2026-08-25T00:01:04Z
if run_verify "$TMP/expired-key-out.txt" "$TMP/result-report.txt" "$TMP/expired-manifest.txt" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted a key expired before verification' >&2
  exit 1
fi
grep -q '^trusted-key-is-valid-at-attestation-and-verification: FAIL$' "$TMP/expired-key-out.txt"

write_manifest "$TMP/revoked-manifest.txt" "$PUBLIC_SHA" REVOKED
if run_verify "$TMP/revoked-key-out.txt" "$TMP/result-report.txt" "$TMP/revoked-manifest.txt" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted a revoked key declaration' >&2
  exit 1
fi
grep -q '^trusted-key-is-not-declared-revoked: FAIL$' "$TMP/revoked-key-out.txt"

write_envelope "$TMP/early-envelope.txt" "$RESULT_SHA" 2026-08-25T00:01:02Z
sign_envelope "$TMP/early-envelope.txt" "$TMP/early-signature.bin"
if run_verify "$TMP/early-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/public.pem" "$TMP/early-envelope.txt" "$TMP/early-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted attestation before result completion' >&2
  exit 1
fi
grep -q '^attestation-follows-bound-execution-result: FAIL$' "$TMP/early-out.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: PASS$' "$TMP/early-out.txt"

write_envelope "$TMP/unsafe-envelope.txt" "$RESULT_SHA" 2026-08-25T00:01:04Z YES
sign_envelope "$TMP/unsafe-envelope.txt" "$TMP/unsafe-signature.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/public.pem" "$TMP/unsafe-envelope.txt" "$TMP/unsafe-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted a signed launch claim' >&2
  exit 1
fi
grep -q '^attestation-forbids-smc-mmio-device-write-and-launch: FAIL$' "$TMP/unsafe-out.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: PASS$' "$TMP/unsafe-out.txt"

cp "$TMP/envelope.txt" "$TMP/duplicate-envelope.txt"
printf 'attestation-id: duplicate\n' >> "$TMP/duplicate-envelope.txt"
sign_envelope "$TMP/duplicate-envelope.txt" "$TMP/duplicate-signature.bin"
if run_verify "$TMP/duplicate-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/public.pem" "$TMP/duplicate-envelope.txt" "$TMP/duplicate-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted duplicate signed fields' >&2
  exit 1
fi
grep -q '^attestation-envelope-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"
grep -q '^attestation-envelope-is-canonical: FAIL$' "$TMP/duplicate-out.txt"

cp "$TMP/result-report.txt" "$TMP/changed-result.txt"
printf 'changed: yes\n' >> "$TMP/changed-result.txt"
if run_verify "$TMP/changed-result-out.txt" "$TMP/changed-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted changed upstream result bytes' >&2
  exit 1
fi
grep -q '^attestation-envelope-binds-upstream-result: FAIL$' "$TMP/changed-result-out.txt"

head -c 63 "$TMP/signature.bin" > "$TMP/short-signature.bin"
if run_verify "$TMP/short-signature-out.txt" "$TMP/result-report.txt" "$TMP/manifest.txt" "$TMP/public.pem" "$TMP/envelope.txt" "$TMP/short-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: attestation gate accepted a truncated signature' >&2
  exit 1
fi
grep -q '^detached-signature-size-is-ed25519: FAIL$' "$TMP/short-signature-out.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: FAIL$' "$TMP/short-signature-out.txt"

echo 'PASS: M7 independent authority-attestation signature gate'
