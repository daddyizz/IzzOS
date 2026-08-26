#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m2-route-attestation.py"
PYTHON="${PYTHON:-python3}"
OPENSSL="${OPENSSL:-openssl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BUILD='CPH2415_15.0.0.1901(EX01)'
ROUTE='temporary-chainload-attestation-fixture'

cat > "$TMP/m2.txt" <<EOF
Target: OnePlus 10T 5G / ovaltine / SM8475
Firmware ID: $BUILD
Selected launch route: $ROUTE
Route decision: TEMPORARY_ROUTE_VALIDATED
Persistent writes: FORBIDDEN
Slot changes: FORBIDDEN
Route validation evidence reference: route-evidence.txt
EOF

for role in before-state route-transcript diagnostic-output after-state; do
  printf 'synthetic-%s-%s\n' "$role" "$BUILD" > "$TMP/$role.txt"
done
{
  echo 'Schema: IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1'
  echo 'Target: OnePlus 10T 5G / CPH2415 / ovaltine / SM8475'
  echo "Firmware ID: $BUILD"
  echo "Selected launch route: $ROUTE"
  echo 'Route decision: TEMPORARY_ROUTE_VALIDATED'
  echo 'Device execution observed: YES'
  echo 'Diagnostic payload reached: YES'
  echo 'Controlled result recorded: YES'
  echo 'Stock boot restored: YES'
  echo 'Persistent writes observed: NO'
  echo 'Slot change observed: NO'
  echo 'User data mutation observed: NO'
  echo 'Required artifact roles: before-state route-transcript diagnostic-output after-state'
  for role in before-state route-transcript diagnostic-output after-state; do
    file="$TMP/$role.txt"
    printf 'Artifact record: %s|%s.txt|%s|%s\n' \
      "$role" "$role" "$(stat -c '%s' "$file")" "$(sha256sum "$file" | awk '{print $1}')"
  done
} > "$TMP/route-evidence.txt"

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$TMP/private.pem" -pubout -out "$TMP/public.pem" 2>/dev/null
PUBLIC_SHA="$(sha256sum "$TMP/public.pem" | awk '{print $1}')"
MANIFEST_SHA="$(sha256sum "$TMP/m2.txt" | awk '{print $1}')"
ROUTE_SHA="$(sha256sum "$TMP/route-evidence.txt" | awk '{print $1}')"

write_key_manifest() {
  local output="$1" revoked="${2:-NOT_REVOKED_AT_VERIFICATION}" valid_until="${3:-2027-01-01T00:00:00Z}" public_sha="${4:-$PUBLIC_SHA}"
  cat > "$output" <<EOF
trusted-route-attester-key-schema: IZZOS_M2_ROUTE_ATTESTER_KEY_V1
authority-key-id: izzos-m2-route-attester-test-01
authority-role: M2_INDEPENDENT_TEMPORARY_ROUTE_ATTESTER
signature-algorithm: ED25519
public-key-sha256: $public_sha
valid-from-utc: 2026-01-01T00:00:00Z
valid-until-utc: $valid_until
key-revocation-status: $revoked
trust-anchor-state: CALLER_SUPPLIED_PIN_PENDING_GOVERNANCE
attestation-scope: M2_CONTENT_BOUND_TEMPORARY_ROUTE_EVIDENCE_ONLY
key-custody: EXTERNAL_TO_VERIFIER
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
EOF
}

write_envelope() {
  local output="$1" manifest_sha="${2:-$MANIFEST_SHA}" route_sha="${3:-$ROUTE_SHA}" launch="${4:-NO}"
  cat > "$output" <<EOF
route-attestation-envelope-schema: IZZOS_M2_ROUTE_ATTESTATION_ENVELOPE_V1
authority-key-id: izzos-m2-route-attester-test-01
signature-algorithm: ED25519
m2-manifest-sha256: $manifest_sha
content-bound-route-evidence-sha256: $route_sha
exact-device-build: $BUILD
selected-launch-route: $ROUTE
observation-id: CPH2415-EX01-route-observation-test
attestation-id: CPH2415-EX01-route-attestation-test
observation-completed-at-utc: 2026-08-25T00:01:00Z
attested-at-utc: 2026-08-25T00:01:01Z
attestation-scope: M2_CONTENT_BOUND_TEMPORARY_ROUTE_EVIDENCE_ONLY
route-evidence-authenticity: INDEPENDENTLY_ATTESTED_BY_PINNED_KEY
device-execution-observed: YES
diagnostic-payload-reached: YES
controlled-result-recorded: YES
stock-boot-restored: YES
persistent-writes-observed: NO
slot-change-observed: NO
user-data-mutation-observed: NO
route-specific-packaging-authorization: NO
payload-launch-authorization: $launch
EOF
}

sign_envelope() {
  local envelope="$1" signature="$2" private_key="${3:-$TMP/private.pem}"
  "$OPENSSL" pkeyutl -sign -inkey "$private_key" -rawin -in "$envelope" -out "$signature" 2>/dev/null
}

run_verify() {
  local output="$1" key_manifest="${2:-$TMP/key-manifest.txt}" public_key="${3:-$TMP/public.pem}" envelope="${4:-$TMP/envelope.txt}" signature="${5:-$TMP/signature.bin}" verification="${6:-2026-08-25T00:01:02Z}" route_evidence="${7:-$TMP/route-evidence.txt}"
  BASH="$(command -v bash)" OPENSSL="$OPENSSL" "$PYTHON" "$VERIFY" \
    "$TMP/m2.txt" "$route_evidence" "$key_manifest" "$public_key" \
    "$envelope" "$signature" "$verification" "$output"
}

write_key_manifest "$TMP/key-manifest.txt"
write_envelope "$TMP/envelope.txt"
sign_envelope "$TMP/envelope.txt" "$TMP/signature.bin"

if ! run_verify "$TMP/pass.txt" >/dev/null; then
  cat "$TMP/pass.txt" >&2
  echo 'ERROR: valid signed route-attestation fixture did not pass' >&2
  exit 1
fi
grep -q '^upstream-content-bound-route-evidence-passes: PASS$' "$TMP/pass.txt"
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: PASS$' "$TMP/pass.txt"
grep -q '^route-specific-packaging-authorization: NO$' "$TMP/pass.txt"
grep -q '^payload-launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED$' "$TMP/pass.txt"

sed 's/attestation-id: CPH2415-EX01-route-attestation-test/attestation-id: CPH2415-EX01-route-attestation-tampered/' "$TMP/envelope.txt" > "$TMP/tampered-envelope.txt"
if run_verify "$TMP/tampered-out.txt" "$TMP/key-manifest.txt" "$TMP/public.pem" "$TMP/tampered-envelope.txt" "$TMP/signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted changed envelope bytes' >&2
  exit 1
fi
grep -q '^detached-signature-verifies-with-pinned-ed25519-key: FAIL$' "$TMP/tampered-out.txt"

"$OPENSSL" genpkey -algorithm ED25519 -out "$TMP/rogue-private.pem" 2>/dev/null
sign_envelope "$TMP/envelope.txt" "$TMP/rogue-signature.bin" "$TMP/rogue-private.pem"
if run_verify "$TMP/rogue-out.txt" "$TMP/key-manifest.txt" "$TMP/public.pem" "$TMP/envelope.txt" "$TMP/rogue-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted rogue-key signature' >&2
  exit 1
fi

write_key_manifest "$TMP/revoked-key.txt" REVOKED
if run_verify "$TMP/revoked-out.txt" "$TMP/revoked-key.txt" >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted revoked key' >&2
  exit 1
fi

if run_verify "$TMP/expired-out.txt" "$TMP/key-manifest.txt" "$TMP/public.pem" "$TMP/envelope.txt" "$TMP/signature.bin" 2027-01-01T00:00:01Z >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted verification after key expiry' >&2
  exit 1
fi

write_envelope "$TMP/unsafe-envelope.txt" "$MANIFEST_SHA" "$ROUTE_SHA" YES
sign_envelope "$TMP/unsafe-envelope.txt" "$TMP/unsafe-signature.bin"
if run_verify "$TMP/unsafe-out.txt" "$TMP/key-manifest.txt" "$TMP/public.pem" "$TMP/unsafe-envelope.txt" "$TMP/unsafe-signature.bin" >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted launch authorization' >&2
  exit 1
fi

printf 'tamper\n' >> "$TMP/diagnostic-output.txt"
if run_verify "$TMP/artifact-tamper-out.txt" "$TMP/key-manifest.txt" "$TMP/public.pem" "$TMP/envelope.txt" "$TMP/signature.bin" 2026-08-25T00:01:02Z "$TMP/route-evidence.txt" >/dev/null 2>&1; then
  echo 'ERROR: signed route-attestation gate accepted mutated route artifact' >&2
  exit 1
fi
grep -q '^upstream-content-bound-route-evidence-passes: FAIL$' "$TMP/artifact-tamper-out.txt"

echo 'M2 signed route-attestation tests: PASS'
