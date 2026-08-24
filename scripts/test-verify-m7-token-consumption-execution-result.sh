#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-token-consumption-execution-result.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TOKEN_SHA="$(printf 'm7-one-shot-token-fixture' | sha256sum | awk '{print $1}')"
cat > "$TMP/request.txt" <<EOF
one-shot-authorization-schema: IZZOS_M7_ONE_SHOT_EXECUTION_AUTHORIZATION_REQUEST_V1
authorization-token-sha256: $TOKEN_SHA
authorization-use-count: 1
requested-wrapper-execution-scope: EXACTLY_ONCE_FOR_BOUND_EVIDENCE_CAPTURE_ONLY
atomic-token-consumption: REQUIRED_BEFORE_WRAPPER_INVOCATION
exact-device-build: CPH2413_15.0.0.1901(EX01)
capture-id: CPH2413-EX01-runtime-ownership-test
expires-at-utc: 2026-08-25T00:05:00Z
device-writes: NONE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
REQUEST_SHA="$(sha256sum "$TMP/request.txt" | awk '{print $1}')"

cat > "$TMP/pre-ledger.txt" <<'EOF'
used-token-ledger-schema: IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1
EOF
PRE_SHA="$(sha256sum "$TMP/pre-ledger.txt" | awk '{print $1}')"
cat "$TMP/pre-ledger.txt" > "$TMP/post-ledger.txt"
printf 'used-token-sha256: %s\n' "$TOKEN_SHA" >> "$TMP/post-ledger.txt"
POST_SHA="$(sha256sum "$TMP/post-ledger.txt" | awk '{print $1}')"

cat > "$TMP/readiness.txt" <<EOF
authorization-request-sha256: $REQUEST_SHA
used-token-ledger-sha256: $PRE_SHA
authorization-token-sha256: $TOKEN_SHA
expected-authorization-token-sha256: $TOKEN_SHA
evaluation-timestamp-utc: 2026-08-25T00:01:00Z
authorization-token-state: UNUSED_IN_SUPPLIED_LEDGER
atomic-token-consumption: REQUIRED_EXTERNAL
wrapper-execution-authorization: NO
launch-authorization: NO
classification: M7_FRESH_ONE_SHOT_EXECUTION_TOKEN_READY_ATOMIC_CONSUMPTION_REQUIRED
EOF
READINESS_SHA="$(sha256sum "$TMP/readiness.txt" | awk '{print $1}')"

printf 'synthetic bound wrapper evidence capture\n' > "$TMP/evidence.bin"
EVIDENCE_SHA="$(sha256sum "$TMP/evidence.bin" | awk '{print $1}')"

write_receipt() {
  local output="$1" post_sha="${2:-$POST_SHA}" consumed="${3:-2026-08-25T00:01:01Z}" budget_after="${4:-0}" device_writes="${5:-NONE}" evidence_sha="${6:-$EVIDENCE_SHA}"
  cat > "$output" <<EOF
token-consumption-receipt-schema: IZZOS_M7_ATOMIC_TOKEN_CONSUMPTION_RECEIPT_V1
authorization-readiness-report-sha256: $READINESS_SHA
authorization-request-sha256: $REQUEST_SHA
pre-use-ledger-sha256: $PRE_SHA
post-use-ledger-sha256: $post_sha
authorization-token-sha256: $TOKEN_SHA
consumption-id: CPH2413-EX01-consumption-test
consumed-at-utc: $consumed
consumption-operation-assertion: ATOMIC_COMPARE_TOKEN_ABSENT_AND_APPEND_ONCE
token-precondition: ABSENT
token-postcondition: PRESENT_EXACTLY_ONCE
invocation-budget-before: 1
invocation-budget-after: $budget_after
ledger-write-scope: EXACT_POST_USE_LEDGER_APPEND_ONLY
execution-evidence-artifact-sha256: $evidence_sha
atomicity-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
device-storage-writes: $device_writes
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
EOF
}

write_result() {
  local output="$1" receipt_sha="$2" started="${3:-2026-08-25T00:01:02Z}" completed="${4:-2026-08-25T00:01:03Z}" invocations="${5:-1}" mmio="${6:-NONE}" evidence_sha="${7:-$EVIDENCE_SHA}"
  cat > "$output" <<EOF
wrapper-execution-result-schema: IZZOS_M7_BOUND_WRAPPER_EXECUTION_RESULT_V1
token-consumption-receipt-sha256: $receipt_sha
authorization-readiness-report-sha256: $READINESS_SHA
authorization-request-sha256: $REQUEST_SHA
authorization-token-sha256: $TOKEN_SHA
execution-evidence-artifact-sha256: $evidence_sha
exact-device-build: CPH2413_15.0.0.1901(EX01)
capture-id: CPH2413-EX01-runtime-ownership-test
execution-id: CPH2413-EX01-wrapper-result-test
execution-started-at-utc: $started
execution-completed-at-utc: $completed
wrapper-invocation-count: $invocations
wrapper-transfer-count: 1
wrapper-return-count: 0
execution-outcome: BOUND_EVIDENCE_CAPTURE_ASSERTED_COMPLETE
execution-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
runtime-ownership-snapshot-status: EXACT_AUTHORIZED_SNAPSHOT_ASSERTED_UNCHANGED
smc-calls: NONE
mmio-writes: $mmio
device-storage-writes: NONE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
payload-launch-authorization: NO
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
EOF
}

write_receipt "$TMP/receipt.txt"
RECEIPT_SHA="$(sha256sum "$TMP/receipt.txt" | awk '{print $1}')"
write_result "$TMP/result.txt" "$RECEIPT_SHA"

run_verify() {
  local output="$1" readiness="${2:-$TMP/readiness.txt}" request="${3:-$TMP/request.txt}" pre="${4:-$TMP/pre-ledger.txt}" post="${5:-$TMP/post-ledger.txt}" receipt="${6:-$TMP/receipt.txt}" evidence="${7:-$TMP/evidence.bin}" result="${8:-$TMP/result.txt}"
  "$PYTHON" "$VERIFY" "$readiness" "$request" "$pre" "$post" "$receipt" "$evidence" "$result" "$output"
}

run_verify "$TMP/pass.txt" >/dev/null
grep -q '^post-use-ledger-is-exact-single-token-append: PASS$' "$TMP/pass.txt"
grep -q '^consumption-receipt-binds-readiness-request-and-ledgers: PASS$' "$TMP/pass.txt"
grep -q '^execution-result-binds-receipt-readiness-request-and-token: PASS$' "$TMP/pass.txt"
grep -q '^wrapper-execution-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_TOKEN_CONSUMPTION_RESULT_SCHEMA_PASS_ATOMICITY_AUTHENTICITY_REQUIRED$' "$TMP/pass.txt"

cat "$TMP/post-ledger.txt" > "$TMP/replay-ledger.txt"
printf 'used-token-sha256: %s\n' "$TOKEN_SHA" >> "$TMP/replay-ledger.txt"
if run_verify "$TMP/replay-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/replay-ledger.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted a duplicate consumed token' >&2
  exit 1
fi
grep -q '^post-use-ledger-is-valid-and-token-present-once: FAIL$' "$TMP/replay-out.txt"
grep -q '^post-use-ledger-is-exact-single-token-append: FAIL$' "$TMP/replay-out.txt"

cp "$TMP/post-ledger.txt" "$TMP/unknown-ledger.txt"
printf 'unexpected-ledger-field: unsafe\n' >> "$TMP/unknown-ledger.txt"
if run_verify "$TMP/unknown-ledger-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/unknown-ledger.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted an unknown ledger field' >&2
  exit 1
fi
grep -q '^post-use-ledger-is-valid-and-token-present-once: FAIL$' "$TMP/unknown-ledger-out.txt"
grep -q '^post-use-ledger-is-exact-single-token-append: FAIL$' "$TMP/unknown-ledger-out.txt"

printf X >> "$TMP/changed-evidence.bin"
if run_verify "$TMP/changed-evidence-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/receipt.txt" "$TMP/changed-evidence.bin" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted changed evidence bytes' >&2
  exit 1
fi
grep -q '^consumption-receipt-binds-token-and-evidence-artifact: FAIL$' "$TMP/changed-evidence-out.txt"
grep -q '^execution-result-binds-evidence-artifact: FAIL$' "$TMP/changed-evidence-out.txt"

write_receipt "$TMP/expired-receipt.txt" "$POST_SHA" 2026-08-25T00:05:01Z
EXPIRED_RECEIPT_SHA="$(sha256sum "$TMP/expired-receipt.txt" | awk '{print $1}')"
write_result "$TMP/expired-result.txt" "$EXPIRED_RECEIPT_SHA" 2026-08-25T00:05:01Z 2026-08-25T00:05:01Z
if run_verify "$TMP/expired-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/expired-receipt.txt" "$TMP/evidence.bin" "$TMP/expired-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted consumption after expiry' >&2
  exit 1
fi
grep -q '^consumption-time-is-inside-readiness-window: FAIL$' "$TMP/expired-out.txt"
grep -q '^execution-result-time-follows-consumption-and-finishes-inside-window: FAIL$' "$TMP/expired-out.txt"

write_result "$TMP/multiple-result.txt" "$RECEIPT_SHA" 2026-08-25T00:01:02Z 2026-08-25T00:01:03Z 2
if run_verify "$TMP/multiple-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/receipt.txt" "$TMP/evidence.bin" "$TMP/multiple-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted multiple wrapper invocations' >&2
  exit 1
fi
grep -q '^execution-result-has-one-non-returning-transfer: FAIL$' "$TMP/multiple-out.txt"

write_receipt "$TMP/unsafe-receipt.txt" "$POST_SHA" 2026-08-25T00:01:01Z 0 PRESENT
UNSAFE_RECEIPT_SHA="$(sha256sum "$TMP/unsafe-receipt.txt" | awk '{print $1}')"
write_result "$TMP/unsafe-receipt-result.txt" "$UNSAFE_RECEIPT_SHA"
if run_verify "$TMP/unsafe-receipt-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/unsafe-receipt.txt" "$TMP/evidence.bin" "$TMP/unsafe-receipt-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted a device-storage write claim' >&2
  exit 1
fi
grep -q '^consumption-receipt-forbids-device-write-and-launch: FAIL$' "$TMP/unsafe-receipt-out.txt"

write_result "$TMP/unsafe-result.txt" "$RECEIPT_SHA" 2026-08-25T00:01:02Z 2026-08-25T00:01:03Z 1 PRESENT
if run_verify "$TMP/unsafe-result-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/receipt.txt" "$TMP/evidence.bin" "$TMP/unsafe-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted an MMIO-write claim' >&2
  exit 1
fi
grep -q '^execution-result-forbids-smc-mmio-device-write-and-launch: FAIL$' "$TMP/unsafe-result-out.txt"

cp "$TMP/result.txt" "$TMP/duplicate-result.txt"
printf 'wrapper-invocation-count: 1\n' >> "$TMP/duplicate-result.txt"
if run_verify "$TMP/duplicate-result-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/pre-ledger.txt" "$TMP/post-ledger.txt" "$TMP/receipt.txt" "$TMP/evidence.bin" "$TMP/duplicate-result.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted a duplicate unique result field' >&2
  exit 1
fi
grep -q '^execution-result-fields-are-present-once: FAIL$' "$TMP/duplicate-result-out.txt"

cp "$TMP/pre-ledger.txt" "$TMP/changed-pre-ledger.txt"
printf 'used-token-sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >> "$TMP/changed-pre-ledger.txt"
if run_verify "$TMP/changed-pre-out.txt" "$TMP/readiness.txt" "$TMP/request.txt" "$TMP/changed-pre-ledger.txt" "$TMP/post-ledger.txt" >/dev/null 2>&1; then
  echo 'ERROR: result gate accepted changed pre-use ledger bytes' >&2
  exit 1
fi
grep -q '^authorization-readiness-binds-pre-use-ledger: FAIL$' "$TMP/changed-pre-out.txt"
grep -q '^post-use-ledger-is-exact-single-token-append: FAIL$' "$TMP/changed-pre-out.txt"

echo 'PASS: M7 token-consumption receipt and execution-result binding gate'
