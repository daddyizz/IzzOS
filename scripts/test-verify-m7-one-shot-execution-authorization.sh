#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-one-shot-execution-authorization.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/device-promotion.txt" <<'EOF'
dsc-fdf-promotion-authorization: NO
android-container-construction-authorization: NO
launch-authorization: NO
classification: M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED
EOF
DEVICE_SHA="$(sha256sum "$TMP/device-promotion.txt" | awk '{print $1}')"

cat > "$TMP/wrapper.txt" <<EOF
device-promotion-readiness-sha256: $DEVICE_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
launch-authorization: NO
classification: M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED
EOF
WRAPPER_SHA="$(sha256sum "$TMP/wrapper.txt" | awk '{print $1}')"
SNAPSHOT_SHA="$(printf 'exact-runtime-ownership-snapshot' | sha256sum | awk '{print $1}')"

cat > "$TMP/ownership.txt" <<EOF
wrapper-execution-report-sha256: $WRAPPER_SHA
runtime-ownership-snapshot-sha256: $SNAPSHOT_SHA
capture-id: CPH2413-EX01-runtime-ownership-test
capture-timestamp-utc: 2026-08-25T00:00:00Z
exact-device-build: CPH2413_15.0.0.1901(EX01)
ownership-evidence-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
ownership-snapshot-lifetime: EXACT_CAPTURE_INSTANT_ONLY
dsc-fdf-promotion-authorization: NO
container-build-authorization: NO
launch-authorization: NO
classification: M7_RUNTIME_DESTINATION_OWNERSHIP_SCHEMA_PASS_AUTHENTICITY_FRESHNESS_REQUIRED
EOF
OWNERSHIP_SHA="$(sha256sum "$TMP/ownership.txt" | awk '{print $1}')"

cat > "$TMP/ledger-empty.txt" <<'EOF'
used-token-ledger-schema: IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1
EOF

write_request() {
  local output="$1" capture="${2:-2026-08-25T00:00:00Z}" authorized="${3:-2026-08-25T00:00:30Z}" expires="${4:-2026-08-25T00:05:00Z}" count="${5:-1}" launch="${6:-NO}" nonce="${7:-1111111111111111111111111111111111111111111111111111111111111111}"
  "$PYTHON" - "$output" "$OWNERSHIP_SHA" "$SNAPSHOT_SHA" "$WRAPPER_SHA" "$DEVICE_SHA" "$capture" "$authorized" "$expires" "$count" "$launch" "$nonce" <<'PY'
import hashlib
import sys
from pathlib import Path

output, ownership, snapshot, wrapper, device, capture, authorized, expires, count, launch, nonce = sys.argv[1:]
fields = [
    ("one-shot-authorization-schema", "IZZOS_M7_ONE_SHOT_EXECUTION_AUTHORIZATION_REQUEST_V1"),
    ("runtime-ownership-report-sha256", ownership),
    ("runtime-ownership-snapshot-sha256", snapshot),
    ("wrapper-execution-report-sha256", wrapper),
    ("device-promotion-readiness-sha256", device),
    ("exact-device-build", "CPH2413_15.0.0.1901(EX01)"),
    ("capture-id", "CPH2413-EX01-runtime-ownership-test"),
    ("capture-timestamp-utc", capture),
    ("authorized-at-utc", authorized),
    ("expires-at-utc", expires),
    ("authorization-nonce", nonce),
    ("authorization-use-count", count),
    ("requested-wrapper-execution-scope", "EXACTLY_ONCE_FOR_BOUND_EVIDENCE_CAPTURE_ONLY"),
    ("authorization-authority-authenticity", "DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED"),
    ("atomic-token-consumption", "REQUIRED_BEFORE_WRAPPER_INVOCATION"),
    ("device-writes", "NONE"),
    ("persistent-writes", "FORBIDDEN"),
    ("slot-changes", "FORBIDDEN"),
    ("payload-launch-authorization", launch),
    ("dsc-fdf-promotion-authorization", "NO"),
    ("container-build-authorization", "NO"),
]
canonical = "".join(f"{key}={value}\n" for key, value in fields)
token = hashlib.sha256(canonical.encode()).hexdigest()
rendered = []
for key, value in fields:
    rendered.append(f"{key}: {value}")
    if key == "authorization-nonce":
        rendered.append(f"authorization-token-sha256: {token}")
Path(output).write_text("\n".join(rendered) + "\n", newline="\n")
PY
}

run_verify() {
  local output="$1" request="${2:-$TMP/request.txt}" ledger="${3:-$TMP/ledger-empty.txt}" evaluation="${4:-2026-08-25T00:01:00Z}" ownership="${5:-$TMP/ownership.txt}" wrapper="${6:-$TMP/wrapper.txt}" device="${7:-$TMP/device-promotion.txt}"
  "$PYTHON" "$VERIFY" "$ownership" "$wrapper" "$device" "$request" "$ledger" "$evaluation" "$output"
}

write_request "$TMP/request.txt"
run_verify "$TMP/pass.txt" >/dev/null
grep -q '^ownership-snapshot-is-not-future-or-stale: PASS$' "$TMP/pass.txt"
grep -q '^authorization-token-digest-is-canonical: PASS$' "$TMP/pass.txt"
grep -q '^authorization-token-is-unused-in-supplied-ledger: PASS$' "$TMP/pass.txt"
grep -q '^wrapper-execution-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_FRESH_ONE_SHOT_EXECUTION_TOKEN_READY_ATOMIC_CONSUMPTION_REQUIRED$' "$TMP/pass.txt"

TOKEN_SHA="$(awk -F': ' '$1=="authorization-token-sha256" {print $2}' "$TMP/request.txt")"
cat > "$TMP/ledger-used.txt" <<EOF
used-token-ledger-schema: IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1
used-token-sha256: $TOKEN_SHA
EOF
if run_verify "$TMP/replay-out.txt" "$TMP/request.txt" "$TMP/ledger-used.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a replayed token' >&2
  exit 1
fi
grep -q '^authorization-token-is-unused-in-supplied-ledger: FAIL$' "$TMP/replay-out.txt"
grep -q '^classification: M7_ONE_SHOT_EXECUTION_AUTHORIZATION_READINESS_BLOCKED$' "$TMP/replay-out.txt"

if run_verify "$TMP/expired-out.txt" "$TMP/request.txt" "$TMP/ledger-empty.txt" 2026-08-25T00:05:01Z >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted an expired token' >&2
  exit 1
fi
grep -q '^evaluation-is-inside-authorization-window: FAIL$' "$TMP/expired-out.txt"

write_request "$TMP/stale-request.txt" 2026-08-25T00:00:00Z 2026-08-25T00:00:30Z 2026-08-25T00:05:00Z
if run_verify "$TMP/stale-out.txt" "$TMP/stale-request.txt" "$TMP/ledger-empty.txt" 2026-08-25T00:06:00Z >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a stale ownership snapshot' >&2
  exit 1
fi
grep -q '^ownership-snapshot-is-not-future-or-stale: FAIL$' "$TMP/stale-out.txt"

write_request "$TMP/count-two.txt" 2026-08-25T00:00:00Z 2026-08-25T00:00:30Z 2026-08-25T00:05:00Z 2
if run_verify "$TMP/count-two-out.txt" "$TMP/count-two.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a multiple-use request' >&2
  exit 1
fi
grep -q '^authorization-use-count-is-exactly-one: FAIL$' "$TMP/count-two-out.txt"

write_request "$TMP/unsafe.txt" 2026-08-25T00:00:00Z 2026-08-25T00:00:30Z 2026-08-25T00:05:00Z 1 YES
if run_verify "$TMP/unsafe-out.txt" "$TMP/unsafe.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a payload-launch claim' >&2
  exit 1
fi
grep -q '^authorization-request-forbids-write-promotion-container-and-launch: FAIL$' "$TMP/unsafe-out.txt"

sed 's/^authorization-token-sha256: .*/authorization-token-sha256: 0000000000000000000000000000000000000000000000000000000000000000/' "$TMP/request.txt" > "$TMP/tampered-token.txt"
if run_verify "$TMP/tampered-token-out.txt" "$TMP/tampered-token.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a changed token digest' >&2
  exit 1
fi
grep -q '^authorization-token-digest-is-canonical: FAIL$' "$TMP/tampered-token-out.txt"

cp "$TMP/request.txt" "$TMP/duplicate.txt"
printf 'authorization-use-count: 1\n' >> "$TMP/duplicate.txt"
if run_verify "$TMP/duplicate-out.txt" "$TMP/duplicate.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted a duplicate unique field' >&2
  exit 1
fi
grep -q '^authorization-request-fields-are-present-once: FAIL$' "$TMP/duplicate-out.txt"

cp "$TMP/wrapper.txt" "$TMP/changed-wrapper.txt"
printf 'changed: yes\n' >> "$TMP/changed-wrapper.txt"
if run_verify "$TMP/changed-wrapper-out.txt" "$TMP/request.txt" "$TMP/ledger-empty.txt" 2026-08-25T00:01:00Z "$TMP/ownership.txt" "$TMP/changed-wrapper.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted changed wrapper-report bytes' >&2
  exit 1
fi
grep -q '^upstream-ownership-binds-wrapper-report: FAIL$' "$TMP/changed-wrapper-out.txt"
grep -q '^authorization-request-binds-wrapper-report: FAIL$' "$TMP/changed-wrapper-out.txt"

cat > "$TMP/duplicate-ledger.txt" <<EOF
used-token-ledger-schema: IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1
used-token-sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
used-token-sha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EOF
if run_verify "$TMP/duplicate-ledger-out.txt" "$TMP/request.txt" "$TMP/duplicate-ledger.txt" >/dev/null 2>&1; then
  echo 'ERROR: one-shot gate accepted duplicate ledger entries' >&2
  exit 1
fi
grep -q '^used-token-ledger-entries-are-valid-and-unique: FAIL$' "$TMP/duplicate-ledger-out.txt"

echo 'PASS: M7 fresh one-shot execution-authorization readiness gate'
