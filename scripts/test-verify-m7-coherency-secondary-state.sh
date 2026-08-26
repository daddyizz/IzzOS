#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-coherency-secondary-state.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/cross-core.txt" <<'EOF'
capture-source: SAME_PRE_SEC_CROSS_CORE_RENDEZVOUS
secondary-cpu-return-state: HELD_OR_PARKED_AFTER_READ_ONLY_CAPTURE
expected-mpidr-affinities: 0x0,0x1,0x2,0x3
observed-mpidr-affinities: 0x0,0x1,0x2,0x3
primary-mpidr-affinity: 0x0
coherency-domain-consistency: NOT_PROVEN
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS
EOF
CROSS_SHA="$(sha256sum "$TMP/cross-core.txt" | awk '{print $1}')"

cat > "$TMP/raw.txt" <<EOF
coherency-state-schema: IZZOS_M7_COHERENCY_SECONDARY_STATE_V1
cross-core-register-report-sha256: $CROSS_SHA
capture-source: SAME_PRE_SEC_CROSS_CORE_RENDEZVOUS
evidence-kind: IMPLEMENTATION_DEFINED_FIRMWARE_HANDOFF_ASSERTION
domain-token-kind: PLATFORM_FIRMWARE_OPAQUE_ID
cpu-record-count: 4
cpu-coherency: affinity=0x0 role=PRIMARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=PRE_SEC_ENTRY payload-state=PRE_SEC_ONLY
cpu-coherency: affinity=0x1 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=PARKED payload-state=NOT_RUNNING
cpu-coherency: affinity=0x2 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=NOT_RELEASED payload-state=NOT_RUNNING
cpu-coherency: affinity=0x3 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=PARKED payload-state=NOT_RUNNING
secondary-release-action: NONE
coherency-configuration-action: NONE
maintenance-operation-action: NONE
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local raw="$1" out="$2" cross="${3:-$TMP/cross-core.txt}"
  "$PYTHON" "$VERIFY" "$cross" "$raw" "$out"
}

run_verify "$TMP/raw.txt" "$TMP/pass.txt" >/dev/null
grep -q '^cross-core-register-consistency-pass: PASS$' "$TMP/pass.txt"
grep -q '^cpu-affinity-set-matches-cross-core-topology: PASS$' "$TMP/pass.txt"
grep -q '^exactly-one-primary-role-is-declared: PASS$' "$TMP/pass.txt"
grep -q '^primary-role-matches-cross-core-primary: PASS$' "$TMP/pass.txt"
grep -q '^all-cpus-assert-one-opaque-domain: PASS$' "$TMP/pass.txt"
grep -q '^maintenance-broadcast-is-asserted-enabled-on-all-cpus: PASS$' "$TMP/pass.txt"
grep -q '^secondary-cpus-are-held-and-not-running-payload: PASS$' "$TMP/pass.txt"
grep -q '^coherency-proof: NOT_YET_PROVEN$' "$TMP/pass.txt"
grep -q '^sec-wrapper-implementation-authorization: NO$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS$' "$TMP/pass.txt"

cp "$TMP/cross-core.txt" "$TMP/tampered-cross-core.txt"
printf X >> "$TMP/tampered-cross-core.txt"
if run_verify "$TMP/raw.txt" "$TMP/tampered-cross-core-out.txt" "$TMP/tampered-cross-core.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted a tampered cross-core report" >&2
  exit 1
fi
grep -q '^raw-binds-exact-cross-core-report: FAIL$' "$TMP/tampered-cross-core-out.txt"

sed '/affinity=0x3/d; s/cpu-record-count: 4/cpu-record-count: 3/' "$TMP/raw.txt" > "$TMP/missing-secondary.txt"
if run_verify "$TMP/missing-secondary.txt" "$TMP/missing-secondary-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted a missing secondary CPU" >&2
  exit 1
fi
grep -q '^cpu-affinity-set-matches-cross-core-topology: FAIL$' "$TMP/missing-secondary-out.txt"

sed 's/affinity=0x1 role=SECONDARY/affinity=0x1 role=PRIMARY/' "$TMP/raw.txt" > "$TMP/two-primary.txt"
if run_verify "$TMP/two-primary.txt" "$TMP/two-primary-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted two primary roles" >&2
  exit 1
fi
grep -q '^exactly-one-primary-role-is-declared: FAIL$' "$TMP/two-primary-out.txt"

sed 's/affinity=0x3 role=SECONDARY domain-token=0xA/affinity=0x3 role=SECONDARY domain-token=0xB/' "$TMP/raw.txt" > "$TMP/split-domain.txt"
if run_verify "$TMP/split-domain.txt" "$TMP/split-domain-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted split coherency-domain tokens" >&2
  exit 1
fi
grep -q '^all-cpus-assert-one-opaque-domain: FAIL$' "$TMP/split-domain-out.txt"
grep -q '^coherency-domain-assertion: BLOCKED$' "$TMP/split-domain-out.txt"

sed 's/affinity=0x2 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED/affinity=0x2 role=SECONDARY domain-token=0xA maintenance-broadcast=DISABLED/' "$TMP/raw.txt" > "$TMP/broadcast-disabled.txt"
if run_verify "$TMP/broadcast-disabled.txt" "$TMP/broadcast-disabled-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted disabled maintenance broadcast" >&2
  exit 1
fi
grep -q '^maintenance-broadcast-is-asserted-enabled-on-all-cpus: FAIL$' "$TMP/broadcast-disabled-out.txt"
grep -q '^maintenance-broadcast-assertion: BLOCKED$' "$TMP/broadcast-disabled-out.txt"

sed 's/affinity=0x3 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=PARKED payload-state=NOT_RUNNING/affinity=0x3 role=SECONDARY domain-token=0xA maintenance-broadcast=ENABLED execution-state=RUNNING payload-state=RUNNING/' "$TMP/raw.txt" > "$TMP/secondary-running.txt"
if run_verify "$TMP/secondary-running.txt" "$TMP/secondary-running-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted a secondary running the payload" >&2
  exit 1
fi
grep -q '^secondary-cpus-are-held-and-not-running-payload: FAIL$' "$TMP/secondary-running-out.txt"
grep -q '^secondary-cpu-state-assertion: BLOCKED$' "$TMP/secondary-running-out.txt"

sed 's/coherency-configuration-action: NONE/coherency-configuration-action: PERFORMED/' "$TMP/raw.txt" > "$TMP/action-performed.txt"
if run_verify "$TMP/action-performed.txt" "$TMP/action-performed-out.txt" >/dev/null 2>&1; then
  echo "ERROR: coherency verifier accepted an unapproved coherency action" >&2
  exit 1
fi
grep -q '^raw-asserts-no-coherency-configuration-action: FAIL$' "$TMP/action-performed-out.txt"
grep -q '^classification: M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_BLOCKED$' "$TMP/action-performed-out.txt"

echo "PASS: M7 coherency-domain and secondary-CPU assertion schema gate"
