#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERIALIZE="$ROOT/scripts/serialize-m7-smccc-feature-availability-capture.py"
VERIFY="$ROOT/scripts/verify-m7-smccc-el3-feature-availability.py"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/handoff.txt" <<'EOF'
el3-fp-simd-trap-disabled: PASS
el3-pointer-authentication-access-enabled: PASS
el3-mte-access-enabled: PASS
el3-sve-access-enabled: PASS
el3-sme-access-enabled: NOT_REQUIRED_FEATURE_ABSENT
secure-el3-observation: SELF_REPORTED_HANDOFF_ASSERTION_ONLY
secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN
capture-route-authorization: NOT_PROVEN
coherency-mechanism-implementation: NOT_PUBLICLY_PROVEN
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS
EOF

HANDOFF_SHA="$(sha256sum "$TMP/handoff.txt" | awk '{print $1}')"
HEADER_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.h" | awk '{print $1}')"
SOURCE_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.c" | awk '{print $1}')"
TRANSPORT_SHA="$(sha256sum "$LIB/M7SmcccCallAArch64.S" | awk '{print $1}')"
EMITTER_HEADER_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.h" | awk '{print $1}')"
EMITTER_SOURCE_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.c" | awk '{print $1}')"
BINDING_SHA="$(printf 'm7-serializer-authorization-binding' | sha256sum | awk '{print $1}')"

cat > "$TMP/route-authorization.txt" <<EOF
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
authorization-binding-schema: IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1
authorization-binding-sha256: $BINDING_SHA
output-buffer-address: 0x90000000
output-buffer-capacity: 0x1000
output-buffer-alignment: 0x1000
route-authorization-authenticity: DECLARED_PROJECT_OWNER_REVIEW_NOT_CRYPTOGRAPHICALLY_ATTESTED
authorization-scope: BOUND_SMCCC_FEATURE_AVAILABILITY_CAPTURE_ONLY
payload-launch-authorization: NO
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
collector-invocation-authorization: EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY
classification: M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS
EOF
ROUTE_SHA="$(sha256sum "$TMP/route-authorization.txt" | awk '{print $1}')"

write_capture() {
  local path="$1" outcome="$2" calls="$3" queries="$4"
  cat > "$path" <<EOF
collector-capture-schema: IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1
secure-el3-handoff-report-sha256: $HANDOFF_SHA
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
route-authorization-report-sha256: $ROUTE_SHA
authorization-binding-sha256: $BINDING_SHA
authorized-output-buffer-address: 0x90000000
authorized-output-buffer-capacity: 0x1000
authorized-output-buffer-alignment: 0x1000
capture-origin: PRE_SEC_NONSECURE_EL2
caller-security-state: NONSECURE
caller-exception-level: EL2
route-authorization-input: BOUND_SINGLE_USE_TOKEN
collector-outcome: $outcome
calls-issued: $calls
feature-queries-issued: $queries
vendor-or-sip-smc-action: NONE
direct-el3-register-read-action: NONE
secure-monitor-modification-action: NONE
mmio-action: NONE
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
launch-authorization: NO
EOF
}

write_capture "$TMP/supported-capture.txt" COMPLETE 5 3
cat >> "$TMP/supported-capture.txt" <<'EOF'
collector-call: index=0 fid=0x80000000 arg1=0x0 x0=0x10004 x1=IGNORED
collector-call: index=1 fid=0x80000001 arg1=0xC0000003 x0=0x0 x1=IGNORED
collector-call: index=2 fid=0xC0000003 arg1=0x1E1100 x0=0x0 x1=0x4010000
collector-call: index=3 fid=0xC0000003 arg1=0x1E1140 x0=0x0 x1=0x500
collector-call: index=4 fid=0xC0000003 arg1=0x1E1320 x0=0x0 x1=0x0
EOF

serialize() {
  local capture="$1" raw="$2" report="$3" handoff="${4:-$TMP/handoff.txt}" route="${5:-$TMP/route-authorization.txt}"
  "$PYTHON" "$SERIALIZE" "$handoff" "$capture" "$raw" "$report" "$route"
}

serialize "$TMP/supported-capture.txt" "$TMP/supported-raw.txt" "$TMP/supported-report.txt" >/dev/null
grep -q '^capture-binds-exact-handoff: PASS$' "$TMP/supported-report.txt"
grep -q '^capture-binds-exact-route-authorization-report: PASS$' "$TMP/supported-report.txt"
grep -q '^capture-binds-exact-authorization-binding: PASS$' "$TMP/supported-report.txt"
grep -q '^capture-buffer-matches-route-authorization: PASS$' "$TMP/supported-report.txt"
grep -q '^complete-outcome-has-five-calls: PASS$' "$TMP/supported-report.txt"
grep -q '^raw-el3-register-disclosure: FORBIDDEN$' "$TMP/supported-report.txt"
grep -q '^classification: M7_SMCCC_CAPTURE_SERIALIZATION_PASS$' "$TMP/supported-report.txt"
grep -q '^capture-serialization: DETERMINISTIC_COLLECTOR_TRANSCRIPT_V1$' "$TMP/supported-raw.txt"
grep -q '^smccc-feature-query: register=SCR_EL3 opcode=0x1E1100 status=SUCCESS availability-mask=0x4010000$' "$TMP/supported-raw.txt"
if grep -q '^scr-el3:' "$TMP/supported-raw.txt"; then
  echo "ERROR: serializer disclosed a raw SCR_EL3 value" >&2
  exit 1
fi

serialize "$TMP/supported-capture.txt" "$TMP/supported-raw-2.txt" "$TMP/supported-report-2.txt" >/dev/null
cmp "$TMP/supported-raw.txt" "$TMP/supported-raw-2.txt"

"$PYTHON" "$VERIFY" "$TMP/handoff.txt" "$TMP/supported-raw.txt" "$TMP/supported-gate.txt" >/dev/null
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS$' "$TMP/supported-gate.txt"

write_capture "$TMP/unsupported-capture.txt" FEATURE_UNAVAILABLE 2 0
cat >> "$TMP/unsupported-capture.txt" <<'EOF'
collector-call: index=0 fid=0x80000000 arg1=0x0 x0=0x10004 x1=IGNORED
collector-call: index=1 fid=0x80000001 arg1=0xC0000003 x0=0xFFFFFFFF x1=IGNORED
EOF
serialize "$TMP/unsupported-capture.txt" "$TMP/unsupported-raw.txt" "$TMP/unsupported-report.txt" >/dev/null
grep -q '^classification: M7_SMCCC_CAPTURE_SERIALIZATION_PASS$' "$TMP/unsupported-report.txt"
grep -q '^feature-availability-support: NOT_SUPPORTED$' "$TMP/unsupported-raw.txt"
grep -q '^feature-query-count: 0$' "$TMP/unsupported-raw.txt"
"$PYTHON" "$VERIFY" "$TMP/handoff.txt" "$TMP/unsupported-raw.txt" "$TMP/unsupported-gate.txt" >/dev/null
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_UNSUPPORTED$' "$TMP/unsupported-gate.txt"

assert_blocked() {
  local name="$1" expression="$2" check="$3"
  sed "$expression" "$TMP/supported-capture.txt" > "$TMP/$name.txt"
  if serialize "$TMP/$name.txt" "$TMP/$name-raw.txt" "$TMP/$name-report.txt" >/dev/null 2>&1; then
    echo "ERROR: serializer accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$TMP/$name-report.txt"
  grep -q '^raw-manifest-write-action: NONE$' "$TMP/$name-report.txt"
  grep -q '^classification: M7_SMCCC_CAPTURE_SERIALIZATION_BLOCKED$' "$TMP/$name-report.txt"
  test ! -e "$TMP/$name-raw.txt"
}

assert_blocked wrong-source-hash \
  "s/collector-source-sha256: $SOURCE_SHA/collector-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  capture-collector-source-sha256-matches
assert_blocked wrong-emitter-source-hash \
  "s/transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA/transcript-emitter-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  capture-transcript-emitter-source-sha256-matches
assert_blocked wrong-route-report-hash \
  "s/route-authorization-report-sha256: $ROUTE_SHA/route-authorization-report-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  capture-binds-exact-route-authorization-report
assert_blocked wrong-authorization-binding \
  "s/authorization-binding-sha256: $BINDING_SHA/authorization-binding-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  capture-binds-exact-authorization-binding
assert_blocked wrong-authorized-buffer \
  's/authorized-output-buffer-address: 0x90000000/authorized-output-buffer-address: 0x90001000/' \
  capture-buffer-matches-route-authorization
assert_blocked wrong-fid \
  's/index=1 fid=0x80000001/index=1 fid=0x82000001/' \
  discovery-call-is-exact-success
assert_blocked wrong-order \
  's/index=2 fid=/index=3 fid=/' \
  collector-call-indexes-are-canonical
assert_blocked query-error \
  's/index=3 fid=0xC0000003 arg1=0x1E1140 x0=0x0/index=3 fid=0xC0000003 arg1=0x1E1140 x0=0xFFFFFFFD/' \
  cptr_el3-availability-call-is-exact-success
assert_blocked raw-el3-injection \
  '$a scr-el3: 0x4030501' \
  capture-has-no-raw-el3-register-fields
assert_blocked vendor-action \
  's/vendor-or-sip-smc-action: NONE/vendor-or-sip-smc-action: PERFORMED/' \
  capture-vendor-or-sip-smc-action-is-exact
assert_blocked relaxed-launch \
  's/launch-authorization: NO/launch-authorization: YES/' \
  capture-launch-authorization-is-exact
assert_blocked version-unavailable-outcome \
  's/collector-outcome: COMPLETE/collector-outcome: VERSION_UNAVAILABLE/' \
  collector-outcome-is-serializable

cp "$TMP/handoff.txt" "$TMP/tampered-handoff.txt"
printf X >> "$TMP/tampered-handoff.txt"
if serialize "$TMP/supported-capture.txt" "$TMP/tampered-raw.txt" "$TMP/tampered-report.txt" "$TMP/tampered-handoff.txt" >/dev/null 2>&1; then
  echo "ERROR: serializer accepted a tampered handoff report" >&2
  exit 1
fi
grep -q '^capture-binds-exact-handoff: FAIL$' "$TMP/tampered-report.txt"
test ! -e "$TMP/tampered-raw.txt"

cp "$TMP/route-authorization.txt" "$TMP/tampered-route.txt"
printf X >> "$TMP/tampered-route.txt"
if serialize "$TMP/supported-capture.txt" "$TMP/tampered-route-raw.txt" "$TMP/tampered-route-report.txt" "$TMP/handoff.txt" "$TMP/tampered-route.txt" >/dev/null 2>&1; then
  echo "ERROR: serializer accepted a tampered route-authorization report" >&2
  exit 1
fi
grep -q '^capture-binds-exact-route-authorization-report: FAIL$' "$TMP/tampered-route-report.txt"
test ! -e "$TMP/tampered-route-raw.txt"

sed 's/payload-launch-authorization: NO/payload-launch-authorization: YES/' "$TMP/route-authorization.txt" > "$TMP/launch-route.txt"
if serialize "$TMP/supported-capture.txt" "$TMP/launch-route-raw.txt" "$TMP/launch-route-report.txt" "$TMP/handoff.txt" "$TMP/launch-route.txt" >/dev/null 2>&1; then
  echo "ERROR: serializer accepted a payload-launch-authorizing route" >&2
  exit 1
fi
grep -q '^route-authorization-denies-launch-and-writes: FAIL$' "$TMP/launch-route-report.txt"
test ! -e "$TMP/launch-route-raw.txt"

cp "$TMP/supported-raw.txt" "$TMP/stale-raw.txt"
sed "s/authorization-binding-sha256: $BINDING_SHA/authorization-binding-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  "$TMP/supported-capture.txt" > "$TMP/stale-capture.txt"
if serialize "$TMP/stale-capture.txt" "$TMP/stale-raw.txt" "$TMP/stale-report.txt" >/dev/null 2>&1; then
  echo "ERROR: serializer accepted an invalid capture over a stale raw manifest" >&2
  exit 1
fi
test ! -e "$TMP/stale-raw.txt"
grep -q '^raw-manifest-write-action: NONE$' "$TMP/stale-report.txt"

echo "PASS: M7 deterministic SMCCC capture serializer round trip"
