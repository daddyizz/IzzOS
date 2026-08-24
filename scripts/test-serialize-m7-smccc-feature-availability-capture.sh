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
capture-origin: PRE_SEC_NONSECURE_EL2
caller-security-state: NONSECURE
caller-exception-level: EL2
route-authorization-input: EXPLICIT_CALLER_ASSERTION_NOT_INDEPENDENTLY_ATTESTED
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
  local capture="$1" raw="$2" report="$3" handoff="${4:-$TMP/handoff.txt}"
  "$PYTHON" "$SERIALIZE" "$handoff" "$capture" "$raw" "$report"
}

serialize "$TMP/supported-capture.txt" "$TMP/supported-raw.txt" "$TMP/supported-report.txt" >/dev/null
grep -q '^capture-binds-exact-handoff: PASS$' "$TMP/supported-report.txt"
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

echo "PASS: M7 deterministic SMCCC capture serializer round trip"
