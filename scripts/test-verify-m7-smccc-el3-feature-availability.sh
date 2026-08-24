#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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
BINDING_SHA="$(printf 'm7-final-gate-authorization-binding' | sha256sum | awk '{print $1}')"
CAPTURE_SHA="$(printf 'm7-final-gate-collector-capture' | sha256sum | awk '{print $1}')"

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

write_raw() {
  local path="$1" support="$2" discovery="$3" action="$4" count="$5" outcome="$6"
  cat > "$path" <<EOF
smccc-feature-availability-schema: IZZOS_M7_SMCCC_EL3_FEATURE_AVAILABILITY_V1
secure-el3-handoff-report-sha256: $HANDOFF_SHA
route-authorization-report-sha256: $ROUTE_SHA
authorization-binding-sha256: $BINDING_SHA
collector-capture-sha256: $CAPTURE_SHA
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
collector-outcome: $outcome
capture-serialization: DETERMINISTIC_COLLECTOR_TRANSCRIPT_V1
capture-route-authorization: BOUND_SINGLE_USE_TOKEN_TO_DECLARED_PROJECT_REVIEW
authorized-output-buffer-address: 0x90000000
authorized-output-buffer-capacity: 0x1000
authorized-output-buffer-alignment: 0x1000
capture-source: PRE_SEC_NONSECURE_EL2_SMCCC_ARCHITECTURE_SERVICE
caller-security-state: NONSECURE
caller-exception-level: EL2
smccc-conduit: SMC
smccc-service-owner: ARM_ARCHITECTURE_SERVICE_OEN_0
smccc-version-fid: 0x80000000
smccc-version-x0: 0x10004
smccc-arch-features-fid: 0x80000001
feature-availability-discovery-target-fid: 0xC0000003
feature-availability-discovery-x0: $discovery
feature-availability-fid: 0xC0000003
feature-availability-support: $support
availability-result-semantics: SANITIZED_FEATURE_ENABLEMENT_MASK_NOT_RAW_EL3_REGISTER
feature-query-count: $count
smc-query-action: $action
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

write_raw "$TMP/supported.txt" SUPPORTED 0x0 VERSION_DISCOVERY_AND_FEATURE_AVAILABILITY_READS_ONLY 3 COMPLETE
cat >> "$TMP/supported.txt" <<'EOF'
smccc-feature-query: register=SCR_EL3 opcode=0x1E1100 status=SUCCESS availability-mask=0x4010000
smccc-feature-query: register=CPTR_EL3 opcode=0x1E1140 status=SUCCESS availability-mask=0x500
smccc-feature-query: register=MDCR_EL3 opcode=0x1E1320 status=SUCCESS availability-mask=0x0
EOF

run_verify() {
  local raw="$1" out="$2" handoff="${3:-$TMP/handoff.txt}" route="${4:-$TMP/route-authorization.txt}"
  "$PYTHON" "$VERIFY" "$handoff" "$raw" "$out" "$route"
}

run_verify "$TMP/supported.txt" "$TMP/supported-out.txt" >/dev/null
grep -q '^supported-route-opcodes-are-exact: PASS$' "$TMP/supported-out.txt"
grep -q '^smccc-fp-simd-availability: PASS$' "$TMP/supported-out.txt"
grep -q '^smccc-pointer-authentication-availability: PASS$' "$TMP/supported-out.txt"
grep -q '^smccc-mte-availability: PASS$' "$TMP/supported-out.txt"
grep -q '^smccc-sve-availability: PASS$' "$TMP/supported-out.txt"
grep -q '^smccc-sme-scr-availability: NOT_REQUIRED_FEATURE_ABSENT$' "$TMP/supported-out.txt"
grep -q '^scr-ns-rw-hce-fiq-corroboration: OUT_OF_SCOPE_NOT_REPORTED_BY_SERVICE$' "$TMP/supported-out.txt"
grep -q '^launch-authorization: NO$' "$TMP/supported-out.txt"
grep -q '^raw-binds-exact-route-authorization-report: PASS$' "$TMP/supported-out.txt"
grep -q '^raw-binds-exact-authorization-binding: PASS$' "$TMP/supported-out.txt"
grep -q '^raw-buffer-matches-route-authorization: PASS$' "$TMP/supported-out.txt"
grep -q '^capture-route-binding: EXACT_SINGLE_USE_TOKEN_REPORT_MATCH$' "$TMP/supported-out.txt"
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS$' "$TMP/supported-out.txt"

write_raw "$TMP/unsupported.txt" NOT_SUPPORTED 0xFFFFFFFF VERSION_AND_ARCH_FEATURE_DISCOVERY_ONLY 0 FEATURE_UNAVAILABLE
run_verify "$TMP/unsupported.txt" "$TMP/unsupported-out.txt" >/dev/null
grep -q '^unsupported-route-discovery-returned-not-supported: PASS$' "$TMP/unsupported-out.txt"
grep -q '^unsupported-route-has-no-feature-queries: PASS$' "$TMP/unsupported-out.txt"
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_UNSUPPORTED$' "$TMP/unsupported-out.txt"
grep -q '^launch-authorization: NO$' "$TMP/unsupported-out.txt"

cp "$TMP/handoff.txt" "$TMP/tampered-handoff.txt"
printf X >> "$TMP/tampered-handoff.txt"
if run_verify "$TMP/supported.txt" "$TMP/tampered-handoff-out.txt" "$TMP/tampered-handoff.txt" >/dev/null 2>&1; then
  echo "ERROR: SMCCC verifier accepted a tampered handoff report" >&2
  exit 1
fi
grep -q '^raw-binds-exact-secure-el3-handoff: FAIL$' "$TMP/tampered-handoff-out.txt"

assert_blocked() {
  local name="$1" expression="$2" check="$3"
  sed "$expression" "$TMP/supported.txt" > "$TMP/$name.txt"
  if run_verify "$TMP/$name.txt" "$TMP/$name-out.txt" >/dev/null 2>&1; then
    echo "ERROR: SMCCC verifier accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$TMP/$name-out.txt"
  grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_BLOCKED$' "$TMP/$name-out.txt"
}

assert_blocked wrong-owner \
  's/ARM_ARCHITECTURE_SERVICE_OEN_0/SIP_SERVICE_OEN_2/' \
  raw-smccc-service-owner-is-exact
assert_blocked wrong-fid \
  's/feature-availability-fid: 0xC0000003/feature-availability-fid: 0xC2000003/' \
  raw-feature-availability-fid-is-exact
assert_blocked wrong-opcode \
  's/opcode=0x1E1100/opcode=0x1E1101/' \
  supported-route-opcodes-are-exact
assert_blocked pauth-not-enabled \
  's/availability-mask=0x4010000/availability-mask=0x4000000/' \
  smccc-pointer-authentication-availability
assert_blocked mte-not-enabled \
  's/availability-mask=0x4010000/availability-mask=0x10000/' \
  smccc-mte-availability
assert_blocked sve-not-enabled \
  's/availability-mask=0x500/availability-mask=0x400/' \
  smccc-sve-availability
assert_blocked vendor-call \
  's/vendor-or-sip-smc-action: NONE/vendor-or-sip-smc-action: PERFORMED/' \
  raw-vendor-or-sip-smc-action-is-exact
assert_blocked relaxed-launch \
  's/launch-authorization: NO/launch-authorization: YES/' \
  raw-launch-authorization-is-exact
assert_blocked wrong-route-digest \
  "s/route-authorization-report-sha256: $ROUTE_SHA/route-authorization-report-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  raw-binds-exact-route-authorization-report
assert_blocked wrong-authorization-binding \
  "s/authorization-binding-sha256: $BINDING_SHA/authorization-binding-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  raw-binds-exact-authorization-binding
assert_blocked wrong-buffer \
  's/authorized-output-buffer-address: 0x90000000/authorized-output-buffer-address: 0x90001000/' \
  raw-buffer-matches-route-authorization
assert_blocked wrong-component \
  "s/collector-source-sha256: $SOURCE_SHA/collector-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  raw-collector-source-sha256-matches
assert_blocked wrong-supported-outcome \
  's/collector-outcome: COMPLETE/collector-outcome: FEATURE_UNAVAILABLE/' \
  supported-route-collector-outcome-is-complete

cp "$TMP/route-authorization.txt" "$TMP/tampered-route.txt"
printf X >> "$TMP/tampered-route.txt"
if run_verify "$TMP/supported.txt" "$TMP/tampered-route-out.txt" "$TMP/handoff.txt" "$TMP/tampered-route.txt" >/dev/null 2>&1; then
  echo "ERROR: SMCCC verifier accepted a tampered route-authorization report" >&2
  exit 1
fi
grep -q '^raw-binds-exact-route-authorization-report: FAIL$' "$TMP/tampered-route-out.txt"

sed 's/payload-launch-authorization: NO/payload-launch-authorization: YES/' "$TMP/route-authorization.txt" > "$TMP/launch-route.txt"
if run_verify "$TMP/supported.txt" "$TMP/launch-route-out.txt" "$TMP/handoff.txt" "$TMP/launch-route.txt" >/dev/null 2>&1; then
  echo "ERROR: SMCCC verifier accepted route authorization that permits launch" >&2
  exit 1
fi
grep -q '^route-authorization-denies-launch-and-writes: FAIL$' "$TMP/launch-route-out.txt"

sed 's/collector-outcome: FEATURE_UNAVAILABLE/collector-outcome: COMPLETE/' "$TMP/unsupported.txt" > "$TMP/wrong-unsupported-outcome.txt"
if run_verify "$TMP/wrong-unsupported-outcome.txt" "$TMP/wrong-unsupported-outcome-out.txt" >/dev/null 2>&1; then
  echo "ERROR: SMCCC verifier accepted an unsupported route with COMPLETE outcome" >&2
  exit 1
fi
grep -q '^unsupported-route-collector-outcome-is-feature-unavailable: FAIL$' "$TMP/wrong-unsupported-outcome-out.txt"

echo "PASS: M7 SMCCC EL3 feature-availability route gate"
