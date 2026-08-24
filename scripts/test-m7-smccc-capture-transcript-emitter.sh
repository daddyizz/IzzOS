#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
SERIALIZE="$ROOT/scripts/serialize-m7-smccc-feature-availability-capture.py"
VERIFY="$ROOT/scripts/verify-m7-smccc-el3-feature-availability.py"
PYTHON="${PYTHON:-python3}"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" "$ROOT/scripts/verify-m7-smccc-transcript-emitter-source.py" "$ROOT" > "$TMP/source-contract.txt"
grep -q '^emitter-measures-before-buffer-write: PASS$' "$TMP/source-contract.txt"
grep -q '^emitter-is-not-integrated-into-current-diagnostic: PASS$' "$TMP/source-contract.txt"
grep -q '^classification: M7_SMCCC_TRANSCRIPT_EMITTER_SOURCE_CONTRACT_PASS$' "$TMP/source-contract.txt"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "PASS: M7 deterministic SMCCC transcript emitter (source checks; host C compiler unavailable)"
  exit 0
fi

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
BINDING_SHA="$(printf 'm7-emitter-authorization-binding' | sha256sum | awk '{print $1}')"

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

cat > "$TMP/harness.c" <<'EOF'
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "M7SmcccCaptureTranscript.h"

typedef struct {
  M7_SMCCC_RESULT Responses[5];
  size_t ResponseCount;
  size_t CallCount;
} FAKE_TRANSPORT;

static void
FakeInvoke(uint64_t Fid, uint64_t Arg1, M7_SMCCC_RESULT *Result, void *Context)
{
  FAKE_TRANSPORT *Fake = (FAKE_TRANSPORT *)Context;
  (void)Fid;
  (void)Arg1;
  assert(Fake->CallCount < Fake->ResponseCount);
  *Result = Fake->Responses[Fake->CallCount++];
}

static void
ParseDigest(const char *Text, uint8_t Digest[M7_SMCCC_ROUTE_DIGEST_SIZE])
{
  uint32_t Index;
  assert(strlen(Text) == M7_SMCCC_ROUTE_DIGEST_SIZE * 2);
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    unsigned int Value;
    assert(sscanf(&Text[Index * 2], "%2x", &Value) == 1);
    Digest[Index] = (uint8_t)Value;
  }
}

static void
PrepareAuthorization(
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation,
  const char *RouteReportSha256,
  const char *AuthorizationBindingSha256
  )
{
  memset(Token, 0, sizeof(*Token));
  memset(Expectation, 0, sizeof(*Expectation));
  Token->Magic = M7_SMCCC_ROUTE_TOKEN_MAGIC;
  Token->FormatVersion = M7_SMCCC_ROUTE_TOKEN_VERSION;
  Token->TokenSize = (uint32_t)sizeof(*Token);
  Token->PolicyFlags = M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS;
  Token->InvocationBudget = 1;
  Token->SmcccCallLimit = M7_SMCCC_MAX_CALLS;
  Token->OutputBufferAddress = UINT64_C(0x90000000);
  Token->OutputBufferCapacity = M7_SMCCC_ROUTE_MIN_BUFFER_CAPACITY;
  Token->OutputBufferAlignment = UINT64_C(0x1000);
  Expectation->OutputBufferAddress = Token->OutputBufferAddress;
  Expectation->OutputBufferCapacity = Token->OutputBufferCapacity;
  Expectation->OutputBufferAlignment = Token->OutputBufferAlignment;
  ParseDigest(RouteReportSha256, Token->RouteAuthorizationReportSha256);
  ParseDigest(AuthorizationBindingSha256, Token->AuthorizationBindingSha256);
  memcpy(Expectation->RouteAuthorizationReportSha256, Token->RouteAuthorizationReportSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
  memcpy(Expectation->AuthorizationBindingSha256, Token->AuthorizationBindingSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
}

int main(int Argc, char **Argv)
{
  M7_SMCCC_CALLER_STATE State = {0};
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN Token;
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION Expectation;
  M7_SMCCC_TRANSCRIPT_BINDING Binding;
  M7_SMCCC_TRANSCRIPT_BINDING InvalidBinding;
  M7_SMCCC_CAPTURE Capture;
  M7_SMCCC_CAPTURE Tampered;
  FAKE_TRANSPORT Fake = {0};
  char Buffer[4096];
  char Small[8] = {'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X'};
  size_t Length;
  size_t Index;

  assert(Argc == 10);
  Binding = (M7_SMCCC_TRANSCRIPT_BINDING){Argv[2], Argv[3], Argv[4], Argv[5], Argv[6], Argv[7]};
  PrepareAuthorization(&Token, &Expectation, Argv[8], Argv[9]);
  State.CallerExceptionLevel = M7_SMCCC_EXPECTED_CALLER_EL;
  State.CallerIsNonSecure = 1;
  State.RouteAuthorizationToken = &Token;
  State.RouteAuthorizationExpectation = &Expectation;

  if (strcmp(Argv[1], "supported") == 0) {
    Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0, 0}, {0, 0x4010000}, {0, 0x500}, {0, 0}}, .ResponseCount = 5 };
    assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorComplete);
  } else {
    assert(strcmp(Argv[1], "unsupported") == 0);
    Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0xFFFFFFFF, 0}}, .ResponseCount = 2 };
    assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorFeatureUnavailable);
  }

  assert(M7EmitSmcccCaptureTranscript(&Binding, &Capture, NULL, 0, &Length) == M7SmcccTranscriptBufferTooSmall);
  assert(Length > sizeof(Small));
  assert(M7EmitSmcccCaptureTranscript(&Binding, &Capture, Small, sizeof(Small), &Length) == M7SmcccTranscriptBufferTooSmall);
  for (Index = 0; Index < sizeof(Small); ++Index) {
    assert(Small[Index] == 'X');
  }
  assert(M7EmitSmcccCaptureTranscript(&Binding, &Capture, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptSuccess);
  assert(strlen(Buffer) == Length);

  Tampered = Capture;
  ++Tampered.CallsIssued;
  assert(M7EmitSmcccCaptureTranscript(&Binding, &Tampered, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptCaptureNotSerializable);
  Tampered = Capture;
  Tampered.FeatureQueries[0].RegisterOpcode = 0;
  assert(M7EmitSmcccCaptureTranscript(&Binding, &Tampered, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptCaptureNotSerializable);
  Tampered = Capture;
  memset(Tampered.AuthorizationBindingSha256, 0, sizeof(Tampered.AuthorizationBindingSha256));
  assert(M7EmitSmcccCaptureTranscript(&Binding, &Tampered, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptCaptureNotSerializable);
  InvalidBinding = Binding;
  InvalidBinding.TranscriptEmitterSourceSha256 = "bad";
  assert(M7EmitSmcccCaptureTranscript(&InvalidBinding, &Capture, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptInvalidBinding);
  assert(M7EmitSmcccCaptureTranscript(&Binding, NULL, Buffer, sizeof(Buffer), &Length) == M7SmcccTranscriptInvalidArgument);

  fputs(Buffer, stdout);
  return 0;
}
EOF

"$CC" -std=c11 -Wall -Wextra -Werror -I"$LIB" \
  "$LIB/M7SmcccFeatureAvailabilityCollector.c" \
  "$LIB/M7SmcccCaptureTranscript.c" \
  "$TMP/harness.c" -o "$TMP/emitter-test"

emit() {
  local mode="$1" output="$2"
  "$TMP/emitter-test" "$mode" "$HANDOFF_SHA" "$HEADER_SHA" "$SOURCE_SHA" "$TRANSPORT_SHA" \
    "$EMITTER_HEADER_SHA" "$EMITTER_SOURCE_SHA" "$ROUTE_SHA" "$BINDING_SHA" > "$output"
}

emit supported "$TMP/supported-capture.txt"
emit supported "$TMP/supported-capture-2.txt"
cmp "$TMP/supported-capture.txt" "$TMP/supported-capture-2.txt"
grep -q '^collector-outcome: COMPLETE$' "$TMP/supported-capture.txt"
grep -q "^route-authorization-report-sha256: $ROUTE_SHA$" "$TMP/supported-capture.txt"
grep -q "^authorization-binding-sha256: $BINDING_SHA$" "$TMP/supported-capture.txt"
grep -q '^route-authorization-input: BOUND_SINGLE_USE_TOKEN$' "$TMP/supported-capture.txt"
grep -q '^authorized-output-buffer-address: 0x90000000$' "$TMP/supported-capture.txt"
grep -q '^calls-issued: 5$' "$TMP/supported-capture.txt"
grep -q '^collector-call: index=4 fid=0xC0000003 arg1=0x1E1320 x0=0x0 x1=0x0$' "$TMP/supported-capture.txt"
"$PYTHON" "$SERIALIZE" "$TMP/handoff.txt" "$TMP/supported-capture.txt" "$TMP/supported-raw.txt" "$TMP/supported-report.txt" "$TMP/route-authorization.txt" >/dev/null
grep -q '^classification: M7_SMCCC_CAPTURE_SERIALIZATION_PASS$' "$TMP/supported-report.txt"
"$PYTHON" "$VERIFY" "$TMP/handoff.txt" "$TMP/supported-raw.txt" "$TMP/supported-gate.txt" >/dev/null
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS$' "$TMP/supported-gate.txt"

emit unsupported "$TMP/unsupported-capture.txt"
grep -q '^collector-outcome: FEATURE_UNAVAILABLE$' "$TMP/unsupported-capture.txt"
grep -q '^calls-issued: 2$' "$TMP/unsupported-capture.txt"
test "$(grep -c '^collector-call:' "$TMP/unsupported-capture.txt")" -eq 2
"$PYTHON" "$SERIALIZE" "$TMP/handoff.txt" "$TMP/unsupported-capture.txt" "$TMP/unsupported-raw.txt" "$TMP/unsupported-report.txt" "$TMP/route-authorization.txt" >/dev/null
grep -q '^classification: M7_SMCCC_CAPTURE_SERIALIZATION_PASS$' "$TMP/unsupported-report.txt"
"$PYTHON" "$VERIFY" "$TMP/handoff.txt" "$TMP/unsupported-raw.txt" "$TMP/unsupported-gate.txt" >/dev/null
grep -q '^classification: M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_UNSUPPORTED$' "$TMP/unsupported-gate.txt"

echo "PASS: M7 deterministic SMCCC transcript emitter and serializer round trip"
