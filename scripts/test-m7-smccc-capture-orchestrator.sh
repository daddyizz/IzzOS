#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-smccc-capture-orchestrator-source.py"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" "$VERIFY" "$ROOT" > "$TMP/source-gate.txt"
grep -q '^orchestrator-validates-binding-before-collector: PASS$' "$TMP/source-gate.txt"
grep -q '^orchestrator-binds-actual-output-buffer-before-collector: PASS$' "$TMP/source-gate.txt"
grep -q '^orchestrator-is-not-integrated-into-current-diagnostic: PASS$' "$TMP/source-gate.txt"
grep -q '^classification: M7_SMCCC_CAPTURE_ORCHESTRATOR_SOURCE_CONTRACT_PASS$' "$TMP/source-gate.txt"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "PASS: M7 bound SMCCC capture orchestrator (source checks; host C compiler unavailable)"
  exit 0
fi

cat > "$TMP/harness.c" <<'EOF'
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "M7SmcccCaptureOrchestrator.h"

typedef struct {
  M7_SMCCC_RESULT Responses[M7_SMCCC_MAX_CALLS];
  size_t ResponseCount;
  size_t CallCount;
} FAKE_TRANSPORT;

_Alignas(4096) static char mOutputBuffer[4096];

static const M7_SMCCC_TRANSCRIPT_BINDING mBinding = {
  .SecureEl3HandoffReportSha256 = "1111111111111111111111111111111111111111111111111111111111111111",
  .CollectorHeaderSha256 = "2222222222222222222222222222222222222222222222222222222222222222",
  .CollectorSourceSha256 = "3333333333333333333333333333333333333333333333333333333333333333",
  .CollectorTransportSha256 = "4444444444444444444444444444444444444444444444444444444444444444",
  .TranscriptEmitterHeaderSha256 = "5555555555555555555555555555555555555555555555555555555555555555",
  .TranscriptEmitterSourceSha256 = "6666666666666666666666666666666666666666666666666666666666666666",
  .CaptureOrchestratorHeaderSha256 = "7777777777777777777777777777777777777777777777777777777777777777",
  .CaptureOrchestratorSourceSha256 = "8888888888888888888888888888888888888888888888888888888888888888"
};

static void
FakeInvoke (
  uint64_t Fid,
  uint64_t Arg1,
  M7_SMCCC_RESULT *Result,
  void *Context
  )
{
  FAKE_TRANSPORT *Fake;

  Fake = (FAKE_TRANSPORT *)Context;
  assert(Fake->CallCount < Fake->ResponseCount);
  if (Fake->CallCount == 0) {
    assert(Fid == M7_SMCCC_VERSION_FID && Arg1 == 0);
  } else if (Fake->CallCount == 1) {
    assert(Fid == M7_SMCCC_ARCH_FEATURES_FID && Arg1 == M7_SMCCC_FEATURE_AVAILABILITY_FID);
  } else {
    assert(Fid == M7_SMCCC_FEATURE_AVAILABILITY_FID);
  }
  *Result = Fake->Responses[Fake->CallCount++];
}

static void
PrepareAuthorization (
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation
  )
{
  memset(Token, 0, sizeof (*Token));
  memset(Expectation, 0, sizeof (*Expectation));
  Token->Magic = M7_SMCCC_ROUTE_TOKEN_MAGIC;
  Token->FormatVersion = M7_SMCCC_ROUTE_TOKEN_VERSION;
  Token->TokenSize = (uint32_t)sizeof (*Token);
  Token->PolicyFlags = M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS;
  Token->InvocationBudget = 1;
  Token->SmcccCallLimit = M7_SMCCC_MAX_CALLS;
  Token->OutputBufferAddress = (uint64_t)(uintptr_t)mOutputBuffer;
  Token->OutputBufferCapacity = sizeof (mOutputBuffer);
  Token->OutputBufferAlignment = 4096;
  memset(Token->RouteAuthorizationReportSha256, 0xA5, M7_SMCCC_ROUTE_DIGEST_SIZE);
  memset(Token->AuthorizationBindingSha256, 0x5A, M7_SMCCC_ROUTE_DIGEST_SIZE);
  Expectation->OutputBufferAddress = Token->OutputBufferAddress;
  Expectation->OutputBufferCapacity = Token->OutputBufferCapacity;
  Expectation->OutputBufferAlignment = Token->OutputBufferAlignment;
  memcpy(Expectation->RouteAuthorizationReportSha256, Token->RouteAuthorizationReportSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
  memcpy(Expectation->AuthorizationBindingSha256, Token->AuthorizationBindingSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
}

static void
AssertOutputUntouched (void)
{
  size_t Index;

  for (Index = 0; Index < sizeof (mOutputBuffer); ++Index) {
    assert(mOutputBuffer[Index] == 'X');
  }
}

static void
ResetOutput (void)
{
  memset(mOutputBuffer, 'X', sizeof (mOutputBuffer));
}

int
main (void)
{
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN Token;
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION Expectation;
  M7_SMCCC_ORCHESTRATION_RESULT Result;
  M7_SMCCC_TRANSCRIPT_BINDING InvalidBinding;
  FAKE_TRANSPORT Fake;

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){
    .Responses = {{0x10004, 0}, {0, 0}, {0, 0x4010000}, {0, 0x500}, {0, 0}},
    .ResponseCount = 5
  };
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorSuccess);
  assert(Result.CollectorOutcome == M7SmcccCollectorComplete);
  assert(Result.TranscriptStatus == M7SmcccTranscriptSuccess);
  assert(Result.TranscriptLength == strlen(mOutputBuffer));
  assert(Fake.CallCount == 5 && Token.Consumed == 1 && Token.InvocationBudget == 0);
  assert(strstr(mOutputBuffer, "collector-outcome: COMPLETE\n") != NULL);
  assert(strstr(mOutputBuffer, "capture-orchestrator-source-sha256: 8888888888888888888888888888888888888888888888888888888888888888\n") != NULL);

  ResetOutput();
  Fake = (FAKE_TRANSPORT){0};
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorCollectorRejected);
  assert(Result.CollectorOutcome == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0);
  AssertOutputUntouched();

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){.Responses = {{0x10004, 0}, {0xFFFFFFFF, 0}}, .ResponseCount = 2};
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorSuccess);
  assert(Result.CollectorOutcome == M7SmcccCollectorFeatureUnavailable);
  assert(Fake.CallCount == 2);
  assert(strstr(mOutputBuffer, "collector-outcome: FEATURE_UNAVAILABLE\n") != NULL);

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){0};
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer + 1, sizeof (mOutputBuffer) - 1, &Result) == M7SmcccOrchestratorOutputBufferMismatch);
  assert(Token.Consumed == 0 && Fake.CallCount == 0);
  AssertOutputUntouched();

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){0};
  InvalidBinding = mBinding;
  InvalidBinding.CaptureOrchestratorSourceSha256 = "bad";
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&InvalidBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorInvalidArgument);
  assert(Token.Consumed == 0 && Fake.CallCount == 0);
  AssertOutputUntouched();

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){0};
  Expectation.AuthorizationBindingSha256[0] ^= 1;
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorCollectorRejected);
  assert(Token.Consumed == 0 && Fake.CallCount == 0);
  AssertOutputUntouched();

  PrepareAuthorization(&Token, &Expectation);
  ResetOutput();
  Fake = (FAKE_TRANSPORT){.Responses = {{0x10004, 0}, {0, 0}, {1, 0}}, .ResponseCount = 3};
  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), &Result) == M7SmcccOrchestratorCollectorRejected);
  assert(Result.CollectorOutcome == M7SmcccCollectorQueryError);
  assert(Token.Consumed == 1 && Fake.CallCount == 3);
  AssertOutputUntouched();

  assert(M7RunBoundSmcccFeatureAvailabilityCapture(&mBinding, &Token, &Expectation, FakeInvoke, &Fake, mOutputBuffer, sizeof (mOutputBuffer), NULL) == M7SmcccOrchestratorInvalidArgument);
  return 0;
}
EOF

"$CC" -std=c11 -Wall -Wextra -Werror -I"$LIB" \
  "$LIB/M7SmcccFeatureAvailabilityCollector.c" \
  "$LIB/M7SmcccCaptureTranscript.c" \
  "$LIB/M7SmcccCaptureOrchestrator.c" \
  "$TMP/harness.c" -o "$TMP/orchestrator-test"
"$TMP/orchestrator-test"

echo "PASS: M7 bound SMCCC capture orchestrator"
