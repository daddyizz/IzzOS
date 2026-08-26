#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PYTHON" "$ROOT/scripts/verify-m7-smccc-collector-source.py" "$ROOT" > "$TMP/source-contract.txt"
grep -q '^aarch64-transport-has-one-smc-zero: PASS$' "$TMP/source-contract.txt"
grep -q '^collector-is-not-integrated-into-current-diagnostic: PASS$' "$TMP/source-contract.txt"
grep -q '^classification: M7_SMCCC_COLLECTOR_SOURCE_CONTRACT_PASS$' "$TMP/source-contract.txt"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "PASS: M7 SMCCC feature-availability collector contract (source checks; host C compiler unavailable)"
  exit 0
fi

cat > "$TMP/harness.c" <<'EOF'
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "M7SmcccFeatureAvailabilityCollector.h"

typedef struct {
  M7_SMCCC_RESULT Responses[5];
  uint64_t Fids[5];
  uint64_t Args[5];
  size_t ResponseCount;
  size_t CallCount;
} FAKE_TRANSPORT;

static void
FakeInvoke(uint64_t Fid, uint64_t Arg1, M7_SMCCC_RESULT *Result, void *Context)
{
  FAKE_TRANSPORT *Fake = (FAKE_TRANSPORT *)Context;
  assert(Fake->CallCount < Fake->ResponseCount);
  Fake->Fids[Fake->CallCount] = Fid;
  Fake->Args[Fake->CallCount] = Arg1;
  *Result = Fake->Responses[Fake->CallCount++];
}

static void
FillDigest(uint8_t Digest[M7_SMCCC_ROUTE_DIGEST_SIZE], uint8_t Seed)
{
  uint32_t Index;
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    Digest[Index] = (uint8_t)(Seed + Index);
  }
}

static void
ResetAuthorization(
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation
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
  FillDigest(Token->RouteAuthorizationReportSha256, UINT8_C(0x10));
  FillDigest(Token->AuthorizationBindingSha256, UINT8_C(0x80));
  Expectation->OutputBufferAddress = Token->OutputBufferAddress;
  Expectation->OutputBufferCapacity = Token->OutputBufferCapacity;
  Expectation->OutputBufferAlignment = Token->OutputBufferAlignment;
  memcpy(Expectation->RouteAuthorizationReportSha256, Token->RouteAuthorizationReportSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
  memcpy(Expectation->AuthorizationBindingSha256, Token->AuthorizationBindingSha256, M7_SMCCC_ROUTE_DIGEST_SIZE);
}

static M7_SMCCC_CALLER_STATE
AuthorizedEl2(
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation
  )
{
  M7_SMCCC_CALLER_STATE State = {0};
  State.CallerExceptionLevel = 2;
  State.CallerIsNonSecure = 1;
  State.RouteAuthorizationToken = Token;
  State.RouteAuthorizationExpectation = Expectation;
  return State;
}

int main(void)
{
  M7_SMCCC_CAPTURE Capture;
  M7_SMCCC_CALLER_STATE State;
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN Token;
  M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION Expectation;
  FAKE_TRANSPORT Fake = {0};

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(NULL, &Expectation);
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0 && Capture.CallsIssued == 0 && Capture.AuthorizedOutputBufferAddress == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  State.CallerExceptionLevel = 1;
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorWrongCallerState);
  assert(Fake.CallCount == 0 && Token.Consumed == 0 && Token.InvocationBudget == 1);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Token.AuthorizationBindingSha256[0] ^= UINT8_C(1);
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0 && Token.Consumed == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Token.PolicyFlags |= UINT32_C(0x80000000);
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0 && Token.Consumed == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Token.OutputBufferAddress += 1;
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0 && Token.Consumed == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0, 0}, {0, 0x4010000}, {0, 0x500}, {0, 0}}, .ResponseCount = 5 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorComplete);
  assert(Fake.CallCount == 5 && Capture.CallsIssued == 5 && Capture.FeatureQueriesIssued == 3);
  assert(Token.Consumed == 1 && Token.InvocationBudget == 0);
  assert(Capture.AuthorizedOutputBufferAddress == Token.OutputBufferAddress);
  assert(Capture.AuthorizedOutputBufferCapacity == Token.OutputBufferCapacity);
  assert(Capture.AuthorizedOutputBufferAlignment == Token.OutputBufferAlignment);
  assert(memcmp(Capture.RouteAuthorizationReportSha256, Expectation.RouteAuthorizationReportSha256, M7_SMCCC_ROUTE_DIGEST_SIZE) == 0);
  assert(memcmp(Capture.AuthorizationBindingSha256, Expectation.AuthorizationBindingSha256, M7_SMCCC_ROUTE_DIGEST_SIZE) == 0);
  assert(Fake.Fids[0] == M7_SMCCC_VERSION_FID && Fake.Args[0] == 0);
  assert(Fake.Fids[1] == M7_SMCCC_ARCH_FEATURES_FID && Fake.Args[1] == M7_SMCCC_FEATURE_AVAILABILITY_FID);
  assert(Fake.Fids[2] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[2] == M7_SMCCC_SCR_EL3_OPCODE);
  assert(Fake.Fids[3] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[3] == M7_SMCCC_CPTR_EL3_OPCODE);
  assert(Fake.Fids[4] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[4] == M7_SMCCC_MDCR_EL3_OPCODE);
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 5 && Capture.CallsIssued == 0 && Capture.AuthorizedOutputBufferAddress == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0xFFFFFFFF, 0}}, .ResponseCount = 1 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorVersionUnavailable);
  assert(Fake.CallCount == 1 && Capture.FeatureQueriesIssued == 0 && Token.Consumed == 1);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10000, 0}}, .ResponseCount = 1 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorVersionTooOld);
  assert(Fake.CallCount == 1);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0xFFFFFFFF, 0}}, .ResponseCount = 2 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorFeatureUnavailable);
  assert(Fake.CallCount == 2 && Capture.FeatureQueriesIssued == 0);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0xFFFFFFFD, 0}}, .ResponseCount = 2 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorDiscoveryError);
  assert(Fake.CallCount == 2);

  ResetAuthorization(&Token, &Expectation);
  State = AuthorizedEl2(&Token, &Expectation);
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0, 0}, {0, 1}, {0xFFFFFFFD, 0}}, .ResponseCount = 4 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorQueryError);
  assert(Fake.CallCount == 4 && Capture.FeatureQueriesIssued == 2);
  return 0;
}
EOF

"$CC" -std=c11 -Wall -Wextra -Werror -I"$LIB" \
  "$LIB/M7SmcccFeatureAvailabilityCollector.c" "$TMP/harness.c" \
  -o "$TMP/collector-test"
"$TMP/collector-test"

echo "PASS: M7 SMCCC feature-availability collector contract and host harness"
