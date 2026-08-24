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

static M7_SMCCC_CALLER_STATE AuthorizedEl2(void)
{
  M7_SMCCC_CALLER_STATE State = {2, 1, 1};
  return State;
}

int main(void)
{
  M7_SMCCC_CAPTURE Capture;
  M7_SMCCC_CALLER_STATE State;
  FAKE_TRANSPORT Fake = {0};

  State = AuthorizedEl2();
  State.RouteIsAuthorized = 0;
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 0 && Capture.CallsIssued == 0);

  State = AuthorizedEl2();
  State.CallerExceptionLevel = 1;
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorWrongCallerState);
  assert(Fake.CallCount == 0);

  State = AuthorizedEl2();
  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0, 0}, {0, 0x4010000}, {0, 0x500}, {0, 0}}, .ResponseCount = 5 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorComplete);
  assert(Fake.CallCount == 5 && Capture.CallsIssued == 5 && Capture.FeatureQueriesIssued == 3);
  assert(Fake.Fids[0] == M7_SMCCC_VERSION_FID && Fake.Args[0] == 0);
  assert(Fake.Fids[1] == M7_SMCCC_ARCH_FEATURES_FID && Fake.Args[1] == M7_SMCCC_FEATURE_AVAILABILITY_FID);
  assert(Fake.Fids[2] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[2] == M7_SMCCC_SCR_EL3_OPCODE);
  assert(Fake.Fids[3] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[3] == M7_SMCCC_CPTR_EL3_OPCODE);
  assert(Fake.Fids[4] == M7_SMCCC_FEATURE_AVAILABILITY_FID && Fake.Args[4] == M7_SMCCC_MDCR_EL3_OPCODE);

  Fake = (FAKE_TRANSPORT){ .Responses = {{0xFFFFFFFF, 0}}, .ResponseCount = 1 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorVersionUnavailable);
  assert(Fake.CallCount == 1 && Capture.FeatureQueriesIssued == 0);

  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10000, 0}}, .ResponseCount = 1 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorVersionTooOld);
  assert(Fake.CallCount == 1);

  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0xFFFFFFFF, 0}}, .ResponseCount = 2 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorFeatureUnavailable);
  assert(Fake.CallCount == 2 && Capture.FeatureQueriesIssued == 0);

  Fake = (FAKE_TRANSPORT){ .Responses = {{0x10004, 0}, {0xFFFFFFFD, 0}}, .ResponseCount = 2 };
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorDiscoveryError);
  assert(Fake.CallCount == 2);

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
