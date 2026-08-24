#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GENERATE="$ROOT/scripts/generate-m7-smccc-route-token.py"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

HEADER_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.h" | awk '{print $1}')"
SOURCE_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.c" | awk '{print $1}')"
TRANSPORT_SHA="$(sha256sum "$LIB/M7SmcccCallAArch64.S" | awk '{print $1}')"
EMITTER_HEADER_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.h" | awk '{print $1}')"
EMITTER_SOURCE_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.c" | awk '{print $1}')"
SEC_SHA="$(printf 'm7-sec-requirements' | sha256sum | awk '{print $1}')"
OBSERVATION_SHA="$(printf 'm7-entry-observation' | sha256sum | awk '{print $1}')"
RECOVERY_SHA="$(printf 'm7-recovery-evidence' | sha256sum | awk '{print $1}')"
ROUTE_SHA="$(printf 'm7-route-evidence' | sha256sum | awk '{print $1}')"
BINDING_SHA="$(printf 'm7-authorization-binding' | sha256sum | awk '{print $1}')"

cat > "$TMP/authorization.txt" <<EOF
sec-requirements-sha256: $SEC_SHA
qualcomm-entry-observation-sha256: $OBSERVATION_SHA
recovery-evidence-sha256: $RECOVERY_SHA
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
route-evidence-sha256: $ROUTE_SHA
authorization-binding-schema: IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1
authorization-binding-sha256: $BINDING_SHA
exact-device-build: CPH2413_15.0.0.1901(EX01)
route-candidate: exact-reviewed-temporary-pre-sec-route
recovery-emergency-status: AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED
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

generate() {
  local authorization="$1" header="$2" source="$3" report="$4"
  "$PYTHON" "$GENERATE" "$authorization" "$header" "$source" "$report"
}

HEADER_OUT="$TMP/M7SmcccRouteAuthorizationProvision.h"
SOURCE_OUT="$TMP/M7SmcccRouteAuthorizationProvision.c"
REPORT_OUT="$TMP/generation.txt"
generate "$TMP/authorization.txt" "$HEADER_OUT" "$SOURCE_OUT" "$REPORT_OUT" >/dev/null

AUTH_SHA="$(sha256sum "$TMP/authorization.txt" | awk '{print $1}')"
grep -q "^#define IZZOS_M7_SMCCC_ROUTE_AUTHORIZATION_REPORT_SHA256 \"$AUTH_SHA\"$" "$HEADER_OUT"
grep -q "^#define IZZOS_M7_SMCCC_AUTHORIZATION_BINDING_SHA256 \"$BINDING_SHA\"$" "$HEADER_OUT"
grep -q '^M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN gIzzOSM7SmcccRouteAuthorizationToken = {$' "$SOURCE_OUT"
grep -q '^  .PolicyFlags = M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS,$' "$SOURCE_OUT"
grep -q '^  .InvocationBudget = UINT32_C(1),$' "$SOURCE_OUT"
grep -q '^  .SmcccCallLimit = M7_SMCCC_MAX_CALLS,$' "$SOURCE_OUT"
grep -q '^  .OutputBufferAddress = UINT64_C(0x90000000),$' "$SOURCE_OUT"
grep -q '^  .OutputBufferCapacity = UINT64_C(0x1000),$' "$SOURCE_OUT"
grep -q '^generated-header-write-action: WRITTEN$' "$REPORT_OUT"
grep -q '^generated-source-write-action: WRITTEN$' "$REPORT_OUT"
grep -q '^payload-launch-authorization: NO$' "$REPORT_OUT"
grep -q '^classification: M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS$' "$REPORT_OUT"

cp "$HEADER_OUT" "$TMP/first.h"
cp "$SOURCE_OUT" "$TMP/first.c"
cp "$REPORT_OUT" "$TMP/first-report.txt"
generate "$TMP/authorization.txt" "$HEADER_OUT" "$SOURCE_OUT" "$REPORT_OUT" >/dev/null
cmp "$TMP/first.h" "$HEADER_OUT"
cmp "$TMP/first.c" "$SOURCE_OUT"
cmp "$TMP/first-report.txt" "$REPORT_OUT"

if command -v "$CC" >/dev/null 2>&1; then
  cat > "$TMP/harness.c" <<'EOF'
#include <assert.h>
#include <stddef.h>

#include "M7SmcccRouteAuthorizationProvision.h"

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

int main(void)
{
  M7_SMCCC_CALLER_STATE State = {0};
  M7_SMCCC_CAPTURE Capture;
  FAKE_TRANSPORT Fake = { .Responses = {{0x10004, 0}, {0, 0}, {0, 1}, {0, 2}, {0, 3}}, .ResponseCount = 5 };

  assert(gIzzOSM7SmcccRouteAuthorizationToken.Magic == M7_SMCCC_ROUTE_TOKEN_MAGIC);
  assert(gIzzOSM7SmcccRouteAuthorizationToken.InvocationBudget == 1);
  assert(gIzzOSM7SmcccRouteAuthorizationToken.Consumed == 0);
  assert(gIzzOSM7SmcccRouteAuthorizationExpectation.OutputBufferAddress == UINT64_C(0x90000000));
  State.CallerExceptionLevel = M7_SMCCC_EXPECTED_CALLER_EL;
  State.CallerIsNonSecure = 1;
  State.RouteAuthorizationToken = &gIzzOSM7SmcccRouteAuthorizationToken;
  State.RouteAuthorizationExpectation = &gIzzOSM7SmcccRouteAuthorizationExpectation;
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorComplete);
  assert(Fake.CallCount == 5);
  assert(Capture.AuthorizedOutputBufferAddress == gIzzOSM7SmcccRouteAuthorizationExpectation.OutputBufferAddress);
  assert(Capture.RouteAuthorizationReportSha256[0] == gIzzOSM7SmcccRouteAuthorizationExpectation.RouteAuthorizationReportSha256[0]);
  assert(Capture.AuthorizationBindingSha256[0] == gIzzOSM7SmcccRouteAuthorizationExpectation.AuthorizationBindingSha256[0]);
  assert(gIzzOSM7SmcccRouteAuthorizationToken.InvocationBudget == 0);
  assert(gIzzOSM7SmcccRouteAuthorizationToken.Consumed == 1);
  assert(M7CollectSmcccFeatureAvailability(&State, FakeInvoke, &Fake, &Capture) == M7SmcccCollectorRouteNotAuthorized);
  assert(Fake.CallCount == 5);
  return 0;
}
EOF

  "$CC" -std=c11 -Wall -Wextra -Werror -I"$LIB" -I"$TMP" \
    "$LIB/M7SmcccFeatureAvailabilityCollector.c" "$SOURCE_OUT" "$TMP/harness.c" \
    -o "$TMP/generated-token-test"
  "$TMP/generated-token-test"
fi

assert_blocked() {
  local name="$1" expression="$2" check="$3"
  local authorization="$TMP/$name-authorization.txt"
  local header="$TMP/$name.h"
  local source="$TMP/$name.c"
  local report="$TMP/$name-report.txt"
  sed "$expression" "$TMP/authorization.txt" > "$authorization"
  if generate "$authorization" "$header" "$source" "$report" >/dev/null 2>&1; then
    echo "ERROR: route-token generator accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$report"
  grep -q '^generated-header-write-action: NONE$' "$report"
  grep -q '^generated-source-write-action: NONE$' "$report"
  grep -q '^classification: M7_SMCCC_ROUTE_TOKEN_PROVISIONING_BLOCKED$' "$report"
  test ! -e "$header"
  test ! -e "$source"
}

assert_blocked blocked-classification \
  's/M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS/M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_BLOCKED/' \
  authorization-classification-passes
assert_blocked wrong-component-hash \
  "s/collector-source-sha256: $SOURCE_SHA/collector-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  authorization-collector-source-sha256-matches
assert_blocked zero-binding \
  "s/authorization-binding-sha256: $BINDING_SHA/authorization-binding-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" \
  authorization-binding-digest-is-valid
assert_blocked assisted-recovery \
  's/AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED/ASSISTED_HARD_RECOVERY_DOCUMENTED/' \
  authorization-recovery-is-verified
assert_blocked misaligned-buffer \
  's/output-buffer-address: 0x90000000/output-buffer-address: 0x90000001/' \
  authorization-buffer-alignment-is-safe
assert_blocked payload-launch \
  's/payload-launch-authorization: NO/payload-launch-authorization: YES/' \
  authorization-denies-payload-launch
assert_blocked relaxed-invocation \
  's/collector-invocation-authorization: EXACTLY_ONCE_FOR_BOUND_CAPTURE_ONLY/collector-invocation-authorization: REUSABLE/' \
  authorization-permits-one-bound-capture

cp "$TMP/authorization.txt" "$TMP/duplicate-authorization.txt"
printf 'authorization-binding-sha256: %s\n' "$BINDING_SHA" >> "$TMP/duplicate-authorization.txt"
if generate "$TMP/duplicate-authorization.txt" "$TMP/duplicate.h" "$TMP/duplicate.c" "$TMP/duplicate-report.txt" >/dev/null 2>&1; then
  echo "ERROR: route-token generator accepted a duplicate authorization field" >&2
  exit 1
fi
grep -q '^authorization-fields-are-present-once: FAIL$' "$TMP/duplicate-report.txt"
test ! -e "$TMP/duplicate.h"
test ! -e "$TMP/duplicate.c"

cp "$HEADER_OUT" "$TMP/stale.h"
cp "$SOURCE_OUT" "$TMP/stale.c"
sed 's/payload-launch-authorization: NO/payload-launch-authorization: YES/' "$TMP/authorization.txt" > "$TMP/stale-invalid.txt"
if generate "$TMP/stale-invalid.txt" "$TMP/stale.h" "$TMP/stale.c" "$TMP/stale-report.txt" >/dev/null 2>&1; then
  echo "ERROR: route-token generator accepted an unsafe report over stale outputs" >&2
  exit 1
fi
test ! -e "$TMP/stale.h"
test ! -e "$TMP/stale.c"
grep -q '^classification: M7_SMCCC_ROUTE_TOKEN_PROVISIONING_BLOCKED$' "$TMP/stale-report.txt"

echo "PASS: M7 deterministic route-authorization token provisioning"
