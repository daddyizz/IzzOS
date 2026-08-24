#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN_GENERATOR="$ROOT/scripts/generate-m7-smccc-route-token.py"
CAPTURE_GENERATOR="$ROOT/scripts/generate-m7-smccc-capture-provision.py"
LIB="$ROOT/uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
PYTHON="${PYTHON:-python3}"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/handoff.txt" <<'EOF'
secure-el3-observation: SELF_REPORTED_HANDOFF_ASSERTION_ONLY
secure-el3-prerequisite-compliance: NOT_INDEPENDENTLY_PROVEN
sec-wrapper-implementation-authorization: NO
launch-authorization: NO
classification: M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS
EOF

HEADER_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.h" | awk '{print $1}')"
SOURCE_SHA="$(sha256sum "$LIB/M7SmcccFeatureAvailabilityCollector.c" | awk '{print $1}')"
TRANSPORT_SHA="$(sha256sum "$LIB/M7SmcccCallAArch64.S" | awk '{print $1}')"
EMITTER_HEADER_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.h" | awk '{print $1}')"
EMITTER_SOURCE_SHA="$(sha256sum "$LIB/M7SmcccCaptureTranscript.c" | awk '{print $1}')"
ORCHESTRATOR_HEADER_SHA="$(sha256sum "$LIB/M7SmcccCaptureOrchestrator.h" | awk '{print $1}')"
ORCHESTRATOR_SOURCE_SHA="$(sha256sum "$LIB/M7SmcccCaptureOrchestrator.c" | awk '{print $1}')"
SEC_SHA="$(printf 'm7-capture-provision-sec' | sha256sum | awk '{print $1}')"
OBSERVATION_SHA="$(printf 'm7-capture-provision-observation' | sha256sum | awk '{print $1}')"
RECOVERY_SHA="$(printf 'm7-capture-provision-recovery' | sha256sum | awk '{print $1}')"
ROUTE_EVIDENCE_SHA="$(printf 'm7-capture-provision-route' | sha256sum | awk '{print $1}')"
BINDING_SHA="$(printf 'm7-capture-provision-binding' | sha256sum | awk '{print $1}')"

cat > "$TMP/authorization.txt" <<EOF
sec-requirements-sha256: $SEC_SHA
qualcomm-entry-observation-sha256: $OBSERVATION_SHA
recovery-evidence-sha256: $RECOVERY_SHA
collector-header-sha256: $HEADER_SHA
collector-source-sha256: $SOURCE_SHA
collector-transport-sha256: $TRANSPORT_SHA
transcript-emitter-header-sha256: $EMITTER_HEADER_SHA
transcript-emitter-source-sha256: $EMITTER_SOURCE_SHA
capture-orchestrator-header-sha256: $ORCHESTRATOR_HEADER_SHA
capture-orchestrator-source-sha256: $ORCHESTRATOR_SOURCE_SHA
route-evidence-sha256: $ROUTE_EVIDENCE_SHA
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

TOKEN_HEADER="$TMP/M7SmcccRouteAuthorizationProvision.h"
TOKEN_SOURCE="$TMP/M7SmcccRouteAuthorizationProvision.c"
TOKEN_REPORT="$TMP/token-generation.txt"
"$PYTHON" "$TOKEN_GENERATOR" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT" >/dev/null

generate() {
  local handoff="$1" authorization="$2" token_header="$3" token_source="$4" token_report="$5" header="$6" source="$7" report="$8"
  "$PYTHON" "$CAPTURE_GENERATOR" "$handoff" "$authorization" "$token_header" "$token_source" "$token_report" "$header" "$source" "$report"
}

CAPTURE_HEADER="$TMP/M7SmcccCaptureProvision.h"
CAPTURE_SOURCE="$TMP/M7SmcccCaptureProvision.c"
CAPTURE_REPORT="$TMP/capture-provisioning.txt"
generate "$TMP/handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT" "$CAPTURE_HEADER" "$CAPTURE_SOURCE" "$CAPTURE_REPORT" >/dev/null

HANDOFF_SHA="$(sha256sum "$TMP/handoff.txt" | awk '{print $1}')"
grep -q "^#define IZZOS_M7_SMCCC_SECURE_EL3_HANDOFF_REPORT_SHA256 \"$HANDOFF_SHA\"$" "$CAPTURE_HEADER"
grep -q '^#include "M7SmcccRouteAuthorizationProvision.h"$' "$CAPTURE_HEADER"
grep -q '^extern const M7_SMCCC_TRANSCRIPT_BINDING gIzzOSM7SmcccTranscriptBinding;$' "$CAPTURE_HEADER"
grep -q '^M7RunProvisionedSmcccFeatureAvailabilityCapture ($' "$CAPTURE_HEADER"
grep -q "^  .CaptureOrchestratorSourceSha256 = \"$ORCHESTRATOR_SOURCE_SHA\"$" "$CAPTURE_SOURCE"
grep -q '^           &gIzzOSM7SmcccRouteAuthorizationToken,$' "$CAPTURE_SOURCE"
grep -q '^           &gIzzOSM7SmcccRouteAuthorizationExpectation,$' "$CAPTURE_SOURCE"
grep -q '^real-transport-selection: CALLER_SUPPLIED_NOT_GENERATED$' "$CAPTURE_REPORT"
grep -q '^capture-provision-is-not-integrated-into-current-diagnostic: PASS$' "$CAPTURE_REPORT"
grep -q "^generated-header-sha256: $(sha256sum "$CAPTURE_HEADER" | awk '{print $1}')$" "$CAPTURE_REPORT"
grep -q "^generated-source-sha256: $(sha256sum "$CAPTURE_SOURCE" | awk '{print $1}')$" "$CAPTURE_REPORT"
grep -q '^payload-launch-authorization: NO$' "$CAPTURE_REPORT"
grep -q '^classification: M7_SMCCC_CAPTURE_PROVISIONING_PASS$' "$CAPTURE_REPORT"

cp "$CAPTURE_HEADER" "$TMP/first-capture.h"
cp "$CAPTURE_SOURCE" "$TMP/first-capture.c"
cp "$CAPTURE_REPORT" "$TMP/first-capture-report.txt"
generate "$TMP/handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT" "$CAPTURE_HEADER" "$CAPTURE_SOURCE" "$CAPTURE_REPORT" >/dev/null
cmp "$TMP/first-capture.h" "$CAPTURE_HEADER"
cmp "$TMP/first-capture.c" "$CAPTURE_SOURCE"
cmp "$TMP/first-capture-report.txt" "$CAPTURE_REPORT"

if command -v "$CC" >/dev/null 2>&1; then
  cat > "$TMP/harness.c" <<'EOF'
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "M7SmcccCaptureProvision.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

typedef struct {
  M7_SMCCC_RESULT Responses[M7_SMCCC_MAX_CALLS];
  size_t ResponseCount;
  size_t CallCount;
} FAKE_TRANSPORT;

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

int
main (
  int Argc,
  char **Argv
  )
{
  M7_SMCCC_ORCHESTRATION_RESULT Result;
  M7_SMCCC_ORCHESTRATOR_STATUS Status;
  FAKE_TRANSPORT Fake;
  char *Buffer;
  size_t CallsAfterFirstRun;

  assert(Argc == 2);
  Buffer = mmap(
             (void *)(uintptr_t)UINT64_C(0x90000000),
             0x1000,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
             -1,
             0
             );
  assert(Buffer != MAP_FAILED);
  assert((uint64_t)(uintptr_t)Buffer == UINT64_C(0x90000000));

  if (strcmp(Argv[1], "supported") == 0) {
    Fake = (FAKE_TRANSPORT){
      .Responses = {{0x10004, 0}, {0, 0}, {0, 0x4010000}, {0, 0x500}, {0, 0}},
      .ResponseCount = 5
    };
  } else {
    assert(strcmp(Argv[1], "unsupported") == 0);
    Fake = (FAKE_TRANSPORT){.Responses = {{0x10004, 0}, {0xFFFFFFFF, 0}}, .ResponseCount = 2};
  }

  assert(M7IsValidSmcccTranscriptBinding(&gIzzOSM7SmcccTranscriptBinding));
  Status = M7RunProvisionedSmcccFeatureAvailabilityCapture(FakeInvoke, &Fake, Buffer, 0x1000, &Result);
  assert(Status == M7SmcccOrchestratorSuccess);
  if (strcmp(Argv[1], "supported") == 0) {
    assert(Result.CollectorOutcome == M7SmcccCollectorComplete);
    assert(strstr(Buffer, "collector-outcome: COMPLETE\n") != NULL);
  } else {
    assert(Result.CollectorOutcome == M7SmcccCollectorFeatureUnavailable);
    assert(strstr(Buffer, "collector-outcome: FEATURE_UNAVAILABLE\n") != NULL);
  }
  assert(Result.TranscriptStatus == M7SmcccTranscriptSuccess);
  assert(Result.TranscriptLength == strlen(Buffer));
  assert(strstr(Buffer, "secure-el3-handoff-report-sha256: " IZZOS_M7_SMCCC_SECURE_EL3_HANDOFF_REPORT_SHA256 "\n") != NULL);
  assert(strstr(Buffer, "route-authorization-report-sha256: " IZZOS_M7_SMCCC_ROUTE_AUTHORIZATION_REPORT_SHA256 "\n") != NULL);
  assert(strstr(Buffer, "authorization-binding-sha256: " IZZOS_M7_SMCCC_AUTHORIZATION_BINDING_SHA256 "\n") != NULL);
  CallsAfterFirstRun = Fake.CallCount;
  assert(gIzzOSM7SmcccRouteAuthorizationToken.Consumed == 1);
  assert(M7RunProvisionedSmcccFeatureAvailabilityCapture(FakeInvoke, &Fake, Buffer, 0x1000, &Result) == M7SmcccOrchestratorCollectorRejected);
  assert(Fake.CallCount == CallsAfterFirstRun);
  assert(munmap(Buffer, 0x1000) == 0);
  return 0;
}
EOF

  "$CC" -std=c11 -Wall -Wextra -Werror -I"$LIB" -I"$TMP" \
    "$LIB/M7SmcccFeatureAvailabilityCollector.c" \
    "$LIB/M7SmcccCaptureTranscript.c" \
    "$LIB/M7SmcccCaptureOrchestrator.c" \
    "$TOKEN_SOURCE" "$CAPTURE_SOURCE" "$TMP/harness.c" -o "$TMP/capture-provision-test"
  "$TMP/capture-provision-test" supported
  "$TMP/capture-provision-test" unsupported
fi

expect_blocked() {
  local name="$1" check="$2" handoff="$3" authorization="$4" token_header="$5" token_source="$6" token_report="$7"
  local header="$TMP/$name-capture.h" source="$TMP/$name-capture.c" report="$TMP/$name-report.txt"
  cp "$CAPTURE_HEADER" "$header"
  cp "$CAPTURE_SOURCE" "$source"
  if generate "$handoff" "$authorization" "$token_header" "$token_source" "$token_report" "$header" "$source" "$report" >/dev/null 2>&1; then
    echo "ERROR: capture-provision generator accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$report"
  grep -q '^generated-header-write-action: NONE$' "$report"
  grep -q '^generated-source-write-action: NONE$' "$report"
  grep -q '^classification: M7_SMCCC_CAPTURE_PROVISIONING_BLOCKED$' "$report"
  test ! -e "$header"
  test ! -e "$source"
}

sed 's/M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS/M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_BLOCKED/' "$TMP/handoff.txt" > "$TMP/bad-handoff.txt"
expect_blocked bad-handoff handoff-classification-passes "$TMP/bad-handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT"

sed 's/payload-launch-authorization: NO/payload-launch-authorization: YES/' "$TMP/authorization.txt" > "$TMP/bad-authorization.txt"
expect_blocked bad-authorization authorization-denies-launch-and-writes "$TMP/handoff.txt" "$TMP/bad-authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT"

cp "$TOKEN_SOURCE" "$TMP/tampered-token.c"
printf X >> "$TMP/tampered-token.c"
expect_blocked tampered-token token-report-binds-generated-source "$TMP/handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TMP/tampered-token.c" "$TOKEN_REPORT"

TAMPERED_TOKEN_SHA="$(sha256sum "$TMP/tampered-token.c" | awk '{print $1}')"
sed "s/generated-source-sha256: [0-9a-f]*/generated-source-sha256: $TAMPERED_TOKEN_SHA/" "$TOKEN_REPORT" > "$TMP/forged-token-report.txt"
expect_blocked forged-token-report token-source-is-exact-deterministic-provision "$TMP/handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TMP/tampered-token.c" "$TMP/forged-token-report.txt"

sed "s/generated-source-sha256: [0-9a-f]*/generated-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" "$TOKEN_REPORT" > "$TMP/bad-token-report.txt"
expect_blocked bad-token-report token-report-binds-generated-source "$TMP/handoff.txt" "$TMP/authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TMP/bad-token-report.txt"

sed "s/capture-orchestrator-source-sha256: $ORCHESTRATOR_SOURCE_SHA/capture-orchestrator-source-sha256: 0000000000000000000000000000000000000000000000000000000000000000/" "$TMP/authorization.txt" > "$TMP/bad-component.txt"
expect_blocked bad-component authorization-capture-orchestrator-source-sha256-matches "$TMP/handoff.txt" "$TMP/bad-component.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT"

cp "$TMP/authorization.txt" "$TMP/duplicate-authorization.txt"
printf 'authorization-binding-sha256: %s\n' "$BINDING_SHA" >> "$TMP/duplicate-authorization.txt"
expect_blocked duplicate-authorization authorization-fields-are-present-once "$TMP/handoff.txt" "$TMP/duplicate-authorization.txt" "$TOKEN_HEADER" "$TOKEN_SOURCE" "$TOKEN_REPORT"

echo "PASS: M7 deterministic bound SMCCC capture provisioning"
