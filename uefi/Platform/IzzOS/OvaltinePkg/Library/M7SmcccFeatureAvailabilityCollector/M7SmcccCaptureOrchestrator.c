#include "M7SmcccCaptureOrchestrator.h"

static void
InitializeResult (
  M7_SMCCC_ORCHESTRATION_RESULT *Result
  )
{
  Result->CollectorOutcome = M7SmcccCollectorInvalidArgument;
  Result->TranscriptStatus = M7SmcccTranscriptInvalidArgument;
  Result->TranscriptLength = 0;
}

static int
OutputBufferMatchesExpectation (
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation,
  char *OutputBuffer,
  size_t OutputBufferCapacity
  )
{
  return Expectation->OutputBufferAddress == (uint64_t)(uintptr_t)OutputBuffer &&
         Expectation->OutputBufferCapacity == (uint64_t)OutputBufferCapacity &&
         OutputBufferCapacity == (size_t)Expectation->OutputBufferCapacity;
}

M7_SMCCC_ORCHESTRATOR_STATUS
M7RunBoundSmcccFeatureAvailabilityCapture (
  const M7_SMCCC_TRANSCRIPT_BINDING *Binding,
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation,
  M7_SMCCC_INVOKE Invoke,
  void *InvokeContext,
  char *OutputBuffer,
  size_t OutputBufferCapacity,
  M7_SMCCC_ORCHESTRATION_RESULT *Result
  )
{
  M7_SMCCC_CALLER_STATE CallerState;
  M7_SMCCC_CAPTURE Capture;

  if (Result == 0) {
    return M7SmcccOrchestratorInvalidArgument;
  }
  InitializeResult (Result);

  if (Binding == 0 || Token == 0 || Expectation == 0 || Invoke == 0 ||
      OutputBuffer == 0 || OutputBufferCapacity == 0 ||
      !M7IsValidSmcccTranscriptBinding (Binding)) {
    return M7SmcccOrchestratorInvalidArgument;
  }
  if (!OutputBufferMatchesExpectation (Expectation, OutputBuffer, OutputBufferCapacity)) {
    return M7SmcccOrchestratorOutputBufferMismatch;
  }

  CallerState.CallerExceptionLevel = M7_SMCCC_EXPECTED_CALLER_EL;
  CallerState.CallerIsNonSecure = 1;
  CallerState.Reserved[0] = 0;
  CallerState.Reserved[1] = 0;
  CallerState.Reserved[2] = 0;
  CallerState.RouteAuthorizationToken = Token;
  CallerState.RouteAuthorizationExpectation = Expectation;

  Result->CollectorOutcome = M7CollectSmcccFeatureAvailability (
                               &CallerState,
                               Invoke,
                               InvokeContext,
                               &Capture
                               );
  if (Result->CollectorOutcome != M7SmcccCollectorComplete &&
      Result->CollectorOutcome != M7SmcccCollectorFeatureUnavailable) {
    return M7SmcccOrchestratorCollectorRejected;
  }

  Result->TranscriptStatus = M7EmitSmcccCaptureTranscript (
                               Binding,
                               &Capture,
                               OutputBuffer,
                               OutputBufferCapacity,
                               &Result->TranscriptLength
                               );
  if (Result->TranscriptStatus != M7SmcccTranscriptSuccess) {
    return M7SmcccOrchestratorTranscriptRejected;
  }
  return M7SmcccOrchestratorSuccess;
}
