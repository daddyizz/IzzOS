#ifndef M7_SMCCC_CAPTURE_ORCHESTRATOR_H
#define M7_SMCCC_CAPTURE_ORCHESTRATOR_H

#include <stddef.h>

#include "M7SmcccCaptureTranscript.h"

typedef enum {
  M7SmcccOrchestratorSuccess = 0,
  M7SmcccOrchestratorInvalidArgument,
  M7SmcccOrchestratorOutputBufferMismatch,
  M7SmcccOrchestratorCollectorRejected,
  M7SmcccOrchestratorTranscriptRejected
} M7_SMCCC_ORCHESTRATOR_STATUS;

typedef struct {
  M7_SMCCC_COLLECTOR_OUTCOME CollectorOutcome;
  M7_SMCCC_TRANSCRIPT_STATUS TranscriptStatus;
  size_t TranscriptLength;
} M7_SMCCC_ORCHESTRATION_RESULT;

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
  );

#endif
