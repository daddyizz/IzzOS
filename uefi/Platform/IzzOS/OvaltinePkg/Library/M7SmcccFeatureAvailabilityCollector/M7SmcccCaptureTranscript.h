#ifndef M7_SMCCC_CAPTURE_TRANSCRIPT_H
#define M7_SMCCC_CAPTURE_TRANSCRIPT_H

#include <stddef.h>

#include "M7SmcccFeatureAvailabilityCollector.h"

#define M7_SMCCC_SHA256_HEX_LENGTH 64U

typedef struct {
  const char *SecureEl3HandoffReportSha256;
  const char *CollectorHeaderSha256;
  const char *CollectorSourceSha256;
  const char *CollectorTransportSha256;
  const char *TranscriptEmitterHeaderSha256;
  const char *TranscriptEmitterSourceSha256;
  const char *CaptureOrchestratorHeaderSha256;
  const char *CaptureOrchestratorSourceSha256;
} M7_SMCCC_TRANSCRIPT_BINDING;

typedef enum {
  M7SmcccTranscriptSuccess = 0,
  M7SmcccTranscriptInvalidArgument,
  M7SmcccTranscriptInvalidBinding,
  M7SmcccTranscriptCaptureNotSerializable,
  M7SmcccTranscriptBufferTooSmall
} M7_SMCCC_TRANSCRIPT_STATUS;

int
M7IsValidSmcccTranscriptBinding (
  const M7_SMCCC_TRANSCRIPT_BINDING *Binding
  );

M7_SMCCC_TRANSCRIPT_STATUS
M7EmitSmcccCaptureTranscript (
  const M7_SMCCC_TRANSCRIPT_BINDING *Binding,
  const M7_SMCCC_CAPTURE *Capture,
  char *Buffer,
  size_t BufferCapacity,
  size_t *TranscriptLength
  );

#endif
