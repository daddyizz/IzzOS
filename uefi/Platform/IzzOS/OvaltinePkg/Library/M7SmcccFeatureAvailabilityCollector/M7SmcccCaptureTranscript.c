#include "M7SmcccCaptureTranscript.h"

typedef struct {
  char *Buffer;
  size_t Length;
} TRANSCRIPT_WRITER;

static const uint64_t mExpectedRegisterOpcodes[M7_SMCCC_MAX_FEATURE_QUERIES] = {
  M7_SMCCC_SCR_EL3_OPCODE,
  M7_SMCCC_CPTR_EL3_OPCODE,
  M7_SMCCC_MDCR_EL3_OPCODE
};

static int
IsHexDigit (
  char Value
  )
{
  return (Value >= '0' && Value <= '9') ||
         (Value >= 'a' && Value <= 'f') ||
         (Value >= 'A' && Value <= 'F');
}

static char
ToLowerHex (
  char Value
  )
{
  if (Value >= 'A' && Value <= 'F') {
    return (char)(Value + ('a' - 'A'));
  }
  return Value;
}

static int
IsExactSha256 (
  const char *Value
  )
{
  size_t Index;

  if (Value == 0) {
    return 0;
  }
  for (Index = 0; Index < M7_SMCCC_SHA256_HEX_LENGTH; ++Index) {
    if (!IsHexDigit (Value[Index])) {
      return 0;
    }
  }
  return Value[M7_SMCCC_SHA256_HEX_LENGTH] == '\0';
}

static int
IsNotSupported (
  uint64_t Value
  )
{
  return Value == M7_SMCCC_NOT_SUPPORTED_32 ||
         Value == M7_SMCCC_NOT_SUPPORTED_64;
}

static int
IsSerializableSmcccVersion (
  uint64_t Value
  )
{
  return (Value >> 16) == UINT64_C(1) &&
         (Value & UINT64_C(0xFFFF)) >= UINT64_C(1);
}

static int
HasCanonicalQueryStorage (
  const M7_SMCCC_CAPTURE *Capture
  )
{
  uint32_t Index;

  for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
    if (Capture->FeatureQueries[Index].RegisterOpcode != mExpectedRegisterOpcodes[Index]) {
      return 0;
    }
  }
  return 1;
}

static int
IsSerializableCapture (
  const M7_SMCCC_CAPTURE *Capture
  )
{
  uint32_t Index;

  if (!IsSerializableSmcccVersion (Capture->SmcccVersionResult) ||
      !HasCanonicalQueryStorage (Capture)) {
    return 0;
  }

  if (Capture->Outcome == M7SmcccCollectorComplete) {
    if (Capture->CallsIssued != M7_SMCCC_MAX_CALLS ||
        Capture->FeatureQueriesIssued != M7_SMCCC_MAX_FEATURE_QUERIES ||
        Capture->FeatureDiscoveryResult != M7_SMCCC_SUCCESS) {
      return 0;
    }
    for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
      if (Capture->FeatureQueries[Index].Status != M7_SMCCC_SUCCESS) {
        return 0;
      }
    }
    return 1;
  }

  if (Capture->Outcome == M7SmcccCollectorFeatureUnavailable) {
    if (Capture->CallsIssued != 2 ||
        Capture->FeatureQueriesIssued != 0 ||
        !IsNotSupported (Capture->FeatureDiscoveryResult)) {
      return 0;
    }
    for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
      if (Capture->FeatureQueries[Index].Status != M7_SMCCC_NOT_SUPPORTED_64 ||
          Capture->FeatureQueries[Index].AvailabilityMask != 0) {
        return 0;
      }
    }
    return 1;
  }

  return 0;
}

static void
AppendCharacter (
  TRANSCRIPT_WRITER *Writer,
  char Value
  )
{
  if (Writer->Buffer != 0) {
    Writer->Buffer[Writer->Length] = Value;
  }
  ++Writer->Length;
}

static void
AppendText (
  TRANSCRIPT_WRITER *Writer,
  const char *Text
  )
{
  while (*Text != '\0') {
    AppendCharacter (Writer, *Text++);
  }
}

static void
AppendSha256 (
  TRANSCRIPT_WRITER *Writer,
  const char *Value
  )
{
  size_t Index;

  for (Index = 0; Index < M7_SMCCC_SHA256_HEX_LENGTH; ++Index) {
    AppendCharacter (Writer, ToLowerHex (Value[Index]));
  }
}

static void
AppendDecimal (
  TRANSCRIPT_WRITER *Writer,
  uint32_t Value
  )
{
  char Digits[10];
  size_t Count;

  Count = 0;
  do {
    Digits[Count++] = (char)('0' + (Value % 10));
    Value /= 10;
  } while (Value != 0);

  while (Count != 0) {
    AppendCharacter (Writer, Digits[--Count]);
  }
}

static void
AppendHex (
  TRANSCRIPT_WRITER *Writer,
  uint64_t Value
  )
{
  static const char Digits[] = "0123456789ABCDEF";
  char Reverse[16];
  size_t Count;

  AppendText (Writer, "0x");
  Count = 0;
  do {
    Reverse[Count++] = Digits[Value & UINT64_C(0xF)];
    Value >>= 4;
  } while (Value != 0);

  while (Count != 0) {
    AppendCharacter (Writer, Reverse[--Count]);
  }
}

static void
AppendBindingLine (
  TRANSCRIPT_WRITER *Writer,
  const char *Label,
  const char *Value
  )
{
  AppendText (Writer, Label);
  AppendText (Writer, ": ");
  AppendSha256 (Writer, Value);
  AppendCharacter (Writer, '\n');
}

static void
AppendCall (
  TRANSCRIPT_WRITER *Writer,
  uint32_t Index,
  uint64_t Fid,
  uint64_t Arg1,
  uint64_t X0,
  int IncludeX1,
  uint64_t X1
  )
{
  AppendText (Writer, "collector-call: index=");
  AppendDecimal (Writer, Index);
  AppendText (Writer, " fid=");
  AppendHex (Writer, Fid);
  AppendText (Writer, " arg1=");
  AppendHex (Writer, Arg1);
  AppendText (Writer, " x0=");
  AppendHex (Writer, X0);
  AppendText (Writer, " x1=");
  if (IncludeX1) {
    AppendHex (Writer, X1);
  } else {
    AppendText (Writer, "IGNORED");
  }
  AppendCharacter (Writer, '\n');
}

static void
RenderTranscript (
  TRANSCRIPT_WRITER *Writer,
  const M7_SMCCC_TRANSCRIPT_BINDING *Binding,
  const M7_SMCCC_CAPTURE *Capture
  )
{
  uint32_t Index;

  AppendText (Writer, "collector-capture-schema: IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1\n");
  AppendBindingLine (Writer, "secure-el3-handoff-report-sha256", Binding->SecureEl3HandoffReportSha256);
  AppendBindingLine (Writer, "collector-header-sha256", Binding->CollectorHeaderSha256);
  AppendBindingLine (Writer, "collector-source-sha256", Binding->CollectorSourceSha256);
  AppendBindingLine (Writer, "collector-transport-sha256", Binding->CollectorTransportSha256);
  AppendBindingLine (Writer, "transcript-emitter-header-sha256", Binding->TranscriptEmitterHeaderSha256);
  AppendBindingLine (Writer, "transcript-emitter-source-sha256", Binding->TranscriptEmitterSourceSha256);
  AppendText (Writer, "capture-origin: PRE_SEC_NONSECURE_EL2\n");
  AppendText (Writer, "caller-security-state: NONSECURE\n");
  AppendText (Writer, "caller-exception-level: EL2\n");
  AppendText (Writer, "route-authorization-input: EXPLICIT_CALLER_ASSERTION_NOT_INDEPENDENTLY_ATTESTED\n");
  AppendText (Writer, "collector-outcome: ");
  AppendText (Writer, Capture->Outcome == M7SmcccCollectorComplete ? "COMPLETE\n" : "FEATURE_UNAVAILABLE\n");
  AppendText (Writer, "calls-issued: ");
  AppendDecimal (Writer, Capture->CallsIssued);
  AppendCharacter (Writer, '\n');
  AppendText (Writer, "feature-queries-issued: ");
  AppendDecimal (Writer, Capture->FeatureQueriesIssued);
  AppendCharacter (Writer, '\n');
  AppendText (Writer, "vendor-or-sip-smc-action: NONE\n");
  AppendText (Writer, "direct-el3-register-read-action: NONE\n");
  AppendText (Writer, "secure-monitor-modification-action: NONE\n");
  AppendText (Writer, "mmio-action: NONE\n");
  AppendText (Writer, "device-writes: NONE\n");
  AppendText (Writer, "persistent-writes: NONE\n");
  AppendText (Writer, "slot-changes: NONE\n");
  AppendText (Writer, "observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED\n");
  AppendText (Writer, "launch-authorization: NO\n");

  AppendCall (Writer, 0, M7_SMCCC_VERSION_FID, 0, Capture->SmcccVersionResult, 0, 0);
  AppendCall (
    Writer,
    1,
    M7_SMCCC_ARCH_FEATURES_FID,
    M7_SMCCC_FEATURE_AVAILABILITY_FID,
    Capture->FeatureDiscoveryResult,
    0,
    0
    );
  if (Capture->Outcome != M7SmcccCollectorComplete) {
    return;
  }
  for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
    AppendCall (
      Writer,
      Index + 2,
      M7_SMCCC_FEATURE_AVAILABILITY_FID,
      Capture->FeatureQueries[Index].RegisterOpcode,
      Capture->FeatureQueries[Index].Status,
      1,
      Capture->FeatureQueries[Index].AvailabilityMask
      );
  }
}

M7_SMCCC_TRANSCRIPT_STATUS
M7EmitSmcccCaptureTranscript (
  const M7_SMCCC_TRANSCRIPT_BINDING *Binding,
  const M7_SMCCC_CAPTURE *Capture,
  char *Buffer,
  size_t BufferCapacity,
  size_t *TranscriptLength
  )
{
  TRANSCRIPT_WRITER Writer;

  if (Binding == 0 || Capture == 0 || TranscriptLength == 0) {
    return M7SmcccTranscriptInvalidArgument;
  }
  if (!IsExactSha256 (Binding->SecureEl3HandoffReportSha256) ||
      !IsExactSha256 (Binding->CollectorHeaderSha256) ||
      !IsExactSha256 (Binding->CollectorSourceSha256) ||
      !IsExactSha256 (Binding->CollectorTransportSha256) ||
      !IsExactSha256 (Binding->TranscriptEmitterHeaderSha256) ||
      !IsExactSha256 (Binding->TranscriptEmitterSourceSha256)) {
    return M7SmcccTranscriptInvalidBinding;
  }
  if (!IsSerializableCapture (Capture)) {
    return M7SmcccTranscriptCaptureNotSerializable;
  }

  Writer.Buffer = 0;
  Writer.Length = 0;
  RenderTranscript (&Writer, Binding, Capture);
  *TranscriptLength = Writer.Length;
  if (Buffer == 0 || BufferCapacity <= Writer.Length) {
    return M7SmcccTranscriptBufferTooSmall;
  }

  Writer.Buffer = Buffer;
  Writer.Length = 0;
  RenderTranscript (&Writer, Binding, Capture);
  Buffer[Writer.Length] = '\0';
  return M7SmcccTranscriptSuccess;
}
