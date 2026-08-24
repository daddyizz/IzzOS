#include "M7SmcccFeatureAvailabilityCollector.h"

static const uint64_t mFeatureRegisterOpcodes[M7_SMCCC_MAX_FEATURE_QUERIES] = {
  M7_SMCCC_SCR_EL3_OPCODE,
  M7_SMCCC_CPTR_EL3_OPCODE,
  M7_SMCCC_MDCR_EL3_OPCODE
};

static int
IsNotSupported (
  uint64_t Value
  )
{
  return Value == M7_SMCCC_NOT_SUPPORTED_32 ||
         Value == M7_SMCCC_NOT_SUPPORTED_64;
}

static int
IsSmcccVersionAtLeastOneOne (
  uint64_t Value
  )
{
  uint32_t Version;
  uint32_t Major;
  uint32_t Minor;

  Version = (uint32_t)Value;
  Major = Version >> 16;
  Minor = Version & UINT32_C(0xFFFF);
  return Major > 1 || (Major == 1 && Minor >= 1);
}

static void
InitializeCapture (
  M7_SMCCC_CAPTURE *Capture
  )
{
  uint32_t Index;

  Capture->Outcome = M7SmcccCollectorInvalidArgument;
  Capture->CallsIssued = 0;
  Capture->FeatureQueriesIssued = 0;
  Capture->SmcccVersionResult = 0;
  Capture->FeatureDiscoveryResult = 0;
  for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
    Capture->FeatureQueries[Index].RegisterOpcode = mFeatureRegisterOpcodes[Index];
    Capture->FeatureQueries[Index].Status = M7_SMCCC_NOT_SUPPORTED_64;
    Capture->FeatureQueries[Index].AvailabilityMask = 0;
  }
}

M7_SMCCC_COLLECTOR_OUTCOME
M7CollectSmcccFeatureAvailability (
  const M7_SMCCC_CALLER_STATE *CallerState,
  M7_SMCCC_INVOKE Invoke,
  void *InvokeContext,
  M7_SMCCC_CAPTURE *Capture
  )
{
  M7_SMCCC_RESULT Result;
  uint32_t Index;

  if (Capture == 0) {
    return M7SmcccCollectorInvalidArgument;
  }

  InitializeCapture (Capture);
  if (CallerState == 0 || Invoke == 0) {
    return Capture->Outcome;
  }

  if (CallerState->RouteIsAuthorized != 1) {
    Capture->Outcome = M7SmcccCollectorRouteNotAuthorized;
    return Capture->Outcome;
  }

  if (CallerState->CallerExceptionLevel != M7_SMCCC_EXPECTED_CALLER_EL ||
      CallerState->CallerIsNonSecure != 1) {
    Capture->Outcome = M7SmcccCollectorWrongCallerState;
    return Capture->Outcome;
  }

  Invoke (M7_SMCCC_VERSION_FID, 0, &Result, InvokeContext);
  Capture->CallsIssued = 1;
  Capture->SmcccVersionResult = Result.X0;
  if (IsNotSupported (Result.X0)) {
    Capture->Outcome = M7SmcccCollectorVersionUnavailable;
    return Capture->Outcome;
  }

  if (!IsSmcccVersionAtLeastOneOne (Result.X0)) {
    Capture->Outcome = M7SmcccCollectorVersionTooOld;
    return Capture->Outcome;
  }

  Invoke (
    M7_SMCCC_ARCH_FEATURES_FID,
    M7_SMCCC_FEATURE_AVAILABILITY_FID,
    &Result,
    InvokeContext
    );
  Capture->CallsIssued = 2;
  Capture->FeatureDiscoveryResult = Result.X0;
  if (IsNotSupported (Result.X0)) {
    Capture->Outcome = M7SmcccCollectorFeatureUnavailable;
    return Capture->Outcome;
  }

  if (Result.X0 != M7_SMCCC_SUCCESS) {
    Capture->Outcome = M7SmcccCollectorDiscoveryError;
    return Capture->Outcome;
  }

  for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
    Invoke (
      M7_SMCCC_FEATURE_AVAILABILITY_FID,
      mFeatureRegisterOpcodes[Index],
      &Result,
      InvokeContext
      );
    ++Capture->CallsIssued;
    ++Capture->FeatureQueriesIssued;
    Capture->FeatureQueries[Index].Status = Result.X0;
    Capture->FeatureQueries[Index].AvailabilityMask = Result.X1;
    if (Result.X0 != M7_SMCCC_SUCCESS) {
      Capture->Outcome = M7SmcccCollectorQueryError;
      return Capture->Outcome;
    }
  }

  Capture->Outcome = M7SmcccCollectorComplete;
  return Capture->Outcome;
}
