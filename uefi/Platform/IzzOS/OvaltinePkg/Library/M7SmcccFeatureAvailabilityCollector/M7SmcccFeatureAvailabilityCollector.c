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

static int
IsZeroDigest (
  const uint8_t Digest[M7_SMCCC_ROUTE_DIGEST_SIZE]
  )
{
  uint32_t Index;
  uint8_t Combined;

  Combined = 0;
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    Combined |= Digest[Index];
  }
  return Combined == 0;
}

static int
EqualDigest (
  const uint8_t Left[M7_SMCCC_ROUTE_DIGEST_SIZE],
  const uint8_t Right[M7_SMCCC_ROUTE_DIGEST_SIZE]
  )
{
  uint32_t Index;
  uint8_t Difference;

  Difference = 0;
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    Difference |= (uint8_t)(Left[Index] ^ Right[Index]);
  }
  return Difference == 0;
}

static int
IsPowerOfTwo (
  uint64_t Value
  )
{
  return Value != 0 && (Value & (Value - 1)) == 0;
}

static int
HasSafeBoundOutputBuffer (
  const M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation
  )
{
  if (Token->OutputBufferAddress != Expectation->OutputBufferAddress ||
      Token->OutputBufferCapacity != Expectation->OutputBufferCapacity ||
      Token->OutputBufferAlignment != Expectation->OutputBufferAlignment) {
    return 0;
  }
  if (Token->OutputBufferAddress == 0 ||
      Token->OutputBufferCapacity < M7_SMCCC_ROUTE_MIN_BUFFER_CAPACITY ||
      Token->OutputBufferCapacity > M7_SMCCC_ROUTE_MAX_BUFFER_CAPACITY ||
      Token->OutputBufferAlignment < M7_SMCCC_ROUTE_MIN_BUFFER_ALIGNMENT ||
      !IsPowerOfTwo (Token->OutputBufferAlignment) ||
      Token->OutputBufferAddress % Token->OutputBufferAlignment != 0) {
    return 0;
  }
  return Token->OutputBufferAddress <= UINT64_MAX - Token->OutputBufferCapacity;
}

static int
ValidateAndConsumeRouteAuthorization (
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token,
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *Expectation
  )
{
  if (Token == 0 || Expectation == 0) {
    return 0;
  }
  if (Token->Magic != M7_SMCCC_ROUTE_TOKEN_MAGIC ||
      Token->FormatVersion != M7_SMCCC_ROUTE_TOKEN_VERSION ||
      Token->TokenSize != (uint32_t)sizeof (*Token) ||
      Token->PolicyFlags != M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS ||
      Token->InvocationBudget != 1 ||
      Token->SmcccCallLimit != M7_SMCCC_MAX_CALLS ||
      Token->Consumed != 0) {
    return 0;
  }
  if (IsZeroDigest (Token->RouteAuthorizationReportSha256) ||
      IsZeroDigest (Token->AuthorizationBindingSha256) ||
      IsZeroDigest (Expectation->RouteAuthorizationReportSha256) ||
      IsZeroDigest (Expectation->AuthorizationBindingSha256) ||
      !EqualDigest (Token->RouteAuthorizationReportSha256, Expectation->RouteAuthorizationReportSha256) ||
      !EqualDigest (Token->AuthorizationBindingSha256, Expectation->AuthorizationBindingSha256) ||
      !HasSafeBoundOutputBuffer (Token, Expectation)) {
    return 0;
  }

  Token->Consumed = 1;
  Token->InvocationBudget = 0;
  return 1;
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
  Capture->AuthorizedOutputBufferAddress = 0;
  Capture->AuthorizedOutputBufferCapacity = 0;
  Capture->AuthorizedOutputBufferAlignment = 0;
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    Capture->RouteAuthorizationReportSha256[Index] = 0;
    Capture->AuthorizationBindingSha256[Index] = 0;
  }
  for (Index = 0; Index < M7_SMCCC_MAX_FEATURE_QUERIES; ++Index) {
    Capture->FeatureQueries[Index].RegisterOpcode = mFeatureRegisterOpcodes[Index];
    Capture->FeatureQueries[Index].Status = M7_SMCCC_NOT_SUPPORTED_64;
    Capture->FeatureQueries[Index].AvailabilityMask = 0;
  }
}

static void
BindAuthorizationToCapture (
  M7_SMCCC_CAPTURE *Capture,
  const M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *Token
  )
{
  uint32_t Index;

  Capture->AuthorizedOutputBufferAddress = Token->OutputBufferAddress;
  Capture->AuthorizedOutputBufferCapacity = Token->OutputBufferCapacity;
  Capture->AuthorizedOutputBufferAlignment = Token->OutputBufferAlignment;
  for (Index = 0; Index < M7_SMCCC_ROUTE_DIGEST_SIZE; ++Index) {
    Capture->RouteAuthorizationReportSha256[Index] = Token->RouteAuthorizationReportSha256[Index];
    Capture->AuthorizationBindingSha256[Index] = Token->AuthorizationBindingSha256[Index];
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

  if (CallerState->CallerExceptionLevel != M7_SMCCC_EXPECTED_CALLER_EL ||
      CallerState->CallerIsNonSecure != 1) {
    Capture->Outcome = M7SmcccCollectorWrongCallerState;
    return Capture->Outcome;
  }

  if (!ValidateAndConsumeRouteAuthorization (
        CallerState->RouteAuthorizationToken,
        CallerState->RouteAuthorizationExpectation
        )) {
    Capture->Outcome = M7SmcccCollectorRouteNotAuthorized;
    return Capture->Outcome;
  }
  BindAuthorizationToCapture (Capture, CallerState->RouteAuthorizationToken);

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
