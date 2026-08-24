#ifndef M7_SMCCC_FEATURE_AVAILABILITY_COLLECTOR_H
#define M7_SMCCC_FEATURE_AVAILABILITY_COLLECTOR_H

#include <stdint.h>

#define M7_SMCCC_VERSION_FID              UINT64_C(0x80000000)
#define M7_SMCCC_ARCH_FEATURES_FID        UINT64_C(0x80000001)
#define M7_SMCCC_FEATURE_AVAILABILITY_FID UINT64_C(0xC0000003)

#define M7_SMCCC_SCR_EL3_OPCODE           UINT64_C(0x1E1100)
#define M7_SMCCC_CPTR_EL3_OPCODE          UINT64_C(0x1E1140)
#define M7_SMCCC_MDCR_EL3_OPCODE          UINT64_C(0x1E1320)

#define M7_SMCCC_SUCCESS                   UINT64_C(0)
#define M7_SMCCC_NOT_SUPPORTED_32          UINT64_C(0xFFFFFFFF)
#define M7_SMCCC_NOT_SUPPORTED_64          UINT64_C(0xFFFFFFFFFFFFFFFF)

#define M7_SMCCC_EXPECTED_CALLER_EL        UINT32_C(2)
#define M7_SMCCC_MAX_FEATURE_QUERIES       UINT32_C(3)
#define M7_SMCCC_MAX_CALLS                 UINT32_C(5)

typedef struct {
  uint64_t X0;
  uint64_t X1;
} M7_SMCCC_RESULT;

typedef void (*M7_SMCCC_INVOKE)(
  uint64_t Fid,
  uint64_t Arg1,
  M7_SMCCC_RESULT *Result,
  void *Context
  );

typedef struct {
  uint32_t CallerExceptionLevel;
  uint8_t CallerIsNonSecure;
  uint8_t RouteIsAuthorized;
} M7_SMCCC_CALLER_STATE;

typedef struct {
  uint64_t RegisterOpcode;
  uint64_t Status;
  uint64_t AvailabilityMask;
} M7_SMCCC_FEATURE_QUERY;

typedef enum {
  M7SmcccCollectorComplete = 0,
  M7SmcccCollectorFeatureUnavailable,
  M7SmcccCollectorVersionUnavailable,
  M7SmcccCollectorVersionTooOld,
  M7SmcccCollectorRouteNotAuthorized,
  M7SmcccCollectorWrongCallerState,
  M7SmcccCollectorDiscoveryError,
  M7SmcccCollectorQueryError,
  M7SmcccCollectorInvalidArgument
} M7_SMCCC_COLLECTOR_OUTCOME;

typedef struct {
  M7_SMCCC_COLLECTOR_OUTCOME Outcome;
  uint32_t CallsIssued;
  uint32_t FeatureQueriesIssued;
  uint64_t SmcccVersionResult;
  uint64_t FeatureDiscoveryResult;
  M7_SMCCC_FEATURE_QUERY FeatureQueries[M7_SMCCC_MAX_FEATURE_QUERIES];
} M7_SMCCC_CAPTURE;

M7_SMCCC_COLLECTOR_OUTCOME
M7CollectSmcccFeatureAvailability (
  const M7_SMCCC_CALLER_STATE *CallerState,
  M7_SMCCC_INVOKE Invoke,
  void *InvokeContext,
  M7_SMCCC_CAPTURE *Capture
  );

void
M7SmcccInvokeAArch64 (
  uint64_t Fid,
  uint64_t Arg1,
  M7_SMCCC_RESULT *Result,
  void *Context
  );

#endif
