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

#define M7_SMCCC_ROUTE_TOKEN_MAGIC          UINT64_C(0x495A4D37534D4343)
#define M7_SMCCC_ROUTE_TOKEN_VERSION        UINT32_C(1)
#define M7_SMCCC_ROUTE_DIGEST_SIZE          UINT32_C(32)
#define M7_SMCCC_ROUTE_MIN_BUFFER_CAPACITY  UINT64_C(0x1000)
#define M7_SMCCC_ROUTE_MAX_BUFFER_CAPACITY  UINT64_C(0x10000)
#define M7_SMCCC_ROUTE_MIN_BUFFER_ALIGNMENT UINT64_C(0x40)

#define M7_SMCCC_ROUTE_POLICY_PRE_SEC                    UINT32_C(0x00000001)
#define M7_SMCCC_ROUTE_POLICY_NONSECURE                  UINT32_C(0x00000002)
#define M7_SMCCC_ROUTE_POLICY_EL2                        UINT32_C(0x00000004)
#define M7_SMCCC_ROUTE_POLICY_PRIMARY_CPU                UINT32_C(0x00000008)
#define M7_SMCCC_ROUTE_POLICY_OUTPUT_NONSECURE           UINT32_C(0x00000010)
#define M7_SMCCC_ROUTE_POLICY_EXACT_CAPTURE_ONLY         UINT32_C(0x00000020)
#define M7_SMCCC_ROUTE_POLICY_NO_DEVICE_WRITES           UINT32_C(0x00000040)
#define M7_SMCCC_ROUTE_POLICY_NO_PAYLOAD_LAUNCH          UINT32_C(0x00000080)
#define M7_SMCCC_ROUTE_POLICY_HOST_SERIALIZATION_REQUIRED UINT32_C(0x00000100)

#define M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS ( \
  M7_SMCCC_ROUTE_POLICY_PRE_SEC | \
  M7_SMCCC_ROUTE_POLICY_NONSECURE | \
  M7_SMCCC_ROUTE_POLICY_EL2 | \
  M7_SMCCC_ROUTE_POLICY_PRIMARY_CPU | \
  M7_SMCCC_ROUTE_POLICY_OUTPUT_NONSECURE | \
  M7_SMCCC_ROUTE_POLICY_EXACT_CAPTURE_ONLY | \
  M7_SMCCC_ROUTE_POLICY_NO_DEVICE_WRITES | \
  M7_SMCCC_ROUTE_POLICY_NO_PAYLOAD_LAUNCH | \
  M7_SMCCC_ROUTE_POLICY_HOST_SERIALIZATION_REQUIRED \
  )

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
  uint64_t Magic;
  uint32_t FormatVersion;
  uint32_t TokenSize;
  uint32_t PolicyFlags;
  uint32_t InvocationBudget;
  uint32_t SmcccCallLimit;
  uint32_t Consumed;
  uint64_t OutputBufferAddress;
  uint64_t OutputBufferCapacity;
  uint64_t OutputBufferAlignment;
  uint8_t RouteAuthorizationReportSha256[M7_SMCCC_ROUTE_DIGEST_SIZE];
  uint8_t AuthorizationBindingSha256[M7_SMCCC_ROUTE_DIGEST_SIZE];
} M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN;

typedef struct {
  uint64_t OutputBufferAddress;
  uint64_t OutputBufferCapacity;
  uint64_t OutputBufferAlignment;
  uint8_t RouteAuthorizationReportSha256[M7_SMCCC_ROUTE_DIGEST_SIZE];
  uint8_t AuthorizationBindingSha256[M7_SMCCC_ROUTE_DIGEST_SIZE];
} M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION;

typedef struct {
  uint32_t CallerExceptionLevel;
  uint8_t CallerIsNonSecure;
  uint8_t Reserved[3];
  M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN *RouteAuthorizationToken;
  const M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION *RouteAuthorizationExpectation;
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
