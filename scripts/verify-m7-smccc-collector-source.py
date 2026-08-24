#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
HEADER = LIB / "M7SmcccFeatureAvailabilityCollector.h"
SOURCE = LIB / "M7SmcccFeatureAvailabilityCollector.c"
ASM = LIB / "M7SmcccCallAArch64.S"
DSC = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc"
INF = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag/OvaltineDiag.inf"

for required in (HEADER, SOURCE, ASM, DSC, INF):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 collector source not found: {required}")

header = HEADER.read_text(errors="replace")
source = SOURCE.read_text(errors="replace")
assembly = ASM.read_text(errors="replace")
integration = DSC.read_text(errors="replace") + "\n" + INF.read_text(errors="replace")

required_defines = {
    "M7_SMCCC_VERSION_FID": "0x80000000",
    "M7_SMCCC_ARCH_FEATURES_FID": "0x80000001",
    "M7_SMCCC_FEATURE_AVAILABILITY_FID": "0xC0000003",
    "M7_SMCCC_SCR_EL3_OPCODE": "0x1E1100",
    "M7_SMCCC_CPTR_EL3_OPCODE": "0x1E1140",
    "M7_SMCCC_MDCR_EL3_OPCODE": "0x1E1320",
}

checks = []
for name, value in required_defines.items():
    checks.append((f"{name.lower()}-is-exact", bool(re.search(rf"(?m)^#define\s+{name}\s+UINT64_C\({value}\)\s*$", header))))

consume_index = source.find("Token->Consumed = 1;")
first_call_index = source.find("Invoke (M7_SMCCC_VERSION_FID")
checks.extend(
    [
        ("collector-removes-loose-route-boolean", "RouteIsAuthorized" not in header + source),
        ("collector-has-bound-route-token-types", "M7_SMCCC_ROUTE_AUTHORIZATION_TOKEN" in header and "M7_SMCCC_ROUTE_AUTHORIZATION_EXPECTATION" in header),
        ("collector-has-exact-required-policy-flags", "M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS" in header and "Token->PolicyFlags != M7_SMCCC_ROUTE_REQUIRED_POLICY_FLAGS" in source),
        ("collector-binds-route-report-and-evidence-digests", "RouteAuthorizationReportSha256" in header + source and "AuthorizationBindingSha256" in header + source and source.count("EqualDigest (") >= 3),
        ("collector-binds-safe-output-buffer", "HasSafeBoundOutputBuffer" in source and "M7_SMCCC_ROUTE_MIN_BUFFER_CAPACITY" in source and "M7_SMCCC_ROUTE_MAX_BUFFER_CAPACITY" in source),
        ("collector-consumes-token-before-first-smc", consume_index >= 0 and first_call_index >= 0 and consume_index < first_call_index),
        ("collector-zeroes-invocation-budget-on-consume", "Token->InvocationBudget = 0;" in source),
        ("collector-rejects-token-replay", "Token->Consumed != 0" in source),
        ("collector-copies-token-binding-into-capture", "BindAuthorizationToCapture" in source and "Capture->RouteAuthorizationReportSha256[Index] = Token->RouteAuthorizationReportSha256[Index]" in source and "Capture->AuthorizationBindingSha256[Index] = Token->AuthorizationBindingSha256[Index]" in source),
        ("collector-copies-authorized-buffer-into-capture", "Capture->AuthorizedOutputBufferAddress = Token->OutputBufferAddress" in source and "Capture->AuthorizedOutputBufferCapacity = Token->OutputBufferCapacity" in source and "Capture->AuthorizedOutputBufferAlignment = Token->OutputBufferAlignment" in source),
        ("collector-has-explicit-nonsecure-el2-gate", "CallerState->CallerExceptionLevel != M7_SMCCC_EXPECTED_CALLER_EL" in source and "CallerState->CallerIsNonSecure != 1" in source),
        ("collector-discovers-before-feature-queries", source.find("Invoke (\n    M7_SMCCC_ARCH_FEATURES_FID") < source.find("Invoke (\n      M7_SMCCC_FEATURE_AVAILABILITY_FID")),
        ("collector-stops-on-version-unavailable", "M7SmcccCollectorVersionUnavailable" in source),
        ("collector-stops-on-feature-unavailable", "M7SmcccCollectorFeatureUnavailable" in source),
        ("collector-caps-call-count-at-five", "M7_SMCCC_MAX_CALLS                 UINT32_C(5)" in header and "M7_SMCCC_MAX_FEATURE_QUERIES       UINT32_C(3)" in header),
        ("aarch64-transport-has-one-smc-zero", len(re.findall(r"(?m)^\s*smc\s+#0\s*$", assembly)) == 1),
        ("aarch64-transport-has-no-el3-system-register-access", not re.search(r"(?mi)^\s*(mrs|msr)\b[^\n]*_el3\b", assembly)),
        ("collector-has-no-mmio-storage-or-exitbootservices", not re.search(r"(?i)\b(mmio|blockio|diskio|exitbootservices|ufs|flash|erase|slot)\b", header + source)),
        ("collector-is-not-integrated-into-current-diagnostic", "M7SmcccFeatureAvailabilityCollector" not in integration and "M7SmcccCallAArch64" not in integration),
    ]
)

failed = [name for name, passed in checks if not passed]
print("IzzOS Milestone 7 SMCCC collector source contract")
print("Device commands executed: NONE")
print("SMC calls executed: NONE")
print("Launch commands executed: NONE")
print()
for name, passed in checks:
    print(f'{name}: {"PASS" if passed else "FAIL"}')
print()
print("current-dsc-inf-integration: FORBIDDEN_AND_ABSENT")
print("device-route-authorization: BOUND_SINGLE_USE_TOKEN_REQUIRED_NOT_INTEGRATED")
print("mmio-initialization-authorization: NO")
print("launch-authorization: NO")
if failed:
    print("classification: M7_SMCCC_COLLECTOR_SOURCE_CONTRACT_BLOCKED")
    raise SystemExit(1)
print("classification: M7_SMCCC_COLLECTOR_SOURCE_CONTRACT_PASS")
