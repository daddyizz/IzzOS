#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
HEADER = LIB / "M7SmcccCaptureOrchestrator.h"
SOURCE = LIB / "M7SmcccCaptureOrchestrator.c"
DSC = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc"
INF = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag/OvaltineDiag.inf"

for required in (HEADER, SOURCE, DSC, INF):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 SMCCC orchestrator source not found: {required}")

header = HEADER.read_text(errors="replace")
source = SOURCE.read_text(errors="replace")
integration = DSC.read_text(errors="replace") + "\n" + INF.read_text(errors="replace")

binding_gate = source.find("!M7IsValidSmcccTranscriptBinding (Binding)")
buffer_gate = source.find("!OutputBufferMatchesExpectation (Expectation, OutputBuffer, OutputBufferCapacity)")
collector_call = source.find("M7CollectSmcccFeatureAvailability (")
emitter_call = source.find("M7EmitSmcccCaptureTranscript (")

checks = [
    ("orchestrator-exposes-one-bounded-entrypoint", header.count("M7RunBoundSmcccFeatureAvailabilityCapture (") == 1 and source.count("M7RunBoundSmcccFeatureAvailabilityCapture (") == 1),
    ("orchestrator-validates-binding-before-collector", 0 <= binding_gate < collector_call),
    ("orchestrator-binds-actual-output-buffer-before-collector", 0 <= buffer_gate < collector_call and "Expectation->OutputBufferAddress == (uint64_t)(uintptr_t)OutputBuffer" in source and "OutputBufferCapacity == (size_t)Expectation->OutputBufferCapacity" in source),
    ("orchestrator-fixes-caller-to-nonsecure-el2", "CallerState.CallerExceptionLevel = M7_SMCCC_EXPECTED_CALLER_EL;" in source and "CallerState.CallerIsNonSecure = 1;" in source),
    ("orchestrator-collects-exactly-once", source.count("M7CollectSmcccFeatureAvailability (") == 1),
    ("orchestrator-emits-only-after-serializable-outcome", collector_call < source.find("Result->CollectorOutcome != M7SmcccCollectorComplete") < emitter_call and source.count("M7EmitSmcccCaptureTranscript (") == 1),
    ("orchestrator-allows-only-complete-or-feature-unavailable", "Result->CollectorOutcome != M7SmcccCollectorComplete" in source and "Result->CollectorOutcome != M7SmcccCollectorFeatureUnavailable" in source),
    ("orchestrator-propagates-transcript-length", "&Result->TranscriptLength" in source),
    ("orchestrator-does-not-call-real-transport-directly", "M7SmcccInvokeAArch64" not in header + source),
    ("orchestrator-has-no-direct-smc-or-system-register-instruction", not re.search(r"(?mi)^\s*(smc|hvc|mrs|msr)\b", source)),
    ("orchestrator-has-no-runtime-storage-or-device-write-api", not re.search(r"(?i)\b(malloc|calloc|realloc|free|fopen|fwrite|blockio|diskio|exitbootservices|ufs|flash|erase|format|slot)\b", header + source)),
    ("orchestrator-is-not-integrated-into-current-diagnostic", "M7SmcccCaptureOrchestrator" not in integration and "M7RunBoundSmcccFeatureAvailabilityCapture" not in integration),
]

failed = [name for name, passed in checks if not passed]
print("IzzOS Milestone 7 bound SMCCC capture orchestrator source contract")
print("Device commands executed: NONE")
print("SMC calls executed: NONE")
print("Launch commands executed: NONE")
print()
for name, passed in checks:
    print(f'{name}: {"PASS" if passed else "FAIL"}')
print()
print("current-dsc-inf-integration: FORBIDDEN_AND_ABSENT")
print("real-transport-selection: CALLER_SUPPLIED_AFTER_BOUND_ROUTE_ONLY")
print("payload-launch-authorization: NO")
if failed:
    print("classification: M7_SMCCC_CAPTURE_ORCHESTRATOR_SOURCE_CONTRACT_BLOCKED")
    raise SystemExit(1)
print("classification: M7_SMCCC_CAPTURE_ORCHESTRATOR_SOURCE_CONTRACT_PASS")
