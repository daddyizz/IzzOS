#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
LIB = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Library/M7SmcccFeatureAvailabilityCollector"
HEADER = LIB / "M7SmcccCaptureTranscript.h"
SOURCE = LIB / "M7SmcccCaptureTranscript.c"
DSC = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/OvaltineDiag.dsc"
INF = ROOT / "uefi/Platform/IzzOS/OvaltinePkg/Applications/OvaltineDiag/OvaltineDiag.inf"

for required in (HEADER, SOURCE, DSC, INF):
    if not required.is_file():
        raise SystemExit(f"ERROR: required M7 transcript-emitter source not found: {required}")

header = HEADER.read_text(errors="replace")
source = SOURCE.read_text(errors="replace")
integration = DSC.read_text(errors="replace") + "\n" + INF.read_text(errors="replace")

required_literals = [
    "collector-capture-schema: IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1\\n",
    "capture-origin: PRE_SEC_NONSECURE_EL2\\n",
    "caller-security-state: NONSECURE\\n",
    "caller-exception-level: EL2\\n",
    "route-authorization-input: EXPLICIT_CALLER_ASSERTION_NOT_INDEPENDENTLY_ATTESTED\\n",
    "vendor-or-sip-smc-action: NONE\\n",
    "direct-el3-register-read-action: NONE\\n",
    "secure-monitor-modification-action: NONE\\n",
    "mmio-action: NONE\\n",
    "device-writes: NONE\\n",
    "persistent-writes: NONE\\n",
    "slot-changes: NONE\\n",
    "observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED\\n",
    "launch-authorization: NO\\n",
]

checks = [
    ("emitter-has-all-fixed-schema-and-safety-lines", all(value in source for value in required_literals)),
    ("emitter-binds-six-exact-sha256-values", header.count("Sha256;") == 6 and source.count("IsExactSha256 (Binding->") == 6),
    ("emitter-normalizes-hash-case", "ToLowerHex (Value[Index])" in source),
    ("emitter-allows-only-complete-or-feature-unavailable", "Capture->Outcome == M7SmcccCollectorComplete" in source and "Capture->Outcome == M7SmcccCollectorFeatureUnavailable" in source),
    ("emitter-reconstructs-only-compile-time-fids", "M7_SMCCC_VERSION_FID" in source and "M7_SMCCC_ARCH_FEATURES_FID" in source and source.count("M7_SMCCC_FEATURE_AVAILABILITY_FID") >= 2),
    ("emitter-requires-canonical-register-opcodes", "mExpectedRegisterOpcodes" in source and "HasCanonicalQueryStorage" in source),
    ("emitter-measures-before-buffer-write", source.find("Writer.Buffer = 0;") < source.find("Writer.Buffer = Buffer;")),
    ("emitter-nul-terminates-only-after-capacity-check", source.find("BufferCapacity <= Writer.Length") < source.find("Buffer[Writer.Length] = '\\0';")),
    ("emitter-has-no-smc-or-system-register-instruction", not re.search(r"(?mi)^\s*(smc|hvc|mrs|msr)\b", source)),
    ("emitter-has-no-runtime-or-storage-api", not re.search(r"(?i)\b(malloc|calloc|realloc|free|fopen|fwrite|blockio|diskio|exitbootservices|flash|erase)\b", header + source)),
    ("emitter-does-not-emit-direct-el3-register-fields", not re.search(r'"(?:scr-el3|cptr-el3|mdcr-el3|icc-sre-el3|icc-ctlr-el3|zcr-el3|smcr-el3):', source, re.IGNORECASE)),
    ("emitter-is-not-integrated-into-current-diagnostic", "M7SmcccCaptureTranscript" not in integration),
]

failed = [name for name, passed in checks if not passed]
print("IzzOS Milestone 7 deterministic SMCCC transcript-emitter source contract")
print("Device commands executed: NONE")
print("SMC calls executed: NONE")
print("Launch commands executed: NONE")
print()
for name, passed in checks:
    print(f'{name}: {"PASS" if passed else "FAIL"}')
print()
print("current-dsc-inf-integration: FORBIDDEN_AND_ABSENT")
print("device-route-authorization: NOT_PROVEN")
print("launch-authorization: NO")
if failed:
    print("classification: M7_SMCCC_TRANSCRIPT_EMITTER_SOURCE_CONTRACT_BLOCKED")
    raise SystemExit(1)
print("classification: M7_SMCCC_TRANSCRIPT_EMITTER_SOURCE_CONTRACT_PASS")
