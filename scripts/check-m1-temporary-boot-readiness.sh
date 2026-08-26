#!/usr/bin/env bash
set -euo pipefail

PREFLIGHT="${1:-out/temporary-route-preflight.txt}"
PAYLOAD_DOC="${2:-docs/M1_CURRENT_PAYLOAD.txt}"

blocked=0

if [[ ! -f "$PREFLIGHT" ]]; then
  echo "ERROR: temporary-route preflight evidence not found: $PREFLIGHT" >&2
  blocked=1
elif ! grep -q '^classification: TEMPORARY_ROUTE_PREFLIGHT_PASS$' "$PREFLIGHT"; then
  echo "ERROR: temporary-route preflight has not passed" >&2
  blocked=1
fi

if [[ ! -f "$PAYLOAD_DOC" ]]; then
  echo "ERROR: current payload identity file not found: $PAYLOAD_DOC" >&2
  blocked=1
elif ! grep -q '^Payload ID: M1-DIAG-R3$' "$PAYLOAD_DOC"; then
  echo "ERROR: current M1 payload identity is not M1-DIAG-R3" >&2
  blocked=1
fi

host_out="$(bash "$(dirname "$0")/check-host-fastboot-toolchain.sh" 2>&1 || true)"
printf '%s\n' "$host_out"
if ! grep -q '^classification: HOST_FASTBOOT_TOOLCHAIN_PASS$' <<<"$host_out"; then
  echo "ERROR: host fastboot toolchain gate has not passed" >&2
  blocked=1
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: M1_TEMPORARY_ROUTE_BLOCKED"
  echo "decision: prerequisites are incomplete; do not execute fastboot boot or any device launch command."
  exit 1
fi

echo "preflight-evidence: PASS"
echo "host-fastboot-toolchain: PASS"
echo "current-payload: M1-DIAG-R3"
echo "payload-form: PE32+ EFI ARM64 application"
echo "required-launch-container: Android boot image compatible with the exact device boot chain"
echo "classification: M1_TEMPORARY_ROUTE_PACKAGING_REQUIRED"
echo "decision: host and device prerequisites pass, but the raw EFI application is not itself a valid fastboot boot container. Build and independently verify an exact-device temporary Android boot-image wrapper/chain-loader before any launch authorization. Persistent writes and slot changes remain forbidden."
