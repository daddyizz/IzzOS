#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <m2-manifest.txt> <recovery-evidence.txt>" >&2
  exit 2
fi

MANIFEST="$1"
RECOVERY="$2"
[[ -f "$MANIFEST" ]] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 2; }
[[ -f "$RECOVERY" ]] || { echo "ERROR: recovery evidence not found: $RECOVERY" >&2; exit 2; }

value() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$MANIFEST"
}

route="$(value 'Selected launch route' || true)"
decision="$(value 'Route decision' || true)"
writes="$(value 'Persistent writes' || true)"
slots="$(value 'Slot changes' || true)"
evidence="$(value 'Route validation evidence reference' || true)"
firmware="$(value 'Firmware ID' || true)"

blocked=0

if [[ "$decision" != "TEMPORARY_ROUTE_VALIDATED" ]]; then
  echo "ERROR: route decision is not TEMPORARY_ROUTE_VALIDATED: ${decision:-UNKNOWN}" >&2
  blocked=1
fi

if [[ -z "$route" || "$route" == "NONE" ]]; then
  echo "ERROR: selected launch route is missing/unset" >&2
  blocked=1
fi

if [[ "$writes" != "FORBIDDEN" ]]; then
  echo "ERROR: persistent writes must remain FORBIDDEN" >&2
  blocked=1
fi

if [[ "$slots" != "FORBIDDEN" ]]; then
  echo "ERROR: slot changes must remain FORBIDDEN" >&2
  blocked=1
fi

case "${evidence,,}" in
  ""|unknown|n/a|na|none|todo|tbd|unset|unvalidated|-)
    echo "ERROR: route validation evidence reference is missing/placeholder" >&2
    blocked=1
    ;;
esac

case "${firmware,,}" in
  ""|unknown|n/a|na|none|todo|tbd|unset|unvalidated|unvalidated-firmware|ci-unvalidated|-)
    echo "ERROR: firmware ID is not exact/validated" >&2
    blocked=1
    ;;
esac

if ! recovery_out="$(bash "$(dirname "$0")/verify-m2-recovery-evidence.sh" "$RECOVERY" 2>&1)"; then
  echo "$recovery_out" >&2
  echo "ERROR: recovery evidence gate did not pass" >&2
  blocked=1
elif ! grep -q '^classification: RECOVERY_EVIDENCE_COMPLETE$' <<<"$recovery_out"; then
  echo "ERROR: recovery evidence did not report RECOVERY_EVIDENCE_COMPLETE" >&2
  blocked=1
fi

recovery_build="$(awk -F': ' '$1 == "OxygenOS build" {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$RECOVERY")"
if [[ -n "$firmware" && -n "$recovery_build" && "$firmware" != "$recovery_build" ]]; then
  echo "ERROR: manifest firmware ID and recovery OxygenOS build do not match" >&2
  blocked=1
fi

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: M2_ROUTE_NOT_AUTHORIZED"
  exit 1
fi

echo "classification: M2_ROUTE_AUTHORIZED_FOR_PACKAGING"
echo "selected-route: $route"
echo "firmware-id: $firmware"
echo "recovery-evidence: COMPLETE"
echo "decision: manifest and recovery gates permit route-specific packaging only; this script does not execute adb, fastboot, boot, flash, or any device command."
