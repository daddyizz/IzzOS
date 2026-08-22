#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <m2-manifest.txt>" >&2
  exit 2
fi

MANIFEST="$1"
[[ -f "$MANIFEST" ]] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 2; }

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

if [[ "$blocked" -ne 0 ]]; then
  echo "classification: M2_ROUTE_NOT_AUTHORIZED"
  exit 1
fi

echo "classification: M2_ROUTE_AUTHORIZED_FOR_PACKAGING"
echo "selected-route: $route"
echo "firmware-id: $firmware"
echo "decision: manifest gates permit route-specific packaging only; this script does not execute adb, fastboot, boot, flash, or any device command."
