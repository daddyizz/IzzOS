#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <inspection.txt> <m2-manifest.txt> <recovery-evidence.txt> <stock-manifest...>" >&2
  exit 2
fi

INSPECTION="$1"
M2_MANIFEST="$2"
RECOVERY="$3"
shift 3
STOCK_MANIFESTS=("$@")

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
blockers=()

run_gate() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '%-34s PASS\n' "$name"
  else
    printf '%-34s BLOCKED\n' "$name"
    blockers+=("$name")
  fi
}

printf 'IzzOS M2 readiness report\n'
printf '==========================\n'
run_gate "stock image set consistency" bash "$ROOT_DIR/scripts/verify-stock-image-set.sh" "${STOCK_MANIFESTS[@]}"
run_gate "M2 evidence bundle consistency" bash "$ROOT_DIR/scripts/verify-m2-evidence-bundle.sh" "$INSPECTION" "$M2_MANIFEST" "${STOCK_MANIFESTS[@]}"
run_gate "recovery evidence" bash "$ROOT_DIR/scripts/verify-m2-recovery-evidence.sh" "$RECOVERY"
run_gate "evidence freshness" bash "$ROOT_DIR/scripts/verify-evidence-freshness.sh" "$INSPECTION" "$M2_MANIFEST" "$RECOVERY"
run_gate "route authorization" bash "$ROOT_DIR/scripts/verify-m2-route-authorization.sh" "$M2_MANIFEST" "$RECOVERY"

printf '\n'
if [[ ${#blockers[@]} -eq 0 ]]; then
  echo 'classification: READY_FOR_ROUTE_SPECIFIC_PACKAGING'
  echo 'decision: all host-side evidence gates passed; this report does not authorize or execute a device launch.'
else
  echo 'classification: M2_READINESS_BLOCKED'
  echo "blocker-count: ${#blockers[@]}"
  for blocker in "${blockers[@]}"; do
    echo "blocker: $blocker"
  done
  echo 'decision: resolve every blocker before route-specific packaging.'
  exit 1
fi
