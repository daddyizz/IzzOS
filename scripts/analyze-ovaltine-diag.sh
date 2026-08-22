#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <ovaltine-diag-output.txt>" >&2
  exit 2
fi

INPUT="$1"
if [[ ! -f "${INPUT}" ]]; then
  echo "ERROR: file not found: ${INPUT}" >&2
  exit 2
fi

line_value() {
  local pattern="$1"
  grep -m1 -E "${pattern}" "${INPUT}" || true
}

GOP_RES_LINE="$(line_value '^\[GOP\] resolution=')"
GOP_FB_LINE="$(line_value '^\[GOP\] framebuffer-base=')"
MEM_HDR_LINE="$(line_value '^\[MEM\] descriptors=')"
RESULT_LINE="$(line_value '^\[RESULT\] ' )"

printf 'IzzOS Ovaltine diagnostic output analysis\n'
printf '=========================================\n'

if [[ -n "${GOP_RES_LINE}" && -n "${GOP_FB_LINE}" ]]; then
  RESOLUTION="$(printf '%s\n' "${GOP_RES_LINE}" | sed -n 's/.*resolution=\([0-9]*x[0-9]*\).*/\1/p')"
  PPSL="$(printf '%s\n' "${GOP_RES_LINE}" | sed -n 's/.*pixels-per-scanline=\([0-9]*\).*/\1/p')"
  PIXEL_FORMAT="$(printf '%s\n' "${GOP_RES_LINE}" | sed -n 's/.*format=\([0-9]*\).*/\1/p')"
  FB_BASE="$(printf '%s\n' "${GOP_FB_LINE}" | sed -n 's/.*framebuffer-base=\(0x[0-9A-Fa-f]*\).*/\1/p')"
  FB_SIZE="$(printf '%s\n' "${GOP_FB_LINE}" | sed -n 's/.*framebuffer-size=\(0x[0-9A-Fa-f]*\).*/\1/p')"

  echo "GOP: AVAILABLE"
  echo "resolution: ${RESOLUTION:-unknown}"
  echo "pixels-per-scanline: ${PPSL:-unknown}"
  echo "pixel-format: ${PIXEL_FORMAT:-unknown}"
  echo "framebuffer-base: ${FB_BASE:-unknown}"
  echo "framebuffer-size: ${FB_SIZE:-unknown}"

  if [[ -n "${FB_BASE}" && -n "${FB_SIZE}" ]]; then
    FB_BASE_DEC=$((FB_BASE))
    FB_SIZE_DEC=$((FB_SIZE))
    FB_END_DEC=$((FB_BASE_DEC + FB_SIZE_DEC))
    printf 'framebuffer-end-exclusive: 0x%X\n' "${FB_END_DEC}"
  fi
else
  GOP_UNAVAILABLE="$(line_value '^\[GOP\] unavailable:')"
  if [[ -n "${GOP_UNAVAILABLE}" ]]; then
    echo "GOP: UNAVAILABLE"
    echo "${GOP_UNAVAILABLE}"
  else
    echo "GOP: INSUFFICIENT_DATA"
  fi
fi

echo

if [[ -n "${MEM_HDR_LINE}" ]]; then
  DECLARED_COUNT="$(printf '%s\n' "${MEM_HDR_LINE}" | sed -n 's/.*descriptors=\([0-9]*\).*/\1/p')"
  DESC_SIZE="$(printf '%s\n' "${MEM_HDR_LINE}" | sed -n 's/.*descriptor-size=\([0-9]*\).*/\1/p')"
  DESC_VERSION="$(printf '%s\n' "${MEM_HDR_LINE}" | sed -n 's/.*version=\([0-9]*\).*/\1/p')"
  ACTUAL_COUNT="$(grep -c -E '^\[MEM\] [0-9]{3} ' "${INPUT}" || true)"

  echo "memory-map: PRESENT"
  echo "declared-descriptors: ${DECLARED_COUNT:-unknown}"
  echo "parsed-descriptors: ${ACTUAL_COUNT}"
  echo "descriptor-size: ${DESC_SIZE:-unknown}"
  echo "descriptor-version: ${DESC_VERSION:-unknown}"

  if [[ -n "${DECLARED_COUNT}" && "${DECLARED_COUNT}" -ne "${ACTUAL_COUNT}" ]]; then
    echo "memory-map-integrity: MISMATCH"
  else
    echo "memory-map-integrity: OK"
  fi

  echo "descriptor-types:"
  grep -E '^\[MEM\] [0-9]{3} ' "${INPUT}" \
    | awk '{print $3}' \
    | sort \
    | uniq -c \
    | awk '{printf "  %s: %s\n", $2, $1}'
else
  echo "memory-map: MISSING"
fi

echo
if [[ -n "${RESULT_LINE}" ]]; then
  echo "result-line: ${RESULT_LINE}"
else
  echo "result-line: MISSING"
fi

echo
if grep -q '^\[RESULT\] memory-map dump completed' "${INPUT}"; then
  echo "classification: DIAGNOSTIC_CAPTURE_COMPLETE"
else
  echo "classification: DIAGNOSTIC_CAPTURE_INCOMPLETE"
fi
