#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <exact-stock-hash-lock.txt> [provenance-manifest ...]" >&2
  exit 2
fi

LOCK="$1"
shift
[[ -f "$LOCK" ]] || { echo "ERROR: exact-stock hash lock not found: $LOCK" >&2; exit 2; }

field() {
  local key="$1"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$LOCK"
}

require_single_field() {
  local key="$1" count
  count="$(awk -F': ' -v key="$key" '$1 == key {count++} END {print count + 0}' "$LOCK")"
  [[ "$count" -eq 1 ]] || { echo "ERROR: hash-lock field must appear exactly once: $key" >&2; return 1; }
}

for required_field in Schema Target Product/region 'Build ID' 'Source package' \
  'Source package SHA256' 'Payload SHA256' 'Canonical image source' 'Required roles' 'Absent roles'; do
  require_single_field "$required_field" || exit 1
done

SCHEMA="$(field Schema)"
TARGET="$(field Target)"
BUILD="$(field 'Build ID')"
SOURCE="$(field 'Canonical image source')"
SOURCE_SHA="$(field 'Source package SHA256' | tr 'A-F' 'a-f')"
PAYLOAD_SHA="$(field 'Payload SHA256' | tr 'A-F' 'a-f')"
REQUIRED_ROLES="$(field 'Required roles')"
ABSENT_ROLES="$(field 'Absent roles')"

[[ "$SCHEMA" == "IZZOS_EXACT_STOCK_HASH_LOCK_V1" ]] || { echo "ERROR: unsupported exact-stock hash-lock schema" >&2; exit 1; }
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: source-package SHA256 is invalid" >&2; exit 1; }
[[ "$PAYLOAD_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: payload SHA256 is invalid" >&2; exit 1; }
[[ "$REQUIRED_ROLES" == "boot vendor_boot dtbo vbmeta" ]] || { echo "ERROR: required-role set is not the M1 first-wave set" >&2; exit 1; }
[[ "$ABSENT_ROLES" == "init_boot" ]] || { echo "ERROR: init_boot absence is not recorded" >&2; exit 1; }

declare -A LOCK_FILE=()
declare -A LOCK_SIZE=()
declare -A LOCK_SHA=()
declare -A LOCK_POLICY=()
record_count=0

while IFS= read -r record; do
  IFS='|' read -r role file size sha policy extra <<<"$record"
  [[ -n "$role" && -n "$file" && -n "$size" && -n "$sha" && -n "$policy" && -z "${extra:-}" ]] || {
    echo "ERROR: malformed image record" >&2
    exit 1
  }
  [[ -z "${LOCK_FILE[$role]:-}" ]] || { echo "ERROR: duplicate image record role: $role" >&2; exit 1; }
  [[ "$file" == "$(basename "$file")" && "$file" != *'/'* && "$file" != *'\'* ]] || {
    echo "ERROR: image record filename must be a basename: $file" >&2
    exit 1
  }
  [[ "$size" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: image record size is invalid: $role" >&2; exit 1; }
  sha="${sha,,}"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: image record SHA256 is invalid: $role" >&2; exit 1; }
  case "$policy" in required|optional-recovery) ;; *) echo "ERROR: invalid image record policy: $policy" >&2; exit 1 ;; esac
  LOCK_FILE[$role]="$file"
  LOCK_SIZE[$role]="$size"
  LOCK_SHA[$role]="$sha"
  LOCK_POLICY[$role]="$policy"
  record_count=$((record_count + 1))
done < <(awk -F': ' '$1 == "Image record" {sub("^[^:]+:[[:space:]]*", ""); print}' "$LOCK")

[[ "$record_count" -eq 5 ]] || { echo "ERROR: expected exactly five locked image records" >&2; exit 1; }
for role in boot vendor_boot dtbo vbmeta; do
  [[ "${LOCK_POLICY[$role]:-}" == "required" ]] || { echo "ERROR: required locked role missing: $role" >&2; exit 1; }
done
[[ "${LOCK_POLICY[recovery]:-}" == "optional-recovery" ]] || { echo "ERROR: recovery lock record missing" >&2; exit 1; }

if [[ $# -eq 0 ]]; then
  echo "classification: EXACT_STOCK_HASH_LOCK_VALID"
  echo "Target: $TARGET"
  echo "Build ID: $BUILD"
  echo "Required image roles: $REQUIRED_ROLES"
  echo "decision: the committed lock schema is internally valid; no proprietary image bytes were supplied or accepted."
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -A SEEN=()

manifest_value() {
  local manifest="$1" key="$2"
  awk -F': ' -v key="$key" '$1 == key {sub("^[^:]+:[[:space:]]*", ""); print; exit}' "$manifest"
}

for manifest in "$@"; do
  bash "$SCRIPT_DIR/verify-stock-image-provenance.sh" "$manifest" >/dev/null
  device="$(manifest_value "$manifest" 'Device model/product')"
  build="$(manifest_value "$manifest" 'OxygenOS build')"
  role="$(manifest_value "$manifest" 'Image role')"
  file="$(manifest_value "$manifest" 'Image file')"
  size="$(manifest_value "$manifest" 'Image size bytes')"
  sha="$(manifest_value "$manifest" 'Image SHA256' | tr 'A-F' 'a-f')"
  source="$(manifest_value "$manifest" 'Image source')"

  [[ "$device" == "$TARGET" ]] || { echo "ERROR: manifest target does not match exact-stock lock: $manifest" >&2; exit 1; }
  [[ "$build" == "$BUILD" ]] || { echo "ERROR: manifest build does not match exact-stock lock: $manifest" >&2; exit 1; }
  [[ "$source" == "$SOURCE" ]] || { echo "ERROR: manifest source identity does not match exact-stock lock: $manifest" >&2; exit 1; }
  [[ -n "${LOCK_FILE[$role]:-}" ]] || { echo "ERROR: manifest role is not present in exact-stock lock: $role" >&2; exit 1; }
  [[ -z "${SEEN[$role]:-}" ]] || { echo "ERROR: duplicate manifest role: $role" >&2; exit 1; }
  [[ "$file" == "${LOCK_FILE[$role]}" && "$size" == "${LOCK_SIZE[$role]}" && "$sha" == "${LOCK_SHA[$role]}" ]] || {
    echo "ERROR: manifest content identity does not match exact-stock lock: $role" >&2
    exit 1
  }
  SEEN[$role]=yes
done

for role in boot vendor_boot dtbo vbmeta; do
  [[ "${SEEN[$role]:-}" == "yes" ]] || { echo "ERROR: required exact-stock manifest missing: $role" >&2; exit 1; }
done

echo "classification: EXACT_STOCK_IMAGE_LOCK_PASS"
echo "Target: $TARGET"
echo "Build ID: $BUILD"
echo "Verified image count: $#"
echo "Required image roles: $REQUIRED_ROLES"
echo "content-binding: PASS"
echo "launch-authorization: NO"
echo "decision: supplied co-located image bytes match the exact-build hash lock and provenance source identity; this does not authorize packaging or device launch."
