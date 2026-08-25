#!/usr/bin/env bash

# Shared Android SDK Platform-Tools resolver.
#
# Resolution order is explicit override, configured Android SDK roots, the
# standard per-user Windows SDK location, then PATH. This prevents an old PATH
# entry from silently shadowing a current SDK installation while still making
# every selection controllable and testable.

_izzos_posix_path() {
  local path="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$path" 2>/dev/null || printf '%s\n' "$path"
  else
    printf '%s\n' "$path"
  fi
}

_izzos_tool_from_root() {
  local root="$1" tool="$2" candidate
  [[ -n "$root" ]] || return 1
  root="$(_izzos_posix_path "$root")"
  for candidate in "$root/platform-tools/$tool" "$root/platform-tools/$tool.exe"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

izzos_resolve_android_tool() {
  local tool="$1" override="${2:-}" candidate local_sdk

  if [[ -n "$override" ]]; then
    if [[ -x "$override" ]]; then
      printf '%s\n' "$override"
      return 0
    fi
    candidate="$(command -v "$override" 2>/dev/null || true)"
    [[ -n "$candidate" ]] || return 1
    printf '%s\n' "$candidate"
    return 0
  fi

  candidate="$(_izzos_tool_from_root "${ANDROID_SDK_ROOT:-}" "$tool" 2>/dev/null || true)"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  candidate="$(_izzos_tool_from_root "${ANDROID_HOME:-}" "$tool" 2>/dev/null || true)"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  if [[ -n "${LOCALAPPDATA:-}" ]]; then
    local_sdk="$(_izzos_posix_path "$LOCALAPPDATA")/Android/Sdk"
    candidate="$(_izzos_tool_from_root "$local_sdk" "$tool" 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  command -v "$tool" 2>/dev/null
}
