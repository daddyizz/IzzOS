#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-m7-sm8475-coherency-provenance.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/assertion.txt" <<'EOF'
implementation-defined-coherency-mechanism: NOT_INDEPENDENTLY_VALIDATED
coherency-proof: NOT_YET_PROVEN
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
sec-wrapper-implementation-authorization: NO
mmio-initialization-authorization: NO
launch-authorization: NO
classification: M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS
EOF
ASSERTION_SHA="$(sha256sum "$TMP/assertion.txt" | awk '{print $1}')"

cat > "$TMP/raw.txt" <<EOF
coherency-provenance-schema: IZZOS_M7_SM8475_COHERENCY_PROVENANCE_V1
coherency-assertion-report-sha256: $ASSERTION_SHA
target-platform: ONEPLUS_10T_CPH2413_SM8475_CAPE
official-source-repository: https://github.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475
official-source-branch: oneplus/sm8475_s_12.1_oneplus_10t_5g
official-source-commit: a24e032ef338174bfa835bed0f8e2ad3620f4ffc
cape-dtsi-path: kernel_platform/qcom/proprietary/devicetree/qcom/cape.dtsi
cape-dtsi-blob-sha1: 9534c9c207dd293f7771ff072dbe9f350b448996
psci-binding-path: kernel_platform/qcom/proprietary/devicetree/bindings/arm/psci.txt
psci-binding-blob-sha1: a2c4f1d524929bb788360542690061ade0c4f543
source-fetch-policy: IMMUTABLE_COMMIT_AND_BLOB_IDENTITY_ONLY
cape-enabled-cpu-count: 8
cape-cpu-enable-method: PSCI
cape-psci-compatible: arm,psci-1.0
cape-psci-conduit: SMC
secondary-cpu-control-owner: EL3_PSCI_PLATFORM_FIRMWARE
public-source-coherency-register: NOT_PUBLISHED
public-source-coherency-mask: NOT_PUBLISHED
public-source-coherency-sequence: NOT_PUBLISHED
cpuectlr-smpen-assumption: FORBIDDEN_WITHOUT_EXACT_SM8475_SOURCE
mmio-address-assumption: FORBIDDEN
source-boundary: PSCI_OWNERSHIP_PROVEN_INTERNAL_COHERENCY_MECHANISM_NOT_PUBLISHED
observation-authenticity: SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED
capture-route-authorization: NOT_PROVEN
device-writes: NONE
persistent-writes: NONE
slot-changes: NONE
launch-authorization: NO
EOF

run_verify() {
  local raw="$1" out="$2" assertion="${3:-$TMP/assertion.txt}"
  "$PYTHON" "$VERIFY" "$assertion" "$raw" "$out"
}

run_verify "$TMP/raw.txt" "$TMP/pass.txt" >/dev/null
grep -q '^manifest-binds-exact-assertion-report: PASS$' "$TMP/pass.txt"
grep -q '^manifest-official-source-commit-is-exact: PASS$' "$TMP/pass.txt"
grep -q '^manifest-cape-dtsi-blob-sha1-is-exact: PASS$' "$TMP/pass.txt"
grep -q '^manifest-psci-binding-blob-sha1-is-exact: PASS$' "$TMP/pass.txt"
grep -q '^public-source-boundary: PSCI_SMC_FIRMWARE_OWNERSHIP_PROVEN_EXACT_COHERENCY_IMPLEMENTATION_UNAVAILABLE$' "$TMP/pass.txt"
grep -q '^coherency-register-authorization: NO$' "$TMP/pass.txt"
grep -q '^cpuectlr-smpen-authorization: NO$' "$TMP/pass.txt"
grep -q '^launch-authorization: NO$' "$TMP/pass.txt"
grep -q '^classification: M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS$' "$TMP/pass.txt"

cp "$TMP/assertion.txt" "$TMP/tampered-assertion.txt"
printf X >> "$TMP/tampered-assertion.txt"
if run_verify "$TMP/raw.txt" "$TMP/tampered-assertion-out.txt" "$TMP/tampered-assertion.txt" >/dev/null 2>&1; then
  echo "ERROR: provenance verifier accepted a tampered assertion report" >&2
  exit 1
fi
grep -q '^manifest-binds-exact-assertion-report: FAIL$' "$TMP/tampered-assertion-out.txt"

assert_blocked() {
  local name="$1" expression="$2" check="$3"
  sed "$expression" "$TMP/raw.txt" > "$TMP/$name.txt"
  if run_verify "$TMP/$name.txt" "$TMP/$name-out.txt" >/dev/null 2>&1; then
    echo "ERROR: provenance verifier accepted $name" >&2
    exit 1
  fi
  grep -q "^$check: FAIL$" "$TMP/$name-out.txt"
  grep -q '^classification: M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_BLOCKED$' "$TMP/$name-out.txt"
}

assert_blocked wrong-commit \
  's/a24e032ef338174bfa835bed0f8e2ad3620f4ffc/7278ce9a3c8539b4630d6988cc80f90c31c07336/' \
  manifest-official-source-commit-is-exact
assert_blocked wrong-cape-blob \
  's/9534c9c207dd293f7771ff072dbe9f350b448996/1534c9c207dd293f7771ff072dbe9f350b448996/' \
  manifest-cape-dtsi-blob-sha1-is-exact
assert_blocked guessed-smpen \
  's/public-source-coherency-register: NOT_PUBLISHED/public-source-coherency-register: CPUECTLR_EL1.SMPEN/' \
  manifest-public-source-coherency-register-is-exact
assert_blocked guessed-mmio \
  's/mmio-address-assumption: FORBIDDEN/mmio-address-assumption: 0x17A00000/' \
  manifest-mmio-address-assumption-is-exact
assert_blocked wrong-cpu-count \
  's/cape-enabled-cpu-count: 8/cape-enabled-cpu-count: 4/' \
  manifest-cape-enabled-cpu-count-is-exact
assert_blocked relaxed-launch \
  's/launch-authorization: NO/launch-authorization: YES/' \
  manifest-launch-authorization-is-exact

echo "PASS: M7 SM8475 coherency provenance boundary gate"
