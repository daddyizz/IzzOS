#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDITOR="$ROOT/scripts/report-m7-device-promotion-readiness.py"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/host.txt" <<'EOF'
device-commands: NONE
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
launch-authorization: NO
classification: M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED
EOF

cat > "$TMP/device.txt" <<'EOF'
IzzOS M1 exact-device evidence merge
Classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
Target: OnePlus 10T 5G / ovaltine / SM8475
Target match: yes
Build ID: CPH2413_15.0.0.1901(EX01)
Current slot: a
Bootloader unlocked: yes
Userspace fastboot: no
ADB classification: NEED_EXACT_FASTBOOT_INSPECTION
Fastboot classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
Fastboot target observation: platform-compatible
ADB evidence SHA256: 0000000000000000000000000000000000000000000000000000000000000000
Fastboot evidence SHA256: 1111111111111111111111111111111111111111111111111111111111111111
Collector mode: READ_ONLY
Device writes: NONE
Launch commands executed: NO
Launch authorization: NO
EOF

cat > "$TMP/recovery.txt" <<'EOF'
Device model/product: OnePlus 10T 5G / ovaltine
OxygenOS build: CPH2413_15.0.0.1901(EX01)
Current slot: a
Slot count: 2
Bootloader unlocked: YES
Fastboot mode: classic bootloader fastboot
Stock image source: exact official full package
Stock boot image verified: YES
Stock vendor_boot verified: YES
Stock dtbo verified: YES
Stock vbmeta verified: YES
Stock recovery image verified: YES
Emergency recovery status: AUTHORIZED_SERVICE_HARD_RECOVERY_VERIFIED
Temporary route candidate: classic fastboot temporary boot candidate
Persistent write required: NO
Slot change required: NO
Recovery procedure reference: docs/recovery/CPH2413_15.0.0.1901-EX01.md
EOF

"$PYTHON" "$AUDITOR" "$TMP/host.txt" "$TMP/device.txt" "$TMP/recovery.txt" "$TMP/readiness.txt" >/dev/null
grep -Eq '^input: key=host-readiness .* sha256=[0-9a-f]{64}$' "$TMP/readiness.txt"
grep -q '^recovery-build-matches-device: PASS$' "$TMP/readiness.txt"
grep -q '^recovery-slot-matches-device: PASS$' "$TMP/readiness.txt"
grep -q '^launch-authorization: NO$' "$TMP/readiness.txt"
grep -q '^classification: M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED$' "$TMP/readiness.txt"

cp "$TMP/host.txt" "$TMP/host-duplicate.txt"
printf 'classification: M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED\n' >> "$TMP/host-duplicate.txt"
if "$PYTHON" "$AUDITOR" "$TMP/host-duplicate.txt" "$TMP/device.txt" "$TMP/recovery.txt" "$TMP/duplicate.txt" >/dev/null 2>&1; then
  echo "ERROR: duplicate host classification should be blocked" >&2
  exit 1
fi
grep -q '^host-classification-is-exact: FAIL$' "$TMP/duplicate.txt"

sed 's/Userspace fastboot: no/Userspace fastboot: yes/' "$TMP/device.txt" > "$TMP/fastbootd.txt"
if "$PYTHON" "$AUDITOR" "$TMP/host.txt" "$TMP/fastbootd.txt" "$TMP/recovery.txt" "$TMP/fastbootd-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: userspace fastboot evidence should be blocked" >&2
  exit 1
fi
grep -q '^device-fastboot-is-not-userspace: FAIL$' "$TMP/fastbootd-readiness.txt"

sed 's/ADB evidence SHA256: 0000000000000000000000000000000000000000000000000000000000000000/ADB evidence SHA256: invalid/' "$TMP/device.txt" > "$TMP/bad-source-hash.txt"
if "$PYTHON" "$AUDITOR" "$TMP/host.txt" "$TMP/bad-source-hash.txt" "$TMP/recovery.txt" "$TMP/bad-source-hash-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: malformed source evidence hash should be blocked" >&2
  exit 1
fi
grep -q '^device-adb-source-hash-is-valid: FAIL$' "$TMP/bad-source-hash-readiness.txt"

sed 's/OxygenOS build: CPH2413_15.0.0.1901(EX01)/OxygenOS build: CPH2413_15.0.0.9999(EX01)/' "$TMP/recovery.txt" > "$TMP/wrong-build.txt"
if "$PYTHON" "$AUDITOR" "$TMP/host.txt" "$TMP/device.txt" "$TMP/wrong-build.txt" "$TMP/wrong-build-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: mismatched recovery build should be blocked" >&2
  exit 1
fi
grep -q '^recovery-build-matches-device: FAIL$' "$TMP/wrong-build-readiness.txt"

sed 's/Stock recovery image verified: YES/Stock recovery image verified: NO/' "$TMP/recovery.txt" > "$TMP/unverified-recovery.txt"
if "$PYTHON" "$AUDITOR" "$TMP/host.txt" "$TMP/device.txt" "$TMP/unverified-recovery.txt" "$TMP/unverified-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: unverified stock recovery should be blocked" >&2
  exit 1
fi
grep -q '^recovery-stock-recovery-is-verified: FAIL$' "$TMP/unverified-readiness.txt"

sed 's/launch-authorization: NO/launch-authorization: YES/' "$TMP/host.txt" > "$TMP/unsafe-host.txt"
if "$PYTHON" "$AUDITOR" "$TMP/unsafe-host.txt" "$TMP/device.txt" "$TMP/recovery.txt" "$TMP/unsafe-readiness.txt" >/dev/null 2>&1; then
  echo "ERROR: unsafe host launch claim should be blocked" >&2
  exit 1
fi
grep -q '^host-launch-remains-unauthorized: FAIL$' "$TMP/unsafe-readiness.txt"

echo "PASS: M7 device-promotion evidence audit"
