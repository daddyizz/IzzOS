#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PRE="$TMP_DIR/pre"
POST="$TMP_DIR/post"
mkdir -p "$PRE" "$POST"

printf 'stock boot fixture\n' > "$TMP_DIR/boot.img"
IMAGE_SHA="$(sha256sum "$TMP_DIR/boot.img" | awk '{print $1}')"
IMAGE_SIZE="$(wc -c < "$TMP_DIR/boot.img" | tr -d ' ')"

cat > "$TMP_DIR/risk.txt" <<EOF
IZZOS_M1_OWNER_RISK_ACCEPTANCE_V1
scope: ONE_NON_PERSISTENT_EXACT_STOCK_BOOT_ROUTE_PROBE
exact-stock-boot-sha256: $IMAGE_SHA
persistent-writes: FORBIDDEN
slot-changes: FORBIDDEN
diagnostic-payload-launch: NOT_AUTHORIZED_BY_THIS_RECORD
classification: OWNER_ACCEPTED_ASSISTED_RECOVERY_RISK_FOR_ONE_STOCK_ROUTE_PROBE
EOF

cat > "$TMP_DIR/provenance.txt" <<EOF
Device model/product: OnePlus 10T 5G / ovaltine / SM8475
OxygenOS build: CPH2413_15.0.0.1901(EX01)
Image role: boot
Image file: boot.img
Image size bytes: $IMAGE_SIZE
Image SHA256: $IMAGE_SHA
EOF

cat > "$TMP_DIR/hash-lock.txt" <<EOF
Schema: IZZOS_EXACT_STOCK_HASH_LOCK_V1
Build ID: CPH2413_15.0.0.1901(EX01)
Image record: boot|boot.img|$IMAGE_SIZE|$IMAGE_SHA|required
EOF

cat > "$PRE/ovaltine-inspection.txt" <<'EOF'
[FASTBOOT] connected devices: 1
product: taro
current-slot: a
slot-count: 2
unlocked: yes
secure: yes
is-userspace: no
EOF
cat > "$PRE/ovaltine-inspection-analysis.txt" <<'EOF'
classification: CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED
EOF
printf 'preflight summary\n' > "$PRE/INSPECTION_SUMMARY.txt"
(cd "$PRE" && sha256sum ovaltine-inspection.txt ovaltine-inspection-analysis.txt INSPECTION_SUMMARY.txt > SHA256SUMS)

cat > "$POST/ovaltine-inspection.txt" <<'EOF'
[ADB] authorized devices: 1
model: CPH2413
product: CPH2413
build-id: CPH2413_15.0.0.1901(EX01)
slot-suffix: _a
verified-boot-state: orange
vbmeta-device-state: unlocked
EOF
cat > "$POST/ovaltine-inspection-analysis.txt" <<'EOF'
classification: NEED_EXACT_FASTBOOT_INSPECTION
EOF
printf 'postboot summary\n' > "$POST/INSPECTION_SUMMARY.txt"
(cd "$POST" && sha256sum ovaltine-inspection.txt ovaltine-inspection-analysis.txt INSPECTION_SUMMARY.txt > SHA256SUMS)

RISK_SHA="$(sha256sum "$TMP_DIR/risk.txt" | awk '{print $1}')"
PRE_SHA="$(sha256sum "$PRE/SHA256SUMS" | awk '{print $1}')"
POST_SHA="$(sha256sum "$POST/SHA256SUMS" | awk '{print $1}')"
PROVENANCE_SHA="$(sha256sum "$TMP_DIR/provenance.txt" | awk '{print $1}')"

write_report() {
  cat > "$TMP_DIR/report.txt" <<EOF
IZZOS_M1_EXACT_STOCK_FASTBOOT_BOOT_ROUTE_V1
recorded-date: 2026-08-26
target-model: CPH2413
target-product-android: CPH2413
target-product-fastboot: taro
target-build: CPH2413_15.0.0.1901(EX01)
pre-route-slot: a
post-route-slot-suffix: _a
bootloader-unlocked: yes
bootloader-secure: yes
fastboot-userspace: no
host-fastboot-version: 37.0.0
owner-risk-record-sha256: $RISK_SHA
preflight-checksum-manifest-sha256: $PRE_SHA
postboot-checksum-manifest-sha256: $POST_SHA
stock-provenance-record-sha256: $PROVENANCE_SHA
exact-stock-boot-image-sha256: $IMAGE_SHA
exact-stock-boot-image-size-bytes: $IMAGE_SIZE
command-scope: ONE_NON_PERSISTENT_FASTBOOT_BOOT_EXACT_STOCK_IMAGE
download-result: OKAY
boot-result: OKAY
android-returned: yes
post-route-build-match: yes
post-route-slot-match: yes
persistent-write-command-executed: no
slot-change-command-executed: no
flash-erase-format-unlock-command-executed: no
stock-fastboot-boot-handler-runtime-confirmed: yes
custom-container-validated: no
diagnostic-payload-executed: no
milestone-launch-authorized: no
classification: EXACT_STOCK_FASTBOOT_BOOT_ROUTE_ACCEPTED_CUSTOM_CONTAINER_REQUIRED
EOF
}

verify() {
  "$PYTHON_BIN" "$ROOT_DIR/scripts/verify-m1-stock-fastboot-boot-route.py" \
    "$TMP_DIR/report.txt" \
    "$TMP_DIR/risk.txt" \
    "$PRE" \
    "$POST" \
    "$TMP_DIR/provenance.txt" \
    "$TMP_DIR/boot.img" \
    "$TMP_DIR/hash-lock.txt" \
    "$TMP_DIR/result.txt"
}

write_report
verify >/dev/null
grep -q '^classification: M1_EXACT_STOCK_FASTBOOT_BOOT_ROUTE_EVIDENCE_BOUND$' "$TMP_DIR/result.txt"

sed -i 's/custom-container-validated: no/custom-container-validated: yes/' "$TMP_DIR/report.txt"
if verify >/dev/null 2>&1; then
  echo "ERROR: verifier accepted a custom-container overclaim" >&2
  exit 1
fi
grep -q '^failed-check: custom-container-remains-unvalidated$' "$TMP_DIR/result.txt"

write_report
cp "$POST/ovaltine-inspection.txt" "$TMP_DIR/post-raw.clean"
printf 'tamper\n' >> "$POST/ovaltine-inspection.txt"
if verify >/dev/null 2>&1; then
  echo "ERROR: verifier accepted a tampered postboot bundle" >&2
  exit 1
fi
grep -q '^failed-check: postboot-bundle-checksums-valid$' "$TMP_DIR/result.txt"
mv "$TMP_DIR/post-raw.clean" "$POST/ovaltine-inspection.txt"

write_report
printf 'classification: EXACT_STOCK_FASTBOOT_BOOT_ROUTE_ACCEPTED_CUSTOM_CONTAINER_REQUIRED\n' >> "$TMP_DIR/report.txt"
if verify >/dev/null 2>&1; then
  echo "ERROR: verifier accepted a duplicate classification" >&2
  exit 1
fi
grep -q '^failed-check: report-field-classification-unique$' "$TMP_DIR/result.txt"

echo "M1 exact-stock fastboot boot route verifier tests passed"
