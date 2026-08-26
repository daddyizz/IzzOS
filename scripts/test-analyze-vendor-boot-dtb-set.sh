#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/set"

if ! command -v dtc >/dev/null 2>&1; then
  echo "SKIP: dtc unavailable for synthetic fixture generation"
  exit 0
fi

cat > "$TMP/0.dts" <<'EOF'
/dts-v1/;
/ {
  #address-cells = <2>;
  #size-cells = <2>;
  model = "IzzOS test Cape 0";
  compatible = "qcom,cape";
  memory@80000000 { device_type = "memory"; reg = <0 0x80000000 0 0x10000000>; };
  chosen { linux,usable-memory-range = <0 0x80000000 0 0x10000000>; };
  reserved-memory {
    #address-cells = <2>;
    #size-cells = <2>;
    ranges;
    test@80000000 { reg = <0 0x80000000 0 0x1000>; no-map; };
  };
};
EOF
cat > "$TMP/1.dts" <<'EOF'
/dts-v1/;
/ {
  #address-cells = <2>;
  #size-cells = <2>;
  model = "IzzOS test Cape 1";
  compatible = "qcom,cape";
  memory@80000000 { device_type = "memory"; reg = <0 0x80000000 0 0x20000000>; };
  chosen { };
  reserved-memory {
    #address-cells = <2>;
    #size-cells = <2>;
    ranges;
    test@80000000 { reg = <0 0x80000000 0 0x1000>; no-map; };
  };
};
EOF

dtc -I dts -O dtb "$TMP/0.dts" -o "$TMP/set/dtb-0.dtb"
dtc -I dts -O dtb "$TMP/1.dts" -o "$TMP/set/dtb-1.dtb"

OUT="$TMP/out.txt"
bash "$ROOT/scripts/analyze-vendor-boot-dtb-set.sh" "$TMP/set" "$OUT" >/dev/null

grep -q '^Parser: PURE_BASH_FDT_PROPERTY_WALKER_OD_ONLY$' "$OUT"
grep -q '^DTB count: 2$' "$OUT"
grep -q '^model: IzzOS test Cape 0$' "$OUT"
grep -q '^compatible: qcom,cape$' "$OUT"
grep -q '^root-address-cells: 2$' "$OUT"
grep -q '^root-size-cells: 2$' "$OUT"
grep -q '^memory-reg-raw-hex: 00000000800000000000000010000000$' "$OUT"
grep -q '^reserved-memory-child-count: 1$' "$OUT"
grep -q '^chosen-present: yes$' "$OUT"
grep -q '^chosen-usable-memory-range-raw-hex: 00000000800000000000000010000000$' "$OUT"
grep -q '^  test@80000000 reg=00000000800000000000000000001000$' "$OUT"
grep -q '^classification: VENDOR_BOOT_DTB_SET_PROPERTY_WALKED_NO_DTC$' "$OUT"

if grep -Eq 'command not found|strings:|dtc not found' "$OUT"; then
  echo "ERROR: analyzer leaked an external parser dependency" >&2
  exit 1
fi

echo "PASS: od-only vendor_boot DTB property walker"
