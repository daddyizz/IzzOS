# Internal M9 Exact-Device Evidence Binding

Status: **implementation and attended-device revalidation complete**

This document uses the internal M1 engineering sequence. Internal M9 is not product-roadmap `M9 — Windows Compatibility Validation`; product M1 remains the active roadmap milestone.

## Purpose

Internal M8 made device attendance states deterministic and privacy-safe. Internal M9 closes the next finite boundary: select a current Android SDK Platform-Tools installation deterministically, capture Android and classic-fastboot observations separately, verify both collector checksum manifests and bind the consistent pair without authorizing a launch.

The attended CPH2413 revalidation established:

- Android build `CPH2413_15.0.0.1901(EX01)` on slot `a`;
- classic bootloader fastboot with platform product `taro`;
- two slots, unlocked bootloader, secure state enabled and userspace fastboot disabled;
- `M1_EXACT_DEVICE_EVIDENCE_CONSISTENT` after checksum-bound merge; and
- no flash, erase, format, unlock, slot change or payload launch.

Privacy-safe runtime evidence remains under the local ignored `out/` tree and is not committed.

The exact Android identity is not rewritten to the development codename. On this CPH2413 build, Android reports `device` and `vendor-device` as `OP5552L1`, `product` as `CPH2413`, and classic fastboot reports `taro`. Downstream M2 evidence-bundle verification accepts that complete build-bound tuple as well as the legacy `ovaltine` development identity, while rejecting partial or inconsistent aliases.

## Deterministic Platform-Tools selection

Inspection tooling resolves `adb` and `fastboot` in this order:

1. explicit `ADB_BIN` / `FASTBOOT_BIN` override;
2. `ANDROID_SDK_ROOT/platform-tools`;
3. `ANDROID_HOME/platform-tools`;
4. the standard per-user Windows Android SDK location; and
5. `PATH` fallback.

This prevents a legacy `PATH` entry from shadowing a current SDK installation. Raw inspection and summary files record version numbers but never the selected local filesystem path. ADB protocol older than `1.0.41`, Android Platform-Tools older than 37.x when reported, and fastboot older than 37.x or unversioned are classified as `DEVICE_TOOLCHAIN_REQUIRED`.

## Checksum-bound merge

Before accepting either capture, `merge-m1-device-inspections.sh` now requires a path-constrained checksum manifest containing exactly:

- `ovaltine-inspection.txt`;
- `ovaltine-inspection-analysis.txt`; and
- `INSPECTION_SUMMARY.txt`.

Every entry must appear exactly once and `sha256sum -c` must pass. Missing, extra, duplicate, path-shaped or tampered entries block the merge. The canonical merged record binds both summary hashes and both checksum-manifest hashes.

## Completion boundary

Internal M9 is complete when:

1. SDK tools outrank stale `PATH` tools unless an explicit override is supplied;
2. legacy/unversioned tools produce a deterministic hard stop;
3. valid capture manifests merge and altered captures fail closed;
4. attended Android and classic-fastboot captures merge as exact-device-consistent evidence;
5. all inspection, resolver, merger and host-toolchain tests pass in CI; and
6. the phone returns to authorized Android with no launch or persistent write performed.

This milestone does not prove that the exact bootloader accepts `fastboot boot`, does not create an Android boot wrapper and does not authorize temporary execution. Product M1 proceeds to exact-build stock-image and independently verified temporary-route packaging work.
