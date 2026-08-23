# Physical Device Checkpoint — OnePlus 10T CPH2413

Status: exact-device read-only evidence merged successfully.

## Sanitized observed identity
- Target: OnePlus 10T 5G / ovaltine / SM8475
- Product variant: CPH2413
- OxygenOS build: CPH2413_15.0.0.1901(EX01)
- Android-side device identifier: OP5552L1
- Fastboot product observation: taro (platform-compatible only; not sufficient as exact identity by itself)
- Current slot: a
- Bootloader unlocked: yes
- Userspace fastboot: no
- Fastboot mode: classic bootloader fastboot candidate

## Evidence verdict
- Canonical classification: M1_EXACT_DEVICE_EVIDENCE_CONSISTENT
- Device writes during inspection: NONE
- Launch commands executed: NO
- Launch authorization: NO

Exact device identity is established by the Android-side CPH2413 + OP5552L1 + exact build tuple. The fastboot `taro` observation is accepted only when bound to that exact Android-side capture.

## Next gate
Open exact-build stock-image acquisition planning for CPH2413_15.0.0.1901(EX01). Prefer an exact official OnePlus full/local-install package or exact official payload. Do not mix builds or regional variants.

Required first-wave roles:
- boot.img
- vendor_boot.img
- dtbo.img
- vbmeta.img

Conditional:
- init_boot.img, only if present/relevant in this exact firmware.

Do not commit proprietary stock images to this repository. Create provenance manifests and SHA256 records only.
