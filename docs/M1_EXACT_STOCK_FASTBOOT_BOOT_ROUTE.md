# M1 exact-stock fastboot boot route

Status: **exact stock route accepted at runtime; custom container still required**

## Scope

On 2026-08-26, the project owner explicitly accepted the assisted-recovery risk for one non-persistent route probe using only the exact CPH2413 OxygenOS `15.0.0.1901(EX01)` stock `boot.img`.

The scope excluded every flash, erase, format, unlock and slot-changing command. It did not authorize the raw EFI application, a custom Android boot container, or milestone promotion.

## Bound stock input

- image role: `boot`;
- image size: `201326592` bytes;
- SHA256: `08bf7cce2df493945da3b3c9e5d6dd24ed9ecdc635c6349c177b61081b737fc8`;
- provenance classification: `PROVENANCE_COMPLETE`;
- exact-build hash lock: `IZZOS_EXACT_STOCK_HASH_LOCK_V1`.

Before the route probe, classic fastboot reported:

- product `taro`;
- current slot `a`;
- slot count `2`;
- unlocked `yes`;
- secure `yes`;
- userspace fastboot `no`.

## Runtime result

Fastboot 37.0.0 accepted the exact stock image as a temporary boot payload:

- download: `OKAY` in 5.311 seconds;
- boot: `OKAY` in 0.482 seconds;
- total fastboot duration: 5.792 seconds.

Android returned without a separate recovery command. The post-route read-only capture reported the same build, slot `_a`, verified-boot state `orange`, and vbmeta device state `unlocked`.

No flash, erase, format, unlock or slot-changing command was executed. The observation proves that the exact bootloader's stock `fastboot boot` handler is reachable and accepted this exact stock boot-image format. It does not prove that a custom kernel/firmware container will initialize safely.

## Offline evidence verification

The private `out/` evidence can be checked with:

```bash
python3 scripts/verify-m1-stock-fastboot-boot-route.py \
  out/m1-exact-stock-fastboot-boot-route-20260826.txt \
  out/m1-owner-risk-acceptance-20260826.txt \
  out/m1-stock-route-probe-preflight-20260826 \
  out/m1-stock-route-probe-postboot-20260826 \
  /path/to/boot.img.provenance.txt \
  /path/to/boot.img \
  docs/CPH2413_15.0.0.1901_EX01_STOCK_HASHES.txt \
  out/m1-stock-fastboot-boot-route-verification-20260826.txt
```

Required result for this limited observation:

```text
classification: M1_EXACT_STOCK_FASTBOOT_BOOT_ROUTE_EVIDENCE_BOUND
```

The verifier binds the owner-risk record, preflight and postboot checksum manifests, stock provenance, exact stock bytes and repository hash lock. It rejects duplicate fields, tampered bundles, a changed image, unsafe command claims and any assertion that a custom container or diagnostic payload was validated.

## Remaining M1 boundary

This result removes uncertainty about whether classic fastboot on this exact firmware implements and accepts a non-persistent stock boot operation. M1 still requires:

1. a standalone AArch64 firmware/chain-loader with independently verified entry and memory-placement assumptions;
2. an exact Android boot v4 container derived without modifying proprietary stock images;
3. host verification of the custom container and payload identity;
4. separate, narrowly scoped authorization before any custom device launch;
5. diagnostic output plus post-launch stock-return evidence.

Persistent writes and slot changes remain forbidden.
