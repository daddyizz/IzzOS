# Stock Image Acquisition Policy — OnePlus 10T 5G

Status: **pre-M2 safety policy**

This document defines how IzzOS should obtain and accept stock boot-critical images for the exact OnePlus 10T test firmware.

## Priority order

1. Exact official OnePlus full/local-install package for the same device variant and OxygenOS build as the test phone.
2. Exact official OnePlus package containing a complete payload from which the required images can be reproducibly extracted.
3. Read-only extraction from the exact physical phone only when an official package with matching build cannot provide the required image set and a safe extraction method is available.
4. Third-party mirrors are evidence leads only until cryptographic identity and provenance are established against an official source or the exact device.

## Incremental OTA warning

An OTA announcement or update ZIP must not automatically be treated as a full stock recovery source. Incremental packages may contain only deltas or may depend on a specific source build.

Before accepting an OTA-derived image set, verify that the package actually contains or can reproducibly reconstruct the exact required images for the target build.

## Required image candidates

The final required set depends on the exact firmware and validated launch route. Likely boot-chain candidates include:

- `boot.img`
- `vendor_boot.img`
- `dtbo.img`
- `vbmeta.img`
- `init_boot.img` only if present/relevant on the exact stock firmware

Do not request or extract extra partitions merely because another Qualcomm device used them.

## Provenance requirement

Every accepted image must have an IzzOS provenance manifest generated with:

```bash
bash scripts/create-stock-image-provenance.sh \
  <image-file> \
  '<device-model-product>' \
  '<exact-oxygenos-build>' \
  '<image-role>' \
  '<image-source>' \
  '<extraction-method>'
```

The generated manifest records the exact filename, byte size and SHA256 and is checked by `verify-stock-image-provenance.sh`.

For multiple images, all manifests must also pass:

```bash
bash scripts/verify-stock-image-set.sh <manifest-1> <manifest-2> [...]
```

This blocks mixed-build, mixed-device and duplicate-role sets.

## Acceptance rules

A stock image is not accepted for route-specific packaging unless:

- exact device/product is known;
- exact OxygenOS build is known;
- source and extraction method are auditable;
- SHA256 and byte size are recorded;
- boot metadata is compatible with the exact stock format;
- all images in the set agree on device/build provenance;
- recovery gate requirements are satisfied.

Passing provenance does not authorize flashing or temporary boot. It only establishes that the source material can be audited.

## Repository hygiene

Do not commit proprietary OnePlus firmware images into the public IzzOS repository. Store only non-sensitive metadata, hashes, tooling and documentation unless licensing explicitly permits redistribution.

Before committing manifests or logs, redact personal identifiers. Device model/product, firmware build and cryptographic hashes are engineering metadata and should remain when needed for reproducibility.

## Current OnePlus distribution note

OnePlus publishes software-update guidance and device rollout announcements, but rollout packages may be incremental. IzzOS therefore validates package completeness instead of assuming that every official OTA is a full recovery package.
