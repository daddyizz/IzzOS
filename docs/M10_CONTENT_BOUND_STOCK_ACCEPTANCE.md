# Internal M10 Content-Bound Stock Acceptance

Status: **host-side implementation complete; proprietary image bytes remain local**

This document uses the internal M1 engineering sequence. Internal M10 is not product-roadmap `M10 — Performance & Thermal Tuning`; product M1 remains the active roadmap milestone.

## Purpose

Internal M9 bound exact Android and classic-fastboot evidence. Internal M10 closes the next fail-closed boundary: a provenance text file can no longer be treated as complete unless the co-located stock image bytes still match its recorded filename, byte size and SHA256, and the complete first-wave set must also match the committed exact-build hash lock.

No OnePlus image bytes are committed by this milestone.

## Content-bound provenance

`verify-stock-image-provenance.sh` now requires:

- every required field exactly once;
- `Image file` to be a basename with no path component;
- the named image to exist beside its manifest; and
- actual byte size and SHA256 to equal the recorded values.

Missing images produce `PROVENANCE_IMAGE_MISSING_BLOCKED`; altered bytes produce `PROVENANCE_CONTENT_MISMATCH_BLOCKED`. Only an unchanged, co-located image produces `PROVENANCE_COMPLETE` and `content-binding: PASS`.

## Exact-build hash lock

`CPH2413_15.0.0.1901_EX01_STOCK_HASHES.txt` now contains schema `IZZOS_EXACT_STOCK_HASH_LOCK_V1`, canonical source-package/payload identities, the required role set and machine-readable records for:

- `boot.img`;
- `vendor_boot.img`;
- `dtbo.img`;
- `vbmeta.img`; and
- optional recovery evidence `recovery.img`.

The verifier rejects duplicate/malformed records, source/build/target drift, missing required roles, duplicate manifest roles, path-shaped filenames, size/hash mismatches and post-manifest byte mutation.

Schema-only verification returns `EXACT_STOCK_HASH_LOCK_VALID`. Supplying all four required local manifests and images can return `EXACT_STOCK_IMAGE_LOCK_PASS`; this second result is not claimed until the proprietary files are locally present and pass.

## M2 readiness integration

`report-m2-readiness.sh` now requires an exact-stock hash lock and exposes a separate `exact stock content lock` gate. A mutually consistent but unbound manifest set can no longer produce `READY_FOR_ROUTE_SPECIFIC_PACKAGING`.

## Completion boundary

Internal M10 is complete when:

1. provenance verification is bound to actual co-located bytes;
2. the committed CPH2413 lock schema is machine-verifiable;
3. exact-build acceptance requires all first-wave roles and the canonical source identity;
4. M2 readiness invokes the exact content lock;
5. mutation, missing-role, duplicate-field, path and source-drift tests fail closed; and
6. the complete host suite and CI pass without committing proprietary files.

This milestone does not download firmware, accept unseen local images, validate a temporary launch container or authorize execution. Product M1 remains blocked until the exact local stock files pass `EXACT_STOCK_IMAGE_LOCK_PASS` and later route/packaging gates are independently satisfied.
