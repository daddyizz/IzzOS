# Pre-M2 Temporary Launch Packaging Contract

Status: **host-side preparation only / no device route selected**

This document defines what an IzzOS temporary launch package must guarantee before M2 can begin on the exact OnePlus 10T 5G test device.

## Purpose

`OvaltineDiag.efi` is a verified ARM64 UEFI application, but it is not by itself an Android boot image and must not be flashed directly to any phone partition.

The packaging layer is deliberately route-neutral until exact-device inspection proves which temporary launch mechanism exists on the target firmware.

## Required inputs before route-specific packaging

- exact OnePlus 10T product/model and OxygenOS build;
- current A/B slot;
- bootloader lock state;
- classic bootloader fastboot versus fastbootd state;
- exact stock boot/vendor_boot format for that firmware;
- stock boot-critical image backups or reproducible extraction source;
- auditable provenance for every stock image used as a packaging template;
- documented recovery path back to stock boot;
- explicit evidence that the chosen launch route is temporary and does not require a persistent partition write.

## Stock image provenance gate

Any stock image used to derive or validate an M2 package must have a provenance record containing at minimum:

- device model/product;
- exact OxygenOS build;
- image role (`boot`, `vendor_boot`, `dtbo`, `vbmeta`, etc.);
- exact image filename;
- image size in bytes;
- SHA256 of the exact image bytes;
- source from which the image was obtained;
- extraction method/tool context.

Run:

```bash
bash scripts/verify-stock-image-provenance.sh stock-image-provenance.txt
```

Required result before the image may be trusted as an engineering input:

```text
classification: PROVENANCE_COMPLETE
```

`PROVENANCE_COMPLETE` proves that the co-located image bytes match the manifest's basename, size and SHA256 and that the source claim is present. It does **not** validate boot format, recovery readiness, temporary-launch support, or permission to launch. Exact CPH2413 inputs must additionally pass `verify-exact-stock-hash-lock.sh` against the committed exact-build lock.

## Content-bound route evidence gate

A manifest reference or `TEMPORARY_ROUTE_VALIDATED` text value is not sufficient. Route-specific packaging additionally requires a co-located route-evidence record and the four artifacts named by schema `IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1`:

- before-state;
- route transcript;
- diagnostic output; and
- after-state/stock-return confirmation.

Run:

```bash
bash scripts/verify-m2-route-evidence.sh m2-manifest.txt route-evidence.txt
```

Required result:

```text
classification: TEMPORARY_ROUTE_EVIDENCE_CONTENT_BOUND
```

The verifier recalculates every artifact's byte size and SHA256 and rejects missing, renamed, path-shaped or modified inputs. This is a content-integrity gate, not independent proof that a claimed physical observation is authentic.

## Signed route-attestation boundary

Internal M12 can cryptographically verify an independent attester's detached Ed25519 endorsement of the exact M2 manifest and content-bound route-evidence bytes:

```bash
python3 scripts/verify-m2-route-attestation.py \
  m2-manifest.txt route-evidence.txt trusted-key-manifest.txt \
  authority-public-key.pem signed-envelope.txt detached-signature.bin \
  2026-08-25T00:00:00Z route-attestation-report.txt
```

The current success classification, `M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED`, is deliberately non-authorizing. Until the pinned attester key has independently reviewed custody, revocation and rotation governance, the report must continue to state `route-specific-packaging-authorization: NO` and `payload-launch-authorization: NO`.

## Route-attester governance boundary

Internal M13 adds canonical, governance-root-signed policy and revocation-registry records. The verifier binds both records to the exact M12 report, active attester key manifest and public key; checks epochs, sequences, validity windows, custody separation, scheduled rotation and emergency revocation policy; and rejects changed or stale records.

```bash
python3 scripts/verify-m2-route-attester-governance.py \
  route-attestation-report.txt trusted-key-manifest.txt authority-public-key.pem \
  governance-root-manifest.txt governance-root-public-key.pem \
  governance-policy.txt policy-signature.bin \
  revocation-registry.txt registry-signature.bin \
  2026-08-25T00:00:00Z route-governance-report.txt
```

Its success classification, `M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED`, remains non-authorizing because the root is caller pinned and not enrolled by the repository. It does not establish independent custody, authenticate a physical observation or permit route-specific packaging or launch.

## Repository root-enrollment contract boundary

Internal M14 fixes a host-test governance public key and canonical enrollment record at repository-owned paths. `verify-m2-route-governance-root-enrollment.py` rejects any M13 root manifest or public-key bytes that do not match that exact SHA256-pinned enrollment:

```bash
python3 scripts/verify-m2-route-governance-root-enrollment.py \
  route-governance-report.txt governance-root-manifest.txt \
  governance-root-public-key.pem 2026-08-25T00:00:00Z \
  root-enrollment-report.txt
```

The committed anchor is explicitly `HOST_TEST_ONLY_NOT_PRODUCTION`. Its pass classification remains production-root-required and continues to withhold packaging and launch authorization. No private governance key is stored in the repository.

## Governance-root recovery continuity boundary

Internal M15 validates an emergency transition away from the exact M14 host-test root without replacing that anchor silently. The transition must revoke the old root, bind the exact M14 report and repository enrollment, pin three distinct repository test-custodian keys, carry at least two valid custodian signatures, and carry a replacement-root possession signature. The replacement root must also sign a monotonic anti-rollback checkpoint.

The M15 classification remains host-test-only and requires production custody plus physical device evidence. It does not authorize route-specific packaging or launch.

## Packaging invariants

Any future M2 package must:

1. embed or chain-load the already verified `OvaltineDiag.efi` payload;
2. preserve the payload SHA256 in package metadata;
3. identify the exact stock firmware/build it was derived from;
4. reference SHA256-proven stock image inputs rather than unnamed files;
5. never reuse boot-header offsets or addresses copied from an older Snapdragon target;
6. contain no partition flashing command;
7. contain no slot-changing command;
8. contain no bootloader unlock command;
9. fail closed when the detected device/firmware does not match its manifest;
10. provide a dry-run/inspection mode before any launch operation;
11. leave stock boot intact after a reboot.

## Route-neutral package layout

A future generated package should use a structure similar to:

```text
out/m2-launch/<firmware-id>/
  manifest.txt
  payload/
    OvaltineDiag.efi
    SHA256SUMS
  stock-inputs/
    provenance/
      <image>.txt
  derived/
    <route-specific temporary image or chain-load files>
  logs/
    packaging-report.txt
```

`derived/` must remain empty until exact-device inspection selects and validates a route.

## Manifest minimum fields

- IzzOS source revision
- EDK2 revision
- `OvaltineDiag.efi` SHA256
- target model/product
- target OxygenOS build
- expected slot topology
- expected bootloader mode
- selected launch route
- persistent writes: `FORBIDDEN`
- route validation evidence basename plus content-bound artifact records
- stock input SHA256/provenance references

## Route decision states

- `BLOCKED_TARGET_MISMATCH`
- `BLOCKED_BOOTLOADER_LOCKED`
- `BLOCKED_FASTBOOTD_ONLY`
- `INSUFFICIENT_DEVICE_DATA`
- `CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED`
- `CHAINLOAD_CANDIDATE_UNVERIFIED`
- `TEMPORARY_ROUTE_VALIDATED`

Only `TEMPORARY_ROUTE_VALIDATED` may advance to an actual M2 launch package.

## Rollback acceptance gate

Before first launch, IzzOS must be able to answer all of these with evidence:

- How does the phone return to stock boot after a failed diagnostic launch?
- Which stock images/build are required for recovery?
- Are the exact recovery images identified by SHA256 and provenance?
- Does the launch touch slot metadata?
- Does it write boot, vendor_boot, init_boot, dtbo, vbmeta, abl, xbl, or any other persistent partition?
- Is emergency recovery for the exact variant understood well enough to stop if the temporary route behaves unexpectedly?

If any answer is unknown, the launch stays blocked.

## M2 entry condition

M2 begins only after exact-device inspection plus route research produces `TEMPORARY_ROUTE_VALIDATED`. Until then, this document is a packaging contract, not a launch instruction.
