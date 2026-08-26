# Internal M14 Repository Governance-Root Enrollment Contract

Status: **host-side repository-enforcement mechanics complete; production root and physical evidence remain absent**

This document uses the internal M1 engineering sequence. Internal M14 is not product-roadmap `M14 — Installer / Recovery / Update System`; product M1 remains active.

## Purpose

Internal M13 verifies root-signed governance policy and revocation records but accepts a caller-pinned governance root. Internal M14 adds a fixed repository trust boundary: the verifier loads one canonical enrollment record and one exact public-key file from repository-owned paths rather than accepting a caller-selected enrollment source.

The enrolled key is deliberately labeled `HOST_TEST_ONLY_NOT_PRODUCTION`. It exists only to prove deterministic repository enforcement, identity binding, SHA256 pinning and fail-closed policy behavior. Its private key is not present in the repository, and the test anchor cannot authorize packaging or device launch.

## Fixed repository inputs

- `config/m2-route-governance-root-enrollment.txt`
- `config/m2-route-governance-root-test-public.pem`

The canonical enrollment record pins:

- enrollment and governance-root identities;
- the exact repository-relative public-key path and SHA256;
- the host-test-only environment;
- production replacement review requirements;
- offline custody separation;
- dual-control scheduled rotation;
- external two-of-three emergency recovery; and
- no-write, no-slot-change, no-packaging and no-launch policy.

## Verifier boundary

`verify-m2-route-governance-root-enrollment.py` accepts only the upstream M13 report, corresponding root manifest/public key, verification timestamp and output path. The enrollment record and enrolled public key are not command-line parameters: they are resolved from fixed paths relative to the verifier's repository root.

The gate requires the M13 report to bind the exact supplied root manifest and key, then requires those exact key bytes to equal the repository-enrolled key. It rejects a rogue key even when a synthetic upstream report consistently names it.

## Deliberate non-authorization

Success is:

```text
classification: M2_ROUTE_GOVERNANCE_ROOT_REPOSITORY_ENROLLMENT_CONTRACT_PASS_PRODUCTION_ROOT_REQUIRED
```

This classification proves the host-side enrollment contract only. It does not claim that the test root has production custody, validate a physical observation or permit an M2 package or launch.

## Completion boundary

Internal M14 is complete when:

1. enrollment and key paths are fixed by repository code;
2. enrollment and root manifests have strict canonical schemas;
3. the exact root PEM bytes match both manifest and repository SHA256 pins;
4. the upstream M13 report binds the exact manifest and key;
5. rogue keys, identity mismatches, duplicated fields, expired enrollment and unsafe authorization fail closed;
6. no private key is committed and every successful report remains non-authorizing; and
7. the complete host suite and CI pass without device interaction.

Internal M15 adds a host-test emergency root-recovery transition, replacement-root possession proof and monotonic anti-rollback checkpoint without changing the M14 anchor in place. Production root provisioning and exact-device evidence remain outside this test enrollment.
