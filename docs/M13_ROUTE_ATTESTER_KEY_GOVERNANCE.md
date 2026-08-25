# Internal M13 Route-Attester Key Governance

Status: **host-side governance mechanics complete; independent root enrollment and exact-device evidence remain absent**

This document uses the internal M1 engineering sequence. Internal M13 is not product-roadmap `M13 — Phone/Desktop Experience`; product M1 remains the active roadmap milestone.

## Purpose

Internal M12 verifies that a caller-pinned Ed25519 attester key signed the exact temporary-route attestation bytes, but it deliberately leaves key custody, rotation and revocation governance unresolved. Internal M13 adds a second signature layer: a governance root signs both a canonical policy and its canonical revocation snapshot.

No production governance root is enrolled, no production attester key is provisioned and no exact CPH2413 physical route is attested by this milestone.

## Governance inputs

`verify-m2-route-attester-governance.py` requires:

- the exact passing internal-M12 route-attestation report;
- its active route-attester key manifest and Ed25519 public key;
- a canonical governance-root manifest and matching Ed25519 public key;
- a canonical governance policy and detached 64-byte root signature;
- a canonical revocation registry and detached 64-byte root signature;
- an explicit UTC verification timestamp; and
- an output report path that does not overwrite any input.

The policy binds the exact M12 report, active key manifest, active public key and revocation-registry bytes by SHA256. It also records a positive epoch and sequence, a nonzero previous-policy digest, root identity, custody separation, dual-control rotation and immediate emergency-revocation requirements.

The registry binds the same active key and governance epoch/sequence, states whether it is revoked or replaced, and has a bounded freshness interval. The verifier requires coherent ordering across active-key validity, root validity, policy issue/effective time, registry generation/expiry and the caller's verification time.

## Fail-closed behavior

The gate rejects:

- missing, duplicated, reordered or noncanonical fields;
- a key whose exact PEM bytes do not match its pinned SHA256;
- changed policy bytes or a signature made by another root;
- changed registry bytes, a rogue signature or a revoked/replaced active key;
- mismatched epoch, sequence, root, active-key or upstream-report bindings;
- stale or expired governance data;
- weakened custody, rotation or emergency-revocation rules; and
- any record claiming persistent writes, slot changes, packaging permission or launch permission.

The verifier executes no ADB, fastboot, device-write or launch command.

## Deliberate non-authorization

A successful result is:

```text
classification: M2_ROUTE_ATTESTER_GOVERNANCE_SIGNATURE_PASS_ROOT_ENROLLMENT_REQUIRED
```

This proves only that the supplied, SHA256-pinned governance root signed the exact policy and registry bytes that bind the upstream M12 report and active attester key. The root manifest must state `CALLER_SUPPLIED_ROOT_PENDING_REPOSITORY_ENROLLMENT`; the repository does not yet independently establish its identity or custody.

Every input and output therefore retains:

```text
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
```

Internal M13 is intentionally not a passing M2-readiness authorization gate.

## Completion boundary

Internal M13 is complete when:

1. root, policy and registry records have strict canonical schemas with fields appearing exactly once;
2. the policy content-binds the exact M12 report, active key manifest, active public key and registry;
3. both governance records have valid detached Ed25519 signatures from the pinned root;
4. epoch, sequence, custody, rotation, revocation and validity rules fail closed;
5. tampered, rogue, revoked, stale, expired and unsafe fixtures are rejected;
6. success still withholds packaging and launch authorization; and
7. the complete host suite and CI pass without device interaction.

Internal M14 implements the repository-enforcement contract with an explicitly non-production host-test public anchor. Production enrollment with independently controlled custody, plus a monotonic root-transition/recovery publication chain, remains required. Exact stock acceptance and genuine physical route evidence are separate prerequisites.
