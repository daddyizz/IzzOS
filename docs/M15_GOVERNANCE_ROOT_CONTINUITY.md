# Internal M15 Governance-Root Recovery Continuity

Status: **host-side recovery, possession and anti-rollback mechanics complete; production custody and physical evidence remain absent**

This document uses the internal M1 engineering sequence. Internal M15 is not product-roadmap `M15 — Release Candidate`; product M1 remains active.

## Purpose

Internal M14 fixes an explicitly non-production governance public key at a repository-owned path. Internal M15 proves that the host-side trust chain cannot replace that key silently: an emergency transition must preserve the exact M14 source binding, revoke the old root, obtain an external recovery quorum, prove possession of the replacement root and publish a monotonic checkpoint.

All roots and custodians in this milestone are host-test-only public keys. No private key is committed, and no record authorizes device interaction.

## Fixed repository test keys

M15 keeps the exact M14 public anchor and adds fixed public keys for:

- one replacement governance root; and
- three distinct recovery custodians.

The verifier resolves all five public keys from repository-owned `config/` paths. A caller cannot substitute the recovery quorum or replacement root through command-line paths.

## Emergency recovery transition

Canonical schema `IZZOS_M2_ROUTE_GOVERNANCE_ROOT_TRANSITION_V1` binds:

- the exact passing M14 report and repository enrollment record;
- the previous root manifest/key and `REVOKED_EFFECTIVE_AT_TRANSITION` state;
- the replacement root manifest/key;
- all three repository recovery-custodian key hashes;
- a strictly advancing governance epoch and reset sequence;
- `EMERGENCY_RECOVERY_2_OF_3` policy; and
- no-write, no-slot-change, no-packaging and no-launch policy.

At least two of the three custodians must sign the exact transition bytes. The replacement root must independently sign those same bytes to prove possession.

## Anti-rollback checkpoint

Canonical schema `IZZOS_M2_ROUTE_GOVERNANCE_ROOT_ANTI_ROLLBACK_CHECKPOINT_V1` binds the exact transition, a nonzero previous-checkpoint digest, replacement root manifest/key and the same next epoch/sequence. The replacement root signs the checkpoint.

The gate rejects a lower epoch/sequence, changed transition, insufficient quorum, a non-revoked old root, rogue replacement proof, changed checkpoint, expiry or any unsafe authorization claim.

## Deliberate non-authorization

Success is:

```text
classification: M2_ROUTE_GOVERNANCE_ROOT_CONTINUITY_HOST_TEST_PASS_DEVICE_EVIDENCE_REQUIRED
```

This classification validates only test-key continuity mechanics. Production governance roots and custodians still require independent operational provisioning. Exact stock acceptance, temporary execution, runtime capture and unchanged stock return require attended phone evidence.

## Completion boundary

Internal M15 is complete when:

1. the M14 repository anchor remains unchanged rather than being replaced in place;
2. previous and replacement roots are content-bound by exact manifest/key SHA256;
3. three distinct fixed recovery custodians are pinned;
4. at least two custodians sign the exact transition;
5. the replacement root proves possession and signs the monotonic checkpoint;
6. tamper, insufficient quorum, revocation discontinuity, rollback, expiry and launch claims fail closed;
7. no private key is committed and all success remains non-authorizing; and
8. the complete host suite and CI pass without device interaction.

Internal M16 additionally binds this signed checkpoint to exact predecessor material and a repository-published head so an alternate same-epoch history fails closed. The next product-M1 boundary remains physical: collect genuine exact-device stock and temporary-route execution evidence, then prove controlled return to unchanged stock state. No phone command is authorized by M15 itself.
