# Internal M16 Governance Checkpoint History

Status: **host-side predecessor binding and fork detection complete; production publication and physical evidence remain absent**

This document uses the internal M1 engineering sequence. Internal M16 is not product-roadmap `M16 — IzzOS 1.0 Final`; product M1 remains active.

## Purpose

Internal M15 proves one emergency root transition and signs a monotonic checkpoint, but its predecessor is represented only by a nonzero digest. Internal M16 fixes the exact predecessor material and the exact signed M15 head in a repository-owned history anchor so a caller cannot silently substitute a different head at the same governance epoch and sequence.

## Repository history anchor

`config/m2-route-governance-checkpoint-history-test-anchor.txt` canonically binds:

- the exact predecessor anchor material and its SHA256;
- the exact M15 head-checkpoint SHA256;
- the fixed replacement-root public-key SHA256;
- governance epoch `2`, sequence `1`, and entry count `2`;
- an explicit alternate-head rejection policy; and
- no-write, no-slot-change, no-packaging and no-launch policy.

The anchor is explicitly host-test-only. Repository inclusion is not a substitute for an independently witnessed production transparency log.

## Verification boundary

`verify-m2-route-governance-checkpoint-history.py` requires a passing non-authorizing M15 report, the exact canonical checkpoint and its detached Ed25519 signature. It recomputes all hashes, verifies the signature with the repository-fixed replacement root, checks the predecessor link and time window, and rejects an alternate or lower head.

Success is:

```text
classification: M2_ROUTE_GOVERNANCE_CHECKPOINT_HISTORY_HOST_TEST_PASS_PRODUCTION_PUBLICATION_REQUIRED
```

This validates host-side history mechanics only. It does not establish production custody, authenticate physical observations, authorize packaging or permit a phone command.

## Completion boundary

Internal M16 is complete when:

1. predecessor material is present and hashes to the M15 predecessor digest;
2. the exact signed M15 head is pinned by a repository-owned canonical record;
3. the head key, epoch, sequence and entry count match the published anchor;
4. alternate-head, rollback, signature, expiry and unsafe-authorization tests fail closed;
5. no private key is committed;
6. the complete host suite and CI pass without device interaction.

The next product-M1 boundary remains physical and content-bound: repair the local stock provenance target labels, revalidate the exact stock set, independently validate a genuinely temporary execution route, capture runtime diagnostics and prove unchanged stock return.
