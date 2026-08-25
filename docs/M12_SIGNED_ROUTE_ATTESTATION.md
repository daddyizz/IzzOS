# Internal M12 Signed Temporary-Route Attestation

Status: **host-side signature gate complete; attester-key governance and exact-device attestation remain absent**

This document uses the internal M1 engineering sequence. Internal M12 is not product-roadmap `M12 — AAA Gaming Validation`; product M1 remains the active roadmap milestone.

## Purpose

Internal M11 made temporary-route evidence content-bound but explicitly could not prove who endorsed the physical-observation claims. Internal M12 adds a canonical detached-Ed25519 signature gate over the exact M2 manifest and exact M11 route-evidence bytes.

No production attester key is enrolled and no exact CPH2413 route attestation is claimed by this milestone.

## Signed inputs

`verify-m2-route-attestation.py` requires:

- the exact M2 manifest;
- the exact content-bound route-evidence record and its four co-located artifacts;
- a canonical route-attester key manifest;
- the corresponding Ed25519 public key;
- a canonical signed attestation envelope;
- a detached 64-byte Ed25519 signature; and
- an explicit UTC verification timestamp.

The envelope binds the SHA256 of the M2 manifest and route-evidence record, the exact firmware/build, selected route, observation/attestation IDs and timestamps, positive execution/stock-return observations, and negative persistent-write/slot/user-data-mutation observations.

The verifier first reruns the M11 content-bound route gate. It then uses OpenSSL to verify the canonical envelope against the exact public key whose SHA256 is pinned by the supplied key manifest.

## Deliberate non-authorization

A successful result is:

```text
classification: M2_ROUTE_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED
```

This proves only that the supplied pinned key endorsed the exact signed bytes. The key manifest deliberately records `CALLER_SUPPLIED_PIN_PENDING_GOVERNANCE`. The verifier cannot independently measure the phone or establish key custody, revocation and rotation policy.

Both the key manifest and signed envelope must state:

```text
route-specific-packaging-authorization: NO
payload-launch-authorization: NO
```

Therefore M12 is not added as a passing M2-readiness authorization gate. A later internal milestone must establish the trust-anchor governance required before a signed route endorsement can contribute to route-specific packaging readiness.

## Completion boundary

Internal M12 is complete when:

1. the key manifest and envelope have strict canonical schemas with fields appearing once;
2. the envelope binds the exact M2 manifest and M11 route evidence by SHA256;
3. the exact Ed25519 public key is pinned by SHA256;
4. key validity, revocation state and observation/attestation ordering are checked;
5. changed envelopes, rogue signatures, revoked/expired keys, unsafe authorization claims and mutated route artifacts fail closed;
6. success still withholds packaging and launch authorization; and
7. the complete host suite and CI pass without device interaction.

Product M1 remains blocked on exact local stock acceptance, genuine physical route evidence, an independently controlled attester key and reviewed key-governance policy.

