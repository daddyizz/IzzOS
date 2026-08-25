# Internal M11 Content-Bound Temporary-Route Evidence

Status: **host-side implementation complete; exact-device route remains unvalidated**

This document uses the internal M1 engineering sequence. Internal M11 is not product-roadmap `M11 — IzzOS Lightweight Windows Profile`; product M1 remains the active roadmap milestone.

## Purpose

Internal M10 bound exact stock-image claims to the actual local bytes. Internal M11 closes the next fail-open boundary: an M2 manifest can no longer pass route-specific packaging merely by naming a route-evidence file that is absent, stale or unrelated.

No device command is executed and no exact-device temporary-route success is claimed by this milestone.

## Route-evidence schema

`verify-m2-route-evidence.sh` requires schema `IZZOS_TEMPORARY_ROUTE_EVIDENCE_V1` and binds the route record to:

- the exact manifest firmware ID;
- the exact selected launch route;
- `TEMPORARY_ROUTE_VALIDATED` in both records;
- observed diagnostic execution and a controlled result;
- confirmed return to stock boot;
- no persistent write, slot change or user-data mutation; and
- four co-located artifacts: `before-state`, `route-transcript`, `diagnostic-output` and `after-state`.

Each artifact record contains a basename, byte size and SHA256. Missing files, path-shaped names, duplicate/missing roles or altered bytes fail closed as `TEMPORARY_ROUTE_EVIDENCE_BLOCKED`. A complete unchanged synthetic or physical bundle reports `TEMPORARY_ROUTE_EVIDENCE_CONTENT_BOUND`.

Content binding proves internal consistency and mutation resistance. It does not independently prove that a physical observation is authentic.

## Readiness and package integration

`report-m2-readiness.sh` now exposes a separate `content-bound route evidence` gate. `verify-m2-route-authorization.sh` requires that gate and also checks that the recovery record names the same route candidate.

`prepare-m1-device-test-package.sh` copies the route record and all four verified artifacts into `evidence/route/`. The package remains evidence-only: it contains no generated launch command and executes no device command.

## Completion boundary

Internal M11 is complete when:

1. a route-evidence reference must be an existing exact basename;
2. route/build/safety observations are machine-validated;
3. all four required artifacts are content-bound;
4. readiness and package assembly require the content-bound evidence;
5. mutation, missing-role, path, target and firmware-drift cases fail closed; and
6. the full host suite and CI pass without interacting with a phone.

The current CPH2413 route remains unvalidated. Product M1 cannot claim `TEMPORARY_ROUTE_VALIDATED` until genuine exact-device observations and their co-located artifacts pass this gate, in addition to the exact-stock and recovery gates.

