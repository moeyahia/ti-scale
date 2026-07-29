# Historical operational-hazard reconciliation

This source-only reconciliation converts a private authorized-lab history into reusable, reviewable attack knowledge. It does not import private engagement identity, addresses, filesystem locations, transcripts, credentials, or flags. It does not promote any candidate to confirmed or verified memory.

## Reconciled result

Three exact procedure/version candidates are represented:

1. A three-object V8 12.2.0 internal-layout dump on IIS 10.0 and ASP.NET 4.0.30319. The reviewed script attempted four large allocations and made three `DebugPrint` calls in one request. A harmless expression succeeded before it; the request then timed out, the base page remained reachable, and later expression health failed. One recovery reset is supported by the preserved before/after sequence.
2. A version-pinned Path B v2 kernel-transition procedure against the exact VL-Reaper driver and Windows kernel file version 10.0.20348.4163. One execution attempt blocked after the final chain entry, produced no trusted elevation or return evidence, and left ordinary network services responsive. A later artifact explicitly records an operator reset before the next procedure version.
3. A distinct version-pinned Path B v5 procedure. Its non-executing gates passed, but its one execution attempt blocked after transition began for more than five minutes without watcher, restoration, identity, or return proof. The issuing shell was blocked while ordinary network services stayed responsive. No later reset receipt is present in the audited evidence, so this candidate records zero exact resets.

The first hazard is an application-worker failure. The latter two are kernel-transition/issuing-process failures. None is described as a whole-host outage because the preserved health checks show the base web service or ordinary network services remained responsive.

## Count semantics

- Exact procedure attempts represented: 3, one for each immutable procedure version.
- Exact reset minimum supported by the selected evidence: 2.
- Operator-reported engagement-wide reset minimum: 11 (`more than ten` normalized conservatively to `at least 11`).
- Minimum reset episodes not yet attributable to an exact procedure version: 9.

The operator-reported minimum is an engagement-wide lower bound. It must be displayed with each relevant provenance context as an overall burden and must never be summed across candidate bundles. Exact procedure reset counts are separate and may be summed only when their provenance receipts represent distinct reset episodes.

## Reusable safety behavior

An exact match on product, version, stack, procedure version, prerequisites, and state may warn or block the known-bad procedure before target contact. Restoring health does not authorize the same known-bad version. A later attempt requires a distinct reviewed procedure version or materially safer parameters, a fresh health assessment, and a single-use authorization. Candidate, partial, stale, or mismatched knowledge remains advisory and cannot block.

For the application worker, the reusable safe sequence is: restore a clean worker, prove no request remains in flight, run one harmless scalar health check, and use a single bounded non-printing calibration step. For the kernel-transition procedures, the safe sequence is: preserve evidence, restore a clean boot, prove the old process is absent, recompute boot-dependent values, perform offline exact-image analysis, and validate a distinct procedure version without executing it first.

## Operator confirmation still required

- Attribute the remaining nine-or-more reset episodes to exact procedure hashes, sequence, parameters, and state transition.
- Resolve which call in the historical two-call non-returning script-execution sequence caused the application-worker hang, or retain the compound sequence as the only safe match key.
- Confirm whether other internal-layout printing incidents used the reviewed script hash or materially different versions.
- Separate stale-layout crashes from application-worker hangs that actually required a reset.
- Confirm whether the later kernel-transition hang was followed by a reset after the preserved evidence ends.
- Separate long-lived child-process telemetry stalls from application-worker, issuing-process, and whole-host recovery events.

Until those gaps are reviewed, the unmatched reset burden remains an operator statement with opaque provenance; it is not redistributed across procedures and is not used to fabricate reproducibility.

## Provenance and promotion boundary

The fixture supplies aggregate source hashes to the local compiler. The compiler derives `akpr_<HMAC>` provenance receipts and exposes only those opaque receipt IDs in candidate bodies. Private source references are neither returned nor persisted. Every candidate remains pending until an operator reviews its normalized content and exact diff. The fixture creates no `memory_nodes`, `memory_edges`, or `operational_hazard_profiles` by itself.

These aggregate research hashes are not canonical evidence IDs. They remain unpromotable until the [bounded historical hazard importer](./historical-hazard-import.md) selects the exact underlying files, makes protected copies, creates evidence candidates, and an independent reviewer verifies those candidates. Only those exact resulting evidence IDs may be bound to a reusable bundle.

The compiler also supports evidence-backed script artifacts, discoveries, worked outcomes, failed outcomes, explicit failure mechanisms, unaffected components, surviving health signals, and retry-valid conditions. A cited script, discovery, or outcome hash that is absent from the independently verified evidence set fails closed.
