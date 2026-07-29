# Second Brain

The Second Brain is a user-controlled runtime knowledge system. Its reusable Vault is centered on technology stacks, attack applicability, outcomes, operational hazards, and recovery—not target identity or mission history. The complete ontology and projection rules are defined in [Attack Knowledge Vault](./attack-knowledge-vault.md).

## Private record and reusable knowledge

Ti-Scale deliberately separates two data classes:

- The private transactional record retains authorization, scope, target identity, immutable evidence, and audit provenance where required.
- The reusable Attack Knowledge Vault stores sanitized patterns that can improve work against another authorized target with a matching stack.

Box names, IP addresses, domains, client names, mission journeys, credentials, raw logs, and raw evidence are not reusable memory. They may remain protected in the transactional record and be referenced only through an opaque provenance receipt.

Reusable node detail preserves an access-controlled custody projection. An authorized operator can see the originating engagement label, canonical mission/run, evidence receipt, immutable source hash, and opaque private-source reference without copying those identifiers into the reusable node body or graph edges. Operators outside that mission scope receive the reusable record without the private origin fields.

## Operator Preferences

**Second Brain → Operator Preferences** is a separate memory category for explicitly confirmed collaboration and presentation choices. Each row shows the canonical preference node, global/engagement/mission scope, exact confirmation time, profile version, consent policy, applicability categories, and source provenance. Corrections and forgetting continue through the canonical memory record.

Preferences are not Attack Knowledge. They are excluded from the Attack Knowledge Vault projection and cannot weaken authorization, disclosure, evidence, or safety policy. The Operator graph may show preference nodes; the reusable attack graph and its Obsidian Vault remain attack-centric.

## Canonical model

Reusable nodes represent products and versions, OS/kernel constraints, frameworks/runtimes/databases, services and protocols, security controls, topology patterns, vulnerabilities, vectors, techniques, procedures, prerequisites, scripts, tools, discovery and validation patterns, outcomes, operational hazards, target states, recoveries, alternatives, detections, remediations, strategies, lessons, experiments, and benchmarks.

Private mission, run, target, evidence, and audit objects can participate in provenance without being projected as reusable notes.

Edges describe typed relationships such as:

- `has_exact_version`
- `has_version_range`
- `version_in_range`
- `runs_on`
- `built_with`
- `uses_runtime`
- `uses_database`
- `protected_by`
- `has_topology_role`
- `matches_fingerprint`
- `fingerprinted_by`
- `affects`
- `classified_as`
- `applicable_to`
- `not_applicable_to`
- `exploits`
- `requires`
- `has_attribute`
- `implemented_by`
- `tested_against`
- `produces_outcome`
- `failed_because`
- `caused`
- `leaves_in_state`
- `avoid_after`
- `safe_when`
- `requires_recovery`
- `recovered_with`
- `alternative_to`
- `mitigated_by`
- `detected_by`
- `remediated_by`
- `supports`
- `contradicts`
- `derived_from`
- `supersedes`

Every node and edge carries a stable ID, type, title, summary, scope, sensitivity, confidence, lifecycle, provenance, author, version, and timestamps. Edges also explain why the relationship exists.

## Lifecycle

Memory uses explicit states:

- `candidate`
- `confirmed`
- `verified`
- `disputed`
- `stale`
- `superseded`
- `forgotten`

Objective facts may become verified only through their evidence policy. Personal preferences enter review unless an explicit consent policy allows that preference class to be confirmed automatically. Agents cannot approve their own lessons.

## Operational-hazard memory

Failures retain the state transition, not only an error string. A reusable hazard records the matching stack, ordered procedure and parameters, target state before and after, health symptoms, repeat count, reset/recovery cost, unsafe retry conditions, a `do not retry until` gate, and the safer known sequence.

Before retrying or replanning, the supervisor must query failure and hazard memory. A matching high-confidence hazard can require a health check, impose a retry bound, choose a safe alternative, or stop the action. It cannot weaken authorization or policy.

## Context Packs

A Context Pack is the bounded, inspectable result of one memory query. It records:

- private mission/run/action provenance and retrieval purpose,
- normalized observed stack and applicability constraints,
- selected node IDs,
- item dispositions and influence summaries,
- retrieval policy and context budget,
- metrics and creation actor,
- a durable `no relevant memory` outcome when no item qualifies.

The Context Pack contract defines purposes for intake, planning, assignment acceptance, tool selection, attack attempts, phase transitions, failure, replanning, finding validation, reporting, lesson proposals, evaluation, and closeout. A purpose is not proof that a running adapter invoked it.

Ti-Scale provides the memory services used by reviewed Guided and Autonomous
runtime paths. A path may claim Brain use only when it persists the required
Context Pack and usage record; availability of memory services alone is not
proof that an agent consulted them.

## Retrieval policy

Retrieval combines:

- product/version/CPE/package matching,
- OS, kernel, runtime, protocol, topology, prerequisite, and security-control matching,
- indexed lexical search,
- bounded graph-neighborhood traversal,
- recency and scope filters,
- confirmation and verification state,
- verified success, failure, hazard, recovery, and counterexample weighting.

Policy enforces engagement isolation, maximum sensitivity, allowed node types, lifecycle state, expiry, exclusions, disclosure class, and context budget. Target-specific identity is never used as a substitute for stack applicability.

## Provider disclosure

Verification and provider disclosure are separate decisions. A confirmed node can remain local-only.

Provider context contains minimized titles, summaries, and relevance explanations. It is wrapped as untrusted data, excludes restricted content, records sanitization actions, and binds an exposure receipt when sent. Instructions found inside memory content must not become provider instructions.

## User controls

The UI supports reviewing candidates, confirming or rejecting them, correcting nodes, disputing, pinning, setting expiry, and forgetting. A rejection can create a privacy-safe suppression against immediate relearning.

Forgetting removes reusable content and derived retrieval state, including versions, sources, embeddings, edges, Context Pack items, caches, and managed vault projections. A content-free audit record may remain to prove that the privacy action occurred.

## Graph behavior

The graph displays real stored nodes and edges only. It does not create topology to make the canvas appear populated. An empty or sparsely connected graph means the canonical store has few eligible relationships, active filters exclude records, or relationships have not yet been supported by provenance.

The default canvas uses a bilateral brain layout with an address-free attack-knowledge spine. Slow orbital parallax may run while the canvas is visible. Selecting a node sends a signal only across its real stored relationships and highlights the supported success, hazard, and recovery paths. The background has no grid. Reduced-motion mode disables rotation and traveling signals while retaining static selection and directional cues.

Use the accessible table view when canvas interaction is unsuitable. Large graph tests cover progressive loading and bounded neighborhoods; release performance still requires measurement on the target deployment hardware.

## Operational checklist

- Confirm memory is enabled in **Second Brain → Control**.
- Review applicability, scope, sensitivity, and disclosure before confirming a candidate.
- Inspect `Context used` before trusting personalization claims.
- Resolve contradictions instead of deleting inconvenient history.
- Review stale knowledge and expiry.
- Inspect matching operational hazards and health gates before repeating a procedure.
- Verify vault synchronization separately from database health.
- Never store credentials, session tokens, private keys, or raw confidential payloads as reusable memory.
