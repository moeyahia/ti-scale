# Second Brain

The Second Brain is a user-controlled knowledge graph for mission context, operational experience, and confirmed preferences. It is an active runtime service, not a decorative visualization.

## Canonical model

Nodes can represent operators, preferences, missions, runs, plans, phases, steps, agents, tools, capabilities, tactics, techniques, procedures, targets, assets, entities, decisions, evidence, findings, artifacts, failures, recoveries, evaluations, lessons, reports, and sources.

Edges describe typed relationships such as:

- `prefers`
- `applies_to`
- `belongs_to`
- `executed_by`
- `used_in`
- `targets`
- `produced`
- `supports`
- `contradicts`
- `depends_on`
- `derived_from`
- `learned_from`
- `recovered_by`
- `supersedes`
- `verified_by`
- `influenced`

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

## Context Packs

A Context Pack is the bounded, inspectable result of one memory query. It records:

- mission, run, step, action, or message scope,
- journey and purpose,
- selected node IDs,
- item dispositions and influence summaries,
- retrieval policy and context budget,
- metrics and creation actor,
- a durable `no relevant memory` outcome when no item qualifies.

Runtime lifecycle hooks exist for intake, planning, assignment acceptance, tool selection, attack attempts, phase transitions, failure, replanning, finding validation, reporting, lesson proposals, evaluation, and closeout.

The default server provides these services but does not execute agent work until a production execution adapter is attached. Do not claim that an agent used the Brain unless a persisted Context Pack and usage record exist.

## Retrieval policy

Retrieval combines:

- exact identifiers and properties,
- indexed lexical search,
- bounded graph-neighborhood traversal,
- recency and scope filters,
- confirmation and verification state,
- optional exact-node-only selection.

Policy enforces engagement and mission isolation, maximum sensitivity, journey permissions, allowed node types, lifecycle state, expiry, exclusions, and context budget. A global preference is eligible only when explicitly global and permitted for the current journey.

## Provider disclosure

Verification and provider disclosure are separate decisions. A confirmed node can remain local-only.

Provider context contains minimized titles, summaries, and relevance explanations. It is wrapped as untrusted data, excludes restricted content, records sanitization actions, and binds an exposure receipt when sent. Instructions found inside memory content must not become provider instructions.

## User controls

The UI supports reviewing candidates, confirming or rejecting them, correcting nodes, disputing, pinning, setting expiry, and forgetting. A rejection can create a privacy-safe suppression against immediate relearning.

Forgetting removes reusable content and derived retrieval state, including versions, sources, embeddings, edges, Context Pack items, caches, and managed vault projections. A content-free audit record may remain to prove that the privacy action occurred.

## Graph behavior

The graph displays real stored nodes and edges only. It does not create topology to make the canvas appear populated. An empty or sparsely connected graph means the canonical store has few eligible relationships, active filters exclude records, or relationships have not yet been supported by provenance.

Use the accessible table view when canvas interaction is unsuitable. Large graph tests cover progressive loading and bounded neighborhoods; release performance still requires measurement on the target deployment hardware.

## Operational checklist

- Confirm memory is enabled in **Second Brain → Control**.
- Review scope and sensitivity before confirming a candidate.
- Inspect `Context used` before trusting personalization claims.
- Resolve contradictions instead of deleting inconvenient history.
- Review stale knowledge and expiry.
- Verify vault synchronization separately from database health.
- Never store credentials, session tokens, private keys, or raw confidential payloads as reusable memory.
