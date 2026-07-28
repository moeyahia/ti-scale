# Reusable Knowledge Outcomes

Ti-Scale classifies reusable attack knowledge with two evidence-backed outcome tags:

- `success`
- `failed`

The absence of either tag means **unclassified/supporting knowledge**. A reusable procedure, version fingerprint, prerequisite, or other reviewed node may carry both tags because the same knowledge can succeed in one exact technology context and fail in another. Outcomes are therefore immutable many-to-many links, not a mutable status field on the memory node.

## Classification authority

Titles, node types, imported Markdown, historical prose, and model output cannot assign an outcome. `ReusableKnowledgeOutcomeService` derives the tag from a canonical terminal `AttackAttempt`:

- `succeeded` derives `success`;
- `failed` derives `failed`;
- every other attempt state is ineligible.

The reusable node must be verified, operator-confirmed, global attack knowledge and must already belong to that exact attempt's immutable reviewed knowledge context. Every classification also requires non-command, verified evidence linked to the exact attempt as `supports` or `outcome`, a verified chain-of-custody event, and a hash-chained audit record with an actor and reason.

Database triggers independently enforce these rules. After classification, the outcome link, relevant attempt outcome, reviewed knowledge context, evidence identity and verification fields, exact attempt/evidence binding, and verified custody receipt cannot be changed or deleted.

## Historical material

Historical extraction records only `reportedStatus`, `outcomeClassification: unclassified`, and its text-only classification basis. Migration 33 intentionally performs no outcome backfill. Historical outcome candidates require manual review and a future canonical AttackAttempt/evidence binding; the batch promoter cannot use prose or a source hash as a shortcut.

Migration 40 adds a separate immutable historical-claim ledger for
`reported_success`, `reported_failure`, `mixed`, and `unknown`. These values
remain explicitly unverified and do not populate this table. See
[Historical reported outcomes](./historical-reported-outcomes.md).

The read-only historical audit applies the same boundary before any operator
review begins. It requires an exact non-synthetic mission/run, a canonical
represented `AttackAttempt`, typed intent/technique/target context, a terminal
result, reviewed reusable-knowledge membership, and verified non-command
evidence with chain-of-custody linked to that exact attempt. The audit returns
only counts, reason categories, cursors, and SHA-256 receipts; it never returns
historical source content and has no mutation mode.

```bash
bun run server/migration/historical-attempt-outcome-dry-run-cli.ts audit \
  --dry-run \
  --db /path/to/ti-scale.sqlite
```

A reported outcome in a conversation or note remains visible as reported
history, but it is not an authoritative success/failure classification. A
generic import container is likewise provenance, not proof that an attack was
executed in that synthetic mission/run.

## API and Vault projection

Second Brain list, graph, and detail responses expose `outcomeTags`. List and graph routes accept `outcome=success`, `outcome=failed`, or `outcome=unclassified`.

Obsidian notes project canonical tags as read-only descriptive YAML and native tags:

```yaml
outcome_tags:
  - "success"
  - "failed"
tags:
  - "ti-scale/outcome/success"
  - "ti-scale/outcome/failed"
```

Unclassified notes omit these values. A user may edit the YAML for ordinary note interoperability, but Vault import never creates an outcome classification. Only the canonical service and proof contract can do that; the next canonical export restores the database-derived projection.

## Validation

Focused tests cover dual outcomes, unrelated-node rejection, weak-evidence rejection, direct SQL bypass rejection, immutable reviewed bindings, no historical backfill, hash-only deterministic historical auditing, synthetic-import rejection, read-only CLI operation, API filters/projections, Obsidian round-trip, unclassified omission, and forged Vault-tag rejection.

The outcome migration and audit do not import historical data or mutate a live
Vault. Import, Vault projection, and any later evidence-backed outcome review
remain separately reconciled operations.
