# Outcome evidence projection

Ti-Scale outcome categories are independent evidence-linked tags, not an
exclusive status. A reusable technique, script, procedure, or technology fact
can be associated with a successful terminal attempt, a failed terminal
attempt, or both in different exact contexts.

## Frontend/API contract

Memory graph and node-detail records may expose:

```ts
outcomeTags?: Array<"success" | "failed">;
```

The stable order is `success`, then `failed`. Missing or empty tags mean
**Supporting / unclassified**. Clients must not infer a terminal outcome from
the node type, title, summary, lifecycle, folder, or nearby graph nodes.

## Proposed Obsidian projection

For a note with both independently verified outcome links:

```yaml
---
outcome_tags:
  - success
  - failed
tags:
  - ti-scale/outcome/success
  - ti-scale/outcome/failed
---
```

For supporting or unclassified knowledge, omit `outcome_tags` and both outcome
tags entirely. Do not write `unclassified` as if it were an observed result.

Projection rules:

- Include `success` only when the reusable global node has an immutable link to
  a canonical terminal AttackAttempt with verified non-command evidence and
  chain-of-custody support.
- Include `failed` under the same standard for a failed terminal AttackAttempt.
- Preserve both values when both relationships exist; never let a later result
  overwrite the earlier evidence-linked category.
- Keep the YAML array and tags deduplicated and in stable order.
- SQLite remains canonical. A Vault edit that changes outcome tags should enter
  the normal reviewed import/conflict path rather than silently rewriting the
  evidence relationship.

Historical source claims use the separate `reported_outcome` YAML property and
`ti-scale/reported-outcome/*` tags. They must never appear in `outcome_tags`.
See [Historical reported outcomes](./historical-reported-outcomes.md).
