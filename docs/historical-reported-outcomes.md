# Historical reported outcomes

Historical source claims and verified attack outcomes are different data
classes in Ti-Scale.

- `success` and `failed` remain canonical, evidence-backed classifications.
  They require a terminal `AttackAttempt`, its reviewed reusable-knowledge
  context, verified non-command evidence, chain of custody, and an audit
  receipt.
- `reported_success`, `reported_failure`, `mixed`, and `unknown` describe only
  what a sanitized historical source bundle reported. They never create an
  `AttackAttempt`, verify evidence, or populate
  `reusable_knowledge_outcome_links`.

`unknown` means that the sanitized bundle contained no supported structured
outcome marker. It does not mean that an attack was attempted or failed.

## Deterministic classification

Policy `historical-reported-outcome/v1` reads only compiler-sanitized bundle
JSON and existing opaque source-custody bindings. It does not reopen private
source files or inspect raw logs. Accepted signals are deliberately narrow:

- typed operational-hazard outcome records;
- typed `outcome` facts with `reportedOutcome` or `reportedStatus`;
- the earlier compiler shape `{status, verification: "candidate"}`.

Titles, summaries, nearby graph nodes, filenames, target names, IP addresses,
and free-form keyword matches do not classify an outcome. A bundle must retain
reusable technique or technology-stack context and pass the reusable-memory
secret and operational-locator boundary.

Classification confidence measures confidence in interpreting the source
claim. It is never confidence that the attack actually succeeded or failed.

## Review and execution

The outcome tables and guards are additive. Migration 40 introduced the
reported-only model, migration 41 corrected the insert guard for Ti-Scale's
two-hash custody model, and migration 42 added the indexed node-to-claim lookup
used by the Vault projection. Migrations 41 and 42 do not request a migration
snapshot and do not rewrite source, memory, claim, or Vault content.

The two hashes deliberately identify different things:

- `attack_knowledge_provenance_receipts.source_hash` identifies the sanitized
  compiler segment or record;
- `historical_attack_knowledge_bundle_sources.source_hash` identifies the raw
  verified-reference source object.

Custody is therefore proven through the bundle receipt plus the exact candidate
occurrence, completed import context, inventory receipt, and verified source
object. The hashes must not be equated.

Preview the bounded classification page before applying it:

```bash
bun run db:migrate --db /path/to/review.sqlite

bun run history:classify-reported-outcomes -- \
  preview \
  --dry-run \
  --db /path/to/review.sqlite \
  --max-records 250 > /path/to/reported-outcomes-page.json
```

Review `previewHash`, counts, rejection reasons, bundle/source set hashes, and
the next cursor. Applying the page requires that exact hash and an explicit
reported-only acknowledgement:

```bash
bun run history:classify-reported-outcomes -- \
  apply \
  --db /path/to/review.sqlite \
  --max-records 250 \
  --expected-preview-hash "$PREVIEW_HASH" \
  --actor "$OPERATOR_ID" \
  --reason "Reviewed as historical source claims only" \
  --acknowledge-reported-only
```

For later pages, pass the exact `nextCursor` to both preview and apply with
`--cursor`. Each claim identity is deterministic. Replaying an identical page
reuses existing rows; an immutable mismatch fails closed.

The apply command is intentionally unavailable through the application HTTP
surface. It is an operator-controlled maintenance action.

## Vault projection

Once a bundle candidate is materialized as a reusable global memory node, its
reported claim aggregate is projected as descriptive YAML:

```yaml
reported_outcome: mixed
reported_outcome_confidence: 0.75
reported_outcome_claim_count: 4
reported_outcome_source_count: 3
reported_outcome_policy: historical-reported-outcome/v1
tags:
  - ti-scale/reported-outcome/mixed
```

The native tag makes the note filterable in Obsidian. Editing or forging these
fields cannot create a database claim; the next canonical export restores the
database-derived values. Canonical `outcome_tags` remain separate.

## Reversal and limitations

The production migration ledger is forward-only and claim rows are immutable.
This installation intentionally retains no safety snapshots, so reversal is a
forward corrective migration rather than restoration of a retained database
copy. The outcome pipeline never deletes or rewrites the underlying historical
source records.

This pipeline does not reconstruct missing historical `AttackAttempt` records,
convert command output into evidence, prove exploit success, or materialize
staged bundles. Those remain separate reviewed workflows. A materialized node
can receive a reported Vault tag only after its bundle-to-node relationship
exists.
