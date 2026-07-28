# Historical memory confirmation

Ti-Scale can convert a completed historical attack-knowledge import into
operator-confirmed reusable memory without treating that memory as verified
evidence. The confirmation gate is deliberately separate from import,
evidence promotion, and success/failure classification.

Use this workflow only with a completed migration whose source-retention mode
is `verified-reference` and whose Brain projection mode is
`attack-knowledge-only`. The migration inventory receipt, private import
mission, and terminal import run must all be present.

## What the gate does

For one deterministic page of candidates, the gate:

- confirms sanitized, globally reusable candidates produced by the attack
  knowledge compiler;
- suppresses candidates that contain secrets, operational locators, invalid
  taxonomy, non-global scope, or a changed content fingerprint;
- preserves prior operator rejection instead of overriding it;
- materializes only typed relationships already present in the hash-verified
  source bundles;
- reports confirmed candidates that have no unambiguous typed relationship as
  `unlinked` instead of guessing an edge;
- attaches a private `memory_sources` custody record to every confirmed node,
  including its import mission/run, opaque source-evidence candidate ID,
  immutable source hash, source timestamp, and canonical evidence ID when one
  exists;
- binds that custody record to **every exact private source occurrence** by the
  composite identity `(memory_source_id, source_reference)`, so identical
  bytes found in several original files remain separately traceable;
- writes an immutable audit receipt with counts, the next page cursor, and the
  exact unlinked-candidate inventory.

Reusable node content and edges do not contain engagement names, paths, host
addresses, or target labels. Authorized provenance views can follow the opaque
private source binding back to the exact import occurrence. This separation
keeps reusable attack knowledge target-independent while preserving source
custody.

The gate does **not**:

- promote a node to `verified`;
- infer that an attack succeeded or failed;
- turn historical prose into a canonical `AttackAttempt`;
- connect a script to a procedure merely because both appeared in the same
  engagement;
- expose private source paths in reusable memory;
- override a prior rejection.

Success and failure remain unclassified until a terminal canonical attack
attempt and sufficient verified, non-command-output evidence support the
outcome.

## Preview a page

Preview is read-only. Use the exact completed migration ID returned by the
historical importer.

```bash
bun run brain:confirm-historical -- preview \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration migration_<id> \
  --actor operator:local \
  --reason "Confirm this exact page of sanitized historical attack knowledge" \
  --max-candidates 500 \
  --dry-run
```

Review the returned candidate decisions, private source-binding counts, typed
relationship counts, `unlinkedCandidateCount`, and `previewHash`.

## Confirm the exact page

Run uses the same selection arguments and the exact preview hash:

```bash
bun run brain:confirm-historical -- run \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration migration_<id> \
  --actor operator:local \
  --reason "Confirm this exact page of sanitized historical attack knowledge" \
  --max-candidates 500 \
  --expected-preview-hash <PREVIEW_SHA256> \
  --acknowledge-confirm-all-safe
```

If `hasMore` is true, pass the returned `nextSelectionCursor` as `--after` to
both the next preview and its matching run. Never reuse a preview hash with a
different cursor, page size, actor, reason, migration, or inventory state.

Replaying the same authorized page returns the original audit receipt and does
not create duplicate nodes, relationships, or provenance bindings.

## Reconcile repeated identical sources

Several historical files can legitimately produce one reusable memory node and
one `memory_sources` record. They must not be collapsed into a single private
origin. After confirmation or replay repair, the following read-only check must
report `missing_count = 0` for the selected migration:

```sql
WITH expected AS (
  SELECT memory_source.id AS memory_source_id,
    occurrence.source_reference,
    occurrence.source_hash
  FROM memory_sources memory_source
  JOIN historical_attack_knowledge_source_occurrences occurrence
    ON memory_source.source_type = 'historical_attack_knowledge_source_candidate'
   AND memory_source.source_id = occurrence.candidate_id || ':' || occurrence.migration_id
   AND memory_source.source_hash = occurrence.source_hash
  WHERE occurrence.migration_id = :migration_id
)
SELECT COUNT(*) AS expected_count,
  COUNT(binding.memory_source_id) AS present_count,
  COUNT(*) - COUNT(binding.memory_source_id) AS missing_count
FROM expected
LEFT JOIN historical_private_source_bindings binding
  ON binding.memory_source_id = expected.memory_source_id
 AND binding.source_reference = expected.source_reference;
```

List any failure rather than hiding it behind aggregate counts:

```sql
WITH expected AS (
  SELECT memory_source.id AS memory_source_id,
    occurrence.source_reference,
    occurrence.source_hash
  FROM memory_sources memory_source
  JOIN historical_attack_knowledge_source_occurrences occurrence
    ON memory_source.source_type = 'historical_attack_knowledge_source_candidate'
   AND memory_source.source_id = occurrence.candidate_id || ':' || occurrence.migration_id
   AND memory_source.source_hash = occurrence.source_hash
  WHERE occurrence.migration_id = :migration_id
)
SELECT expected.memory_source_id, expected.source_reference, expected.source_hash
FROM expected
LEFT JOIN historical_private_source_bindings binding
  ON binding.memory_source_id = expected.memory_source_id
 AND binding.source_reference = expected.source_reference
WHERE binding.memory_source_id IS NULL
ORDER BY expected.memory_source_id, expected.source_reference;
```

The authorized node-detail API exposes these records as an ordered `origins[]`
array. Each origin is independently access checked and includes its private
source reference plus the owning mission/run/artifact identifiers. An
unauthorized caller receives no origins. These custody records are not semantic
Brain edges and never imply that a script implements a procedure merely because
their bytes occurred in the same historical collection.

## Confirm every page with a bounded resumable driver

For a migration containing many pages, use the all-page driver instead of
copying dozens of cursors and preview hashes by hand:

```bash
bun run brain:confirm-historical-all -- run \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration migration_<id> \
  --actor operator:local \
  --reason "Confirm sanitized historical attack knowledge from this completed migration" \
  --page-size 1000 \
  --max-pages 100 \
  --receipt /var/lib/ti-scale/imports/migration_<id>/confirmation-receipt.json \
  --acknowledge-confirm-all-safe
```

`--max-pages` is a per-invocation safety bound. If the receipt reports
`outcome: bounded`, run the exact command again. Actor, reason, page size,
migration ID, and inventory-receipt hash are fixed by the first invocation;
changing any of them fails closed. The maximum accepted page size and page
bound are both 1,000.

The driver does not weaken the single-page gate. For each page it:

1. starts only from the cursor in the durable checkpoint;
2. creates a fresh preview;
3. executes that exact preview hash;
4. verifies the returned cursor is strictly increasing and matches preview;
5. recomputes migration-wide reconciliation; and
6. publishes the next checkpoint with optimistic concurrency control.

The checkpoint is stored as a private, hash-checked record in the canonical
database after every page. A short lease rejects concurrent all-page drivers;
an interrupted lease expires, while ordinary errors release it immediately.
If a process stops after a page committed but before its aggregate checkpoint
was published, the next invocation replays the page's immutable audit receipt
and advances exactly once.

The external receipt is an atomic mode-`0600` projection containing only page
and aggregate counts, the cursor/hash chain, and reconciliation totals. It
does not contain candidate bodies, source paths, or source-binding inventories.
Terminal completion is refused unless canonical reconciliation reports:

- zero pending eligible candidates;
- zero incompatible eligible candidates;
- zero missing provenance bindings; and
- equal expected/present provenance and eligible/confirmed totals.

Unlinked confirmed candidates remain visible in
`reconciliation.unlinkedConfirmedCount`; they are not silently connected.
Re-running a completed command returns `outcome: replayed` without creating
new nodes, edges, bindings, or page audit records.

## Interpreting unlinked candidates

An unlinked candidate is not necessarily invalid. For example, a source may
contain a real script with a stable content hash but no unique evidence-backed
procedure association. Ti-Scale confirms the script as a source-backed memory,
preserves its private provenance, and reports it as unlinked. A reviewer can
later establish a relationship through a separate evidence-backed review. The
confirmation gate never fabricates that relationship.

## Evidence promotion

Use the separately reviewed historical promotion workflow when canonical
evidence is available and verification is justified. See
[Historical attack-knowledge promotion](./historical-attack-knowledge-promotion.md).
