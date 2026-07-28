# Historical reusable-knowledge orphan-link repair

Historical confirmation intentionally preserves safe facts even when an older
parser could not prove a relationship. This can leave a confirmed or verified
reusable node with private source custody but no graph edge. The orphan-link
repair is a bounded operator workflow for materializing relationships that the
current deterministic parser has already staged from exact, hash-bound source
custody.

The repair does not infer from node titles, graph proximity, co-occurrence,
target names, addresses, engagement names, missions, or runs. It does not
verify nodes or edges. Created edges are operator-confirmed and retain only
opaque reusable provenance; private attribution remains in canonical custody.

## Required order

The repair never scans or re-extracts source files itself. First run the
existing configured historical migration so the current parser can re-open the
verified references and stage any newly recognized typed relationships:

```bash
bun run history:migrate-configured -- <configured migration options>
```

Complete and reconcile that migration before reviewing orphan links. If the
reconciliation reports `no_typed_relationship`, rerunning only this repair will
not change it; the current parser must first emit a relationship from the exact
source.

The database path may be supplied with `--db` or through
`TI_SCALE_DATABASE_PATH`.

## Reconcile

Reconciliation opens the database read-only and reports registry-backed
connected, orphaned, repairable, and unresolved counts:

```bash
bun run brain:repair-historical-links:reconcile -- \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --output ./orphan-link-reconciliation.json
```

`--output` is optional. Persisted output is written atomically with mode 0600;
database files, SQLite sidecars, symlinks, and non-regular targets are refused.

## Preview one bounded page

```bash
bun run brain:repair-historical-links:preview -- \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor operator:local \
  --reason "Review exact source-backed orphan relationships" \
  --max-relationships 100 \
  --dry-run \
  --output ./orphan-link-preview.json
```

Preview opens SQLite read-only and does not create edges or audits. Review the
node types, edge types, aggregate bundle hashes, unresolved reasons, and
`previewHash`. When `hasMore` is true, use `nextProposalKey` as `--after` in a
new separately reviewed page.

## Execute the reviewed page

Repeat the actor, reason, cursor, and page-size values exactly:

```bash
bun run brain:repair-historical-links:execute -- \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor operator:local \
  --reason "Review exact source-backed orphan relationships" \
  --max-relationships 100 \
  --expected-preview-hash <PREVIEW_SHA256> \
  --acknowledge-reviewed-orphan-links \
  --receipt ./orphan-link-execution.json
```

Execute acquires the canonical writer lease, recomputes the page inside the
transaction, and refuses a stale hash. It creates only the reviewed typed
edges, reconciles their staged bundle bindings, appends an immutable audit, and
writes an atomic mode-0600 receipt. Repeating the same reviewed command returns
`replayed` without duplicating edges or audit records.
