# Orphaned historical-migration lease recovery

An interrupted historical importer can finish or fail its migration metadata
and then exit before its `finally` block releases the canonical writer lease.
This recovery path releases only that exact orphaned importer lease. It is not
a general database-unlock command.

## Eligibility gates

The preview and release both fail closed unless all of these remain true:

- the exact lease ID exists and its fencing token matches;
- the lease is active, unexpired, unreleased, and uses the exact writer
  identity `operator:historical-migration` / `historical-engagement-import`;
- no historical importer process is present in the Linux process table;
- at least one canonical migration overlaps the lease interval;
- every overlapping migration is terminal `failed` or `completed` with a
  valid completion time;
- a failed migration has a terminal error summary;
- none of those migrations retains a `pending` or `importing` source;
- the reviewed preview hash still matches at execution time.

Maintenance, standalone-service/runtime, released, expired, wrong-fence, and
unknown leases are never eligible. Release and the tamper-evident audit record
are committed in one immediate SQLite transaction.

## Preview

```bash
bun run server/migration/cli.ts release-orphaned-migration-lease-preview \
  --db /operator/data/ti-scale.sqlite \
  --lease-id canonical_lease_REVIEWED_ID \
  --fencing-token REVIEWED_INTEGER
```

Review the returned owner, operation, expiry, empty process-ID list,
associated migration states, source counters, and `previewHash`.

## Deliberate release

```bash
bun run server/migration/cli.ts release-orphaned-migration-lease \
  --db /operator/data/ti-scale.sqlite \
  --lease-id canonical_lease_REVIEWED_ID \
  --fencing-token REVIEWED_INTEGER \
  --expected-preview-hash REVIEWED_SHA256 \
  --actor operator:reviewer \
  --reason 'Importer process is absent and all associated migration state is terminal.' \
  --acknowledge-orphaned-migration-lease-release
```

If any lease, process, migration, or source state changes after preview, the
hash comparison rejects the release. Generate and review a new preview rather
than bypassing that failure.
