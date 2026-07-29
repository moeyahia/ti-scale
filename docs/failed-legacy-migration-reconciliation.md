# Failed historical import reconciliation

Ti-Scale treats an `importing` child source as a durable database writer. A
process interruption can leave that child state behind even after its parent
migration has reached terminal `failed`. Release and maintenance gates must not
ignore or directly edit that row.

The failed-migration reconciliation command closes only this narrow metadata
condition. It does not delete imported objects, source inventory, candidates,
evidence, quarantine records, or audit history.

## Required proof

The command fails closed unless all of the following are true:

- database migration 35 and the canonical lease tables are installed;
- the selected parent migration is terminal `failed`, has a terminal timestamp,
  and has a recorded error;
- at least one of its child sources remains `pending` or `importing`;
- no historical import process is visible in the local process table;
- no other active canonical historical import lease exists;
- a different, later migration is terminal `completed`;
- that replacement has immutable inventory and reconciliation receipts;
- retention and Brain-projection contracts match;
- for every lingering child, the replacement declares the exact source path as
  a source root and contains one completed source with the same path, relative
  path, type, and stable `source_identity`;
- each replacement source has retained source-object custody.

A changed source content hash is reported but does not defeat the repair when
the stable source identity and exact root match. The later completed migration
is the authoritative coverage proof.

## Preview

Preview is read-only and returns an exact SHA-256-bound proof. Source paths are
represented by hashes in the output.

```bash
bun run server/migration/cli.ts reconcile-failed-preview \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration-id migration_failed_id \
  --replacement-migration-id migration_completed_replacement_id
```

Review the failed parent, replacement, source count, replacement source IDs,
inventory receipt, reconciliation receipt, and `previewHash`.

## Execute

Execution re-runs every proof under a durable canonical writer fence and
requires the exact preview hash plus explicit acknowledgement.

```bash
bun run db:reconcile-failed -- \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration-id migration_failed_id \
  --replacement-migration-id migration_completed_replacement_id \
  --expected-preview-hash lowercase_sha256_from_preview \
  --actor operator:historical-import \
  --reason "Close interrupted child metadata after reviewing the completed replacement receipts" \
  --acknowledge-failed-migration-reconciliation
```

The transaction marks only the failed parent's still-`pending` or
still-`importing` children as `failed`, copies the parent's terminal timestamp
and bounded error into their terminal metadata, and appends a hash-linked audit
record. The audit records opaque source IDs and hashes rather than private
filesystem paths. Existing completed or failed children and all source objects
remain unchanged.

Do not replace this flow with ad hoc SQL. If the preview reports an active
process/lease, mismatched root or identity, missing receipt, changed preview, or
nonterminal replacement, resolve that condition and generate a new preview.
