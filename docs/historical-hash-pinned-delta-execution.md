# Hash-pinned historical delta execution

Ti-Scale can execute a reviewed historical catch-up without rescanning and
reprocessing every configured source file. The handoff is a private exact-file
plan, not the public aggregate planner output.

## Trust boundary

`history:plan-delta` still performs one read-only inventory comparison. With
`--private-plan-output`, the same pass also writes a local-only execution plan
that contains the exact canonical paths, hashes, byte sizes, timestamps,
device/inode identities, classifications, parser dispositions, configuration
binding, canonical migration baseline, and public-plan hash.

The private file:

- is created exclusively and never overwritten;
- must live outside every historical source root;
- is mode `0600` under a trusted, non-writable real directory;
- has a self-hash and a separately reviewed exact-byte SHA-256;
- is never printed to stdout;
- is the only artifact that can authorize exact-file delta execution.

The public JSON remains path-free. Its counts and inventory hashes are useful
for review, but it cannot be passed to the importer as an executable plan.

## Seal a reviewed batch

Use an existing private staging directory owned by root or the isolated
service UID and not writable by group or world:

```bash
CONFIG=/absolute/path/historical-source-roots.v2.json
CONFIG_SHA256=<reviewed-config-sha256>
PLAN_DIR=/var/lib/ti-scale/staging/reviewed-delta
PLAN="$PLAN_DIR/source-delta.private.json"

bun run history:plan-delta -- \
  --config "$CONFIG" \
  --config-sha256 "$CONFIG_SHA256" \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --settle-seconds 300 \
  --private-plan-output "$PLAN" \
  --acknowledge-private-source-paths \
  --dry-run
```

Record `sealedExecutionPlan.sourceSha256` from the path-free stdout receipt.
Do not substitute the aggregate `planHash` for the private file SHA-256.

If the public result is `no_delta` or `blocked_active_sqlite`, no executable
plan is produced. A non-empty active SQLite source requires a reviewed
quiesced snapshot or another explicit remediation; it is never silently
omitted from a primary engagement boundary.

## Delta-only semantic dry run

```bash
PLAN_SHA256=<sealedExecutionPlan.sourceSha256>

bun run history:migrate-configured -- \
  --config "$CONFIG" \
  --config-sha256 "$CONFIG_SHA256" \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --output /var/lib/ti-scale/staging/reviewed-delta-dry-run \
  --settle-seconds 300 \
  --reviewed-source-delta-plan "$PLAN" \
  --reviewed-source-delta-plan-sha256 "$PLAN_SHA256" \
  --acknowledge-reviewed-source-delta \
  --acknowledge-verified-reference \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

The configured importer resolves the original reviewed roots but supplies
only the admitted paths to engagement and generic discovery. Unchanged files
and files created after sealing are not traversed or processed by that batch.
They remain eligible for a later plan.

## Execute

After reviewing the delta-only dry-run reconciliation, repeat the same command
with a new output directory and replace `--dry-run` with `--execute`. Execution
continues to use the existing migration service, writer lease, database safety
snapshot, immutable inventory receipt, verified-reference custody, semantic
extractors, idempotency ledger, reconciliation report, and rollback metadata.

The inventory receipt additionally binds:

- private execution-plan hash;
- public aggregate-plan hash;
- configuration SHA-256;
- completed-migration baseline receipt-set hash;
- admitted file count, bytes, and exact admission inventory hash.

## Fail-closed revalidation

Before discovery or migration mutation, execution rejects:

- a missing, symlinked, non-`0600`, wrongly owned, writable, oversized, or
  byte-hash-mismatched private plan;
- configuration version, SHA, root, or root-mode drift;
- any change in the completed-migration/source-object baseline;
- paths outside their bound root, directory paths, symlinks, physical aliases,
  inode changes, size changes, or modification-time changes;
- any admitted inode currently open for write;
- discovery results whose classification, content hash, sensitivity,
  eligibility, or exact path set differs from the sealed admission.

The importer revalidates verified-reference hashes and inode identity again
during and after semantic processing. A failed or interrupted migration keeps
the existing immutable resume and rollback semantics; resume must provide the
same sealed plan and exact hashes.

## Focused validation

```bash
bun test \
  server/migration/__tests__/HistoricalSourceDeltaPlanner.test.ts \
  server/migration/__tests__/HistoricalSourceDeltaExecution.test.ts \
  server/migration/__tests__/HistoricalSourceDeltaCli.test.ts

bun run typecheck
```

These fixtures use tiny local histories. They prove exact-path traversal,
configuration/baseline/source drift rejection, active-writer rejection,
mode-`0600` sealing, and end-to-end configured CLI delegation without running
a full-corpus scan.
