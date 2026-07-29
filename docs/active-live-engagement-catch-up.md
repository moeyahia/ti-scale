# Active live-engagement catch-up

Ti-Scale can import the settled portion of an operator-owned engagement tree
without stopping the application that is still writing a small number of
files. This path is deliberately narrow: it is available only for
`verified-reference`, `attack-knowledge-only` imports with an immutable
settled-source cutoff.

The ordinary `--settle-seconds` boundary automatically defers every eligible
file whose modification time is newer than the migration-start cutoff. A
long-running listener can also hold an old log open for write even though its
modification time is old. Such a file must be named with
`--defer-active-source`.

On a new run Ti-Scale accepts each explicit deferral only when the exact
regular-file inode is either:

- newer than the immutable settled-source cutoff; or
- held by an open writable Linux file descriptor visible through `/proc`.

The file is not opened for content inspection, parsed, hashed into reusable
knowledge, or registered as accepted custody. Its private absolute path,
device/inode identity, size, modification time, and deferral reason are bound
into the immutable inventory receipt and local reconciliation report. Public
knowledge, prompts, and Vault notes never receive the path.

## Safe procedure

1. Inventory open writable descriptors under the selected root. Review every
   result and do not add unrelated stable files.
2. Run a dry preview with a settle window of at least 60 seconds and one
   `--defer-active-source` argument for each reviewed open writer.
3. Require the preview to show all continuously changing files under the
   recent-write reason and every old open writer under the explicit-active
   reason. Review the local private path list in `reconciliation.json`.
4. Run the same command without `--dry-run`. Do not add or remove explicit
   paths between preview and execution.
5. If the process is interrupted, repeat the exact same roots, settle value,
   explicit paths, retention/projection modes, database, output directory, and
   add `--resume migration_ID`. A resume retains the original active deferral
   even if that writer has since closed; the inventory receipt rejects a path,
   inode, size, or modification-time mismatch.
6. Use a new migration, not resume, after deferred files have settled. Normal
   content-addressed candidate and source-custody deduplication makes the
   catch-up idempotent.

Example:

```bash
bun run db:migrate:historical -- \
  --engagement-root /operator/history/engagement-a \
  --db /operator/data/ti-scale.sqlite \
  --output /operator/imports/engagement-a-catch-up \
  --source-retention verified-reference \
  --acknowledge-verified-reference \
  --brain-projection attack-knowledge-only \
  --acknowledge-attack-knowledge-only \
  --settle-seconds 60 \
  --defer-active-source /operator/history/engagement-a/logs/listener.log \
  --acknowledge-active-source-deferrals \
  --summary-output \
  --dry-run
```

For a reviewed hash-pinned source-root manifest, use the configured wrapper;
it forwards every repeated deferral to the same lower-level safety boundary:

```bash
bun run history:migrate-configured -- \
  --config /operator/config/historical-source-roots.v2.json \
  --config-sha256 '<reviewed-manifest-sha256>' \
  --db /operator/data/ti-scale.sqlite \
  --output /operator/imports/catch-up \
  --settle-seconds 60 \
  --defer-active-source /operator/history/engagement-a/logs/listener.log \
  --defer-active-source /operator/history/engagement-b/logs/provider.jsonl \
  --acknowledge-active-source-deferrals \
  --acknowledge-verified-reference \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

An executing resume must repeat the exact same deferral paths. The configured
wrapper rejects deferrals without the explicit acknowledgement and also
rejects an acknowledgement that names no deferred path.

## Release gates

- No source writer is stopped or altered by the migration.
- Every explicit path is contained by a configured canonical source root.
- Symlinks, directories, duplicate paths, and hard-link aliases are rejected.
- A stale closed file cannot be explicitly omitted.
- Included files retain inode, size, modification-time, and SHA-256
  revalidation before parsing and after semantic extraction.
- Any unlisted source race still fails closed; it is never silently converted
  to evidence or memory.
- `deferredReasonCounts` separates recent writes from verified active-source
  deferrals in both dry-run and completed reconciliation receipts.
- A completed catch-up may be confirmed only after the normal reconciliation,
  integrity, privacy, and source-provenance gates pass.
