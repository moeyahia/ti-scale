# Verified-reference historical migration

Ti-Scale supports a storage-efficient historical import for large operator-owned source trees. The mode inventories and parses source data in place without copying accepted or quarantined source bytes into the migration output.

Verified reference is the only supported source-retention mode for this
installation. The importer rejects protected-copy and backup-root options.

## Attack-knowledge-only command

Run a dry preview first:

```bash
bun run db:migrate:historical -- \
  --db /path/to/command-os-v2.sqlite \
  --source /path/to/historical-engagements \
  --output /path/to/migration-metadata \
  --source-retention verified-reference \
  --acknowledge-verified-reference \
  --brain-projection attack-knowledge-only \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

For deterministic runtime/provider history that must not be interpreted as an
engagement tree, use `--history-root` in place of `--source`. This option is
valid only with the verified-reference and attack-knowledge-only settings
shown above. Hash-pinned multi-root operation should use
`history:migrate-configured` with the reviewed v2 source manifest.

Remove `--dry-run` only after reviewing the reconciliation preview. Both acknowledgements are deliberate and mandatory. The CLI fails before opening or migrating the database when either acknowledgement is missing.

Use exactly the same retention, projection, source-root, database, and output arguments when resuming:

```bash
bun run db:migrate:historical -- \
  --db /path/to/command-os-v2.sqlite \
  --source /path/to/historical-engagements \
  --output /path/to/migration-metadata \
  --source-retention verified-reference \
  --acknowledge-verified-reference \
  --brain-projection attack-knowledge-only \
  --acknowledge-attack-knowledge-only \
  --resume migration_ID
```

## Storage and integrity contract

- No database copy, source copy, archive, or rollback payload is created before canonical schema or domain mutation.
- Accepted files and quarantined regular files are not copied. Their private inventory records retain the SHA-256 hash, byte size, modification time, device/inode identity, classification, and an opaque `legacy-private-source://…` reference.
- Private absolute paths exist only in migration provenance and reconciliation metadata. They are not projected into reusable memory, prompts, Vault notes, or user-facing attack knowledge.
- Every regular source is opened read-only with no symlink following. Containment, inode, size, modification time, and SHA-256 are checked before parsing and rechecked before the transaction commits.
- Symlink targets are never followed or read. Only the link object's content-free fingerprint and filesystem identity are inventoried.
- A source replacement, write race, hash mismatch, missing item, extractor failure, or post-parse identity change rolls back that source transaction and fails closed.
- The reconciliation report explicitly states `protectedSourceCopyCreated: false`, the referenced object and byte totals, and that source availability remains dependent on the operator-owned tree.

Do not move, rewrite, delete, or make the source tree writable during the import. Reference-mode provenance can be revalidated only while the original source objects remain available at their recorded private locations.

For an otherwise settled engagement tree that still has a small reviewed set
of live writers, follow [Active live-engagement catch-up](active-live-engagement-catch-up.md).
That workflow defers only recent or independently verified open-writer files;
it does not weaken exact revalidation for any included file.

## Knowledge projection contract

`attack-knowledge-only` suppresses the legacy per-engagement mission, run, asset, artifact, target, IP, and per-file Brain projection. It creates a private source inventory and allows the bounded semantic extractor to create reusable candidates such as:

- product and application version fingerprints;
- kernel or operating-system family/version observations;
- attack vectors, prerequisites, and technique attributes;
- CVE applicability candidates with source provenance;
- scripts or procedures represented by hash and purpose rather than private path;
- successful outcomes, failed approaches, hang/reset hazards, recovery conditions, and safe sequencing constraints.

Candidates remain unverified until the normal evidence and promotion workflow accepts them. The extractor may create one content-free internal custody mission/run per migration job when canonical foreign keys require it; it does not create one mission or run per historical engagement and is not reusable target knowledge.

The source registry and migration reconciliation are idempotent and resumable. Re-running the same history does not duplicate reusable candidates; each migration run retains its own audit inventory and reconciliation receipt.
