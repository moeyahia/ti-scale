# Historical source discovery

Ti-Scale discovers historical attack knowledge from a hash-pinned list of
operator-owned source boundaries. The v2 manifest covers both engagement
trees and deterministic runtime/provider history without treating every
provider directory as an engagement.

The complete reviewed deployment manifest is:

`deployment/runtime-config/historical-source-roots.v2.json`

Reviewed SHA-256:

`e695fd23511e3ee5e01981a306b937ae81d7338e6e27a18d87af7771d480a704`

The original v1 two-parent manifest remains compatible. The v2 schema accepts
only:

- a stable configuration version;
- one to 64 uniquely identified, non-overlapping absolute paths;
- `children`, which treats safe direct children as engagement roots;
- `engagement-root`, which treats exactly that directory as one engagement;
- `history-root`, which performs generic runtime/provider discovery without
  inferring engagement boundaries;
- required roots, which fail closed when unavailable.

It cannot contain commands, globs, recursive include rules, credentials, or
parser overrides. The loader requires an exact SHA-256 and rejects a symlinked,
writable, owner-drifted, oversized, or changing configuration file.

## Supplemental history coverage

The reviewed v2 manifest adds these independently bounded classes:

- the separate `/home/chillspwn/htb/boxes` engagement tree;
- runtime runs, sessions, events, model logs, memory, and training state;
- Hermes sessions plus Markdown conversations and memory notes;
- Claude project JSONL history;
- Grok JSON/JSONL sessions and bounded logs;
- Codex JSONL sessions that fit the canonical source-size boundary.

Provider and Markdown history uses the same stable-file read, local-only
sanitizer, secret classifier, target/engagement suppression, immutable
verified-reference custody, and candidate-only compiler as other generic
history. A `history-root` file is never copied to reusable memory and its raw
contents are never placed in reconciliation output.

Every history-root source is bounded to 8 MiB, the combined supplemental walk
is bounded to 100,000 files, and traversal is bounded to 24 directory levels.
Exceeding a traversal bound fails closed instead of returning a falsely
complete import. The reconciliation report's
`genericSourceDiscovery` object provides exact aggregate counts and bytes for
scanned, classified, included, deferred, unsupported, excluded, oversized,
and active-SQLite files. It also reports skipped Vault projection and denied
directory counts. Unsupported private paths remain private reconciliation
metadata rather than user-facing knowledge.

## Safety and provenance

Configured discovery delegates to the canonical migration service. That
service:

- collapses lexical and bind-mount aliases by device and inode;
- hashes stable files while retaining source path, size, modification time,
  device, and inode in private migration custody;
- keeps accepted source bytes operator-owned in `verified-reference` mode;
- quarantines secret-bearing, credential-named, private-key, oversized, and
  unstable sources from reusable memory;
- builds relationships only between unambiguous facts in the same verified
  source bundle;
- creates candidates only—no historical fact is automatically verified or
  promoted;
- never writes an Obsidian Vault during migration.

The source walker also fails closed around feedback and live-state hazards:

- an Obsidian directory containing `.obsidian` is not traversed, preventing
  Ti-Scale's own Vault projection from feeding back into the importer;
- SQLite files with a non-empty WAL or journal are excluded and must first be
  copied through an operator-controlled, quiesced snapshot procedure;
- unrecognized SQLite schemas are excluded rather than guessed;
- oversized provider sessions are counted but not hashed or parsed;
- symlinks are never followed.

## Required review sequence

Calculate the exact reviewed configuration digest:

```bash
sha256sum deployment/runtime-config/historical-source-roots.v2.json
```

Run the complete semantic dry run first:

```bash
bun run history:migrate-configured -- \
  --config /root/ti-scale/deployment/runtime-config/historical-source-roots.v2.json \
  --config-sha256 e695fd23511e3ee5e01981a306b937ae81d7338e6e27a18d87af7771d480a704 \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --output /var/lib/ti-scale/staging/historical-all-dry-run \
  --settle-seconds 86400 \
  --acknowledge-verified-reference \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

Review the resulting reconciliation report, especially parent aliases,
manifests, classified bytes, quarantines, deferred recent files, semantic
candidate counts, and relationship distributions. Execution is a separate
command and must change only `--dry-run` to `--execute` while retaining the
same reviewed configuration hash and safety acknowledgements.

The underlying CLI mapping is deliberately narrow:

```text
children        -> --source
engagement-root -> --engagement-root
history-root    -> --history-root
```

`--history-root` is accepted only with verified-reference retention and the
attack-knowledge-only projection. It cannot be used to populate the legacy
target-centric mission projection.

Repeated execution remains hash-addressed and candidate-deduplicated. If a
source is still changing, the settled-source boundary defers it to a later run
instead of reading an unstable partial record.

For catch-up after an earlier completed import, do not repeat the complete
semantic walk merely because the public delta count is small. Use the private
hash-pinned exact-file handoff described in
[Hash-pinned historical delta execution](./historical-hash-pinned-delta-execution.md).
That path seals exact admissions during one read-only comparison and makes the
configured importer inspect only that reviewed batch.
