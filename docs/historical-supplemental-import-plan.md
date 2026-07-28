# Supplemental historical import plan

This plan covers only historical sources that are absent from the reviewed v1
two-root migration. It must run as a separate migration after that migration
has reached a terminal state.

## Reviewed source boundary

Manifest:

`deployment/runtime-config/historical-source-roots.supplemental.v2.json`

Reviewed SHA-256:

`08a2ab9fcead05295f51d0199ec85431d7ef7c14d8b8b52df5199362b6382f5a`

The strict v2 manifest contains one `children` root and seven
`history-root` roots:

- `/home/chillspwn/htb/boxes`
- `/var/lib/chillspwn/state`
- `/var/lib/chillspwn/hermes`
- `/var/lib/chillspwn/claude/projects`
- `/root/.claude/projects`
- `/root/.grok/sessions`
- `/root/.grok/logs`
- `/root/.codex/sessions`

It deliberately excludes both roots already covered by the v1 migration:

- `/var/lib/chillspwn/workspaces/htb/boxes`
- `/var/lib/chillspwn/workspaces/engagements`

The focused manifest test proves that the supplemental root set is exactly the
complete reviewed v2 set minus those two v1 roots. Required roots fail closed;
the manifest cannot define commands, globs, parser overrides, credentials, or
optional paths.

## Read-only discovery evidence

Canonical discovery was measured at `2026-07-21T11:07:25.257Z` using the
settled-source cutoff `2026-07-21T11:05:28.735Z`. Discovery used the production
allowlist, an 8 MiB per-file parser limit, a 100,000-file aggregate bound, a
24-level traversal bound, no symlink following, and no source writes.

The separate `/home/chillspwn/htb/boxes` tree produced:

- 1 canonical parent root, 0 aliases, and 0 missing roots;
- 4 engagement manifests;
- 27 accepted files / 57,070 bytes: 23 recon records, 2 notes, 1 log, and 1
  loot record;
- 4 quarantined files / 846,200 bytes, all classified as sensitive content;
- 0 deferred files.

Those four quarantines are also surfaced by the top-level engagement exclusion
list; they are the same four records, not eight distinct files.

The seven generic history roots produced the following exact snapshot:

| Source root | Scanned | Classified | Included | Deferred | Unsupported | Oversized | Active SQLite |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `/var/lib/chillspwn/state` | 12,682 | 8,213 | 8,207 | 3 | 4,286 | 3 | 0 |
| `/var/lib/chillspwn/hermes` | 8,169 | 2,739 | 2,724 | 11 | 2,313 | 2 | 2 |
| `/var/lib/chillspwn/claude/projects` | 484 | 193 | 193 | 0 | 282 | 0 | 0 |
| `/root/.claude/projects` | 482 | 193 | 193 | 0 | 280 | 0 | 0 |
| `/root/.grok/sessions` | 9,653 | 2,949 | 2,933 | 0 | 6,704 | 16 | 0 |
| `/root/.grok/logs` | 6 | 6 | 6 | 0 | 0 | 0 | 0 |
| `/root/.codex/sessions` | 722 | 722 | 263 | 3 | 0 | 456 | 0 |
| **Total** | **32,198** | **15,015** | **14,519** | **17** | **13,865** | **477** | **2** |

Aggregate bytes were 31,833,223,591 scanned, 30,489,905,524 classified,
3,220,106,284 included, and 15,746,779 deferred. The included type counts
were:

- 4,180 session JSON records;
- 2,602 Hermes Markdown conversations or memory notes;
- 2,106 raw model JSONL records;
- 1,968 provider-session JSONL records;
- 1,905 provider log records;
- 1,655 provider-session JSON records;
- 97 runtime run records;
- 3 artifacts;
- 1 dashboard log, 1 memory record, and 1 training record.

Exclusions were explicit and non-silent:

- 3,314 sensitive, generated, or backup filenames;
- 477 files over the immutable 8 MiB semantic-parser boundary;
- 4 SQLite files with an unrecognized/non-allowlisted historical schema;
- 2 active SQLite databases with non-empty WAL or journal state;
- 4 SQLite sidecars;
- 14 symlinks;
- 6 denied generated/cache directories.

The 17 recent files were deferred rather than read. No Obsidian Vault
projection directory was traversed. Active SQLite and oversized provider
sessions remain explicitly reported but are not parsed, guessed, or silently
discarded.

These figures are a timestamped source snapshot, not a promise that live
provider-history directories will remain byte-identical. The migration report
is authoritative for the later dry run and execute run, and any file newer
than that invocation's cutoff is deferred.

## Exact dry-run command

Run from `/root/ti-scale` after the v1 migration has finished:

```bash
SUPPLEMENTAL_MANIFEST=/root/ti-scale/deployment/runtime-config/historical-source-roots.supplemental.v2.json
SUPPLEMENTAL_SHA256=08a2ab9fcead05295f51d0199ec85431d7ef7c14d8b8b52df5199362b6382f5a
SUPPLEMENTAL_STAMP=$(date -u +%Y%m%dT%H%M%SZ)

sha256sum "$SUPPLEMENTAL_MANIFEST"

bun run history:migrate-configured -- \
  --config "$SUPPLEMENTAL_MANIFEST" \
  --config-sha256 "$SUPPLEMENTAL_SHA256" \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --output "/var/lib/ti-scale/staging/historical-supplemental-${SUPPLEMENTAL_STAMP}-dry-run" \
  --settle-seconds 60 \
  --acknowledge-verified-reference \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

The dry run must report all eight required roots, four child engagement
manifests, seven generic history roots, zero automatically verified evidence,
and zero automatically promoted reusable memory. Review its reconciliation
file before executing. The dry run uses a disposable database and does not
mutate the canonical database, source files, or connected Vault.

## Exact execute command

Execution is allowed only after reviewing the dry-run report and confirming
that the v1 migration is terminal. It uses the existing server-owned hazard
binding key; the key value must never be printed or copied into a command.

```bash
SUPPLEMENTAL_EXEC_STAMP=$(date -u +%Y%m%dT%H%M%SZ)

env TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE=/etc/ti-scale/operational-hazard-hmac-key \
  bun run history:migrate-configured -- \
    --config "$SUPPLEMENTAL_MANIFEST" \
    --config-sha256 "$SUPPLEMENTAL_SHA256" \
    --db /var/lib/ti-scale/data/ti-scale.sqlite \
    --output "/var/lib/ti-scale/imports/historical-supplemental-${SUPPLEMENTAL_EXEC_STAMP}" \
    --settle-seconds 60 \
    --acknowledge-verified-reference \
    --acknowledge-attack-knowledge-only \
    --execute
```

Capture the returned migration ID, then run:

```bash
bun run db:reconcile -- \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --migration-id '<returned-migration-id>'

bun run db:verify -- --db /var/lib/ti-scale/data/ti-scale.sqlite
```

Execution is candidate-only and retains private provenance. Confirmation,
evidence verification, outcome classification, promotion, and Vault export
remain separate audited actions; the importer does not fabricate success or
failure and does not write the Vault.

## Focused validation

```bash
bun test \
  server/migration/__tests__/HistoricalSupplementalSourceManifest.test.ts \
  server/migration/__tests__/SupplementalSourceDiscovery.test.ts
```

Expected focused result: 4 tests pass, 0 fail.
