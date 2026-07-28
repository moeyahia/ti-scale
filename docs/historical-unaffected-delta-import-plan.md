# Unaffected historical delta import plan

This plan isolates the historical roots that are not blocked by the active
SQLite/WAL condition under the main HTB workspace tree. It does not alter,
checkpoint, rename, copy, delete, or otherwise mutate any historical source
root. It also does not authorize an import by itself.

## Reviewed source boundary

Manifest:

`deployment/runtime-config/historical-source-roots.unaffected-delta.v2.json`

Reviewed byte SHA-256:

`aac50e19e8176ef0e5f08c2cf22f56eb46584d81b94fd8882d1e2722d08dba60`

The manifest uses the existing strict
`ti-scale.historical-source-roots.v2` schema. It is exactly the complete
ten-root deployment manifest minus this one root:

- `historical-htb-workspaces` — `/var/lib/chillspwn/workspaces/htb/boxes`

The remaining nine required roots retain their reviewed IDs, paths, modes,
and order:

| Root ID | Mode | Path |
| --- | --- | --- |
| `historical-engagement-workspaces` | `children` | `/var/lib/chillspwn/workspaces/engagements` |
| `historical-home-htb-workspaces` | `children` | `/home/chillspwn/htb/boxes` |
| `historical-runtime-state` | `history-root` | `/var/lib/chillspwn/state` |
| `historical-hermes-runtime` | `history-root` | `/var/lib/chillspwn/hermes` |
| `historical-service-claude-projects` | `history-root` | `/var/lib/chillspwn/claude/projects` |
| `historical-operator-claude-projects` | `history-root` | `/root/.claude/projects` |
| `historical-operator-grok-sessions` | `history-root` | `/root/.grok/sessions` |
| `historical-operator-grok-logs` | `history-root` | `/root/.grok/logs` |
| `historical-operator-codex-sessions` | `history-root` | `/root/.codex/sessions` |

Required roots still fail closed when missing. The manifest cannot define
commands, globs, parser overrides, credentials, optional roots, or file-level
exceptions.

## Reviewed 120-file delta

The read-only all-root delta plan captured at
`2026-07-22T10:17:22.125Z` has:

- receipt file SHA-256
  `9b2404a04d20e255eedd33def4a9774b18280e8bb595db41fe357066269c7789`;
- plan hash
  `93d83e91d71a43e902dffac47b5fc1a5537b1f286602b2b3cf8baacaaece3270`;
- 783 total changed/new source versions across all ten roots;
- 663 versions under the excluded HTB workspace root, including its active
  SQLite blocker;
- exactly 120 versions under the unaffected nine-root boundary.

All 120 unaffected versions were semantic-parser eligible:

| Root ID | Ready semantic versions | Classes |
| --- | ---: | --- |
| `historical-runtime-state` | 56 | event JSONL, provider logs, raw model JSONL, run JSON, session JSON |
| `historical-hermes-runtime` | 44 | conversation Markdown |
| `historical-operator-codex-sessions` | 20 | provider-session JSONL |
| Other six retained roots | 0 | no delta at the reviewed boundary |
| **Total** | **120** | **candidate-only local semantic parsing** |

The unaffected delta contained zero custody-only files and zero quarantined
files. Ten recent files were separately deferred by the settled-source
boundary and are not part of the 120. Two non-empty SQLite sidecar conditions
inside the heterogeneous Hermes history root remained explicit generic-source
exclusions; the importer does not open or guess them. The excluded primary HTB
workspace SQLite/WAL remains untouched for a separate quiesced-snapshot path.

The 120 count is evidence for that timestamped inventory, not permission to
silently absorb later writes. Before any execute decision, rerun the read-only
delta planner and review its new plan hash and counts. A changed inventory is
a new batch requiring review.

### Current read-only revalidation

The nine-root manifest was revalidated without writes at
`2026-07-22T11:39:19.122Z`. The result was `ready`, but the live histories had
advanced since the 120-file receipt:

- public receipt SHA-256:
  `2d1fccbb6c6ad6e2497f1fa12a2797d164a357162db70d744fdce444b3ba19b5`;
- plan hash:
  `ea89e0642f632f756444883482ea9da1cb01f21cee792d64a208298fbe87c064`;
- 144 changed/new versions, all semantic-parser eligible;
- zero custody-only versions;
- zero quarantined versions;
- three recent files deferred;
- one active SQLite source explicitly excluded inside the heterogeneous
  Hermes history root.

The additional 24 semantic versions were 16 runtime-state records and eight
Hermes conversation notes. No execute/import was run. The reviewed 120-file
receipt cannot be represented as current source bytes merely by reusing its
old aggregate hash, so an exact 120-file execution remains closed. Review and
approve the newer 144-file inventory, or create a separately verified
quiesced snapshot, before authorizing an execution batch.

## Hash and read-only delta verification

Run from `/root/ti-scale`:

```bash
UNAFFECTED_MANIFEST=/root/ti-scale/deployment/runtime-config/historical-source-roots.unaffected-delta.v2.json
UNAFFECTED_SHA256=aac50e19e8176ef0e5f08c2cf22f56eb46584d81b94fd8882d1e2722d08dba60

sha256sum "$UNAFFECTED_MANIFEST"

bun run history:plan-delta -- \
  --config "$UNAFFECTED_MANIFEST" \
  --config-sha256 "$UNAFFECTED_SHA256" \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --settle-seconds 300 \
  --dry-run
```

`history:plan-delta` opens the canonical database read-only and does not write
the database, source roots, service, or Vault. Its public receipt contains
aggregate root IDs and hashes, not source paths or source content.

## Exact semantic dry-run command

Only after the read-only delta receipt is reviewed, run the importer in dry-run
mode:

```bash
UNAFFECTED_DRY_RUN_STAMP=$(date -u +%Y%m%dT%H%M%SZ)

bun run history:migrate-configured -- \
  --config "$UNAFFECTED_MANIFEST" \
  --config-sha256 "$UNAFFECTED_SHA256" \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --output "/var/lib/ti-scale/staging/historical-unaffected-${UNAFFECTED_DRY_RUN_STAMP}-dry-run" \
  --settle-seconds 300 \
  --acknowledge-verified-reference \
  --acknowledge-attack-knowledge-only \
  --dry-run
```

Dry-run mode performs source discovery and semantic parsing in a disposable
canonical schema. It writes only the requested staging reconciliation report;
it creates no canonical migration, memory candidate, evidence, mission, run,
Vault note, or source-root change. The report must continue to show:

- `dryRun: true`;
- zero automatically verified evidence;
- zero automatically promoted reusable memory;
- verified-reference source retention;
- attack-knowledge-only Brain projection;
- the excluded HTB workspace root absent from `sourceRoots`.

The command deliberately contains no `--execute` form. Execution remains a
separate reviewed operation after the current reconciliation receipt, source
inventory, database lease state, storage headroom, and rollback gate are
approved.

## Focused validation

```bash
bun test \
  server/migration/__tests__/HistoricalUnaffectedSourceManifest.test.ts \
  server/migration/__tests__/HistoricalSourceRootConfiguration.test.ts \
  server/migration/__tests__/HistoricalSourceDeltaPlanner.test.ts
```

The source-manifest test pins the exact bytes and proves that no root other
than `historical-htb-workspaces` was removed. The configured-CLI integration
coverage proves that dry-run semantic parsing uses a disposable database and
leaves its supplied canonical database byte-identical.
