# Obsidian vault

Ti-Scale can project eligible Second Brain records into an Obsidian-compatible Markdown vault. The vault is portable and human-editable, while SQLite remains the transactional source of truth.

## Connection requirements

A vault is active only after all of these conditions are true:

1. `TI_SCALE_VAULT_ROOT` is an absolute allowed filesystem root.
2. Memory control permits vault projection.
3. The operator selects a path inside the allowed root and explicitly grants filesystem permission.
4. A temporary filesystem round trip proves write, read, rename, and delete.
5. The connection record is persisted as connected.

No environment boolean can substitute for these checks or make the user interface report an active connection.

The health test cleans up its temporary directory before reporting success. A missing or inaccessible configured directory fails closed; recovery checks do not silently recreate a disappeared vault.

## Directory structure

Managed notes are classified by domain:

```text
00 Inbox/
10 Operator/
20 Engagements/
21 Missions/
22 Runs/
30 Assets/
31 Network Topology/
32 Applications and Services/
33 Identities and Trusts/
40 Attack Plans/
41 Attack Paths/
42 Attack Attempts/
43 Scripts/
44 CVEs and Advisories/
50 Evidence/
51 Findings/
52 Web Captures/
53 Artifacts/
60 Failures and Recoveries/
61 Logs and Timelines/
70 Lessons/
71 Research Campaigns/
72 Experiments/
73 Strategies/
80 Agents/
81 Tools and MCP/
90 Reports/
99 System/
Attachments/
```

## Note format

Each managed note uses YAML frontmatter with a stable node ID, type, lifecycle, scope, confidence, sensitivity, timestamps, source IDs, tags, author, and version. Typed graph relationships are projected as native `[[wikilinks]]`.

Stable identity does not depend on the filename or display title. Unsafe control characters, traversal segments, and Markdown constructs that could change link meaning are rejected or escaped.

## Synchronization

Synchronization is incremental and idempotent. Ti-Scale compares the canonical version, the last synchronized hashes, and the current file hash.

Possible states include:

- `synced`
- `database_ahead`
- `vault_ahead`
- `conflict`
- `quarantined`

If both sides changed, Ti-Scale creates a conflict record. It does not choose a winner silently. The operator may resolve to the database version, vault version, or a reviewed merge.

Operator-authored notes imported from the inbox become reviewable candidates unless policy allows another lifecycle. Malformed or unsafe notes are quarantined with a bounded explanation.

## Filesystem safety

- Every access stays under the configured root.
- Symbolic links are rejected in managed paths.
- Notes and attachments are written atomically.
- Files use restrictive modes.
- Attachments are type-limited, size-bounded, hashed, and deduplicated.
- Portable exports include a SHA-256 and node-version snapshot.
- Forgetting removes managed projections associated with the forgotten node.

Ti-Scale does not modify `.obsidian` settings.

## CLI

The CLI accepts `--db` and `--vault-root` explicitly. When omitted, the only supported fallbacks are `TI_SCALE_DATABASE_PATH` and `TI_SCALE_VAULT_ROOT`.

Verify a connected vault:

```bash
bun run brain:sync-verify --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Export eligible nodes:

```bash
bun run brain:export-obsidian --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id> --zip
```

Import changed Markdown:

```bash
bun run brain:import-obsidian --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Import creates a timestamped database backup first. Review the JSON receipt and any conflict or quarantine count.

## If only a few nodes are visible

This can be correct for a new database. Check:

- the graph lifecycle and scope filters,
- whether imported notes are still candidates,
- whether eligible memory nodes were projected,
- whether relationship edges exist with provenance,
- whether the selected graph view is local rather than global,
- whether vault sync reported `partial`, `conflict`, or `quarantined`.

Ti-Scale will not invent edges merely to make the graph denser. Create, import, or confirm supported relationships, then reindex and refresh the graph.
