# Obsidian vault

Ti-Scale can project eligible Second Brain records into an Obsidian-compatible Markdown vault. The vault is portable and human-editable, while SQLite remains the transactional source of truth.

## Outcome labels

Evidence-backed `outcome_tags` (`success` and `failed`) are independent from
historical source claims. Source-reported history is projected through
`reported_outcome` and the filterable `ti-scale/reported-outcome/*` tag. A
reported label never proves execution or creates a canonical attack outcome.
See [Historical reported outcomes](./historical-reported-outcomes.md).

## Connection requirements

A vault is active only after all of these conditions are true:

1. `TI_SCALE_VAULT_ROOT` is an absolute allowed filesystem root.
2. Memory control permits vault projection.
3. The operator selects a path inside the allowed root and explicitly grants filesystem permission.
4. A temporary filesystem round trip proves write, read, rename, and delete.
5. The connection record is persisted as connected.

No environment boolean can substitute for these checks or make the user interface report an active connection.

The health test cleans up its temporary directory before reporting success. A missing or inaccessible configured directory fails closed; recovery checks do not silently recreate a disappeared vault.

### Expanding the Attack Knowledge Vault to confirmed knowledge

The reviewed Attack Knowledge Vault starts with verified reusable knowledge.
When an operator later chooses to include explicitly confirmed reusable attack
knowledge, Ti-Scale amends the existing preset connection in place. It does not
create a second Vault, rename the directory, or replace its synchronization
history.

The amendment is deliberately narrow and requires all of the following:

- the exact verified-only preset connection ID and `updated_at` version;
- the exact reviewed old and new policy hashes;
- Memory Control permission for both verified and confirmed projection;
- explicit filesystem permission and a fresh write/read/rename/delete proof on
  the existing directory;
- an explicit scope-amendment acknowledgement and operator-attributed reason;
- an idempotency key and a tamper-evident audit record.

Only `sync_scope_json` and the connection version change atomically. The
connection ID, Vault path, existing notes, sync states, conflicts, and Brain
Atlas installation are retained. The amendment itself writes and deletes zero
Markdown notes. A separate explicit export or synchronization action projects
the newly eligible confirmed nodes.

## Reusable directory structure

Managed notes are classified by reusable attack knowledge, not by engagement or target:

```text
00 Inbox/
20 Technology Products/
21 Versions and Fingerprints/
22 Software Stacks/
23 Security Controls/
30 Topology Patterns/
40 Vulnerabilities and Weaknesses/
41 Attack Vectors/
42 Techniques and Procedures/
43 Prerequisites and Attributes/
44 Discovery and Fingerprints/
45 Scripts and Tools/
50 Outcomes and Validation/
51 Operational Hazards/
52 Recovery and Alternatives/
53 Detection and Remediation/
60 Strategies and Lessons/
61 Research/
Attachments/
```

Mission names, box names, addresses, client identifiers, journey labels, authorization records, raw logs, and raw evidence stay in the protected transactional store. They are not projected into reusable Markdown. Eligible notes may contain an opaque provenance receipt that resolves only through the authorized local application.

## Note format

Each managed note uses YAML frontmatter with a stable knowledge ID, type, lifecycle, applicability constraints, confidence, sensitivity, disclosure class, freshness, opaque provenance receipts, tags, author, and version. Typed graph relationships are projected as native `[[wikilinks]]`.

Reusable attack notes also contain `brain_region`. Its value is generated from
the same 43-type registry used by the server and the in-application renderer;
an imported value that disagrees with the note type is rejected. This prevents
the Obsidian view and Ti-Scale view from silently assigning the same knowledge
to different lobes.

Procedure and hazard notes also preserve normalized stack/version constraints, prerequisites, ordered steps, bounded parameters, target-state transitions, outcome counts, unsafe retry conditions, health gates, recovery patterns, and safer alternatives. Secret-bearing or target-identifying values are rejected or quarantined.

Stable identity does not depend on the filename or display title. Unsafe control characters, traversal segments, and Markdown constructs that could change link meaning are rejected or escaped.

Leading-dot technology names are made visible on every supported platform. For
example, `.NET Runtime` is projected with a `dot-net-runtime-…md` filename while
its original title and stable ID remain in YAML. A previously tracked
`.net-…md` projection is moved atomically when it is unchanged. If the operator
edited the hidden note or the visible destination is occupied by different
content, Ti-Scale preserves it and opens the normal reconciliation path instead
of overwriting either file.

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
- In-place projection receipts include canonical note hashes and node versions.
- Vault archive and portable ZIP creation are disabled by operator policy.
- Forgetting removes managed projections associated with the forgotten node.

Ordinary note synchronization does not modify `.obsidian`. The explicit,
bounded Brain Atlas installer is the only supported exception: it installs one
hash-pinned plugin release, reconciles only Ti-Scale-owned taxonomy mappings,
preserves operator visual settings and unrelated plugins, and never edits
`workspace.json`.

## Brain Atlas plugin

Brain Atlas is optional. It adds an `Open atlas` action to Obsidian's native
ribbon and renders the reusable knowledge graph as six semantic regions:

- frontal — vectors, tactics, techniques, procedures, and strategies;
- parietal — products, versions, software stacks, and security controls;
- temporal — outcomes, hazards, recoveries, alternatives, and lessons;
- occipital — vulnerabilities, discovery, evidence, validation, and research;
- cerebellum — versioned procedures, scripts, tools, health checks, and remediation;
- stem — topology, prerequisites, and reusable attributes.

The authoritative mapping is
`shared/AttackBrainAtlasMappingRegistry.ts`. The deployment profile is generated
and checked rather than maintained as a second handwritten taxonomy:

```bash
bun run brain:atlas:profile:verify
bun run brain:atlas:profile:write   # intentional profile regeneration only
```

Install from a local directory containing the exact reviewed `main.js`,
`manifest.json`, `styles.css`, and `LICENSE` files:

```bash
bun run brain:atlas:install --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id> \
  --source /absolute/reviewed/brain-atlas-release --actor operator:local
```

The installer rejects a symlinked source, a changed byte, a version mismatch,
or a missing license before mutating the Vault. Read-only health verifies the
connection, enablement, pinned hashes, release metadata, profile coverage,
mapped/unmapped nodes, lobe counts, typed edges, and unique linked pairs:

```bash
bun run brain:atlas:health --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

The authenticated read-only API exposes the same receipt at
`GET /api/v2/brain/vault/brain-atlas`.

## CLI

The CLI accepts `--db` and `--vault-root` explicitly. When omitted, the only supported fallbacks are `TI_SCALE_DATABASE_PATH` and `TI_SCALE_VAULT_ROOT`.

Verify a connected vault:

```bash
bun run brain:sync-verify --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Project eligible nodes into the connected Vault in place:

```bash
bun run brain:export-obsidian --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

This command synchronizes canonical Markdown notes only. It does not create an
archive, database copy, Vault copy, or portable handoff.

For a reviewed full projection after confirmed candidates have been promoted
and the connection scope amendment has succeeded, first create a read-only,
content-hashed plan:

```bash
bun run brain:project-vault-all:preview --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Review `eligibleNodeCount`, `writeRequiredNodeCount`,
`attentionRequiredNodeCount`, and `issues`. Execution is deliberately refused
when an operator-edited/untracked note, pending import, open conflict, unsafe
file, or unexpected synchronization row needs attention. Apply the exact
reviewed plan with its returned `planHash`:

```bash
bun run brain:project-vault-all:execute --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id> \
  --expected-plan-hash <reviewed-plan-sha256> \
  --approved-by operator:reviewed-import --approve-projection \
  --concurrency 4 --progress-interval 250
bun run brain:project-vault-all:reconcile --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id> \
  --expected-plan-hash <reviewed-plan-sha256>
bun run brain:sync-verify --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
bun run brain:atlas:health --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Projection is note-atomic, bounded, resumable, and idempotent. A successful run
writes a restrictive, content-free receipt under
`.ti-scale/projection-receipts/`. Final reconciliation compares the complete
eligible population with distinct synchronization state, canonical Markdown
hashes, stable IDs, native wikilinks, attachment links, managed files, open
conflicts, and reusable-memory secret policy. A clean `sync-verify` result alone
does not prove every newly eligible node was exported; the full reconciliation
receipt does.

Portable Vault archives are not available. The CLI rejects `--zip` and
`--brain-atlas`. To use the knowledge on another host, configure a reviewed live
Vault connection there and synchronize in place; do not copy a generated
snapshot. SQLite on the Ti-Scale host remains canonical.

Import changed Markdown:

```bash
bun run brain:import-obsidian --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Import is forward-only and does not create a database or Vault backup. The JSON
receipt reports `"backupPolicy": "disabled_by_operator"`; review its conflict
and quarantine counts before accepting imported changes.

## If only a few nodes are visible

This can be correct for a new database. Check:

- the graph lifecycle and scope filters,
- whether imported notes are still candidates,
- whether eligible memory nodes were projected,
- whether relationship edges exist with provenance,
- whether the selected graph view is local rather than global,
- whether vault sync reported `partial`, `conflict`, or `quarantined`.

Ti-Scale will not invent edges merely to make the graph denser. Compile eligible reusable knowledge, confirm supported relationships, then reindex and refresh the graph. Imported engagement records do not become one node per target; they consolidate into stack, procedure, outcome, hazard, and recovery patterns.
