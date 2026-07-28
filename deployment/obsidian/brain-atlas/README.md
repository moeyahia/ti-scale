# Brain Atlas profile

This profile configures Brain Atlas for the Ti-Scale Attack Knowledge Vault.
It classifies the canonical `type` frontmatter field rather than target names,
IP addresses, mission names, or engagement metadata.

The six anatomical regions have stable operational meanings:

- Frontal: attack vectors, tactics, techniques, procedures, and strategies.
- Parietal: products, exact versions, operating systems, runtimes, frameworks,
  databases, and security controls.
- Temporal: outcomes, failures, operational hazards, recoveries, alternatives,
  and reusable lessons.
- Occipital: discovery, fingerprints, CVEs, advisories, evidence patterns,
  validation patterns, detection, and research.
- Cerebellum: scripts, tools, versioned procedures, health checks, and
  remediation execution.
- Stem: topology patterns, topology roles, prerequisites, and reusable
  attributes.

The pinned release metadata is in `release.json`. The live Vault install must
contain the three verified upstream release assets plus this `data.json` at
`.obsidian/plugins/brain-atlas/`. Brain Atlas registers its own `Open atlas`
ribbon action; do not hand-edit Obsidian workspace files to force the icon.

## Reproducible profile

`data.json` is generated from
`shared/AttackBrainAtlasMappingRegistry.ts`, the same registry imported by the
server and browser graph. Every one of the 43 reusable attack types has exactly
one Brain Atlas kind, region, folder, and plain-language meaning.

```bash
bun run brain:atlas:profile:verify
bun run brain:atlas:profile:write
```

Verification fails if `data.json`, `release.json`, or any registry mapping
drifts. Regeneration preserves no live user preferences; the bounded installer
merges these owned mappings into the existing live `data.json` while preserving
unknown settings, pinned positions, palette, performance, and lobe visibility.

## Installation and health

The repository does not vendor the upstream executable assets. Put the exact
reviewed release files (`main.js`, `manifest.json`, `styles.css`, and `LICENSE`)
in a local non-symlinked directory, then run:

```bash
bun run brain:atlas:install --db /absolute/ti-scale.sqlite \
  --vault-root /absolute/vault-root --connection <connection-id> \
  --source /absolute/reviewed/brain-atlas-release --actor operator:local

bun run brain:atlas:health --db /absolute/ti-scale.sqlite \
  --vault-root /absolute/vault-root --connection <connection-id>
```

The current reviewed-corpus checkpoint is 68 mapped verified global nodes, no
unmapped nodes, region counts `14/22/8/5/12/7` in
frontal/parietal/temporal/occipital/cerebellum/stem order, 44 typed edges, and
42 unique undirected pairs. These are reconciliation facts for that checkpoint,
not permanent product constants; health must change as canonical knowledge is
added or retired.

The installer may update only `.obsidian/plugins/brain-atlas/` and the plugin's
presence in `.obsidian/community-plugins.json`. It preserves unrelated plugins
and never writes `.obsidian/workspace.json`.
