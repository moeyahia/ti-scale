# Explicit operator-preference import

Ti-Scale retains a preference only when the operator deliberately confirms it.
The preference importer is for reviewed product, presentation, accessibility,
and collaboration choices that were stated outside a mission-owned Guided
message. It does not infer personal traits and it cannot change authorization,
action policy, evidence integrity, secret handling, or other safety controls.

## Canonical records

Each accepted manifest item creates or replays the same linked records:

1. a pending `preference` memory candidate through `SecondBrainService.proposeMemory`;
2. a global, operator-authored `preference` node with lifecycle and confirmation
   both set to `confirmed` through `SecondBrainService.confirmCandidate`;
3. a confirmed `preference_profiles` record that points to the node;
4. a granted `preference_observations` record containing the typed value and
   reviewed manifest reference;
5. `memory_sources` provenance containing the manifest hash, timestamp, and a
   bounded redacted summary; and
6. a hash-linked, content-free `memory.preference.confirmed_from_manifest`
   audit record.

Stable candidate, profile, observation, and audit IDs make exact replays
idempotent. A changed candidate, profile, actor, reason, or source hash fails
closed instead of overwriting the previously confirmed preference.

## Manifest safety

The v2 JSON schema accepts only:

- one explicitly identified operator;
- one opaque source reference and UTC acquisition timestamp;
- global preference records with typed application domains;
- internal or private sensitivity; and
- the fixed `explicit_operator_confirmation` consent policy.

The manifest additionally has a mandatory, non-relaxable retention boundary:

- durable preferences only;
- one-time commands excluded;
- target-specific data excluded;
- credentials and secrets excluded; and
- authorization, scope, privacy, evidence, and runtime safety remain enforced.

Every item belongs to one controlled category: autonomy, Brain, communication,
deployment, documentation, memory, model selection, product, roadmap, or
visual. Unknown categories and unknown application domains fail closed.

Unknown fields, duplicate IDs or keys, empty values, excessive nesting,
credentials, authentication material, unsafe file ownership, symlinks,
writable path components, changing files, and a SHA-256 mismatch are rejected.
The manifest cannot contain commands, plugins, tool policy, provider settings,
or executable content.

## Reviewed Ti-Scale manifest

The supplied manifest is:

`deployment/runtime-config/operator-preferences.v2.json`

Its current reviewed byte hash is:

`2235aaee064c2017e031ec20bd657bc1af5432f96032d8b1f3d7c91c76e87aac`

Recalculate and review the digest after any intentional edit:

```bash
sha256sum deployment/runtime-config/operator-preferences.v2.json
```

The manifest contains twenty explicit durable preferences. The original nine
remain: readable technical language, attack-centric memory, titanium identity,
light main UI with a dark titanium Brain graph, mechanical and particle motion
with reduced-motion support, application-owned controls, later native iOS and
Android delivery, high autonomy within enforced policy, and evidence-first
explanations.

The full-conversation audit added eleven material preferences that the v1
manifest did not preserve:

| Category | Retained preference | Why it is durable |
| --- | --- | --- |
| Product | Standalone Ti-Scale product | Repeatedly established the product boundary rather than requesting a temporary refactor. |
| Deployment | Dedicated public repository | Explicit long-lived repository visibility and separation decision. |
| Documentation | Professional standalone documentation | Explicit documentation voice, scope, and independence requirement. |
| Model selection | Quality-first compatible model selection | Repeated instruction to use the best available model, bounded by current capability, policy, disclosure, and mission budgets. |
| Brain | Brain-shaped anatomy | Repeated final direction for two hemispheres, a spinal structure, no grid/background anatomy images, dot-based presentation, rotation, and neuron signals. |
| Visual | Faceted titanium modules | Repeated requirement that controls and panels rhyme with the central engineered form instead of generic cards. |
| Memory | Evidence-backed outcome status | Final decision to preserve both successful and failed reusable approaches with explicit, non-fabricated outcome state. |
| Memory | Private source linkage | Explicit requirement that artifacts such as scripts remain traceable to their source engagement without leaking transient target identity into reusable content. |
| Memory | Dedicated operator-preference category | Explicit request to retain durable operator preferences as visible, controllable memory. |
| Brain | Active connected Obsidian Second Brain | Repeated requirement that Vault connectivity be real and health-verified rather than decorative. |
| Brain | Audited context for every agent | Long-lived requirement that commanders and specialists actively use minimal, scope-safe Context Packs. |

The v1 file is retained as an audit artifact only. The v2 parser rejects it so
an incomplete preference set cannot be imported accidentally.

### Explicitly rejected as preferences

The audit deliberately did **not** retain the following classes:

- port assignments, tunnel commands, deployment timing, background-worker
  instructions, and requests to run an import now: these are one-time
  operational commands;
- target names, addresses, credentials, API keys, tokens, and live engagement
  state: these are sensitive or target-specific records, not preferences;
- requests to disable isolation, unlock every tool, skip backups, or confirm
  every future memory automatically: preferences cannot weaken authorization,
  evidence, privacy, recovery, or runtime safety;
- abandoned or superseded art-generation approaches and vendor/tool choices:
  the retained preference is the final visual principle, not a temporary
  production technique; and
- the earlier suggestion to omit failed attacks: it was superseded by the
  operator's final decision to retain failures with explicit outcome labels.

## Preview

Preview is read-only. It reports the exact normalized node and profile content,
stable IDs, current candidate disposition, content digest, and review hash.

```bash
bun run brain:import-preferences -- preview \
  --manifest /root/ti-scale/deployment/runtime-config/operator-preferences.v2.json \
  --manifest-sha256 2235aaee064c2017e031ec20bd657bc1af5432f96032d8b1f3d7c91c76e87aac \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor local-operator \
  --dry-run
```

Review every item and retain the emitted `previewHash`.

## Execute

Execution requires the exact preview hash and a durable operator reason:

```bash
bun run brain:import-preferences -- execute \
  --manifest /root/ti-scale/deployment/runtime-config/operator-preferences.v2.json \
  --manifest-sha256 2235aaee064c2017e031ec20bd657bc1af5432f96032d8b1f3d7c91c76e87aac \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor local-operator \
  --reason "Operator approved the reviewed Ti-Scale preference manifest" \
  --expected-preview-hash <REVIEWED_PREVIEW_HASH> \
  --acknowledge-explicit-operator-preferences
```

Run this only after the forward-only database integrity and ordinary
change-control checks. The command does not create a database copy and does
not connect, reconfigure, or write an Obsidian Vault.

## Verification

The following checks must all return zero after execution:

```sql
SELECT COUNT(*)
FROM memory_nodes
WHERE node_type = 'preference'
  AND (scope <> 'global'
    OR lifecycle_status <> 'confirmed'
    OR confirmation_state <> 'confirmed'
    OR author_type <> 'operator');

SELECT COUNT(*)
FROM preference_profiles profile
LEFT JOIN memory_nodes node ON node.id = profile.source_node_id
WHERE profile.confirmation_state <> 'confirmed'
   OR profile.consent_policy <> 'explicit_operator_confirmation'
   OR node.node_type <> 'preference'
   OR node.confirmation_state <> 'confirmed';

SELECT COUNT(*)
FROM preference_observations observation
LEFT JOIN preference_profiles profile ON profile.id = observation.profile_id
WHERE observation.consent_state <> 'granted'
   OR profile.id IS NULL;
```

An exact second execution must report only replay counters, must create no new
node, candidate, profile, observation, or audit, and must preserve the same
preview hash.

## Graph and Vault display

Preferences appear in the Memory Graph's **Operator profile** view. The generic
graph places them in **Operator controls**; the Brain Atlas anatomy places them
in the **Brain stem**. They remain absent from the default verified or
verified-plus-confirmed attack-knowledge scope because an operator preference
is confirmed consent, not verified attack evidence.

The connected Attack Knowledge Vault can expose the same canonical profile in
Obsidian only after the separate, version-pinned **Operator Profile scope
amendment** described in `docs/attack-knowledge-vault.md`. That amendment keeps
the existing connection and path, adds the `10 Operator` category, and permits
only:

- the confirmed Operator Profile root;
- confirmed preferences backed by an explicit-consent `preference_profiles`
  record; and
- the finite applicability-domain nodes reached by the manifest-owned
  `applies_to` relationships.

Arbitrary entity nodes, mission/target records, addresses, engagement names,
and restricted content remain outside the projection. The amendment itself
writes no notes. A later explicit export writes the profile notes and preserves
the canonical `prefers` and `applies_to` relationships as native
`[[wikilinks]]`.
