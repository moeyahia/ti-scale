# Contributing

Ti-Scale values small, reviewable changes with explicit evidence.

## Development setup

From the root of a Ti-Scale source checkout:

```bash
bun install --frozen-lockfile
cp .env.example .env
bun run check
```

Use an isolated local database, artifact root, and vault root. Never use client data or an operator's active vault as a test fixture.
Keep documentation, examples, fixtures, and generated metadata self-contained:
use Ti-Scale terminology, repository-relative paths, and synthetic operational
data.

## Change principles

- Preserve exactly two user-facing mission journeys: Autonomous and Guided.
- Keep authorization, policy, evidence, memory, and provider disclosure fail-closed.
- Use domain services and repositories; keep business logic out of route handlers.
- Derive UI options from registries and typed capability manifests.
- Store operational truth in canonical records, not component-local state.
- Do not represent raw output as verified evidence.
- Do not fabricate agents, metrics, topology, events, or memory.
- Do not bypass readiness to make a demonstration appear functional.
- Keep human-facing language precise and readable; place raw technical detail behind explicit disclosure.

## Frontend changes

Every interactive control needs:

- an accessible name and semantic role,
- keyboard and pointer behavior,
- loading, disabled, error, and success states,
- deterministic focus behavior,
- an interaction-manifest entry,
- browser coverage for every material state.

Use the tokenized design system. Respect reduced motion, 200% zoom, touch targets, and non-color status cues.

## Backend changes

- Validate inputs at the HTTP boundary and again at security-sensitive domain boundaries.
- Use prepared statements for user-controlled values.
- Use transactions for state plus event/outbox changes.
- Require idempotency keys for duplicate-sensitive mutations.
- Preserve append-only audit and evidence history.
- Add migrations; never edit a migration already used by a shared deployment.
- Add a structured error code, operator explanation, retryability, and remediation.
- Test process interruption and replay when changing durable workflow behavior.

## Memory and vault changes

- Preserve provenance, lifecycle, sensitivity, scope, author, and version.
- Keep database state canonical.
- Use atomic writes and path policy for managed files.
- Surface conflicts; never overwrite operator edits silently.
- Test forgetting across search, graph edges, context items, embeddings, caches, and vault projections.
- Do not allow reusable memory to contain secrets.

## Research changes

Strategy candidates must stay inside the typed mutable schema. Evaluation, holdout, authorization, disclosure policy, and deployment controls are immutable to candidates. Promotion stages cannot be skipped.

## Tests required

Run at minimum:

```bash
bun run isolation:verify
bun run typecheck
bun run typecheck:e2e
bun run test
bun run build
```

Run focused Playwright tests for changed surfaces and the full browser matrix before requesting release approval. Update the interaction manifest and visual baselines in the same change as the control they describe.

## Pull requests

Include:

- operator-visible outcome,
- architecture and data impact,
- safety and privacy impact,
- tests and measured results,
- migration or rollback needs,
- known limitations.

Do not include secrets, private target data, generated databases, local vault notes, or unredacted browser traces.
