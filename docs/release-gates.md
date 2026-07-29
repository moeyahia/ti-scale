# Release gates

## Product-wide validation status

This checklist tracks complete product-wide validation. It does not determine
whether Ti-Scale is the active standalone service. Current capability is
established separately by installed runtime manifests and live readiness
receipts. Known interaction, browser, visual, soak, and human-review gaps remain
listed here until they are closed.

The local release attestation is a scoped digest and provenance receipt. It is
not a substitute for the remaining product-wide validation or explicit human
approval.

## Gate 1: source and build integrity

- Clean, pinned Git revision
- Reproducible dependency installation
- Strict TypeScript passes
- Production build passes
- Source and build artifact manifests recorded
- Identity asset hashes recorded
- No secrets, databases, logs, private artifacts, or vault notes in the release
- No focused, skipped, quarantined, or retry-masked release tests

## Gate 2: runtime truth

- Database integrity and foreign keys pass
- All required migrations pass from an empty database and a supported prior schema
- Provider, specialist, tool, and policy manifests are fresh and typed
- Autonomous enforcement and Guided exact-step enforcement are proven
- Cancellation, child cleanup, leases, heartbeats, checkpoints, restart, and resume pass
- Every unavailable dependency produces a specific degraded or blocked state
- No production path displays fixture or simulated operational data

## Gate 3: interaction completeness

- Every interactive element exists in `tests/interaction-manifest.json`
- Every manifest option is activated in every material state
- Rendered-element audit has no missing or stale entries
- Every generated internal URL resolves
- Back, forward, refresh, copied links, offline, and reconnect states pass
- All error states explain the cause and corrective action
- Keyboard and pointer behavior produce the same durable result

The manifest's `knownGaps` list must be empty.

## Gate 4: browser and visual quality

- Chromium, Firefox, WebKit, enterprise Chromium, Android-style Chromium, iPhone-style WebKit, and tablet projects pass
- Supported viewport and 200% zoom projects pass
- No uncaught browser errors, unhandled rejections, unexpected console errors, or undeclared network failures
- Visual baselines approved for every primary route and material state
- No essential text clipping, overlap, ambiguous truncation, or unintended horizontal overflow
- Reduced motion remains fully usable
- No critical or serious accessibility violations

## Gate 5: data, evidence, and memory

- Raw logs remain separate from evidence
- Finding verification cannot bypass evidence policy silently
- Evidence routes and artifacts pass direct navigation and refresh
- Structured failure diagnosis exists for every blocked or failed object
- Context Packs are recorded at required lifecycle hooks
- Scope-isolation and cross-engagement leakage tests pass
- Forgetting removes content and derived retrieval state
- Vault round trip, atomic writes, import, connected-Vault export, conflict handling, quarantine, repair, and reindex pass; portable archive endpoints and UI remain policy-disabled
- No-backup enforcement, forward recovery, and reconciliation are rehearsed

## Gate 6: research safety

- Provider exposure is sanitized and receipted
- Prompt-injection tests pass
- Candidates cannot modify authorization, policy, evaluator, holdout, or deployment controls
- Metrics are recomputed locally
- Integrity receipts bind strategy, benchmark, evaluator, environment, events, evidence, and metrics
- Promotion stages cannot be skipped
- Strategy-version reversal is proven without copying application, database, or Vault payloads
- No live mission self-modifies its active strategy

## Gate 7: performance and reliability

- Performance budgets measured on supported desktop and mobile hardware
- Large event, evidence, log, and graph fixtures remain usable
- Event replay and reconnect storm tests pass
- No sustained memory leak in long sessions
- Cancellation leaves no orphaned active work
- Minimum 72-hour automated soak passes
- Operator acceptance period completes without an unresolved release-scope defect

## Gate 8: deployment approval

- Forward-only deployment and recovery procedures are documented and rehearsed
- Static, server, database, artifact, strategy, and Vault forward-recovery boundaries are understood
- Monitoring and on-call ownership are assigned
- Known release-scope defect list is empty
- The complete test-evidence retention policy is explicitly approved and the
  required evidence is durably reviewable
- Explicit human approval is recorded

Only after every gate passes may a build be described as production-ready.

## Suggested evidence commands

```bash
bun run check
bun run test:e2e:release-local
bun run release:attest
bun run db:verify --db /var/lib/ti-scale/data/ti-scale.sqlite
```

Record hashes for command output, browser reports, visual approvals,
accessibility results, performance results, soak receipts, Vault
reconciliation, and the signed release decision only through an explicitly
approved evidence-retention mechanism. The current no-retained-copy policy
limits what can be claimed as durably retained release evidence; it does not
redefine the active service or its deployment mode.
