# Testing

Testing is part of the Ti-Scale product contract. A rendered page or successful build is not sufficient evidence that a control works.

## Local verification

Install dependencies and browser binaries:

```bash
bun install --frozen-lockfile
bunx playwright install
```

Run the primary checks:

```bash
bun run isolation:verify
bun run typecheck
bun run typecheck:e2e
bun run test:policy
bun run test
bun run build
```

Or run the combined gate:

```bash
bun run check
```

## Focused suites

```bash
bun run test:interaction-manifest
bun run test:process-restart
bun run test:e2e
bun run test:e2e:accessibility
```

The local release-profile browser command is:

```bash
bun run test:e2e:release-local
```

It requires the release fixture environment defined by the test harness. Do not point release tests at a live operator database or vault.

## Browser matrix

The Playwright configuration defines:

- Chromium desktop
- Firefox desktop
- WebKit desktop
- Chromium enterprise compatibility
- Android-style Chromium
- iPhone-style WebKit
- tablet Chromium
- 360×800 and 390×844 phone viewports
- 1024×768, 1280×800, 1440×900, 1920×1080, and 2560×1440 desktop viewports
- a 200% zoom contract

The release profile uses zero retries and one worker, forbids focused or
masked tests, and generates screenshots, traces, video, and JSON/HTML reports
on failure. Local reports remain disposable test output. The hosted workflow
removes them rather than uploading or archiving them under the current
no-retained-copy policy.

## Interaction manifest

`tests/interaction-manifest.json` is the machine-readable inventory for visible and keyboard-reachable controls. Each entry records route, fixture state, accessible role and name, input method, expected state transition, API or event side effect, error behavior, reversibility, browser coverage, viewport coverage, and test IDs.

The browser audit compares rendered interactive elements with this manifest. Missing UI entries and stale manifest entries are defects.

The manifest currently records explicit known gaps. Therefore, its presence and validation do not constitute 100% interaction coverage. Release requires the gap list to reach zero and every material option to be activated in every relevant state.

The current source contains 715 interaction groups and nine explicit known-gap
records. The source-bound manifest validator passes 51/51 tests with 4,815
assertions. It verifies the manifest schema, control collections, option
bindings, fixture references, and test mappings; it is not an exhaustive
whole-product option-activation receipt. The earlier Chromium 1440 rendered
control crawl predates this 715-group source and must not be presented as the
current aggregate activation result.

The current test-policy scan covers 532 test files: 464 unit/module files and
68 browser files. It reports zero skipped, focused, todo, expected-failure, or
retry-masked tests. The standalone-source boundary scans 1,212 production
files. Application/server typecheck, E2E typecheck, and `git diff --check` all
pass. These are source-quality gates; they do not replace browser activation,
visual approval, soak evidence, or human release approval.

The current complete unit and integration run passed 2,844/2,844 tests across
464 files with 30,016 assertions in 865.07 seconds, with zero failures and zero
skips. The combined focused rerun for the repaired migration-56 expectations
and Research stage-run mutation-authority inventory passed 15/15 tests with
1,080 assertions. These clean source results do not close the nine known
interaction gaps, four unapproved visual candidates, preview/soak period, or
human sign-off.

### Current bounded Research Lab receipt

The Research Lab is represented by 31 interaction groups. Its canonical browser paths cover the three human-owned campaign drafts, exact setup approval, retryable and optimistic conflicts, durable synthetic-run queueing and cancellation, authoritative local-worker completion, exact start/cancel request retention, explicit discard, response-loss reconciliation without mutation replay, and the signed human-review, shadow, bounded-canary, verification, rejection, stale, supersession, and forward-rollback lifecycle.

The final retry-free Research Lab functional receipts pass 182/182 cases across all 13 configured non-Brain-renderer projects: Chromium, Firefox, WebKit, enterprise Chromium, Android Chromium, iPhone WebKit, tablet Chromium, Chromium at 360, 1024, 1280, 1920, and 2560 pixels, and Chromium at 200% zoom. They contain zero retries, skips, or unexpected failures. The three-engine desktop subset also passes 42/42 with three workers after shared test state was isolated. The generated Playwright receipts are local, ignored test artifacts rather than versioned release attestations.

The Research backend suite passes 135/135 tests with 1,009 assertions. For a
file-backed application, Research uses a dedicated connection to the same
canonical WAL database. When another writer holds the database, a Research
mutation returns a bounded retryable `503 research_store_busy` response instead
of delaying authentication; the same idempotency key can complete and replay
after the writer releases the lock. Source implements the hash-pinned
private-holdout descriptor boundary, server-resolved
`development → validation → private hidden holdout` execution order, opaque
client projection, local evaluation and integrity signing,
restart/idempotency handling, and zero public-provider exposure; the focused
private-holdout boundary separately passes 4/4 tests with 54 assertions. These
bounded results do not prove a provisioned operator-owned descriptor, a live
public-provider path, canonical browser activation of the validation or private
hidden-holdout stages, whole-manifest option activation, cross-browser visual
approval, or the complete full-product browser matrix.

### Current bounded official-NVD receipt

The mission-scoped official-NVD control has dedicated loading, redacted-success, precise dependency-failure, and bounded-retry browser paths. Its focused matrix currently passes 26 expected cases across all 13 applicable general projects with zero retries, skips, unexpected failures, or flaky cases. Local Playwright receipts under the ignored `test-results/` tree are transient execution output, not durable release evidence. The deterministic image is integrity-bound in the checked-in visual-baseline registry as `visual.cve-applicability.official-nvd-receipt.chromium-1440`, but it remains automated drift evidence rather than human visual approval. Durable release evidence would require a future explicitly approved retention mechanism; none is active under the current no-retained-copy policy.

These browser fixtures intercept only the mission-scoped HTTP result. They do not prove a deployed systemd credential, live public-NVD sidecar attestation, or canonical production audit record; those remain explicit release-environment checks.

### Current bounded visual registry

Nineteen deterministic Chromium 1440 baselines currently provide 55 mappings
across 54 unique interaction entries. The bounded Autonomous intake baseline
maps only values and states visible in its final server-normalized review
receipt; it does not claim visual coverage of the earlier edit controls or
every option state. The Evidence baseline maps Begin validation only to the
directly visible persisted non-evidence verification form, not to candidate
selection, rejection, demotion, or later provenance/custody disclosures. The
remaining 661 interaction groups have no mapped visual baseline. The registry
is automated drift evidence only: cross-browser visual approval and human
release approval remain false until the complete visual gate is reviewed.

Run the registered carrier tests with `bun run test:e2e:visual-registry`. Each
carrier receives its own disposable database, API process, UI process, and
Vault root. This prevents a valid state created by one carrier—such as an
active Obsidian Vault—from silently changing another carrier's expected
material state. The runner never updates snapshots and continues through all
carriers so every mismatch is reported in one bounded invocation.

The latest complete registry run executed all 14 carriers with
`snapshotsUpdated=false`: 10 matched their approved bytes and four returned
deterministic screenshot mismatches solely because their candidate images have
not been human-approved. Those four are the canonical exact-runtime Autonomous
intake state, the reduced-motion Brain canvas (an exact 30-pixel difference),
Plan restore, and Plan in-flight decision. They are visual-approval gaps, not
functional-test defects, and no baseline was overwritten. The runner writes
one JSON result per carrier; the four exact candidate-result paths are:

- `test-results/results/visual-registry-1685720-7-e2e-mission-intake-autonomous-minimal.json`
- `test-results/results/visual-registry-1685720-11-e2e-brain-graph-visual-canvas-table.json`
- `test-results/results/visual-registry-1685720-12-e2e-plan-changes-version-restore.json`
- `test-results/results/visual-registry-1685720-13-e2e-plan-changes-inflight-resolution.json`

### Current reviewed plan-version rollback receipt

The mission Plan surface can compare an active plan with an earlier superseded version and prepare a rollback only as an immutable `PlanChangeRequest`. The server requires an operator reason, keeps the historical record unchanged, rechecks current scope, policy, specialist readiness, dependencies, and in-flight work, and requires a separate apply mutation. Apply creates a new version without starting an action.

Focused tests also prove that changed review material invalidates the prior approval, cross-run identifiers do not disclose plan existence, empty or malformed historical plans fail closed, repeated deliberate restores do not collide at the version-integrity boundary, and a lost browser response reuses the same request-derived idempotency key. Post-mutation reads use the canonical reconciliation boundary so an older in-flight read cannot replace the accepted result.

The retry-free local browser receipt currently includes the complete five-test Chromium plan-change suite, five consecutive desktop-WebKit restore runs, and one restore run across Firefox, WebKit, enterprise Chromium, Android Chromium, iPhone WebKit, and tablet Chromium. These focused results do not supply the missing release-wide visual approvals, soak evidence, or human sign-off.

## Test layers

### Unit

Unit tests cover schemas, state machines, policies, repositories, registries, memory safety, event behavior, retry and loop logic, research policy, identity assets, and frontend contracts.

### Integration

Module tests cover database migrations, runtime state, event delivery, mission services, evidence semantics, vault synchronization, process restart, cancellation, failure diagnosis, and route contracts.

### Browser

Browser tests exercise authentication, mission intake, route reliability, decisions, evidence, run intelligence, plan changes, blocked-state recovery, Second Brain, vault conflicts, accessibility, zoom, and system surfaces using isolated canonical fixtures.

Fixtures may label development data, but production paths must never substitute fixture data for unavailable services.

The current Command Palette functional slice passes 24/24 cases across
Chromium 1440, Firefox 1440, and WebKit 1440 with zero retries. It covers
navigation, contextual Autonomous run commands, exact resume and cancellation,
candidate-memory creation, and truthful degraded-domain behavior.

## Browser failure policy

Browser tests fail on:

- uncaught exceptions or unhandled rejections,
- unexpected console errors,
- undeclared non-success network responses,
- missing routes or broken links,
- stuck loading states,
- keyboard traps or focus loss,
- control overlap and essential overflow,
- state changes not reflected after mutation,
- stale data after refresh or reconnect.

## Accessibility

Run automated accessibility scans on material states and verify keyboard traversal, visible focus, name/role/value, critical live regions, reduced motion, non-color status cues, 200% zoom, and the graph's table alternative. Release allows no critical or serious accessibility violations.

The current clean-source automated axe matrix passed 390/390 configured checks
in 9.2 minutes across all 13 general projects, with zero retries, skips,
unexpected failures, or flaky results. It verifies two repairs found during the
matrix: lazy Command Palette loading no longer aborts canonical or contextual
lookups during React StrictMode's development probe, and mobile Autonomous
intake checkboxes now use a 24×24 CSS-pixel target instead of 18×18. The exact
result is `test-results/results/1631796-1785187784400.json`; the corresponding
report is `test-results/html/1631796-1785187784400/index.html`. This is evidence
for the automated axe gate only. It does not replace keyboard, assistive
technology, manual usability, complete WCAG, visual, or human release review.

## Build, bundle, and Web Vitals budgets

The current production build passes its measured bundle gate. Initial
JavaScript is 117,338 bytes gzip against the 250,000-byte budget. The largest
lazy/non-initial JavaScript chunk is 140,177 bytes gzip against the
150,000-byte budget.

The production-byte Web Vitals run
`web-vitals-worker-race-20260727T233800Z` passed 3/3 cases with zero retries,
unexpected failures, skips, or flakes. Its source-integrity receipt reports
`sourceStable=true`. Desktop p75 was FCP 180 ms, LCP 1,188 ms, INP 64 ms, and
CLS 0.0005764481658307613. Mid-tier-mobile p75 was FCP 1,476 ms, LCP 2,456 ms,
INP 88 ms, and CLS 0.0019733796621257387. The local receipt is under
`test-results/performance/web-vitals-worker-race-20260727T233800Z/`.

A dedicated-worker teardown race found by this run was repaired only in the
test harness; production application bytes were unchanged. This bounded
performance result does not replace concurrent-load evidence, the 72-hour
soak, preview acceptance, approved visuals, or human release sign-off. The
guarded preview remains on schema 47 while reviewed source is on schema 56; no
source candidate was deployed and cutover remains closed.

## Release evidence

A release review requires:

- unit and integration results,
- browser HTML and JSON reports,
- failure traces, screenshots, and videos,
- approved visual baselines,
- interaction coverage,
- accessibility results,
- migration and vault reconciliation receipts,
- performance and soak reports,
- release attestation and human sign-off.

The current no-retained-copy policy prevents the hosted workflow from
preserving this complete evidence set after its runner exits. Therefore a
successful hosted run is an execution result, not durable release attestation,
and the cutover gate remains closed. Do not describe transient runner output as
archived evidence.

See [Release gates](release-gates.md) before describing any build as production-ready.
