# Validation status

This page separates evidence from the reviewed source tree from explicitly
labelled observations of the guarded preview installation. It is intentionally
conservative: neither class of evidence is a release approval.

## Reviewed source and guarded-preview truth

| Area | Current reviewed truth |
| --- | --- |
| Product version | `0.1.0-preview.0` |
| Journeys | Exactly two: Autonomous and Guided |
| Source database | Ordered migrations through schema version 56 |
| Guarded-preview database | The running installation remains at version 47. The nine-version difference is a deployment blocker, not permission to migrate or activate a new candidate |
| Guided runtime | A local manual planner and seven reviewed exact-decision local-tool bindings are implemented; these are tool bindings, not seven ready product agents. Every binding remains configuration- and receipt-gated, and provider-backed execution is not implied |
| Autonomous runtime | Three bounded local safe-recon action classes are implemented behind an exact runtime manifest; an unconfigured installation remains fail-closed |
| OpenRouter | Optional, planning-only Guided readiness with a private credential file and fresh durable attestation; it does not grant mission execution |
| Public NVD | Optional, loopback-only, one-tool read adapter for a canonical mission CVE; it cannot contact the assessed target or grant execution |
| Local tools | Registry-backed target-free readiness supports curl, FFUF, host, ncat, capability-free Nmap, ping, and WhatWeb; source availability never grants mission authority |
| Generic MCP execution | Not attached to the default server |
| Second Brain | Canonical memory graph, lifecycle controls, scoped retrieval, and persisted Context Packs are implemented; memory use must be proven by a persisted pack |
| Obsidian | Connection, round-trip health, projection, import, and conflict handling are implemented; export is a forward-only Markdown projection and never creates a restorable application or database archive; no Vault is bundled or active by default |
| Agent Fleet and model assignment | Source exposes all 12 canonical product-agent roles. The guarded preview currently binds five roles: ReconScout and WebBreaker have complete mounted coverage, while SessionRunner, ReportSmith, and VulnIntel have partial capability coverage. CredSmith, ADAttackMapper, CloudSentinel, ReverseSage, FuzzSmith, OSINTSeeker, and SecretHunter are offline. The live catalog exposes one local deterministic enforced model compatible with the five bound roles; it offers no alternative provider, reasoning-effort, or fallback selection, and the seven offline roles have no compatible selectable model |

## Current release blockers

- The interaction manifest contains 715 control groups and nine explicit known-gap records. Its source-bound validator passes 51/51 tests with 4,815 assertions, but this validates the inventory contract rather than activating every option in every material browser state.
- The earlier Chromium 1440 rendered-control crawl predates the current 715-group source and is not current aggregate activation evidence. The last whole-manifest derivation before the current model-setting and Research expansions required 3,546 Chromium 1440 activations and 46,174 across all 14 configured release projects; that aggregate count is now superseded for current-source activation accounting. The model-setting slice independently proves its 910/910 source-bound requirements and the bounded Research functional slice proves 182/182 retry-free cases across all 13 configured non-Brain-renderer projects, but no enforced current-source aggregate receipt set proves the complete manifest.
- Nineteen Chromium 1440 visual baselines provide 55 mappings across 54 unique interaction entries; 661 interaction groups do not yet have a mapped baseline. The Autonomous intake expansion covers only the final server-normalized review receipt, while the Evidence expansion maps Begin validation only to the directly visible persisted non-evidence verification form.
- The isolated visual-registry runner executed all 14 unique screenshot
  carriers against dedicated disposable databases, APIs, UIs, and Vaults with
  zero retries and `snapshotsUpdated=false`. Ten carriers match their approved
  baselines exactly. Four deterministic candidates remain intentionally
  unapproved: the canonical exact-runtime Autonomous intake state, the
  reduced-motion Brain graph (an exact 30-pixel difference), Plan restore, and
  Plan in-flight decision. These are visual-approval gaps rather than
  functional defects, and no baseline was overwritten.
- Cross-browser visual approval and explicit human release approval are false.
- The configured 390-case automated axe matrix, current Chromium route/href
  crawl, and bounded production-byte Web Vitals run are green, but they are not
  a complete WCAG or performance release approval. The retry-free aggregate
  option-activation matrix, concurrent-load evidence, 72-hour soak, and preview
  acceptance period are not complete.
- The guarded deployment proves only three Autonomous safe-recon classes and seven Guided local bindings; broader action classes and provider-backed Guided execution remain unavailable.
- The sealed 2026-07-21 historical inventory receipt and its active Vault
  projection are reconciled. A metadata-only rescan found 232 stable post-seal
  source changes (229 new inventory paths and three changed paths), so a new
  receipt-bound delta import remains required.
- Historical success/failure promotion remains closed because the imported corpus does not contain canonical attempt/evidence bindings. Future imports still require their own source receipts, reconciliation, authorization, and forward-only recovery policy; source code alone is not import evidence.
- A prior schema-37 candidate passed its pre-activation quality gates but exceeded the old 30-second readiness deadline during a cold multi-gigabyte database integrity check. The current release path no longer creates or retains rollback payloads; early authentication admission and a database-sized deadline must be proven before another forward-only deployment.
- The installed preview exposed a release-start permission defect: its unprivileged wrapper could not traverse the root-owned transaction directory and entered a restart loop even though the committed installation journal was valid. A narrow traverse-only ACL restored the running installation without changing its release pointer. Source now creates release-start state through descriptor-bound, no-follow, crash-durable writes; preserves special mode bits; installs the exact traverse-only service ACL; proves the service can traverse and read the committed journal but cannot list or write the root; and verifies the final journal inode and digest. The 71-test focused regression is green, but that source repair has not been deployed and must pass the next forward-only release qualification.
- The guarded preview remains on schema 47 while reviewed source is on schema
  56. No current source candidate has been deployed, no preview/soak period has
  completed, and no human sign-off or cutover approval has been granted.

The source therefore remains **not release-eligible**. See [Release gates](release-gates.md) for the complete approval contract.

## Latest focused local validation evidence

The following evidence was collected through 2026-07-27 from the reviewed source tree and guarded preview deployment. These are focused engineering gates, not a substitute for the complete release matrix, soak period, visual approval, or human release decision.

| Gate | Result |
| --- | --- |
| Current complete source unit and integration suite | 2,844/2,844 passed across 464 files with 30,016 assertions in 865.07 seconds; zero failures and zero skips |
| Repaired schema-56 and mutation-authority cases | The combined focused rerun passed 15/15 tests with 1,080 assertions after aligning migration-56 expectations and registering the authenticated Research stage-run mutation in the authority inventory |
| TypeScript | Application/server typecheck and E2E typecheck passed |
| Standalone source boundary | 1,212 production files across frontend, backend, scripts, and shared contracts scanned; protected legacy UI imports, repository escapes, linked package dependencies, Vite boundary drift, and browser-namespace drift rejected |
| Test-policy integrity | 532 test files scanned: 464 unit/module files and 68 browser files. Zero skipped, focused, todo, expected-failure, or retry-masked tests were found |
| Crash-safe functional release | The current controller commits forward only, performs final verification before terminal success, records content-free recovery state, and retains no restorable payload |
| Complete protected-legacy regression | The fresh read-only legacy `check` completed in 34.656 seconds: server, client, and browser TypeScript checks passed; 1,144 unit tests passed with 0 failures and 6,279 assertions across 162 files; 81 integration cases passed across the OpenRouter, OpenRouter-await, and Board MCP gates; the server entry and final production builds passed. Before/after worktree fingerprints were identical, and the protected application remained healthy on port 3131 |
| Current interaction manifest contract | Current source has 715 groups and nine known gaps. The source-bound validator passed 51/51 tests with 4,815 assertions. This proves the manifest contract and mappings, not aggregate browser option activation |
| Current route and generated-href crawl | 36/36 Chromium 1440 route cases passed with zero retries, skips, unexpected failures, or flakiness. The crawl inspected 78 generated hrefs, traversed all 55 crawlable internal hrefs, and found no generated 404, malformed link, unsupported fragment, or route error |
| Current visual-registry integrity | 19/19 PNG records remain integrity-bound to exact bytes and dimensions. The isolated browser registry ran all 14 carriers without retries and with `snapshotsUpdated=false`: 10 matched exactly, while the canonical exact-runtime Autonomous intake state, reduced-motion Brain canvas (30 exact pixels), Plan restore, and Plan in-flight decision returned deterministic candidate mismatches pending human approval. These four are not functional failures. Exact result artifacts: `test-results/results/visual-registry-1685720-7-e2e-mission-intake-autonomous-minimal.json`, `test-results/results/visual-registry-1685720-11-e2e-brain-graph-visual-canvas-table.json`, `test-results/results/visual-registry-1685720-12-e2e-plan-changes-version-restore.json`, and `test-results/results/visual-registry-1685720-13-e2e-plan-changes-inflight-resolution.json` |
| Particle-core and retired-route compatibility | 6 expected, 6 passed in release-profile Chromium; renderer failure/retry, reduced motion, all control families, canonical route, and retired bookmark redirect covered |
| First-document authentication and boot shell | 5 unit contracts with 64 assertions plus 3 retry-free Chromium paths passed; the particle boot forms once, hands off without a duplicate hero flash, settles under reduced motion, and preserves HttpOnly-session sign-in/sign-out behavior |
| Rejected assembly retirement | Historical focused 2026-07-19 evidence: alias gate 1/1 and the then-current Chromium route/link gate 34/34; no assembly manifest or review GLB request. The current route/href result is the separate 36/36 gate above |
| Latest current-source interaction-manifest validation | 715-group source state: 51/51 tests and 4,815 assertions passed. This source-bound validation is not enforcement-eligible aggregate browser activation and does not prove exhaustive option traversal |
| Focused Chromium shared-server browser gate | 79 expected, 79 passed; 0 skipped, unexpected, or flaky results |
| Focused Firefox and WebKit browser gate | 100 expected, 100 passed; 0 skipped, unexpected, or flaky results |
| Reviewed plan-version browser gate | Chromium plan-change suite 5/5; desktop WebKit stress 5/5; six-project desktop/mobile/tablet matrix 6/6; the repaired in-flight decision surface passed 2/2 on Chromium 1280 and Android Chromium 390; zero retries |
| Current production build and bundle budget | Production build passed with no budget failures. Initial JavaScript is 117,338 bytes gzip against the 250,000-byte budget; the largest lazy/non-initial JavaScript chunk is 140,177 bytes gzip against the 150,000-byte budget |
| Production-byte Web Vitals | Run `web-vitals-worker-race-20260727T233800Z` passed 3/3 cases with zero retries, unexpected failures, skips, or flakes and `sourceStable=true`. Desktop p75 was FCP 180 ms, LCP 1,188 ms, INP 64 ms, and CLS 0.0005764481658307613. Mid-tier-mobile p75 was FCP 1,476 ms, LCP 2,456 ms, INP 88 ms, and CLS 0.0019733796621257387. A dedicated-worker teardown race was repaired only in the test harness; production application bytes were not changed. This bounded run is performance evidence, not release eligibility |
| Source hygiene | Application/server typecheck, E2E typecheck, and `git diff --check` passed |
| Agent Fleet model-setting slice | 52/52 passed across all 13 general release projects in 26.3 minutes with three workers and zero retries. All 12 canonical agent entries expose the same discoverable LLM-settings route by pointer and keyboard; direct deep links focus and reveal the editor after the boot shell clears. The fixture truthfully represents five runtime-bound roles and seven offline roles, and the browser matrix verifies assignment, authentication, provider health, enforcement, disclosure, compatible-specialist, model, reasoning-effort, and fallback availability. The source-bound reporter reconciled 910/910 required receipts at 70 per project with `missing=0`, `duplicate=0`, `unexpected=0`, `invalid=0`, and `reporterErrors=0`. This closes only the focused model-setting slice, not the whole-manifest gate |
| Research Lab functional browser slice | 182/182 passed across all 13 configured non-Brain-renderer projects: Chromium, Firefox, WebKit, enterprise Chromium, Android Chromium, iPhone WebKit, tablet Chromium, Chromium at 360, 1024, 1280, 1920, and 2560 pixels, and Chromium at 200% zoom. The final receipts contain zero retries, skips, or unexpected failures. The three-engine desktop subset passed 42/42 with three workers after shared-state isolation. The paths cover campaign setup and conflict handling, bounded development-run start/cancel, authoritative worker completion, exact retry/discard, committed-response-loss reconciliation without mutation replay, complete signed promotion stages, promotion conflicts, and forward rollback. They do not activate the server-resolved validation or private hidden-holdout stages and do not prove a provisioned operator descriptor, a live public-provider path, whole-manifest activation, or visual approval |
| Research Lab backend suite | 135/135 passed with 1,009 assertions. For a file-backed application, Research uses a dedicated connection to the same canonical WAL database; when another writer holds the database, a Research mutation returns a bounded retryable `503 research_store_busy` response instead of delaying authentication, and the same idempotency key can complete and replay after the writer releases the lock. This proves the reviewed backend Research contracts in source; it is not a release-environment, browser-stage, provider, or deployment receipt |
| Private hidden-holdout backend boundary | 4/4 focused tests passed with 54 assertions. Source implements a hash-pinned operator descriptor, server-resolved `development → validation → private hidden holdout` order, opaque API/event projection, local-only evaluation and integrity signing, restart/idempotency handling, and zero public-provider exposure. This is source-level backend evidence only; it does not claim a provisioned release-environment descriptor, browser activation of the later stages, cross-browser approval, or visual approval |
| Agent Fleet model-setting evidence integrity | The authoritative result is `test-results/results/agent-model-truthful-crossbrowser-20260726T1810Z.json` (957,044 bytes; SHA-256 `693e2d4379437e1fe3d818ea4be1c373c5afcb2db95c4aa2af902b54207ff3bf`) and its receipt ledger is `test-results/results/agent-model-truthful-crossbrowser-20260726T1810Z.interaction-activation-receipts.json` (2,176,704 bytes; SHA-256 `8ddca640a340c09eaaaf9bd7502d37c45a537c5adf49f1d6cde6997aa21cfb8e`). The bound source hashes are model-setting spec `06bf59b6f806a7e7aac0e982802db93539f002d2a03fcba1d2f20040a47833b4`, Titanium selector helper `5bb24723738ed4dd446e67c0e69b839033f6c92f80b6aae47adc954001b08b98`, interaction manifest `f61ea6ae25c057a3fb180b91c26fdc9c94a1f178e3226b1240d251d5fb7cc326`, and model-assignment editor `b8b82af2caa7d0b3b9f1b2ac20f5114f33b0a8fc0ccaaa17d20035faf87e7ad0` |
| Historical reusable-outcome boundary | 16 focused tests passed with 112 assertions; a read-only audit reviewed 14,977 historical bundles and found zero evidence-complete success/failed bindings, so 285 prose-only outcome claims remain explicitly non-authoritative |
| Autonomous Command Palette search | Included in the current 24/24 three-engine Command Palette result with exact contextual mission/run activation, resume and cancellation, navigation, candidate-memory creation, and truthful degraded-domain handling |
| Complete Command Palette slice | 24/24 passed across Chromium 1440, Firefox 1440, and WebKit 1440 with zero retries. Evidence: `test-results/results/1650882-1785188386901.json` and `test-results/html/1650882-1785188386901/index.html` |
| CVE applicability review lifecycle | 13/13 release-project cases passed with one worker and zero retries, skips, unexpected failures, or flaky results; the browser used the real mission-scoped review API, immutable receipt/audit/event/outbox records, refresh/deep-link restoration, and a genuine optimistic-concurrency conflict |
| SQLite statement lifetime and graceful shutdown | 29 focused database/startup/shutdown tests passed with 218 assertions; a prior schema-37 candidate also passed its complete 1,828-test pre-activation gate before exposing the obsolete readiness deadline |
| Release-start admission permissions | 71 focused release-start, service-start-bundle, and no-backup preview tests passed with 683 assertions. The installer uses descriptor-bound no-follow writes, installs the exact traverse-only service ACL, proves service traversal and journal readability while denying root listing/writes, and verifies the final committed journal inode and digest |
| Forward-only release boundary | Backup-capable release entry points are disabled; current migration, static publication, Vault export, and activation paths reject retained copies and use content-free recovery receipts |
| Guarded production mission proof | Autonomous DNS, Autonomous host/service recon, and exact-decision Guided Nmap completed; zero active runs and zero active leases remained |
| Live Guided inventory | Exactly seven reviewed local tools ready through fresh non-authorizing receipts |
| Live Autonomous inventory | Exactly three safe-recon action classes ready through the result-aware specialist boundary |
| Live Second Brain and Vault | 5,512 active confirmed/verified canonical nodes, 5,996 active edges, 387 Context Packs, and 2,305/2,305 eligible notes hash-verified in the connected attack-knowledge Vault with zero pending sync states or conflicts; 650 synchronized notes remain evidence-unlinked islands, 232 post-seal source changes await a new delta import, and 12,414 parser-only script records remain correctly excluded as stale history |
| Vault island-link repair dry run | All 650 island notes were reviewed without mutation; zero links were execution-eligible. Forty-eight staged relationships were rejected because 23 referenced suppressed/unreviewed counterparts and 25 lacked the exact completed-migration custody chain; the focused repair suite passed 11/11 with 139 assertions |
| Authenticated live Chromium | 1/1 passed against port 3132; Command Center, Vault, graph edges, and mission/run deep links verified without browser mutation |
| Current guarded-preview health | Ports 3131 and 3132 both return HTTP 200. Legacy remains active with zero service restarts. Ti-Scale reports API schema 2.4, database migration 47, WAL, foreign keys, verified integrity, zero outbox backlog, and a healthy event stream. Its historical restart counter remains 2,453 from the earlier release-start defect, while the current process has stayed up since 2026-07-26 07:37:50 UTC. The current source repair and schema 56 have not been deployed |
| No-backup and dormant-container boundary | All six forbidden Ti-Scale backup roots are absent. Docker, containerd, kubelet, k3s, and MicroK8s remain inactive |

## Current retry-free browser gate ledger

The ledger below records the newest authoritative run for each current slice. A
focused repair does not turn an older red full slice green; the complete slice
must be rerun without retries.

| Slice | Current result |
| --- | --- |
| Intelligence, Decisions, artifacts, CVE, metrics, and operational lists | **Green:** 25/25 passed in Chromium 1440 with one worker, zero retries, zero skipped, zero unexpected, and zero flaky results |
| Brain core | **Green:** 27/27 passed with zero retries or skipped tests |
| Plan changes and immutable restore | **Green:** 9/9 passed with zero retries or skipped tests |
| Runtime Gate A | **Green:** 67/67 passed in Chromium 1440 with one worker, zero retries, zero skipped, zero unexpected, and zero flaky results |
| Brain graph and Vault | **Green:** 25/25 passed in Chromium 1440 with one worker, zero retries, zero skipped, zero unexpected, and zero flaky results; the 1,000-node graph recorded 42 distinct frames with a 33.4 ms p95 under the unchanged 50 ms gate |
| Automated axe accessibility | **Green:** 390/390 configured checks passed in 9.2 minutes across Chromium, enterprise Chromium, Firefox, WebKit, Android Chromium, iPhone WebKit, tablet, five additional viewport projects, and 200% zoom. Each of the 13 general projects ran 30 cases; there were zero retries, skips, unexpected failures, or flaky results. The run verified the repairs for lazy Command Palette StrictMode request aborts—including canonical and contextual lookups—and for the undersized mobile intake checkbox target, enlarged from 18×18 to 24×24 CSS pixels. Evidence: `test-results/results/1631796-1785187784400.json` and `test-results/html/1631796-1785187784400/index.html`. This is the automated axe gate only, not full WCAG or human accessibility approval |
| Command Palette | **Green:** 24/24 passed across Chromium 1440, Firefox 1440, and WebKit 1440 with zero retries. Navigation, contextual live-run commands, exact resume and cancellation, candidate-memory creation, and truthful degraded-domain behavior were exercised |
| Agent Fleet model settings | **Green:** 52/52 passed across the 13 general release projects—Chromium at 360, 1024, 1280, 1440, 1920, 2560, and 200% zoom; enterprise Chromium; Firefox; WebKit; Android Chromium; iPhone WebKit; and tablet Chromium—in 26.3 minutes with three workers and zero retries, skips, unexpected failures, or flaky results. The source-bound activation ledger reconciled 910/910 requirements with `missing=0`, `duplicate=0`, `unexpected=0`, `invalid=0`, and `reporterErrors=0` |
| Research Lab | **Bounded functional slice green:** 182/182 passed across all 13 configured non-Brain-renderer projects with zero retries, skips, or unexpected failures. The three-engine desktop subset passed 42/42 with three workers after shared-state isolation. Operator provisioning of a real private-holdout descriptor and canonical browser activation of the validation and private hidden-holdout stages remain pending, as do whole-manifest activation and visual approval |

These focused browser slices are now green, but they do not make the source
release-eligible. The 910/910 result closes only the Agent Fleet model-setting
slice. The complete current-source activation-receipt matrix, nine known-gap
closures, visual approvals, the full-product cross-browser release run, the
soak/preview period, and human sign-off remain outstanding. The release,
deployment, default-entry, and cutover gates remain unmet; cutover remains
closed.

The Chromium gate includes the durable Brain/Vault degradation sequence followed by Autonomous intake. It proves that an offline Obsidian projection remains visibly degraded without incorrectly disabling the healthy canonical SQLite Brain. The current measured build remains within the initial and lazy-route gzip budgets.

Local browser evidence is recorded at:

- `test-results/results/chromium-consolidated-gate-2-20260719.json`
- `test-results/html/crossbrowser-gate-20260719-b/index.html`
- `test-results/results/crossbrowser-gate-20260719-b.json`
- `test-results/results/particle-core-closure-20260719-r2.json`
- `test-results/results/meshy-retired-alias-20260719.json`
- `test-results/results/manifest-particle-core-closure-20260719.json`
- `test-results/results/assembly-retirement-20260719.json`
- `test-results/results/route-smoke-assembly-retired-20260719.json`
- `test-results/results/manifest-assembly-retired-20260719.json`
- `test-results/results/palette-autonomous-20260722-r5.json`
- `test-results/results/command-palette-final-fixed-20260724-43195.json`
- `test-results/results/cve-review-lifecycle-20260724-r2.json`
- `test-results/results/manifest-reconciled-20260724T115443Z.json`
- `test-results/results/runtime-e2e-gate-a-verify-43155.json`
- `test-results/results/runtime-e2e-gate-a-final-20260724-43213.json`
- `test-results/results/brain-core-gate-fixed-43160-20260724.json`
- `test-results/results/plan-changes-full-final-43159-20260724.json`
- `test-results/results/brain-vault-gate-20260724-43161.json`
- `test-results/results/brain-vault-final-20260724-43192.json`
- `test-results/results/intelligence-full-root-final-20260724-43172.json`
- `test-results/results/accessibility-full-root-final-20260724-43200.json`
- `test-results/results/zoom-accessibility-full-root-final-20260724-43201.json`
- `test-results/results/accessibility-sse-fixed-20260725T1830Z.json`
- `test-results/results/1631796-1785187784400.json`
- `test-results/html/1631796-1785187784400/index.html`
- `test-results/results/manifest-current-source-20260725T1815Z.json`
- `test-results/results/route-href-current-source-20260726T0005Z.json`
- `test-results/results/agent-model-truth-20260726T1025Z.json`
- `test-results/html/agent-model-truth-20260726T1025Z/index.html`
- `test-results/results/agent-model-crossbrowser-20260726T1045Z.json`
- `test-results/results/agent-model-crossbrowser-20260726T1045Z.interaction-activation-receipts.json`
- `test-results/html/agent-model-crossbrowser-20260726T1045Z/index.html`
- `test-results/results/agent-model-truthful-crossbrowser-20260726T1810Z.json`
- `test-results/results/agent-model-truthful-crossbrowser-20260726T1810Z.interaction-activation-receipts.json`

The older schema-47 guarded preview remains deployed. The current schema-56
source and startup repair have not been deployed, and no default-entry cutover
or release approval was granted.

## Installation-dependent checks

Do not infer these from source or fixture tests. Every installation must separately prove:

1. database integrity, foreign keys, current migration, and forward-recovery admission;
2. authenticated health and journey-specific readiness;
3. the exact runtime provider, specialist, MCP, and tool manifests actually mounted;
4. a Vault connection inside the configured sandbox with a real audited write/read/rename/delete receipt;
5. event-stream replay, cancellation, restart, and checkpoint behavior with disposable data;
6. release browser, accessibility, visual, performance, soak, and human-approval evidence.
