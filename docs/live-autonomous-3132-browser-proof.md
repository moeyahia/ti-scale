# Live Autonomous browser proof on port 3132

## Result

On 2026-07-28 at 16:00:49 UTC, the authenticated Chromium proof completed
against the currently running standalone Ti-Scale service at
`http://127.0.0.1:3132`.

The release-facing result was:

- 1 expected test passed;
- 0 unexpected failures;
- 0 retries, skips, or flaky results;
- 109.5 seconds of test execution;
- one real Autonomous mission completed without a Guided decision or routine
  operator intervention.

The test used the production UI and API routes. It did not intercept, stub, or
mock an application API.

## Authentication and target boundary

The setup reads the operator credential from the root-owned Ti-Scale
configuration file and exchanges it through `POST /api/v2/auth/session`.
Playwright retains only the resulting HttpOnly session cookie for the test and
deletes that temporary browser state during teardown. The operator credential
is not present in the Playwright configuration, command line, report,
screenshot, trace, or proof receipt.

The authorized disposable assessment target was an ephemeral HTTP service on
`127.0.0.2:8080`. It cannot redirect, execute caller input, read host files, or
change persistent target state. It observed 21 requests using `GET`, `HEAD`,
`OPTIONS`, and `TRACE`. The fixture serves only `GET`, `HEAD`, and `OPTIONS`;
the bounded vulnerability/configuration probe's `TRACE` request therefore
received the fixture's deterministic `405 Method Not Allowed` response.

## Browser path proved

The browser exercised the following live path:

1. Open the Autonomous intake.
2. Choose the External Web Assessment template and disposable-local-lab
   environment.
3. Supply the exact loopback target and explicit authorization.
4. Leave title and objective empty so the server resolves recommended
   defaults.
5. Verify all four registry-backed operating-contract checklists remain on
   their recommended defaults.
6. Verify live readiness and the selected ReconScout, WebBreaker, and
   VulnIntel team.
7. Verify all four allowed Second Brain scopes are selected.
8. Review the normalized contract and launch through the UI.
9. Open Live Operations and wait on the canonical run record until terminal
   completion, failing immediately for blocked, failed, cancelled, or
   Guided-wait states.
10. Open the completed Summary, Evidence, Reports, mission Brain, and
    Obsidian Vault surfaces.

The successful canonical records were:

- mission: `mission_a40fe90e-b0da-40c1-84b0-9157759e1631`;
- run: `run_8f0bce9f-b37c-4e5a-9181-388126b79048`;
- terminal status: `completed`;
- verified evidence: 8 records, each with a 64-character content hash;
- reports: 2 canonical report artifacts;
- persisted run Context Packs: 35, including planning and reporting;
- Guided decisions: 0;
- active Vault: `Ti-Scale Attack Knowledge Vault`;
- active Vault connection:
  `vault_57907646-f346-4750-8a56-c9a869e846c5`;
- tracked Vault notes: 2,322;
- Vault round-trip health: read, write, rename, and delete all passed;
- at least one sync state was `synced`.

## Deployed-state defect found

The completed Summary showed valid aggregate completion facts, including
7/7 evaluated criteria, 8/8 visible verified evidence records, 7/7 successful
actions, zero retries, and zero policy violations. However, its canonical
statistics region stated:

> No reproducible metrics snapshot

This is a deployed-state product defect: the completed run did not have a
materialized `RunMetricsSnapshot` even though terminal evidence, evaluation,
and reports were present. The live browser proof does not conceal or treat
that missing snapshot as passed.

## Reproduce

The dedicated configuration refuses a non-loopback service origin and uses
zero retries:

```bash
TI_SCALE_E2E_RUN_ID="live-autonomous-$(date -u +%Y%m%dT%H%M%SZ)" \
TI_SCALE_E2E_EXTERNAL_SERVERS=true \
TI_SCALE_E2E_BASE_URL=http://127.0.0.1:3132 \
TI_SCALE_E2E_API_URL=http://127.0.0.1:3132 \
bunx playwright test --config=playwright.live-autonomous.config.ts
```

The passing JSON result is stored as the disposable local test artifact
`test-results/results/live-autonomous-live-autonomous-20260728T155858Z.json`.
It includes the redacted JSON receipt, browser audit, and Vault screenshot.
These ignored artifacts are test output, not a retained release backup.
