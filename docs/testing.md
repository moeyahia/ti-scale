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

The release profile uses zero retries and one worker, forbids focused tests, and retains screenshots, traces, video, and JSON/HTML reports on failure.

## Interaction manifest

`tests/interaction-manifest.json` is the machine-readable inventory for visible and keyboard-reachable controls. Each entry records route, fixture state, accessible role and name, input method, expected state transition, API or event side effect, error behavior, reversibility, browser coverage, viewport coverage, and test IDs.

The browser audit compares rendered interactive elements with this manifest. Missing UI entries and stale manifest entries are defects.

The manifest currently records explicit known gaps. Therefore, its presence and validation do not constitute 100% interaction coverage. Release requires the gap list to reach zero and every material option to be activated in every relevant state.

## Test layers

### Unit

Unit tests cover schemas, state machines, policies, repositories, registries, memory safety, event behavior, retry and loop logic, research policy, identity assets, and frontend contracts.

### Integration

Module tests cover database migrations, runtime state, event delivery, mission services, evidence semantics, vault synchronization, process restart, cancellation, failure diagnosis, and route contracts.

### Browser

Browser tests exercise authentication, mission intake, route reliability, decisions, evidence, run intelligence, plan changes, blocked-state recovery, Second Brain, vault conflicts, accessibility, zoom, and system surfaces using isolated canonical fixtures.

Fixtures may label development data, but production paths must never substitute fixture data for unavailable services.

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

## Release evidence

Archive:

- unit and integration results,
- browser HTML and JSON reports,
- failure traces, screenshots, and videos,
- approved visual baselines,
- interaction coverage,
- accessibility results,
- migration and vault reconciliation receipts,
- performance and soak reports,
- release attestation and human sign-off.

See [Release gates](release-gates.md) before describing any build as production-ready.
