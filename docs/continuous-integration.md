# Continuous integration

Ti-Scale uses two least-privilege GitHub Actions workflows. Both install the
lockfile exactly with Bun 1.3.14, pin external actions to reviewed commit
SHAs, run without repository write permission, and refuse credential
persistence after checkout.

## Standalone verification

`.github/workflows/ci.yml` runs for every push, pull request, and manual
dispatch. It enforces:

1. Parsed GitHub Actions policy and workflow-inventory validation.
2. Complete test-file inventory and masking-modifier validation.
3. Standalone source-boundary validation.
4. Application and server TypeScript checks.
5. Browser-contract TypeScript checks.
6. Unit and module tests, including the root-ownership boundary suite.
7. Interaction-manifest validation.
8. The production Vite build.
9. Initial and route-chunk gzip budgets.

The same gate can be inspected locally without starting a server:

```bash
bun install --frozen-lockfile
bun run scripts/validate-ci-workflows.ts
bun run check
```

## Full Playwright release profile

`.github/workflows/playwright-release.yml` is attached to pushes, pull
requests, reusable workflow calls, manual dispatches, and the weekly schedule.
It binds the run to the checked-out candidate SHA, resolves and validates the
actual Playwright configuration, repeats the source, type, unit, manifest,
build, and bundle gates, and then installs Chromium, Firefox, and WebKit. It
runs every project in `playwright.config.ts`, including desktop, enterprise
Chromium, mobile, tablet, wide-screen, 200% zoom, and the dedicated Brain
renderer. Before installation it records the lock-installed Playwright
version, browser revisions, browser-manifest SHA-256, Bun/Node versions, and
runner operating-system identity in the job log.

The browser command uses the release profile, a single worker, `forbidOnly`,
manifest and activation-receipt enforcement, a result-policy reporter, and an
explicit `--retries=0`. The reporter fails the process for skipped, fixme,
expected-failure, interrupted, missing, multiply executed, or retried tests.
There is no project filter, so a newly failing browser or viewport cannot be
hidden by a narrow workflow selection.

Each run owns a disposable loopback service, SQLite database, Vault root,
operator credential file, Research integrity key file, and static build
directory. Managed API, Vite, and static-server children receive a constructed
allowlisted environment. Live provider credentials cause configuration to fail
before a browser starts. The workflow never contacts a deployed Ti-Scale
service.

## No retained files

Neither workflow uploads artifacts, invokes an artifact cache, creates an
archive, or retains a duplicate release payload. Generated build and test
files exist only inside the ephemeral runner and are removed by an unconditional
cleanup step. Review the live Actions log for a failed gate and reproduce the
same command locally when deeper diagnosis is required.

Because the current operator policy forbids retained copies and archives, these
workflows are execution gates rather than durable evidence archives. Passing
either workflow proves only the gates executed in that run. The soak period,
evidence-retention policy, and explicit human review described in
[Release gates](release-gates.md) remain separate validation work.
