# Historical Functional Guided Runtime Validation

Validated: 2026-07-19 UTC
Deployment: `functional-brain-observations-20260719T200042Z`
Endpoint: `http://127.0.0.1:3132`

This is a point-in-time validation receipt. It preserves the bounded capability
observed on 2026-07-19 and is not current runtime-readiness truth.

## Validated operating boundary

The audited Ti-Scale installation provided a production-backed Guided
execution slice. An operator could create a Guided mission, review one
represented action with its
normalized parameters, authorize only that exact action, execute it through a
reviewed local specialist boundary, inspect the resulting Engagement Log and
Observation, and return to the durable run after a process restart.

The following reviewed local tools passed real end-to-end runs against the
deployed service:

| Capability | Canonical tool ID | Result |
| --- | --- | --- |
| HTTP response metadata | `kali:curl-http-metadata` | Passed |
| DNS lookup | `kali:host-dns-query` | Passed |
| Host liveness probe | `kali:ping-host-liveness` | Passed |
| TCP connection check | `kali:ncat-tcp-connect` | Passed |

Each live run produced exactly one succeeded action, one Engagement Log record,
and one unverified Observation. None produced an Evidence Candidate or Verified
Evidence because the represented actions did not contain an evidence-promotion
expectation. Expected negative network observations, such as a refused TCP
connection or an unanswered liveness probe, remain completed observations
rather than being misreported as runtime crashes.

## Operational-truth semantics

Workflow completion and evidence verification are independent. A reviewed
tool can complete its bounded action without proving a mission finding. The
Completion Review therefore reports:

- workflow complete;
- not evidence-verified;
- zero evidence coverage when no Verified Evidence exists; and
- the canonical completion basis used by the evaluator.

This prevents a successful process exit, raw output, or a matching output
string from being presented as evidence-backed mission success.

Terminal result delivery is durable. The runtime commits the terminal tool
result and its delivery envelope before notifying downstream consumers. A
crash after that commit can replay the result exactly once after restart. A
failed delivery sink cannot rewrite a successful tool status, error, or human
summary.

## Source and candidate gates

The deployed source passed these retry-free local gates before release:

| Gate | Result |
| --- | --- |
| Application/server TypeScript | Passed |
| E2E TypeScript | Passed |
| Bun unit and integration suite | 1,264 passed, 0 failed; 17,492 assertions |
| Production build | 182 modules built |
| Source whitespace validation | `git diff --check` passed |
| Initial application JavaScript | 425.17 KB raw; 124.53 KB gzip |
| Lazy Three.js route chunk | 561.57 KB raw; 140.37 KB gzip |

Before live deployment, the release was validated with a disposable,
noncanonical fixture dataset and isolated test credentials. The validation
created and completed four disposable missions, then restarted the candidate
service.
All four runs, logs, observations, Context Packs, Brain anchors, and Vault
projections persisted. A second reconciliation pass found no remaining work,
which proves idempotency for that candidate boundary.

## Live persistence and restart validation

After deployment and a deliberate Ti-Scale-only restart:

- all four live smoke runs remained `completed` at full workflow progress;
- each retained one succeeded action, one log, and one unverified observation;
- each retained eight lifecycle Context Packs: one mission-intake pack created
  before run creation and seven run-linked packs;
- each retained a canonical Mission node, Run node, verified `belongs_to` edge,
  and synchronized Vault projections;
- unaccepted terminal result envelopes remained at zero;
- `PRAGMA quick_check` returned `ok`; and
- the database remained on schema migration 16 with WAL and foreign keys.

The current Brain contains 3,294 nodes and 3,395 evidence/provenance-bearing
edges. The configured Obsidian-compatible Vault is `Ti-Scale-Brain`, located at
`/var/lib/ti-scale/vaults/Ti-Scale-Brain`. It contains 3,115 synchronized
Markdown notes and has zero open conflicts.

Historical reconciliation created 24 missing Mission/Run nodes and 22 missing
provenance edges, projected 34 nodes, and reported zero failures or conflicts.
A second dry run reported no missing nodes, edges, or projections. The obsolete
pre-change copy from that earlier workflow was purged; current reconciliation
is forward-only and creates no retained copy.

## Immutable release and forward-recovery boundary

The active application points to:

```text
/opt/ti-scale-server-releases/releases/functional-brain-observations-20260719T200042Z
```

The release receipt records these immutable identities:

| Artifact | SHA-256 |
| --- | --- |
| Server manifest | `053c5bcb6ef949b0f21c143fe7c67b5b50b6eb9abbf1579e4796a100add52cc6` |
| Server tree | `c7c7d24dfb3af7dbcadad938d57e9ce95079aca97cee6bedac2da010aae1176d` |
| Static manifest | `94f7fa0b02a743372eb3fe1d5ed39a1774194d5eb50068b04aa54f1d21bd2bf1` |

Every entry in the release checksum manifest was re-verified after deployment.
The active release is the only retained application payload. Superseded
candidate trees, database copies, Vault copies, snapshots, portable archives,
and rollback payloads are not retained. The release journal contains only
content-free transaction metadata: identities, hashes, phases, timestamps, and
verification outcomes.

Recovery is forward-only. Before a schema commit, the bounded transaction
either completes or leaves the canonical database unchanged. After a schema
commit, no older server may open the database; a compatible reviewed candidate
must complete recovery forward.

The temporary validation forward on port 43174 was removed. The configured
co-hosted-service sentinel retained the same PID and systemd invocation
identity throughout the Ti-Scale deployment, reconciliation, tool runs, and
restart.

## Authenticated browser validation

Live Chromium checks used the real local token exchange without printing or
persisting the token. The login document and session exchange both returned
HTTP 200, the password input disappeared after authentication, the session
cookie remained HttpOnly, and no token-bearing browser-storage key appeared.

The following routes passed at both 1440 by 900 and 390 by 844 CSS pixels:

- Command Center `/`;
- Mission portfolio `/missions`;
- Second Brain `/brain`;
- Memory Graph `/brain/graph`; and
- completed Guided mission
  `/guided/mission_6ae81f5e-f412-4643-ae6e-1cec9cf7e78e`.

All ten document navigations returned HTTP 200 with the expected live heading,
one boot sequence, no page or console error, no HTTP 4xx/5xx response, no stuck
loading state, and no page-level horizontal overflow. Navigation cancelled
nine long-lived event-stream requests as expected; none was a required-request
failure. The durable, secret-free summary receipt is:

```text
test-results/results/live-functional-guided-release-20260719.json
```

## Historical journey readiness

At the time of this receipt, the public health endpoint reported `degraded`,
not failed. This was the combined system state:

- Guided execution: ready;
- all four reviewed exact-step local tools: ready;
- database and event stream: healthy;
- canonical Second Brain and lexical index: healthy;
- one Obsidian Vault connection: connected, reachable, and round-trip verified;
- Autonomous execution: unavailable and fail-closed.

Autonomous execution was unavailable in this audited build. That historical
result does not describe the current service. Provider-backed semantic
interpretation, generic MCP execution, and automatic evidence verification
were not implied by this Guided validation; each capability still requires its
own current readiness proof before the UI can present it as available.
