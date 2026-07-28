# Configuration

Ti-Scale reads server configuration from environment variables. Keep private values in an untracked `.env` file or an operating-system secret store. Browser variables are public at build time.

## Core server settings

| Variable | Purpose | Recommended local value |
| --- | --- | --- |
| `TI_SCALE_HOST` | HTTP bind address | `127.0.0.1` |
| `TI_SCALE_PORT` | Standalone service port | `3132` |
| `TI_SCALE_DATABASE_PATH` | Canonical SQLite file | `./data/ti-scale.sqlite` |
| `TI_SCALE_SCRIPT_SOURCE_ROOT` | Optional absolute, Ti-Scale-namespaced generated-script source root | Derived beside the database |
| `TI_SCALE_PREVIEW` | Allows mutable development static serving; manifest-pinned production releases do not require it | `false` in production |
| `TI_SCALE_SERVE_STATIC` | Serves the built client from the API process | `true` for a single-process deployment |
| `TI_SCALE_KILL_SWITCH` | Starts only the fail-closed disabled response surface | `false` |
| `TI_SCALE_UI_ORIGIN` | Exact browser origin permitted by CORS | Development client origin |
| `TI_SCALE_PROJECTION_INTERVAL_MS` | Runtime projection refresh interval, 1,000–300,000 ms | Server default |

Use absolute paths in managed deployments. Keep the database and script-source roots on storage with appropriate capacity and filesystem-permission controls. This installation's operator policy prohibits retained backups, snapshots, and rollback copies. Artifact metadata may reference other approved canonical stores; there is no general `TI_SCALE_ARTIFACT_ROOT` setting in the current server.

## Forward-only release inputs

Candidate staging intentionally has no environment-variable fallback for its
source or browser build. The operator must pass:

- an absolute clean Git worktree root;
- that same worktree's exact absolute `dist/` path;
- the full expected Git commit;
- the inspected server source-tree SHA-256;
- the inspected static artifact SHA-256;
- one release ID repeated in `--release-id` and `--confirm`.

This keeps ambient shell configuration from silently selecting a different
checkout or build. The immutable production stores remain fixed at
`/opt/ti-scale-server-releases/releases/<release-id>` and
`/var/lib/ti-scale/static-releases/releases/<release-id>`. The package-owned
stager never changes `/opt/ti-scale`, the active static pointer, the database,
or either service itself; it hands the verified pair to the existing
no-backup controller under the same release lock.

Use `bun run release:no-backup:inspect-candidate -- --help` and the exact
procedure in [Deployment](deployment.md#stage-and-deploy-one-forward-only-candidate).
Do not add source/build environment fallbacks or a candidate cache: both would
weaken the explicit pin and zero-retained-backup boundary.

## Authentication

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_OPERATOR_TOKEN` | Private local operator token; must contain at least 24 bytes |
| `TI_SCALE_OPERATOR_TOKEN_FILE` | Preferred absolute private regular file containing the token; mutually exclusive with the inline value |
| `TI_SCALE_OPERATOR_ID` | Stable actor identifier written to audit records |
| `TI_SCALE_SECURE_COOKIES` | Requires HTTPS-only session cookies when `true` |

The operator token is a server secret. Never expose it through `VITE_` variables, logs, screenshots, shell history shared with others, or committed files.

## Vault

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_VAULT_ROOT` | Absolute filesystem sandbox containing all permitted vault paths |

The configured root is an allowlist boundary, not merely a default directory. Managed paths reject traversal and symbolic-link escapes. Connecting a vault also requires an explicit memory-control policy and a successful filesystem round trip.

There is no environment flag that makes a vault active. Vault activation is a persisted, audited connection established only after the operator grants filesystem permission, the path passes its round-trip health check, and the memory-control policy permits projection. This prevents configuration from claiming synchronization is active when no verified connection exists.

Process health composes those persisted records with a read-only sandbox/path check. A Vault is reported active only when its canonical connection is `connected`, its directory remains reachable inside `TI_SCALE_VAULT_ROOT`, and the audited write/read/rename/delete round-trip receipt exists. Health responses expose counts and remediation—not absolute Vault paths.

## Motion Lab candidate review

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_MOTION_REVIEW_ROOT` | Optional absolute directory containing one local candidate-review manifest and its addressed image/GLB files |

When configured, the authenticated `/motion-lab/candidates` route exposes the two source views, static turntable, and an explicitly loaded 3D turntable for operator comparison. The server validates root containment, file type, byte count, SHA-256, and delivery budgets before accepting the directory. The browser independently verifies the model bytes and geometry budget before rendering it.

This is a read-only review boundary. Configuration does not approve the candidate, add it to the production identity, copy it into the public build, or alter the approved WebGL manifest. The review API deliberately has no approve or promote mutation; a later operator decision requires a separate, audited workflow.

## Browser API origin

| Variable | Purpose |
| --- | --- |
| `VITE_TI_SCALE_API_ORIGIN` | API origin used by a separately served development client |

Only values safe for public browser delivery may use the `VITE_` prefix.

## Runtime adapters

Provider, specialist, and tool adapters must report fresh typed manifests and readiness. Do not set a boolean to imply execution capability. The runtime is considered executable only when the server can attest:

- an active action-policy boundary,
- provider authentication and callability,
- a compatible model route,
- at least one capable specialist,
- runnable tool capabilities,
- exact-step Guided enforcement,
- cancellation, heartbeat, lease, and result handling.

The default server includes a local, manual-only Guided planner that cannot contact a provider, target, tool, or MCP server. It intentionally reports Autonomous execution, specialist execution, and generic tool/MCP execution as unavailable until independently attested adapters are attached.

### Capability readiness records

System → Connections reads `GET /api/v2/system/capability-self-tests`. The response reconciles every registered provider, MCP server, tool, and local tool dependency against the current process projection and target-free local health receipts. Each row names the check, availability, freshness, explanation, and remediation. Registry and result totals must reconcile before the snapshot is accepted by the browser.

This endpoint does not launch a tool, contact a mission target, refresh an external credential, or grant mission execution. Its refresh control only rereads the latest bounded startup/local attestations. A passing result still requires a signed mission contract or represented Guided decision, current policy validation, an exact specialist assignment, a control-plane lease, and action-time preflight before execution can occur.

### Trusted runtime source manifest

Ti-Scale may load one deployment-reviewed runtime capability document at
startup. The reference is deliberately all-or-nothing:

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_TRUSTED_RUNTIME_CONFIG_ROOT` | Absolute, trusted directory containing the reviewed document |
| `TI_SCALE_RUNTIME_SOURCE_MANIFEST_PATH` | Absolute non-symlink JSON file below that directory |
| `TI_SCALE_RUNTIME_SOURCE_MANIFEST_SHA256` | Lowercase SHA-256 of the exact reviewed file bytes |

If none of these values is present, the source inventory remains empty. If
only part of the reference is present, the server refuses to start. The loader
checks root containment, every path component, ownership, permissions, file
identity before and after reading, exact byte digest, strict schema, canonical
registry IDs, and all cross-references.

Loading this file makes capability, specialist, provider, MCP, and tool
definitions inspectable; it does not make them executable. Configured agents
are projected offline with no heartbeat, configured MCP servers are
unattested, and configured providers are unauthenticated until their matching
live adapters supply current receipts. Local tools must additionally match
`TI_SCALE_TOOL_BINDING_REGISTRY_PATH` and a current isolated startup receipt.
Runtime-managed OpenRouter and public-NVD IDs cannot be shadowed by the source
file because those states come only from their live adapters.

### Guided OpenRouter configuration

OpenRouter is a planning-only Guided provider boundary. Configuration alone never marks it ready: Ti-Scale still requires a fresh authenticated model attestation, exact usage telemetry, a durable provider-turn audit, a scope-safe Context Pack, and a current run-controller lease before a request may leave the host.

The primary configuration surface is **System → Connections → OpenRouter
connection**. Its authenticated same-origin API writes one canonical record
under `TI_SCALE_PROVIDER_CONFIG_ROOT` (default:
`/var/lib/ti-scale/provider-config`). The directory is mode `0700`; the
configuration and credential are separate service-owned mode-`0600` files.
The API and UI expose only whether a credential exists. They never return,
audit, log, or place the credential in browser storage.

The running process captures the credential once at startup. Saving a new
canonical version therefore reports **Restart required** instead of silently
hot-activating it. After restart, **Verify connection & refresh catalog** runs
the bounded credential/model/completion attestation and republishes only the
secret-free result. The resulting OpenRouter catalog entry remains
`advisor_only` for all twelve canonical specialists; local policy-gated
adapters retain tool and Autonomous execution authority.

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_PROVIDER_CONFIG_ROOT` | Absolute private directory for canonical service-owned provider configuration; defaults to `/var/lib/ti-scale/provider-config` |
| `TI_SCALE_OPENROUTER_GUIDED_ENABLED` | Explicitly enables configuration discovery when set to `true` |
| `TI_SCALE_OPENROUTER_CREDENTIAL_PATH` | Absolute private regular file containing the provider credential |
| `TI_SCALE_OPENROUTER_MODEL` | Pinned provider/model identifier used to derive the immutable model-configuration hash |

The three `TI_SCALE_OPENROUTER_*` variables are a compatibility path used only
when no canonical connection record exists. Their credential file must be
owned by root or the Ti-Scale service account and use mode `0400` or `0600`.
Ti-Scale deliberately rejects `OPENROUTER_API_KEY` and other raw environment
credentials. Never add a provider credential to `.env`, the repository, a
unit-file directive, a command-line argument, or browser storage.

When the file is present but the live audit chain cannot be committed, readiness remains `configured but unattested`. This is an accurate dependency state, not a launchable provider.

The production readiness monitor first uses OpenRouter's documented [current-key](https://openrouter.ai/docs/api/api-reference/api-keys/get-current-key) and [single-model](https://openrouter.ai/docs/api/api-reference/models/get-model) endpoints for bounded checks without sending mission content. It then creates a fresh empty Context Pack, canonical provider turn, single-use exposure receipt, and exact request-hash authorization before issuing one content-free strict-schema completion. Only that complete chain may set `callable=true`. Every refresh uses a new receipt; an old authorized request cannot be replayed. The readiness projection includes the requested model, exact returned model, configuration hash, exact usage flags, and opaque audit receipt ID, but never the credential or provider response body.

This provider remains planning-only. A successful callability receipt does not create a specialist, mount a mission executor, authorize an MCP tool, or satisfy the Autonomous enforcement boundary.

### Public NVD connector

The optional public NVD MCP connector is a separately constrained, loopback-only read path for one official CVE record at a time. Its live identity, one-tool inventory, input schema, output schema, and read-only annotations are attested before the capability is displayed. Capability discovery does not grant mission execution authority.

See [Public NVD MCP connector](public-nvd-mcp.md) for credential installation,
service hardening, live smoke testing, rotation, and forward replacement.

### Local tool readiness registry

`TI_SCALE_TOOL_BINDING_REGISTRY_PATH` may point to an absolute, versioned JSON document containing target-free version/help probes for local tools already declared by the runtime manifest. The startup monitor is mounted in the server, but the registry cannot add tools or grant execution. With the default empty local-tool manifest, readiness truthfully reports `0/0` rather than implying a usable tool fleet.

See [Tool readiness](tool-readiness.md) for the exact schema and limits.

### Reviewed local tool capabilities

Configure all seven values or none. The three documents must live beneath the
same immutable trust root:

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_PATH` | Absolute reviewed local-tool capability JSON path |
| `TI_SCALE_LOCAL_TOOL_TRUSTED_CONFIG_ROOT` | Absolute non-writable directory containing that manifest |
| `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256` | Lowercase SHA-256 of the exact manifest bytes |
| `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_PATH` | Absolute reviewed bubblewrap probe descriptor path |
| `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_SHA256` | Lowercase SHA-256 of the exact probe descriptor bytes |
| `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_PATH` | Absolute reviewed engagement-workspace mapping path |
| `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_SHA256` | Lowercase SHA-256 of the exact workspace document bytes |

The capability document defines absolute binaries, direct argv schemas,
deterministic routing, action/evidence mappings, and execution bounds. The
other two documents pin the isolated readiness worker and logical-to-runtime
workspace boundary. Loading them does not represent local executables as MCP
tools and does not authorize mission work. See
[Local tool capabilities](local-tool-capabilities.md).

After all seven base values load successfully, the optional
`TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED` flag may be set to exact lowercase
`true` through the versioned [reviewed web-assessment activation
bundle](reviewed-web-assessment-capability.md). It composes the bounded WhatWeb
and FFUF bindings into that pinned baseline. Exact `false` leaves them out;
any other nonempty value fails configuration loading.

### Guided Windows and identity operations

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_WINDOWS_IDENTITY_ENABLED` | Enables the reviewed Windows/identity startup projection and exact-step Guided planner when set to exact lowercase `true` |
| `TI_SCALE_WINDOWS_IDENTITY_CREDENTIAL_ROOT` | Absolute private root containing operator-provisioned opaque credential bundles for credential-backed SMB/RPC operations |

The Windows/identity flag does not make every operation available by itself.
Each operation remains selectable only when its executable and authentication
mode have a current runtime receipt. The credential root is optional when only
anonymous operations are used. Credential files never enter the browser,
mission JSON, logs, or reusable memory.

### Local ExploitDB intelligence

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_LOCAL_EXPLOIT_INTELLIGENCE_ENABLED` | Enables the pinned local SearchSploit readiness monitor and its one-action Guided mission route when set to exact lowercase `true` |

This route has no provider or target connection. Startup pins the exact
SearchSploit executable, bubblewrap executable, configuration, and three local
catalog files before exposing the option. Results enter the Engagement Log and
unverified Observation stages only. See [Local tool
capabilities](local-tool-capabilities.md#pinned-local-exploitdb-intelligence).

## Production guidance

- Use `TI_SCALE_HOST=127.0.0.1` behind an authenticated HTTPS reverse proxy unless direct network binding has been explicitly reviewed.
- Set `TI_SCALE_SECURE_COOKIES=true` only when the browser reaches Ti-Scale over HTTPS.
- Run under a dedicated operating-system account.
- Protect configuration files with mode `0600`.
- Keep the canonical database, artifacts, Vault, and active static release in
  distinct directories. Do not configure a backup or rollback store.
- Send `SIGTERM` and wait for graceful shutdown before maintenance that requires the database to be closed.
# Research readiness

Research Lab execution is optional and fail-closed. To enable its local
readiness checks, install
`deployment/runtime-config/research-readiness.env.example` as
`/etc/ti-scale/research-readiness.env` after reviewing its four
`TI_SCALE_RESEARCH_READINESS_*` settings. Install the private signing key as
the systemd credential named `research-integrity-key`, for example as the
root-owned mode-`0600` file
`/etc/credstore/research-integrity-key`. The trusted descriptor
must pin exact absolute paths and SHA-256 identities for
`bubblewrap`, `prlimit`, and the evaluator executable, plus the fixed evaluator
source hash and bounded resource policy.

At startup and before each receipt expires, Ti-Scale proves two independent
owners. `LabEnvironmentManager` deliberately dirties a generated synthetic
fixture, destroys it, recreates it from the immutable typed definition, and
verifies the exact baseline digest. `IsolatedExperimentWorkerLauncher` starts
the same single-use process that receives an admitted experiment and challenges
its UID/GID, namespaces, no-new-privileges state, empty capabilities, mounts,
network denial, credential-free environment, resource limits, and process-group
cleanup. The lab, worker, and admission use separate keys derived from the
private local credential. Fresh one-use receipts bind the experiment, scenario,
benchmark, evaluator, tool manifest, and reset generation.

Missing Research configuration blocks Research only. It does not prevent the
main Ti-Scale service from starting: both the environment file and systemd
credential are optional at the service boundary, while the Research readiness
gate requires the complete pair. Production accepts the signing key only from
the private systemd credential directory or an explicitly configured private
key file; an inline key is test-only.
