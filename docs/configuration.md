# Configuration

Ti-Scale reads server configuration from environment variables. Keep private values in an untracked `.env` file or an operating-system secret store. Browser variables are public at build time.

## Core server settings

| Variable | Purpose | Recommended local value |
| --- | --- | --- |
| `TI_SCALE_HOST` | HTTP bind address | `127.0.0.1` |
| `TI_SCALE_PORT` | Standalone service port | `3132` |
| `TI_SCALE_DATA_ROOT` | Parent directory for local product state | `./data` |
| `TI_SCALE_DATABASE_PATH` | Canonical SQLite file | `./data/ti-scale.sqlite` |
| `TI_SCALE_ARTIFACT_ROOT` | Canonical artifact storage root | `./data/artifacts` |
| `TI_SCALE_PREVIEW` | Enables preview-only serving behavior | `true` during development |
| `TI_SCALE_SERVE_STATIC` | Serves the built client from the API process | `true` for a single-process deployment |
| `TI_SCALE_KILL_SWITCH` | Starts only the fail-closed disabled response surface | `false` |

Use absolute paths in managed deployments. Keep the database and artifact roots on storage with appropriate backup, capacity, and filesystem-permission controls.

## Authentication

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_OPERATOR_TOKEN` | Private local operator token; must contain at least 24 bytes |
| `TI_SCALE_OPERATOR_TOKEN_FILE` | Preferred absolute private regular file containing the token; mutually exclusive with the inline value |
| `TI_SCALE_OPERATOR_ID` | Stable actor identifier written to audit records |
| `TI_SCALE_SECURE_COOKIES` | Requires HTTPS-only session cookies when `true` |

The operator token is a server secret. Never expose it through `VITE_` variables, logs, screenshots, shell history shared with others, or committed files.

## Feature boundaries

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_DATABASE_ENABLED` | Enables the canonical database-backed product surface |
| `TI_SCALE_EVENT_STREAM_ENABLED` | Enables resumable operational events |
| `TI_SCALE_SECOND_BRAIN_ENABLED` | Enables memory services and Context Pack retrieval |

Turning off a dependency must produce an explicit degraded or unavailable state. It must not cause the UI to display stale success.

## Vault

| Variable | Purpose |
| --- | --- |
| `TI_SCALE_VAULT_ROOT` | Absolute filesystem sandbox containing all permitted vault paths |

The configured root is an allowlist boundary, not merely a default directory. Managed paths reject traversal and symbolic-link escapes. Connecting a vault also requires an explicit memory-control policy and a successful filesystem round trip.

There is no environment flag that makes a vault active. Vault activation is a persisted, audited connection established only after the operator grants filesystem permission, the path passes its round-trip health check, and the memory-control policy permits projection. This prevents configuration from claiming synchronization is active when no verified connection exists.

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

The default server intentionally reports these dependencies as unavailable until an adapter is attached.

## Production guidance

- Use `TI_SCALE_HOST=127.0.0.1` behind an authenticated HTTPS reverse proxy unless direct network binding has been explicitly reviewed.
- Set `TI_SCALE_SECURE_COOKIES=true` only when the browser reaches Ti-Scale over HTTPS.
- Run under a dedicated operating-system account.
- Protect configuration files with mode `0600`.
- Keep database, artifacts, vault, static releases, and backups in distinct directories.
- Send `SIGTERM` and wait for graceful shutdown before maintenance that requires the database to be closed.
