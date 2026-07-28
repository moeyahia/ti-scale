# Ti-Scale

Ti-Scale is a mission-centered security operations platform for authorized assessments. It combines structured mission intake, supervised execution boundaries, evidence-backed intelligence, durable event history, and a user-controlled Second Brain in one focused operating environment.

The product exposes exactly two operator journeys:

- **Autonomous** — define the authorized outcome and operating contract, then observe bounded execution and recovery.
- **Guided** — work through one explained, represented step at a time, with deliberate operator decisions.

## Current status

Ti-Scale is under active development and is not release-eligible yet.

| Capability | Current state |
| --- | --- |
| Light-mode application shell and product routes | Implemented; release interaction coverage remains incomplete |
| Mission intake registries and contract review | Implemented; Autonomous execution remains fail-closed |
| SQLite mission, event, intelligence, memory, research, and audit records | Implemented through ordered forward-only migrations; the running installation must report the exact current schema before activation |
| Resumable semantic event stream | Implemented and covered by module tests; release soak remains pending |
| Evidence semantics, failure diagnosis, run metrics, and topology records | Implemented as canonical record and review surfaces |
| Second Brain graph, memory controls, and Context Packs | Implemented; runtime use is valid only when a persisted Context Pack exists |
| Obsidian-compatible vault connection, projection, import, conflicts, and portable export | Implemented; no vault is bundled or automatically connected |
| Guided exact-step runtime | Reviewed network, web, Windows/identity, and pinned local ExploitDB operations are available behind represented operator decisions and fresh capability receipts; an unconfigured operation remains fail-closed |
| Autonomous specialist and tool execution | Optional reviewed local executors are supported; an unconfigured installation remains unavailable and no assessment proof implies a complete engagement |
| Research Lab | Human-owned policy and isolated synthetic execution are under active validation; no candidate can auto-promote or deploy |
| Full cross-browser release gate, soak, and human approval | **Pending** |

The default server fails closed when an execution adapter is unavailable. It returns a structured `503` response instead of simulating work or silently changing mission state. Optional OpenRouter readiness and the public NVD connector are narrow planning/read-only boundaries; neither grants Autonomous or generic tool execution.

## Quick start

Prerequisites:

- Bun 1.3.14 or newer
- Node.js 22 or newer for supported development tooling
- A local filesystem location for the SQLite database, artifacts, and optional vault

From the root of a Ti-Scale source checkout:

```bash
bun install --frozen-lockfile
cp .env.example .env
```

Create a private operator-token file outside the source checkout:

```bash
TOKEN_DIRECTORY="${XDG_CONFIG_HOME:-$HOME/.config}/ti-scale"
install -d -m 700 "$TOKEN_DIRECTORY"
openssl rand -hex 32 > "$TOKEN_DIRECTORY/operator-token"
chmod 600 "$TOKEN_DIRECTORY/operator-token"
printf 'TI_SCALE_OPERATOR_TOKEN_FILE=%s\n' "$TOKEN_DIRECTORY/operator-token"
```

Set `TI_SCALE_OPERATOR_TOKEN_FILE` in `.env` to the absolute path printed by
the final command. Do not copy the token value into source-controlled files.

Initialize the database, verify the repository, and start the product:

```bash
bun run db:migrate --db ./data/ti-scale.sqlite
bun run check
bun run dev
```

Open the configured address. The default standalone service port is `3132`.

See [Getting started](docs/getting-started.md) for the complete setup sequence.

## Architecture at a glance

```text
React client
    │ typed HTTP + resumable SSE
    ▼
Express API boundary
    ├── mission and journey services
    ├── intelligence and evidence services
    ├── run supervision and recovery policies
    ├── Second Brain and vault bridge
    └── research policy and evaluation services
             │
             ▼
        SQLite + artifact store
```

SQLite is the transactional source of truth. Obsidian Markdown is an optional, synchronized, human-editable projection; a partial filesystem write cannot become canonical mission state.

## Documentation

- [Authoritative project goal](docs/project-goal.md)
- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Operations](docs/operations.md)
- [API](docs/api.md)
- [Event model](docs/events.md)
- [Second Brain](docs/second-brain.md)
- [Attack Knowledge Vault](docs/attack-knowledge-vault.md)
- [Obsidian vault](docs/obsidian-vault.md)
- [Security](docs/security.md)
- [Testing](docs/testing.md)
- [Continuous integration](docs/continuous-integration.md)
- [Deployment](docs/deployment.md)
- [Public NVD MCP connector](docs/public-nvd-mcp.md)
- [Contributing](docs/contributing.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Tool readiness](docs/tool-readiness.md)
- [Validation status](docs/validation-status.md)
- [Release gates](docs/release-gates.md)

## Safety principles

- Use Ti-Scale only against systems and environments you are authorized to assess.
- Scope and journey boundaries are enforced by durable domain records, not by UI labels alone.
- Raw operational output is a log until it is parsed, attributed, and promoted through evidence policy.
- Memory cannot expand authorization, reduce evidence requirements, or weaken policy.
- Public model context must be minimized, sanitized, classified, and receipted.
- Research candidates cannot change authorization, evaluation rules, or production code.

## Development

The primary verification command is:

```bash
bun run check
```

Browser suites, release evidence, and the interaction manifest have additional requirements described in [Testing](docs/testing.md). A successful build alone is not a release decision.
