# Ti-Scale

Ti-Scale is a mission-centered security operations platform for authorized assessments. It combines structured mission intake, supervised execution boundaries, evidence-backed intelligence, durable event history, and a user-controlled Second Brain in one focused operating environment.

The product exposes exactly two operator journeys:

- **Autonomous** — define the authorized outcome and operating contract, then observe bounded execution and recovery.
- **Guided** — work through one explained, represented step at a time, with deliberate operator decisions.

## Current status

Ti-Scale is under active development and is not release-eligible yet.

| Capability | Current state |
| --- | --- |
| Light-mode application shell and product routes | Implemented |
| Mission intake registries and contract review | Implemented |
| SQLite mission, event, intelligence, memory, and audit records | Implemented |
| Resumable semantic event stream | Implemented |
| Evidence semantics, failure diagnosis, run metrics, and topology records | Implemented |
| Second Brain graph, memory controls, and context packs | Implemented |
| Obsidian-compatible vault projection, import, conflicts, and portable export | Implemented |
| Provider-backed planning and tool execution | **Not attached to the default server** |
| Full cross-browser release gate, soak, and human approval | **Pending** |

The default server fails closed when an execution adapter is unavailable. It returns a structured `503` response instead of simulating work or silently changing mission state.

## Quick start

Prerequisites:

- Bun 1.3.14 or newer
- Node.js 22 or newer for supported development tooling
- A local filesystem location for the SQLite database, artifacts, and optional vault

```bash
git clone https://github.com/moeyahia/ti-scale.git
cd ti-scale
bun install --frozen-lockfile
cp .env.example .env
```

Generate a private local operator token and place it in `.env`:

```bash
openssl rand -hex 32
```

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

- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Operations](docs/operations.md)
- [API](docs/api.md)
- [Event model](docs/events.md)
- [Second Brain](docs/second-brain.md)
- [Obsidian vault](docs/obsidian-vault.md)
- [Security](docs/security.md)
- [Testing](docs/testing.md)
- [Deployment](docs/deployment.md)
- [Contributing](docs/contributing.md)
- [Troubleshooting](docs/troubleshooting.md)
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
