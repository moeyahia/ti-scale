# Getting started

## 1. Install prerequisites

Use Bun 1.3.14 or newer. Node.js 22 or newer is supported for development utilities that require it.

```bash
bun --version
node --version
```

## 2. Clone and install

```bash
git clone https://github.com/moeyahia/ti-scale.git
cd ti-scale
bun install --frozen-lockfile
```

Do not commit `node_modules`, `.env`, databases, logs, browser traces, or local vault content.

## 3. Create local configuration

```bash
cp .env.example .env
openssl rand -hex 32
```

Set the generated value in a private credential file and point `TI_SCALE_OPERATOR_TOKEN_FILE` to it. Inline `TI_SCALE_OPERATOR_TOKEN` remains available for an ephemeral local process. Keep the service bound to `127.0.0.1` for local use. The default standalone port is `3132`.

At minimum, review:

```dotenv
TI_SCALE_HOST=127.0.0.1
TI_SCALE_PORT=3132
TI_SCALE_DATA_ROOT=./data
TI_SCALE_DATABASE_PATH=./data/ti-scale.sqlite
TI_SCALE_ARTIFACT_ROOT=./data/artifacts
TI_SCALE_OPERATOR_TOKEN_FILE=/absolute/private/path/operator-token
TI_SCALE_OPERATOR_ID=local-operator
TI_SCALE_PREVIEW=true
TI_SCALE_SERVE_STATIC=true
```

The exact supported variables and defaults are documented in [Configuration](configuration.md) and kept in `.env.example`.

## 4. Initialize the database

```bash
bun run db:migrate --db ./data/ti-scale.sqlite
bun run db:verify --db ./data/ti-scale.sqlite
```

The migration command creates the database directory when needed, applies ordered migrations, enables foreign keys and WAL, and reports database health.

## 5. Verify the source tree

```bash
bun run check
```

This runs isolation checks, TypeScript validation, unit and module tests, and a production client build. Browser tests are a separate gate.

## 6. Start Ti-Scale

For development:

```bash
bun run dev
```

For a built client served by the API process:

```bash
bun run build
bun run server
```

Open `http://127.0.0.1:3132` unless you changed the host or port.

## 7. Sign in

Enter the same private operator token stored in the configured credential source. Ti-Scale exchanges it for a time-limited signed browser session. The token is not a browser build variable and must never be placed in a `VITE_` variable.

## 8. Check readiness before creating a mission

Open **System → Connections** or request:

```bash
curl http://127.0.0.1:3132/api/v2/system/readiness
```

Database, authentication, event, memory, provider, specialist, and tool readiness are separate checks. A healthy database check does not imply that mission execution is available.

The default server does not attach provider or tool execution. Autonomous launch and agent-run Guided steps must remain unavailable until those adapters pass readiness. This is expected fail-closed behavior, not a reason to bypass the readiness gate.

## 9. Optional: configure an Obsidian vault

Set an absolute allowed root:

```dotenv
TI_SCALE_VAULT_ROOT=/absolute/path/to/vault-sandbox
```

Then enable memory and vault projection in **Second Brain → Control**, open **Second Brain → Vault**, run the filesystem health check, and connect the selected directory. Ti-Scale does not report a vault as connected until write, read, rename, and delete all succeed in a temporary health directory.

See [Obsidian vault](obsidian-vault.md) for safety and conflict behavior.
