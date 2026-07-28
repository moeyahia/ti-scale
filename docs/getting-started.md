# Getting started

## 1. Install prerequisites

Use Bun 1.3.14 or newer. Node.js 22 or newer is supported for development utilities that require it.

```bash
bun --version
node --version
```

## 2. Install dependencies

Obtain a Ti-Scale source checkout using the download or clone method provided
by the repository host. From the checkout root, run
`bun install --frozen-lockfile`.

Do not commit `node_modules`, `.env`, databases, logs, browser traces, or local vault content.

## 3. Create local configuration

```bash
cp .env.example .env
TOKEN_DIRECTORY="${XDG_CONFIG_HOME:-$HOME/.config}/ti-scale"
install -d -m 700 "$TOKEN_DIRECTORY"
openssl rand -hex 32 > "$TOKEN_DIRECTORY/operator-token"
chmod 600 "$TOKEN_DIRECTORY/operator-token"
printf 'TI_SCALE_OPERATOR_TOKEN_FILE=%s\n' "$TOKEN_DIRECTORY/operator-token"
```

Set `TI_SCALE_OPERATOR_TOKEN_FILE` in `.env` to the absolute path printed by
the final command. Inline `TI_SCALE_OPERATOR_TOKEN` remains available for an
ephemeral local process. Keep the service bound to `127.0.0.1` for local use.
The default standalone port is `3132`.

At minimum, review:

```dotenv
TI_SCALE_HOST=127.0.0.1
TI_SCALE_PORT=3132
TI_SCALE_DATABASE_PATH=./data/ti-scale.sqlite
TI_SCALE_OPERATOR_TOKEN_FILE=<absolute-path-printed-above>
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

Database migrations are forward-only and create no database copy or migration
snapshot:

```bash
bun run db:migrate --db ./data/ti-scale.sqlite
```

The legacy `--no-backup --acknowledge-no-backup-risk` spelling remains accepted
for command compatibility, but is not required. `--backup-dir` is rejected.
The JSON result records
`"backupPolicy": "operator-acknowledged-no-backup"` and recovery after commit
is forward-only.

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

Database, authentication, event, memory, provider, specialist, and tool readiness are separate checks. A healthy database check does not imply that mission execution is available. The local Guided planner can represent operator-run manual steps without contacting a provider, target, tool, or MCP server.

The default server does not attach an Autonomous provider/specialist/tool executor or a generic MCP executor. Autonomous launch and agent-run Guided steps must remain unavailable until those adapters pass readiness. This is expected fail-closed behavior, not a reason to bypass the readiness gate.

## 9. Optional: configure an Obsidian vault

Create a private vault root outside the source checkout:

```bash
VAULT_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/ti-scale/vaults"
install -d -m 700 "$VAULT_ROOT"
printf 'TI_SCALE_VAULT_ROOT=%s\n' "$VAULT_ROOT"
```

Set `TI_SCALE_VAULT_ROOT` in `.env` to the absolute path printed by the final
command. Then enable memory and vault projection in **Second Brain → Control**,
open **Second Brain → Vault**, run the filesystem health check, and connect the
selected directory. Ti-Scale does not report a vault as connected until write,
read, rename, and delete all succeed in a temporary health directory.

See [Obsidian vault](obsidian-vault.md) for safety and conflict behavior.
