# Operations

## Operating posture

Treat readiness as a set of independent proofs. Liveness means the process can answer; readiness means the dependencies needed for a specific journey are available and enforceable.

Public diagnostics:

```text
GET /api/v2/health
GET /api/v2/system/readiness
GET /api/v2/openapi.json
GET /api/v2/contracts/events
GET /api/v2/auth/session
```

`/api/v2/health` is a constant-time process probe. Its database result is the
immutable integrity attestation captured during startup; it never runs
`PRAGMA quick_check` or dependency probes from an HTTP request. Use
`/api/v2/system/readiness` for the current provider, specialist, tool, Brain,
and Vault projection. Use `db:verify` for an explicit full database scan.

All operational data routes require authentication.

## Start and stop

Build and start a single-process deployment:

```bash
bun run build
bun run server
```

Stop with `SIGTERM` or `SIGINT`. The server stops accepting work, closes the HTTP listener, drains application services within its shutdown deadline, and closes the database. If shutdown times out, investigate active event subscribers or attached adapters before restarting.

## Kill switch

`TI_SCALE_KILL_SWITCH=true` starts a minimal fail-closed HTTP response surface instead of operational services. Use it to disable Ti-Scale without deleting state. The kill switch is not a substitute for stopping a compromised host or revoking exposed credentials.

## Health routine

Use this sequence after a deployment, restart, configuration change, or storage incident:

1. Check `/api/v2/health`.
2. Check `/api/v2/system/readiness`.
3. Verify the database.
4. Confirm event-stream connection and heartbeat.
5. Check provider, specialist, and tool readiness separately.
6. Verify the active vault connection if memory projection is enabled.
7. Inspect blocked or recovering runs for a structured diagnosis.

```bash
bun run db:verify --db ./data/ti-scale.sqlite
bun run brain:sync-verify --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

## Forward-only database operations

This installation does not create or retain database backups, migration
snapshots, restore targets, or rollback archives. Database migration is
forward-only by default:

```bash
bun run db:migrate --db ./data/ti-scale.sqlite
bun run db:verify --db ./data/ti-scale.sqlite
```

The compatibility spelling `--no-backup --acknowledge-no-backup-risk` remains
accepted for command compatibility, while `--backup-dir` is rejected. Before
commit, SQLite transaction semantics preserve the original state. After
commit, recovery is forward-only. The release journal retains hashes and
phases, never database bytes.

## Static client releases

Direct static staging, activation, and rollback commands are disabled. A
release is built, verified, activated, and pruned only inside the bounded
forward-only deployment controller. Read-only inspection remains available:

```bash
bun run release:static:verify --root /var/lib/ti-scale/static-releases \
  --release-id <release-id>
bun run release:static:pin --root /var/lib/ti-scale/static-releases
```

The controller removes the superseded static tree in the same controlled
release window. It must never be retained as a rollback copy.

## Blocked and failed work

A blocked badge without detail is insufficient. Each persisted diagnosis should identify:

- the blocked object,
- the human-readable cause and machine category,
- the last successful event,
- the failing dependency or policy rule,
- retry history and preserved progress,
- whether retry is safe,
- valid recovery actions.

Do not repeatedly invoke the same failed action. Follow the bounded recovery path and record the result.

## Events and logs

Use the semantic event stream for live state and the structured log views for troubleshooting. Raw output is not automatically evidence. Keep request IDs and run IDs when escalating an incident; do not copy tokens or restricted payloads into tickets.

## Routine maintenance

- Review database and artifact growth.
- Verify the canonical database directly with integrity and foreign-key checks.
- Resolve vault conflicts and quarantined notes.
- Review stale or disputed memory.
- Review circuit-breaker and dependency health.
- Re-run the interaction and browser gates before promoting a build.
- Rotate the operator token after suspected exposure.
