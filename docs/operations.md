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

## Database backup and restore

Create a timestamped backup:

```bash
bun run db:backup --db ./data/ti-scale.sqlite --output ./backups
```

Record the reported path and SHA-256. Verify both database integrity and foreign keys after any copy or restore.

Restore is deliberately guarded. Stop the service, verify the expected backup hash, and use the restore command with its explicit stopped-service acknowledgment. Never overwrite a running database.

## Static client releases

The static release commands stage immutable build output, verify hashes, switch a small active pointer, pin the active release, and roll the pointer back:

```bash
bun run build
bun run release:static:stage --root /var/lib/ti-scale/static-releases \
  --release-id "$(date -u +%Y%m%dT%H%M%SZ)" --dist ./dist
bun run release:static:verify --root /var/lib/ti-scale/static-releases \
  --release-id <release-id>
bun run release:static:activate --root /var/lib/ti-scale/static-releases \
  --release-id <release-id>
```

A static pointer rollback changes browser assets only. It does not restore the database, cancel runs, revert provider configuration, or reverse artifact writes.

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
- Verify recent backups by opening them read-only and running integrity checks.
- Resolve vault conflicts and quarantined notes.
- Review stale or disputed memory.
- Review circuit-breaker and dependency health.
- Re-run the interaction and browser gates before promoting a build.
- Rotate the operator token after suspected exposure.
