# Troubleshooting

## The service does not start

Check:

1. Bun meets the supported version.
2. `TI_SCALE_PORT` is available and between 1024 and 65535.
3. Exactly one operator-token source is configured: an inline value of at least 24 bytes or a private absolute token file.
4. The database path is writable and points to a regular file location.
5. The database passes integrity checks.
6. Static serving is not enabled without a valid build or active release.

```bash
bun run db:verify --db ./data/ti-scale.sqlite
ss -ltnp | grep ':3132'
```

## Sign-in fails

- Confirm the browser is using the token from the running server's environment.
- Restart after changing the server token.
- Do not place the token in a browser build variable.
- Clear the Ti-Scale site data if a signed session was issued by an earlier token.
- If HTTPS is terminated upstream, ensure secure-cookie configuration matches the browser-facing scheme.

## A mission says execution is unavailable

Read `/api/v2/system/readiness`. The default server has no attached production provider or tool execution adapter, so Autonomous execution and agent-run Guided steps return a structured `503`.

This response is intentional when the adapter is absent. Do not replace it with fixture progress. Attach and attest the provider, specialist, policy, cancellation, and tool boundaries, then rerun readiness.

## A run is blocked

Open its Recovery panel and inspect the persisted diagnosis. Look for the failing component, category, last successful event, retryability, and permitted recovery actions.

Common categories include unavailable providers, unavailable tool servers, missing credentials, target reachability, policy denial, timeout, worker heartbeat loss, unresolved dependencies, insufficient evidence, budget exhaustion, and repeated no-progress actions.

Do not keep retrying a deterministic error. Change the underlying condition or select a materially different bounded strategy.

## No vault appears active

An active connection requires more than a configured path:

- an absolute `TI_SCALE_VAULT_ROOT`
- memory-control policy allowing vault projection
- a path inside the allowed root
- successful write, read, rename, and delete checks
- a persisted connected status

Open **Second Brain → Vault**, run the health check, and review the exact remediation. A missing directory, permission failure, symbolic link, or disabled memory policy prevents connection.

## The graph has only a few visible nodes

For a new database, this can be correct. Check global versus local view, node type, lifecycle, scope, confidence, date, and sensitivity filters. Candidate notes do not become confirmed memory automatically.

The graph shows stored edges only. If nodes are isolated, inspect each node's backlinks and provenance, confirm eligible candidates, import supported notes, then reindex. Do not add guessed relationships solely for visual density.

## Vault changes do not synchronize

Run:

```bash
bun run brain:sync-verify --db ./data/ti-scale.sqlite \
  --vault-root /absolute/vault/root --connection <connection-id>
```

Review `database_ahead`, `vault_ahead`, `conflict`, `missing`, `pending`, and `quarantined` counts. Resolve conflicts in the UI. Use repair or reindex only after checking the expected connection version; these operations preserve conflicts instead of overwriting them.

## Event stream reconnects repeatedly

- Confirm the reverse proxy disables buffering for SSE.
- Preserve `Last-Event-ID` and allow heartbeat traffic.
- Check response timeouts and idle-connection limits.
- Replay from the last per-run sequence.
- Check whether a slow subscriber exceeded its bounded queue.

A reconnect is a transport condition, not mission progress or mission failure.

## An evidence link returns 404

Copy the URL and request ID. Verify that the evidence ID exists, its mission and run relations are canonical, and the artifact has not been quarantined. The UI should show a reconciliation state for genuinely missing data; a generated internal link returning 404 is a release-blocking defect.

Use the published API contract and avoid constructing deep links from missing relationships.

## Database is busy

SQLite uses WAL and a bounded busy timeout. Persistent busy errors usually indicate an unexpectedly long transaction, a stalled writer, an external filesystem tool touching the database, or storage latency.

- Do not copy the live database. This installation has no backup or restore command; diagnose the writer and recover the canonical database forward.
- Check the process list and database directory permissions.
- Stop the service before maintenance that requires exclusive database ownership.
- Do not place the active database on an unreliable network filesystem.

## Reporting a problem

Include:

- Ti-Scale commit and build identifier,
- route and timestamp,
- request ID or trace ID,
- mission and run IDs when safe,
- readiness snapshot,
- concise reproduction,
- sanitized error envelope.

Remove tokens, credentials, target secrets, raw confidential payloads, and private vault content.
