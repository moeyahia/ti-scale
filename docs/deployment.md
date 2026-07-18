# Deployment

## Recommended topology

Run Ti-Scale as a dedicated operating-system user, bound to loopback, behind an HTTPS reverse proxy when remote access is required.

```text
Browser
  │ HTTPS
  ▼
Identity-aware reverse proxy
  │ loopback HTTP
  ▼
Ti-Scale :3132
  ├── SQLite
  ├── artifact store
  ├── static release store
  └── optional vault sandbox
```

## Filesystem layout

One suitable layout is:

```text
/opt/ti-scale/                    application source or release checkout
/etc/ti-scale/ti-scale.env        private server configuration
/var/lib/ti-scale/data/           SQLite database
/var/lib/ti-scale/artifacts/      artifact content
/var/lib/ti-scale/static/         immutable browser releases
/var/lib/ti-scale/vaults/         allowed vault root
/var/backups/ti-scale/            verified backups
```

The service account should own only the directories it must write. Keep configuration mode `0600` and data directories mode `0700` where practical.

## Build and verify

```bash
cd /opt/ti-scale
bun install --frozen-lockfile
bun run check
bun run build
bun run db:migrate --db /var/lib/ti-scale/data/ti-scale.sqlite
bun run db:verify --db /var/lib/ti-scale/data/ti-scale.sqlite
```

Do not deploy when the interaction manifest contains release-scope gaps, the browser matrix has not passed, or execution readiness is being inferred rather than attested.

## Environment

Example server settings:

```dotenv
TI_SCALE_HOST=127.0.0.1
TI_SCALE_PORT=3132
TI_SCALE_DATA_ROOT=/var/lib/ti-scale/data
TI_SCALE_DATABASE_PATH=/var/lib/ti-scale/data/ti-scale.sqlite
TI_SCALE_ARTIFACT_ROOT=/var/lib/ti-scale/artifacts
TI_SCALE_VAULT_ROOT=/var/lib/ti-scale/vaults
TI_SCALE_OPERATOR_ID=local-operator
TI_SCALE_OPERATOR_TOKEN_FILE=/run/credentials/ti-scale.service/operator-token
TI_SCALE_PREVIEW=false
TI_SCALE_SERVE_STATIC=true
TI_SCALE_SECURE_COOKIES=true
TI_SCALE_DATABASE_ENABLED=true
TI_SCALE_EVENT_STREAM_ENABLED=true
TI_SCALE_SECOND_BRAIN_ENABLED=true
TI_SCALE_KILL_SWITCH=false
```

Connect a vault only after the target path and memory policy are reviewed. A configured root alone never reports synchronization as active.
Configure either the inline token or the private token file, never both. Service deployments should prefer a credential file so the secret is absent from the process environment.

## Service manager example

```ini
[Unit]
Description=Ti-Scale
After=network.target

[Service]
Type=simple
User=ti-scale
Group=ti-scale
WorkingDirectory=/opt/ti-scale
EnvironmentFile=/etc/ti-scale/ti-scale.env
ExecStart=/usr/local/bin/bun run server
Restart=on-failure
RestartSec=5
TimeoutStopSec=45
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ti-scale /var/backups/ti-scale

[Install]
WantedBy=multi-user.target
```

Review sandbox settings when attaching an execution adapter. Grant only the exact filesystem, network, and process permissions required by its policy; do not disable host hardening broadly.

## Reverse proxy requirements

- Preserve `Last-Event-ID`.
- Disable response buffering for `/api/v2/events/stream`.
- Allow long-lived SSE responses and heartbeat traffic.
- Preserve `X-Request-ID`.
- Enforce HTTPS, authentication, and appropriate request-size limits.
- Do not cache authenticated JSON or event responses.

## Deployment verification

After restart:

1. Read health and readiness.
2. Sign in through the browser.
3. Verify the active static release.
4. Confirm the database and event stream.
5. Exercise a read-only mission route.
6. Verify any configured vault round trip.
7. Confirm unavailable adapters are shown as unavailable, not healthy.
8. Run a bounded deployment smoke test against disposable data.

## Rollback

Static client rollback, server rollback, database restore, artifact recovery, and strategy rollback are separate operations.

- A static pointer rollback changes only browser assets.
- A server rollback requires API/schema compatibility review.
- A database restore requires the service to be stopped and the backup hash verified.
- Artifacts and vault content require their own reconciliation.
- Active mission work must be checkpointed or safely terminated before runtime changes.

Rehearse and document the complete rollback for the deployed topology before release approval.
