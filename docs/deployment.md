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
/var/lib/ti-scale/static-releases/ immutable browser releases
/var/lib/ti-scale/vaults/         allowed vault root
/var/lib/ti-scale/release-transactions/ content-free forward journal
```

The service account should own only the directories it must write. Keep configuration mode `0600` and data directories mode `0700` where practical.
The release transaction root is a deliberate exception: it remains root-owned,
nonwritable, and non-listable by the service account, but the unprivileged
startup wrapper must have traverse-only access so it can read the exact
fixed-name committed journal. Use the reviewed release-start installer and
preflight; do not broaden read, write, or directory-list permissions.

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

Use the [production backend preflight](production-backend-preflight.md) before
any database, Vault, provider, MCP sidecar, service-unit, or credential change.
Its historical backup and rollback instructions are superseded by the
forward-only no-backup boundary in this document.

The bounded WhatWeb and FFUF configuration has a separate, checksum-bound
[reviewed web-assessment activation procedure](reviewed-web-assessment-capability.md).
Its public CLI verifies source and installed identity but cannot mutate or
withdraw the Ti-Scale systemd drop-in. The coupled forward release retains
ownership of publication, the maintenance window, restart, live readiness
proof, and recovery.

## Forward-only database upgrade boundary

This installation uses a strict operator-selected no-backup policy. Deployment
must not create database copies, migration snapshots, rollback archives,
rehearsal payloads, candidate publication stores, or equivalent restorable
copies under another name.

Every schema migration therefore runs as a bounded forward-only transaction:

```bash
bun run db:migrate --db /var/lib/ti-scale/data/ti-scale.sqlite
```

The compatibility spelling `--no-backup --acknowledge-no-backup-risk` remains
accepted for command compatibility. `--backup-dir` is rejected. The migration
either commits the new schema or leaves the original transaction intact; after
commit, recovery is forward-only. The content-free release journal records
hashes and phases but contains no restorable application or database payload.

## Stage and deploy one forward-only candidate

The supported package path accepts only an explicit, clean Git worktree and
that worktree's exact `dist/` directory. It does not infer a checkout, accept a
dirty tree, rebuild in place, or copy the active release. Candidate creation
and deployment share one kernel release lock; the existing no-backup deploy
controller receives the exact server/static manifest binding before any
pointer or database mutation.

First inspect the immutable identities without staging anything:

```bash
bun run release:no-backup:inspect-candidate -- \
  --source-root /srv/ti-scale-candidate \
  --static-build-root /srv/ti-scale-candidate/dist
```

Record the reported full Git commit, server source-tree SHA-256, and static
artifact SHA-256. Supply all three values deliberately when executing:

```bash
bun run release:no-backup:stage-deploy -- \
  --source-root /srv/ti-scale-candidate \
  --static-build-root /srv/ti-scale-candidate/dist \
  --source-commit FULL_GIT_COMMIT \
  --source-tree-sha256 SERVER_TREE_SHA256 \
  --static-artifact-sha256 STATIC_TREE_SHA256 \
  --release-id RELEASE_ID \
  --confirm RELEASE_ID \
  --execute \
  --acknowledge-no-backup-risk
```

The stage command fails before publication when:

- `--source-root` is not the exact Git worktree root;
- tracked or untracked Git state is dirty;
- `--static-build-root` is not that root's exact `dist/` directory;
- any supplied commit/tree digest differs from the inspected bytes;
- the server/static candidates do not share the same release ID;
- an existing candidate is partial, tampered, or differs from those pins;
- the candidate ID is active or retained by the current static pointer;
- any configured prohibited backup/snapshot payload root is nonempty.

An exact pre-existing pair is reused idempotently. A newly created partial pair
is deleted only after its exact source/build identity and non-active status are
reverified. Once the durable deploy transaction is published, recovery belongs
exclusively to the existing forward-only controller. Use:

```bash
bun run release:no-backup:recover -- \
  --release-id RELEASE_ID \
  --confirm RELEASE_ID \
  --execute \
  --acknowledge-no-backup-risk
```

Neither command creates a database copy, source archive, prior static release
copy, Vault snapshot, or rollback payload. The candidate itself is the
hash-bound target release, not a retained copy of the previous state.

New deployments write
`ti-scale.no-backup-forward-release-receipt.v2` with
`deploymentMode: current_service`. Its release observer is explicitly
standalone and Ti-Scale-only: it neither queries nor requires any unrelated
service. Receipt and journal commitments use `observerProofSha256`.
Interrupted historical
`ti-scale.no-backup-preview-release-receipt.v1` transactions remain readable
and recoverable with their original `legacyIdentitySha256` commitment; that
compatibility path is never used when creating a new release.

The active deployment path accepts the exact canonical schema-60 source
database and migrates it forward to the selected source tree's canonical
migration ceiling (schema 63 for this activation). The controller derives that
ceiling from the ordered migration registry and requires the independently
staged release attestation to match it byte-for-byte. Recovery classifies every
committed schema from 61 through 63 as forward-only: an interruption before the
first schema commit restores the prior pointers, while an interruption after
any schema commit completes the exact committed target forward. Historical
schema-47-to-60 and schema-60-to-60 receipts remain recoverable using the
immutable schema boundary recorded in those receipts; they do not alter the
target of a new release.

Candidate Linux activation files are not treated as a backup payload or as a
side effect of application-pointer publication. Their separate forward-only
installer accepts an exact repeated bundle as a verified no-op and rejects
partial or changed destinations. Once its application drop-in is installed,
Ti-Scale is systemd-bound to a fully notified broker; application startup
cannot pass through a missing, skipped, timed-out, or unattested candidate
transport dependency.

Use `bun run candidate-linux:activate-reviewed-real -- inspect ...` for the
read-only source and installed-file check. Use
`bun run candidate-linux:activate-reviewed-real -- activate --execute
--confirmation ACTIVATE_TI_SCALE_REVIEWED_REAL_CANDIDATE_LINUX_ON_3132 ...`
for the explicit forward-only registration, systemd reload, ordered
adapter/broker activation, Ti-Scale restart, broker attestation, and live
health/readiness/authentication proof. This command creates no backup or
rollback payload and is restricted to the pinned Ti-Scale service and reviewed
candidate dependencies. Exact pins and receipt semantics are documented in
[`reviewed-real-candidate-linux-activation.md`](reviewed-real-candidate-linux-activation.md).

## Environment

Example server settings:

```dotenv
TI_SCALE_HOST=127.0.0.1
TI_SCALE_PORT=3132
TI_SCALE_DATABASE_PATH=/var/lib/ti-scale/data/ti-scale.sqlite
TI_SCALE_SCRIPT_SOURCE_ROOT=/var/lib/ti-scale/ti-scale-artifacts/script-sources
TI_SCALE_VAULT_ROOT=/var/lib/ti-scale/vaults
TI_SCALE_OPERATOR_ID=local-operator
TI_SCALE_OPERATOR_TOKEN_FILE=/run/credentials/ti-scale.service/operator-token
TI_SCALE_PREVIEW=false
TI_SCALE_SERVE_STATIC=true
TI_SCALE_SECURE_COOKIES=true
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
ReadWritePaths=/var/lib/ti-scale

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
9. Verify the unprivileged startup wrapper can traverse the release transaction
   root and validate the committed fixed-name journal without gaining directory
   list or write access.

## Forward recovery

This installation deliberately retains no rollback payload. Before the schema
commit boundary, an interrupted transaction resumes against the existing
state. After commit, recovery can only finish the exact hash-bound target
forward. The startup admission wrapper refuses nonterminal, malformed, or
divergent journal state instead of starting an ambiguous release.

- Active mission work must be drained or deterministically checkpointed before
  runtime changes.
- The content-free transaction journal records phases and SHA-256 values only.
- Failed target files are repaired in place from the reviewed source tree; no
  sibling copy or rollback archive is created.
- A schema already committed by a candidate must never be opened by an older
  server.
- Strategy-version selection is a domain-level operation, not a deployment
  rollback, and does not copy application or database payloads.
