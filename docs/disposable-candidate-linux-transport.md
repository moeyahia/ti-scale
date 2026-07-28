# Disposable candidate Linux transport

Ti-Scale includes a fixture-only candidate transport for proving the complete
typed Autonomous execution path on the local host. It is not a generic command
transport and does not make any external or arbitrary-target readiness claim.

The fixture proves that Ti-Scale can carry an exact, canonical sequence from a
succeeded AttackAttempt through session identity, hash-only user objective
proof, privilege continuation, independent root identity, hash-only root
objective proof, and cleanup. It accepts no command, shell, argv, payload,
credential, caller-selected file, raw flag, or arbitrary target.

## Capability statement

- Candidate class: `disposable_local_fixture_v1`
- Readiness scope: `production_path_proof_only`
- Real-target support: `false`
- Mission-execution ready: `false`
- Exact fixture target: `127.0.0.2`
- Socket: `/run/ti-scale-candidate-linux/broker.sock`
- Socket mode: `0660`, restricted to the existing `ti-scale` GID
- Broker account: the existing `ti-scale` service account, so the broker can
  read the canonical SQLite database and its WAL/SHM without weakening the
  database directory permissions
- Canonical authorization: repeated inside the broker process against the
  current signed contract, current plan, running action, succeeded
  AttackAttempt, exact target, active candidate spec, and current session fence

The manifest model also permits a separately reviewed
`reviewed_real_candidate_v1`. Such a binding must state
`realTargetSupport: true`, supply its own hash-pinned handler profile and pass
the same canonical broker authorization. The disposable profile cannot be
reused for that class.

## No-backup activation sequence

These commands create no backup. Run them only after schema migration 46
succeeds.

1. Build the immutable broker program:

   ```sh
   bun build \
     server/autonomous-runtime/disposable-candidate-linux-broker-cli.ts \
     --target=bun --format=esm \
     --outfile /tmp/disposable-candidate-linux-broker.js
   ```

2. Register the idempotent fixture-only ScriptArtifact, independent observer,
   and candidate specification:

   ```sh
   bun run scripts/register-disposable-candidate-linux-proof.ts \
     --execute \
     --database-path /var/lib/ti-scale/data/ti-scale.sqlite
   ```

   The receipt must report `fixtureOnly: true`,
   `realTargetSupport: false`, and
   `post-exploit:disposable-linux-proof-v1`.

3. Resolve the numeric existing `ti-scale` group ID and install the immutable
   files without starting or restarting either service:

   ```sh
   TI_SCALE_GID="$(getent group ti-scale | cut -d: -f3)"
   bun run scripts/install-disposable-candidate-linux-transport.ts \
     --execute \
     --database-path /var/lib/ti-scale/data/ti-scale.sqlite \
     --post-exploit-spec-id post-exploit:disposable-linux-proof-v1 \
     --broker-bundle-path /tmp/disposable-candidate-linux-broker.js \
     --broker-gid "$TI_SCALE_GID" \
     --socket-gid "$TI_SCALE_GID"
   ```

4. Review the generated hashes, then activate explicitly:

   ```sh
   systemctl daemon-reload
   systemctl enable --now ti-scale-candidate-linux-broker.service
   systemctl status --no-pager ti-scale-candidate-linux-broker.service
   systemctl restart ti-scale.service
   ```

5. Verify the application reports the candidate transport as
   `production_path_proof_only` with `missionExecutionReady: false`. It must
   not project post-exploit tools or report arbitrary/external target
   readiness from this fixture.

The installer stages a Ti-Scale drop-in but never restarts Ti-Scale itself.
This makes the service transition visible and keeps the schema, registration,
broker startup, broker attestation, and application restart as separate
auditable operations.

## Installed files

- `/usr/local/libexec/ti-scale/disposable-candidate-linux-broker.js`
- `/etc/ti-scale/candidate-linux/profile.v1.json`
- `/etc/ti-scale/candidate-linux/manifest.v1.json`
- `/etc/ti-scale/candidate-linux-broker.env`
- `/etc/ti-scale/candidate-linux-runtime.env`
- `/etc/systemd/system/ti-scale-candidate-linux-broker.service`
- `/etc/systemd/system/ti-scale.service.d/80-candidate-linux-transport.conf`
- `/var/lib/ti-scale-candidate-linux/fixture/user.txt`
- `/var/lib/ti-scale-candidate-linux/fixture/root.txt`
- `/var/lib/ti-scale-candidate-linux/state/state.v1.json` after first use

The two proof files contain disposable fixture text. The handler checks their
root ownership, mode, size, and deployment-pinned SHA-256 before use and returns
only the digest and byte count.
