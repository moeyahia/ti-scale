# Reviewed real-candidate Linux activation

Ti-Scale has a production installation boundary for a reviewed,
candidate-specific Linux post-exploitation protocol. Product launch installs a
distinct hash-pinned procedure provider and a conditional adapter bridge. It
does not create any run-scoped activation or dispatch authority. An operator
supplies four owner-controlled protocol files and one exact source profile:

1. the candidate adapter executable;
2. the distinct closed procedure-provider executable;
3. the reviewed-real candidate profile;
4. the reviewed transport broker executable;
5. the reviewed registration executable.

Each file is supplied with its exact lowercase SHA-256 digest from one
non-writable review directory. The profile must identify the approved
ScriptArtifact, independent exploit-outcome observer, post-exploit spec,
transport binding, expected principal, proof paths, installed adapter path,
installed socket, distinct provider path/hash, and closed eight-operation
protocol.

After evidence-backed discovery, the reviewed exploit must be materialized as
an independently validated, byte-identical current-run ScriptArtifact. Those
exploit bytes are never treated as the provider executable. Before plan
construction, Ti-Scale invokes the distinct provider only with target-free
`attest` and `conformance` envelopes. Conformance must return schema-valid
fixtures for all eight operations. Only then does Ti-Scale derive the
current-run typed specification and persist an immutable admission receipt.
Immediately before dispatch, a separate activation binds that admission to the
mission, run, plan, step, AttackAttempt, exact target, represented action,
observer, and validation artifact.

The activated provider receives a single JSON request on stdin containing one
of the eight typed operations. It receives no command, shell, argv, payload,
credential, arbitrary proof path, or provider-authored instruction. It must
return exactly one bounded JSON envelope. Credentials, if that specific
procedure requires them, remain in separately permissioned host-local storage
known to the reviewed procedure; they never cross the runtime request.

### Procedure protocol

The adapter launches the pinned procedure directly with no command-line
arguments, no shell, an empty working directory authority (`/`), a fixed
non-secret environment, bounded output, a 15-second default timeout, and a
bounded concurrency of one. The procedure reads one newline-terminated JSON
envelope from standard input and writes one newline-terminated response:

```json
{"ok":true,"result":{}}
```

or:

```json
{"ok":false,"error":{"code":"stable_code","message":"Operator-readable reason"}}
```

For invocation, `result` is intentionally smaller than the public runtime
receipt:

- `open` and `privilege_escalation`: `{ "accepted": true }`
- `observe_identity`: principal, numeric UID/GID, and group names
- `prove_user_flag_hash` and `prove_root_flag_hash`: SHA-256 and byte count
  only
- `close` and `cleanup`: `{ "closed": true }`
- `observe_root_identity`: the independently observed root UID/GID and groups

The adapter validates each exact result shape and constructs the durable
timestamped receipts itself. Extra fields—including raw flag data—are rejected.
The provider must persist enough candidate-specific session state to enforce
the `sessionArtifactId`, exact target, binding hash, action ID, and lease fence
across its short-lived invocations and process restarts.

## What the installer proves

Before its first filesystem write, the installer:

- reads every input without following symbolic links;
- verifies owner, permissions, stable file identity, executable mode, and
  SHA-256;
- parses the profile as `reviewed_real_candidate_v1`;
- verifies the profile pins the fixed production adapter path and socket;
- loads the canonical database read-only;
- verifies the approved ScriptArtifact and active independent observer;
- verifies the source autonomous run, verified mission, and confirmed
  contract ID, version, and hash;
- recomputes the post-exploit specification hash from canonical database
  fields;
- rejects any conflicting registered specification;
- builds a manifest with exactly eight typed operations and no command,
  shell, argv, payload, credential, or provider field.

The source specification may already be registered or may be
`ready_for_registration`. Registration is a separate explicit mutation.

## Forward-only publication

Run source verification first:

```text
bun run candidate-linux:install-reviewed-real -- source-verify \
  --bundle-version <reviewed-version> \
  --database-path /var/lib/ti-scale/data/ti-scale.sqlite \
  --service-gid <ti-scale-gid> \
  --source-trust-root <review-directory> \
  --profile-path <review-directory/profile.json> \
  --profile-sha256 <sha256> \
  --adapter-path <review-directory/adapter> \
  --adapter-sha256 <sha256> \
  --procedure-path <review-directory/procedure> \
  --procedure-sha256 <sha256> \
  --broker-path <review-directory/broker> \
  --broker-sha256 <sha256> \
  --register-path <review-directory/register> \
  --register-sha256 <sha256>
```

Publication uses the same arguments with `install --execute`. It is
forward-only and idempotent for one exact bundle:

- rerunning the same owner-, mode-, and hash-identical bundle is a verified
  no-op;
- a partial destination, changed byte, or changed ownership/mode is rejected;
- no backup, replacement, migration, or rollback copy is created;
- files are published at fixed paths with root ownership and Ti-Scale group
  access where required;
- no database row is written;
- no `systemctl daemon-reload`, enable, start, restart, or application reload
  occurs;
- no socket is contacted and no target is contacted.

Success is reported as `installed_not_activated` with
`missionExecutionReady: false`,
`conditionalCapability: true`, and
`candidateProcedurePresentAtLaunch: true`. The compatibility field means that
the distinct provider bytes are installed. The same receipt states
`procedureProviderPresentAtLaunch: true` and
`runScopedProcedureActivationPresentAtLaunch: false`; installation never grants
run dispatch. The receipt also copies the profile's parsed `targetScope`
verbatim. An exact-target or endpoint-bound provider therefore remains
explicitly non-general at installation and cannot be promoted into global
mission readiness by the release bundle.

## Forward-only activation command

Installation is not runtime readiness. The privileged activation command
couples the reviewed steps without creating a backup or rollback payload:

```bash
bun run candidate-linux:activate-reviewed-real -- inspect \
  --bundle-version <stable-id> \
  --database-path /var/lib/ti-scale/data/ti-scale.sqlite \
  --service-gid <ti-scale-gid> \
  --source-trust-root <review-root> \
  --profile-path <review-root/profile.json> \
  --profile-sha256 <sha256> \
  --adapter-path <review-root/adapter> \
  --adapter-sha256 <sha256> \
  --procedure-path <review-root/procedure> \
  --procedure-sha256 <sha256> \
  --broker-path <review-root/broker> \
  --broker-sha256 <sha256> \
  --register-path <review-root/register> \
  --register-sha256 <sha256>
```

`inspect` is read-only. It verifies the source authority and reports whether
the complete exact installation is absent or present. A partial installation
or any owner, mode, hash, parent-directory, or receipt drift is an error.

Activation uses the same pins plus:

```bash
bun run candidate-linux:activate-reviewed-real -- activate \
  --execute \
  --confirmation ACTIVATE_TI_SCALE_REVIEWED_REAL_CANDIDATE_LINUX_ON_3132 \
  <the same exact pins>
```

The command runs under the shared release lock and:

1. queries canonical Ti-Scale work state read-only and refuses activation
   while a run, control-plane lease, or external database writer is active;
2. publishes or idempotently verifies the exact bundle;
3. runs the installed registration executable as `ti-scale` with a clean,
   fixed environment and no shell;
4. verifies the installed bytes again after registration and rechecks
   canonical quiescence before systemd mutation;
5. reloads systemd and proves both candidate units, the exact Ti-Scale base
   fragment, and the exact candidate drop-in are loaded;
6. enables both units, starts the adapter, proves its active identity, starts
   the broker, and proves its active identity;
7. restarts only `ti-scale.service`;
8. proves both dependency units and Ti-Scale are active with successful main
   processes and re-proves the exact application fragment/drop-in identity;
9. requests a fresh broker attestation through the canonical Unix socket and
   proves the exact manifest, bindings, and target scopes;
10. proves `/api/v2/health`, `/api/v2/system/readiness`, and the local
   authentication session exchange on `http://127.0.0.1:3132`; and
11. emits an in-memory/stdout activation receipt stating that no backup,
    rollback payload, or unrelated service action occurred.

An exact retry is supported. The bundle install and registration are
idempotent; service enable/start is repeatable; a retry performs a fresh
Ti-Scale restart and repeats every live proof. A failure never rewrites an
existing destination, accepts a partial bundle, or reports readiness from
file presence alone.

The receipt deliberately distinguishes global from target-scoped readiness.
An exact-target provider may report `conditionalPlanningReady: true` while
`missionExecutionReady: false`; this is correct until a mission's authorized
targets match the typed scope. The command never broadens that scope.

The command is scoped exclusively to Ti-Scale and its reviewed candidate
dependencies. It performs no unrelated service stop, restart, enable, or
health probe.

The checked-in systemd lifecycle enforces that order rather than relying on
process timing:

- adapter and broker are `Type=notify` services and remain `activating` until
  their application-level startup checks complete;
- the adapter notifies only after its conditional bridge-composition
  attestation succeeds and it creates the profile-pinned Unix socket; this does
  not claim that a run-scoped provider admission already exists;
- the adapter receives write access only to its state/runtime roots and the
  canonical database directory needed for durable run-scoped attestation; the
  broker opens that database read-only;
- the broker binds its Unix socket, requests a complete attestation through its
  own endpoint, and notifies only after the broker receipt and live adapter
  receipt both validate;
- Ti-Scale uses `Requires`, `BindsTo`, and `After` for the broker. A skipped,
  timed-out, failed, or later-disappearing broker therefore cannot leave the
  application running with a falsely advertised transport;
- missing environment or executable files are hard `AssertPathExists`
  failures, not silently skipped optional units;
- stopping or restarting Ti-Scale propagates to the broker and adapter through
  `PartOf`, preventing a stale activation process from surviving the product
  lifecycle.

The notification helper is invoked as a fixed executable with only
`NOTIFY_SOCKET`. The procedure-provider child receives a fixed clean
environment and never inherits the systemd notification socket.

At execution time, installation pins are not treated as mission authority.
The runtime still requires a locally validated byte-identical current-run
ScriptArtifact, matching observer, target-free provider conformance receipt,
immutable provider admission, current candidate specification, one exact
canonical target, a current represented action, a confirmed contract hash, the
bound AttackAttempt, and the active lease/cancellation fence. Dispatch before
this run-scoped activation fails closed.

## Operator-supplied procedure requirement

The repository contains the concrete, hash-verifying provider process boundary,
adapter composition, admission service, and run-scoped activation bridge.
Completion for a particular candidate still requires an independently
validated byte-identical exploit ScriptArtifact tied to its outcome observer
and represented AttackAttempt. Admission pins the separate provider and its
target-free eight-case conformance receipt. Activation consumes only that
admission; restart re-attests the same provider before reuse. Broker dispatch
then repeats database-backed action, target, attempt, and lease checks.

A generic shell runner, argv forwarder, payload transport, credential surface,
arbitrary file reader, or dynamic module loader is not accepted. The provider
and bridge may be launch-ready, but post-exploit dispatch remains unavailable
until the exact current-run exploit is admitted and its represented activation
is attested.
