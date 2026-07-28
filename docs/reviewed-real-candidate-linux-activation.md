# Reviewed real-candidate Linux activation

Ti-Scale has a production installation boundary for a separately reviewed,
candidate-specific Linux post-exploitation adapter. The platform does not
generate or improvise that adapter. An operator must provide four compiled,
owner-controlled files and one exact profile:

1. the candidate adapter executable;
2. the reviewed-real candidate profile;
3. the reviewed transport broker executable;
4. the reviewed registration executable.

Each file is supplied with its exact lowercase SHA-256 digest from one
non-writable review directory. The profile must identify the approved
ScriptArtifact, independent exploit-outcome observer, post-exploit spec,
transport binding, expected principal, proof paths, installed adapter path,
installed socket, and closed eight-operation protocol.

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
  --broker-path <review-directory/broker> \
  --broker-sha256 <sha256> \
  --register-path <review-directory/register> \
  --register-sha256 <sha256>
```

Publication uses the same arguments with `install --execute`. It is
forward-only:

- no destination may already exist;
- no backup, replacement, migration, or rollback copy is created;
- files are published at fixed paths with root ownership and Ti-Scale group
  access where required;
- no database row is written;
- no `systemctl daemon-reload`, enable, start, restart, or application reload
  occurs;
- no socket is contacted and no target is contacted.

Success is reported as `installed_not_activated` with
`missionExecutionReady: false`.

## Activation remains explicit

Installation is not runtime readiness. A release operator must separately:

1. invoke the installed, hash-pinned registration executable with the exact
   installed manifest environment;
2. reload systemd;
3. start the candidate-specific adapter;
4. start the broker, which refuses readiness unless the adapter returns a
   current profile- and executable-bound attestation;
5. obtain the broker attestation through the canonical runtime registry;
6. confirm the registry reports
   `readinessScope: reviewed_real_candidate` and
   `missionExecutionReady: true`;
7. only then restart Ti-Scale to consume the installed manifest.

At execution time, installation pins are not treated as mission authority.
The runtime still requires a current derived specification, one exact
canonical target, a current signed action, a confirmed contract hash, a
succeeded exploit attempt with verified outcome evidence, and the active
lease/cancellation fence.

## Operator-supplied implementation requirement

The repository intentionally contains no fabricated real-target adapter.
Completion for a particular candidate requires an independently reviewed,
compiled adapter that implements
`ti-scale.reviewed-real-candidate-linux-adapter.v1` through the existing
typed adapter host contract. Its profile and executable hash must match
exactly. A generic shell runner, argv forwarder, payload transport,
credential surface, arbitrary file reader, or dynamic module loader is not
accepted.
