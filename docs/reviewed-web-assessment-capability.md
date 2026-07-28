# Reviewed web-assessment activation

Ti-Scale contains two reviewed, bounded web-assessment bindings:

- `kali:whatweb-bounded-fingerprint` identifies a constrained set of server,
  title, framework-header, and HTML signals for one exact authorized URL.
- `kali:ffuf-bounded-content-discovery` checks one fixed 14-entry path list
  against one exact authorized web origin. It does not recurse or follow
  redirects.

Both tools remain Guided-only in this version. The activation described here
does not grant mission authority, change target scope, authorize an action
class, or replace the exact Guided decision required for execution.

## Immutable activation identity

The production configuration is a versioned bundle:

| Item | Identity |
| --- | --- |
| Bundle | `reviewed-web-assessment-2026.07.20-v1` |
| Service | `ti-scale.service` |
| Descriptor | `deployment/runtime-config/reviewed-web-assessment-activation-bundle.v1.json` |
| Descriptor SHA-256 | `1475b256854a9953c330c1ed1ddcecaa9e33ff66243200ee02199113d49699c4` |
| Environment SHA-256 | `fb6a67dab85ae66c7befe0c9e045aba33e830b5f57d25b1533d014454bef4a5e` |
| Drop-in SHA-256 | `5e0b819fb487b6b3345b8cd36748cccc670c0f3dada139faeb01367f790f0aa6` |

The environment file contains exactly:

```text
TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=true
```

The systemd drop-in loads that environment from the version-addressed bundle
directory. It is installed only under `ti-scale.service.d`; the installer has
no generic service-name parameter.

## Source verification

This command is read-only. It verifies the descriptor, environment, and
drop-in ownership, modes, exact keys, and SHA-256 identities:

```bash
cd /root/ti-scale
bun run scripts/install-reviewed-web-assessment-activation.ts source-verify
```

Expected result:

```text
source_verified: reviewed-web-assessment-2026.07.20-v1; service ti-scale.service; no files installed
```

## Forward-only publication

The activation CLI is intentionally read-only. It does not expose install,
withdraw, or rollback commands. The coupled Ti-Scale release controller must
publish the reviewed bundle as part of the exact forward candidate and then
verify it before the service is restarted.

The forward candidate contains:

- `/etc/ti-scale/runtime/bundles/reviewed-web-assessment-2026.07.20-v1/activation-environment.v1.conf`
- `/etc/ti-scale/runtime/bundles/reviewed-web-assessment-2026.07.20-v1/activation-bundle.v1.json`
- `/etc/systemd/system/ti-scale.service.d/70-reviewed-web-assessment.conf`

No prior drop-in bytes, restorable release, database copy, snapshot, or
rollback payload may be retained. The release journal may record only
content-free transaction metadata such as the bundle identity, file hashes,
phase, timestamp, and verification result.

After forward publication, verify the prepared filesystem identity with:

```bash
bun run scripts/install-reviewed-web-assessment-activation.ts verify-installed
```

## Activation handoff

The main functional release owns the maintenance window, service restart,
health verification, capability-readiness check, and failure recovery. During
that approved release it must perform, in order:

1. Confirm that no active run or control-plane lease will be interrupted.
2. Verify the installed activation bundle.
3. Run `systemctl daemon-reload`.
4. Restart only `ti-scale.service`.
5. Verify API/database/event health.
6. Run authenticated capability self-tests and require current readiness for
   both exact web tool IDs.
7. Run the loopback real-subprocess integration test before permitting a
   target-bearing Guided decision.

The environment flag alone is not a readiness receipt. Ti-Scale must still
join current executable, dependency, Bubblewrap, workspace, result-sink,
cancellation, and normalizer checks before advertising either tool.

## Forward recovery

There is no deployment rollback path. If verification or activation fails,
leave Ti-Scale fail-closed, correct the reviewed candidate, publish the
hash-bound replacement forward, restart only Ti-Scale, and repeat the complete
readiness proof. Do not recreate the previous drop-in from copied bytes.

If a database schema commit occurred in the same release, an older application
build must never be started against that database. Recovery must complete with
a compatible forward candidate.

## Validation commands

```bash
bun test \
  server/web-assessment-tools/__tests__/WebAssessmentToolPack.test.ts \
  server/web-assessment-tools/__tests__/WebAssessmentProcessAdapter.integration.test.ts \
  scripts/release/__tests__/ReviewedWebAssessmentActivationBundle.test.ts

bun x tsc -p tsconfig.server.json --noEmit
```

The subprocess integration uses only an ephemeral `127.0.0.1` HTTP fixture
and a temporary mapped Ti-Scale workspace. It does not contact an external
target.
