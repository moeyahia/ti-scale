# Production backend preflight

This checklist is an operator-run release procedure. Source validation does not authorize installing credentials, changing system services, migrating the canonical database, restarting Ti-Scale, or calling a public provider.

## Current upgrade boundary

Treat any deployment whose schema is behind the target declared by the staged
server manifest as a database upgrade, not a static-file release. The release
workflow must derive and verify that target from the exact staged source; this
runbook intentionally does not duplicate a migration number that will become
stale. Schema changes do not make a provider or tool executable by themselves.

The separately supplied systemd templates provide:

- an isolated, loopback-only public NVD sidecar with exact one-tool/schema attestation;
- a private systemd credential mount for OpenRouter Guided readiness;
- no mission execution authorization merely because either dependency is healthy.

## 1. Freeze and record

1. Record the exact source commit, build manifest, Bun version, service unit version, active database migration, and current health response.
2. Confirm there are no active or recovering runs whose checkpoint could be invalidated by maintenance.
3. Confirm the reviewed source and candidate hashes required for forward recovery remain available.
4. Record the release typecheck and targeted backend test result hashes in the content-free release journal.
5. Verify the root-owned release transaction directory is nonwritable and
   non-listable by the service account while granting that account only the
   traversal needed to read the fixed-name committed startup journal. Run the
   reviewed release-start installer/preflight instead of applying a blanket
   `0700` data-directory rule to this path.

Do not continue when the source tree is dirty in an unexplained way or when a running mission lacks a safe terminal checkpoint.

## 2. Enforce the no-backup boundary

This installation uses the operator-selected forward-only policy:

1. Do not create database copies, migration snapshots, source archives, Vault archives, candidate publication stores, or rollback payloads.
2. Confirm the database migration CLI rejects `--backup-dir`.
3. Confirm direct static stage, activation, and rollback commands are disabled.
4. Confirm the forward-only release journal contains only phases, identities, hashes, and receipts—not restorable payload bytes.
5. Run integrity and foreign-key verification against the canonical database before entering maintenance.

After a schema commit, an older server must never open the newer database.
Recovery finishes the exact reviewed target forward or leaves the service
closed for explicit repair.

## 3. Validate the Vault boundary

1. Configure `TI_SCALE_VAULT_ROOT` as the absolute parent sandbox, for example `/var/lib/ti-scale/vaults`.
2. Confirm the canonical database contains the intended persisted connection and that it is `connected`.
3. Confirm the connection path exists beneath the configured sandbox and contains no symbolic-link escape.
4. Confirm an audited `vault.health.verified` receipt exists for that connection.
5. After deployment, require health to report matching configured, connected, reachable, and health-verified counts.

The health probe is read-only. A missing round-trip receipt must be repaired through the authenticated Vault health workflow, which performs and audits the bounded write/read/rename/delete test; never fabricate the audit record.

## 4. Prepare the public NVD sidecar

1. Review `deployment/systemd/ti-scale-mcp-nvd.service`, its dedicated sysusers entry, and the main-service public-NVD credential drop-in.
2. Create the sidecar bearer credential outside the repository and install it as a private root-owned file. Do not print or place it in an environment variable.
3. Install and verify the unit templates with the host's systemd tooling.
4. Start the sidecar independently and run the secret-safe smoke check.
5. Require exact server name/version, one reviewed `get_cve_details` tool, both pinned schema digests, and read-only annotations.
6. Only then start the main service with its separate systemd credential mount.

A healthy sidecar remains `executionAuthorized=false`. The reviewed source now
contains one authenticated mission-scoped public-read adapter. That adapter
accepts only a canonical opaque CVE applicability record, verifies the mission,
exact run, current-plan step, Ti-Scale control plane, current mission
authorization, and host actor policy, and withholds successful output unless its
invocation provenance is appended to the canonical audit trail. It does not
grant a run lease, specialist execution, target interaction, evidence status,
Guided execution, Autonomous execution, or generic MCP access.

Sidecar health alone does not prove that this adapter is deployed. The main
service must be the matching reviewed source build, use the reviewed database
schema, share the attested client, and expose the documented route contract.

## 5. Prepare OpenRouter readiness

1. Review `deployment/systemd/ti-scale.service.d/30-openrouter-guided.conf`.
2. Create or rotate the OpenRouter completion key outside the repository and install it as a root- or service-owned mode-`0400`/`0600` regular file.
3. Keep the exact provider/model identifier pinned and record its configuration hash in the release receipt.
4. Install the drop-in only after confirming no raw `OPENROUTER_API_KEY` is inherited by the service.
5. Require the bounded key/model check and the subsequent content-free durable completion audit to succeed.

Metadata readiness proves the credential class and exact pinned model. The production monitor then creates a locally persisted empty Context Pack, provider-exposure receipt, and exact durable request authorization before sending one content-free strict-schema completion. `callable=true` requires the exact returned model and usage receipt from that one-shot request. This proves only the planning-provider call path; the standalone server must not advertise mission-level Guided execution until the Guided port, controller lease, and specialist boundary are also mounted.

## 6. Apply the database upgrade

1. Stop the Ti-Scale service cleanly and confirm its process and database writers are gone.
2. Reconfirm the exact reviewed candidate identity and content-free release-journal intent.
3. Run the reviewed migration command once against the exact canonical database.
4. Require the exact staged target migration, SQLite integrity success, foreign-key success, WAL mode, and zero migration errors.
5. Do not edit migration history or open a committed newer schema with an older server. If the transaction did not commit, restart the same exact target; if it did commit, complete forward recovery with that target.

## 7. Start and verify

After installing the exact verified server/static release and approved service configuration:

1. Start the public NVD sidecar, then Ti-Scale.
2. Require `/api/v2/health` to return the exact Ti-Scale liveness identity and a
   healthy cached startup database attestation. Separately require
   `/api/v2/system/readiness` to report structured—not `unknown`—Second Brain,
   provider, MCP, tool, and execution readiness. A healthy liveness response
   never substitutes for a healthy readiness response.
3. Require the Vault projection counts to reconcile with the canonical connection and its audit receipt.
4. Require the public NVD status to be `ready` with `executionAuthorized=false`.
5. Require OpenRouter to show the pinned requested model and configuration hash. It must remain non-callable unless the exact durable completion receipt is present and fresh.
6. Confirm provider/MCP route counts do not claim mission execution adapters that are not mounted.
7. Verify event-stream startup, database migration, no uncaught startup errors, and no unexpected network request failures.
8. Verify the unprivileged startup wrapper can traverse the release transaction
   root and validate the committed installation journal without list or write
   access.
9. With a disposable reviewed mission fixture, call the authenticated
   mission/run/current-step NVD-detail route using only its opaque CVE record ID.
   Require a secret-free, `no-store`, target-free response and the matching
   `cve.nvd_detail.retrieved` audit record.
10. Prove the same route fails closed before MCP invocation for a stale step,
   mismatched run, unverified mission authorization, caller-supplied query
   parameters, and an expired or drifted sidecar attestation.

## 8. Recover forward

No rollback payload is retained. If the candidate fails before schema commit,
the transaction leaves canonical state unchanged and the exact reviewed target
may be retried after correcting the diagnosed cause. If schema commit occurred,
keep the service closed until the exact hash-bound target completes its
forward recovery and passes integrity, readiness, and browser checks.

## Known launch blockers

- A canonical database behind the staged target cannot expose the new provider request/usage contract until the reviewed forward-only migration completes.
- A missing public-NVD sidecar service, shared credential mount, fresh exact
  attestation, or matching deployed mission-read adapter keeps the public NVD
  route unavailable. The source implementation alone is not deployment proof.
- OpenRouter metadata attestation alone is not a Guided execution adapter and cannot satisfy Guided provider callability.
- The standalone server currently advertises no specialist execution fleet, no general MCP execution route, and no Autonomous enforcement path. Those states must remain unavailable rather than being overridden by configuration.
- A Vault connection without configured sandbox access, a reachable path, and its real round-trip audit receipt is degraded even when Markdown files exist on disk.
