# Security

Ti-Scale coordinates authorized security work and therefore treats scope, policy, evidence, memory, and provider disclosure as security boundaries.

## Authorization

- Every mission stores a journey and explicit authorization acknowledgment.
- Allowed targets are normalized before launch and checked again at action time by an attached runtime.
- Autonomous work is limited by a versioned mission contract.
- Guided agent execution is limited to one represented action and normalized parameter set.
- A materially changed action requires a new decision.
- An out-of-contract Autonomous action must choose a safe in-scope alternative or stop safely.

The UI is not an authorization boundary. Server-side services and runtime adapters must enforce the same rules.

## Authentication and sessions

The current deployment model uses one configured local operator token. It supports:

- constant-time token comparison,
- signed time-limited sessions,
- HTTP-only session cookies,
- same-site cookies,
- CSRF binding for cookie-authenticated mutations,
- bearer authentication for non-browser clients,
- explicit actor IDs in audit records.

Use HTTPS and `TI_SCALE_SECURE_COOKIES=true` for any non-local browser path. Rotate the operator token after exposure or operator change.

The current single-operator model is not a complete multi-user identity system. Put externally reachable deployments behind an independently reviewed identity-aware access layer.

## HTTP security

The server emits a restrictive Content Security Policy, frame denial, MIME-sniffing protection, a no-referrer policy, cross-origin isolation headers, and a restricted permissions policy. Cross-origin API access is limited to the configured UI origin.

Review these headers whenever provider connectivity, media sources, or deployment origins change. Do not weaken the policy to hide a configuration error.

## Data at rest

- SQLite files are created with restrictive permissions and checked for integrity.
- Artifact metadata includes hashes, provenance, sensitivity, and canonical storage references.
- Vault writes are sandboxed and atomic.
- Logs and events redact known secret-shaped fields.

Application-level database encryption is not currently provided. Use encrypted
canonical storage where the deployment threat model requires it. This
installation retains no database backup, snapshot, or rollback copy.

## Evidence integrity

Raw logs, observations, evidence candidates, verified evidence, findings, and artifacts are different record classes. A command printing a string cannot verify a finding by itself.

Verified evidence requires provenance and an immutable hash. Findings require sufficient linked evidence or a separately audited operator override. Chain-of-custody changes remain append-only.

## Memory privacy

- Credentials, tokens, private keys, and raw confidential payloads are forbidden in reusable memory.
- Memory scope and sensitivity are enforced during retrieval.
- Personal preference candidates require the configured consent lifecycle.
- Memory confirmation and provider disclosure are independent.
- Forgetting removes content and derived retrieval state.
- Engagement-scoped memory must not cross into another engagement.

## Public provider boundary

Treat every remote model as an external, untrusted service. Only minimized typed context that passes disclosure policy may leave the local boundary. Record provider, model, prompt-template hash, Context Pack, sanitization actions, token telemetry when exact, latency, and exposure receipt.

Do not send raw evidence, complete transcripts, credentials, HTTP bodies, packet data, or unrestricted source trees to a public model.

## Research safety

Research candidates may modify only an approved strategy schema. They cannot modify authorization, tool allowlists, destructive-action policy, disclosure policy, evidence integrity, the evaluation harness, audit retention, deployment settings, or production code.

Research execution readiness is established by two short-lived, locally signed
attestations: one for a disposable lab and one for an isolated worker. Each
attestation comes from a target-free bubblewrap probe with an unshared network,
a private disposable workspace, an empty credential environment, read-only
system binaries, and `prlimit`-enforced CPU, address-space, process, file, and
descriptor bounds. Bubblewrap, `prlimit`, Python, and the fixed evaluator source
are hash-pinned by a trusted descriptor. A missing binary, changed hash, stale
receipt, timeout, incomplete cleanup, or failed isolation check keeps Research
blocked. Merely configuring paths or environment variables is never accepted
as readiness.

The proposal source cannot judge or promote its own candidate. Local
evaluation, integrity receipts, hidden holdout, human review, shadow, and
bounded canary are separate gates. A rejected strategy remains an immutable
domain record; it is not a restorable deployment payload.

## Deployment checklist

- Dedicated operating-system account
- Loopback bind or reviewed firewall rule
- HTTPS reverse proxy for remote access
- Private configuration file, mode `0600`
- Encrypted storage where required
- Forward-only migration and recovery procedure, with zero retained backup
  payloads
- Content-free release audit/transaction journal
- Restricted vault root
- No secrets in browser build variables
- No secrets in repository or test fixtures
- Fresh readiness proof for every execution adapter
- Verified cancellation and child-process cleanup
- Security review before public exposure

## Reporting a vulnerability

Do not open a public issue containing exploit details, secrets, target data, or private deployment information. Use the repository owner's private security reporting channel when available and include the affected version, impact, minimal reproduction, and suggested remediation.
