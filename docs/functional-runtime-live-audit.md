# Historical Functional Runtime Live Audit

Audited: 2026-07-20 UTC
Scope: Ti-Scale service on `127.0.0.1:3132`
Method: authenticated health inspection, deterministic production mission smoke,
read-only browser validation, database integrity inspection, and terminal-work
reconciliation.

This is a point-in-time validation receipt. It preserves what the audited
installation proved on 2026-07-20 and is not current capability or deployment
truth.

## Outcome

The audited Ti-Scale installation provided an operational, bounded mission
runtime for the capabilities listed below.

The live service reports:

- HTTP, database, and event stream: healthy;
- Autonomous execution: ready;
- Guided execution: ready;
- action boundary, delegation, and no-hands commander enforcement: active;
- seven exact-decision Guided local tools: ready;
- three Autonomous safe-recon action classes: ready;
- one enforcing local deterministic policy provider: freshly attested;
- public NVD read adapter: freshly attested;
- canonical Second Brain and lexical index: healthy;
- one connected, reachable, round-trip-verified Obsidian Vault.

Readiness is fail-closed. A target-free readiness receipt grants no mission
authority; every action still requires a matching signed Autonomous contract or
the exact pending Guided decision.

## Deployed release

The server and static assets were activated as one guarded release:

- release ID: `readiness-web-tools-20260720T095944Z`;
- server manifest SHA-256:
  `fa18a7ec63bd6c73f314d1bd8df9dbc902af376767fe77f4c9b779977b73579d`;
- server tree SHA-256:
  `e1ddd42e08facb82d7cc245cf4e570e757983499ce78230171f4e45484713e4d`;
- static manifest SHA-256:
  `f08805b6b410a5cd82f5070941ac50b2304f20dd60f34a363c0cfc85c57177fb`;
- historical deployment-copy paths from this older audit have been purged;
  current deployment uses content-free forward-recovery receipts only.

The canonical database is `/var/lib/ti-scale/data/ti-scale.sqlite` and reported:

- migration: 17;
- journal mode: WAL;
- foreign keys: enabled;
- busy timeout: 5,000 ms;
- integrity: `ok`;
- pending outbox records: 0.

## Live runtime inventory

### Guided exact-step tools

The exact active set is:

1. `kali:curl-http-metadata`
2. `kali:ffuf-bounded-content-discovery`
3. `kali:host-dns-query`
4. `kali:ncat-tcp-connect`
5. `kali:nmap-tcp-connect-service-scan`
6. `kali:ping-host-liveness`
7. `kali:whatweb-bounded-fingerprint`

All use reviewed direct-argument adapters. None accepts a shell command or
free-form flags. WhatWeb and FFUF run through the checksum-bound activation
bundle `reviewed-web-assessment-2026.07.20-v1`.

### Autonomous action classes

The exact active set is:

1. `dns_domain_certificate_discovery`
2. `active_host_discovery`
3. `port_service_enumeration`

Broader classes remain unavailable until they have their own typed binding,
policy mapping, exact scope check, deterministic result semantics, cancellation
proof, and activation receipt. Availability is never inferred merely because a
Kali binary exists on the host.

## Canonical production mission proof

The guarded proof command was:

```bash
bun run scripts/smoke-functional-runtime.ts \
  --execute \
  --confirm functional-runtime-proof-2026.07.20-v2
```

Result: `ti-scale.functional-runtime-proof.v2` passed.

It created three disposable, bounded missions through the authenticated real
API and proved:

- Autonomous DNS completed without a Guided wait;
- Autonomous host liveness and reviewed TCP service scanning completed;
- the Guided commander represented one exact Nmap step and did not dispatch it
  before the operator decision;
- the approved Guided action completed with the reviewed parser;
- raw process output remained an Engagement Log rather than automatic verified
  evidence;
- Autonomous policy-derived facts produced the required verified evidence;
- topology, reports, evaluations, Context Packs, and Vault projections were
  durably queryable;
- all terminal runs cleared current ownership, current step, run lease, pending
  decisions, and nonterminal actions;
- final quiescence was zero active runs and zero active leases.

## Second Brain and Obsidian Vault

The post-proof authenticated snapshot reported:

- Vault: `Ti-Scale-Brain`;
- visible memory nodes: 3,383;
- verified nodes: 3,189;
- candidate nodes: 194;
- memory edges: 3,459;
- persisted Context Packs: 330;
- tracked Vault notes: 3,189;
- open conflicts: 0.

The Vault connection has a current write/read/rename/delete round-trip receipt.
The SQLite graph remains the transactional source of truth; the Vault is its
human-readable synchronized projection.

## Browser proof

The authenticated live Chromium proof passed against port 3132 with no browser
mutation. It verified:

- session establishment through the HttpOnly cookie flow;
- Command Center readiness;
- the active Vault connection;
- a graph containing more than three nodes and at least one real edge;
- durable mission and run deep links;
- zero unexpected console errors or page exceptions.

## Historical validation boundary

This audit proved the deployed bounded runtime slice at the time. It did not
complete the product-wide validation program, which still included:

- completion of every interaction-manifest gap;
- full retry-free browser and viewport matrix;
- approved visual and copy baselines;
- complete accessibility and performance evidence;
- migration, restore, restart, and rollback rehearsals for the final candidate;
- 72-hour automated soak;
- operator acceptance period;
- zero known release-scope defects;
- explicit human release sign-off.

These items describe the remaining work recorded by this historical receipt.
Consult [Validation status](validation-status.md) and live readiness for the
current standalone service state.
