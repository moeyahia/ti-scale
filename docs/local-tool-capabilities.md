# Local tool capability manifest

Ti-Scale describes local Kali executables in one operator-reviewed capability
manifest. The document is a source of capability identity and invocation
constraints; it is not an execution allowlist by itself and is not represented
as an MCP inventory.

The production template is
`deployment/runtime-config/local-tool-capabilities.v1.json`. It currently
defines four enabled operations and one disabled, production-reviewable Nmap
candidate:

| Reviewed tool ID | Operator-facing operation | Required parameters | Action classes | Evidence candidates |
| --- | --- | --- | --- | --- |
| `kali:curl-http-metadata` | Read response headers for one authorized HTTP/S URL | `workspace`, `url` | Web crawling and page capture | HTTP exchange |
| `kali:host-dns-query` | Query one approved DNS name and record type | `workspace`, `name`, `recordType` | DNS, domain, and certificate discovery | DNS or certificate record |
| `kali:ping-host-liveness` | Send two bounded liveness probes to one approved target | `workspace`, `target` | Active host discovery | Asset discovery proof |
| `kali:ncat-tcp-connect` | Check one explicit TCP port on one approved target | `workspace`, `target`, `port` | Active host discovery; port and service enumeration | Asset discovery proof; port/service scan result |

The staged `kali:nmap-tcp-connect-service-scan` binding accepts one normalized
IP address or hostname and an ascending, duplicate-free list of at most 1,024
individual TCP ports. Its fixed argv uses unprivileged TCP connect scanning and
light service detection. It is intentionally operator-disabled until the exact
capability-free executable is installed at the stable
`/opt/ti-scale-toolchain` root and the complete activation wave attests it.

The deterministic planner route is URL metadata to curl, domain records to
host, host liveness to ping, and an explicit target-plus-port check to ncat.
There is no implicit default port, free-form command, PATH lookup, shell
fragment, environment expansion, or arbitrary flag field.

The Kali Nmap executable remains unsuitable for direct service execution: it
carries `cap_net_bind_service`, `cap_net_admin`, and `cap_net_raw` file
capabilities, which conflict with `NoNewPrivileges=yes`. Ti-Scale does not
weaken that safeguard or invoke sudo at runtime. The separately reviewed,
root-run installer, activation steps, and rollback procedure are documented in
`docs/reviewed-nmap-capability.md`. Installation never enables the binding or
grants mission authority by itself.

The separately versioned [reviewed web-assessment activation
bundle](reviewed-web-assessment-capability.md) composes bounded WhatWeb and FFUF
bindings into this same manifest boundary. Its configuration installer never
restarts the service; activation and live readiness proof remain part of the
functional release.

## Reviewed Windows and identity operations

Ti-Scale also derives four Guided Windows and identity choices from the
reviewed runtime tool pack. These choices are registry-backed and become
selectable only while their executable, sandbox, authentication mode, output,
cancellation, and durable exact-step route have current receipts.

| Guided operation | What Ti-Scale does | Authentication |
| --- | --- | --- |
| SMB share list | Requests the share names and types advertised by one approved host; it does not open, write, or execute anything in a share | Anonymous or an opaque private credential reference when that mode is ready |
| SMB identity summary | Reads bounded SMB host, domain, signing, protocol, and share metadata from one approved host | Anonymous or an opaque private credential reference when that mode is ready |
| LDAP root metadata | Reads the fixed public root-directory metadata fields from one approved LDAP endpoint; it does not enumerate users, groups, or computers | Anonymous |
| RPC domain summary | Reads a bounded domain-role and object-count summary from one approved Windows RPC endpoint | Anonymous or an opaque private credential reference when that mode is ready |

Credential references identify root-provisioned systemd credential bundles.
The browser and mission records never contain a password, hash, ticket, cookie,
key, or reusable credential value. Selecting one of these operations creates
exactly one represented Guided action and Ti-Scale still waits for the
operator's decision before dispatch.

The NetExec binding can also compile one exact anonymous SMB identity-summary
action against a signed Autonomous contract. That prepared seam uses the
generic reviewed-local persisted-action envelope and the same direct-argv,
scope, output, cancellation, and no-evidence-promotion checks. The production
Autonomous lifecycle now mounts its dispatcher, durable result sink, resume and
cancellation path, and `ADAttackMapper` assignment. The runtime advertises this
one binding as Autonomous and mission-selectable only while the exact current
NetExec activation receipt, same adapter instance, signed contract, planning
binding, and local deterministic provider attestation all join successfully.
Every other Windows/identity binding remains Guided-only.

## Pinned local ExploitDB intelligence

The optional `kali:searchsploit-local` binding performs one typed SearchSploit
query against the host's pinned local ExploitDB catalog. It supports either:

- one exact CVE identifier; or
- one product name with an optional version and platform.

This binding runs in a new network namespace with a read-only `/usr`, pinned
SearchSploit configuration and catalog hashes, a disposable temporary
filesystem, fixed direct arguments, bounded output, a ten-second execution
limit, cooperative cancellation, and a maximum concurrency of two. It cannot
contact the mission target or a public provider.

The operator-selected query is linked to an authorized mission subject so its
result can be correlated with the observed technology. The subject is not
contacted by SearchSploit. Raw output is retained as one Engagement Log record;
valid catalog matches become unverified Observations. A catalog match is a lead
for version and applicability review, not proof that the target is vulnerable
or that an exploit succeeded. The binding creates no Evidence Candidate,
Verified Evidence, or Finding automatically.

Activation is opt-in:

```text
TI_SCALE_LOCAL_EXPLOIT_INTELLIGENCE_ENABLED=true
```

The intake option is available only after the exact SearchSploit executable,
bubblewrap executable, configuration, all three catalog indexes, isolated
probe, durable Guided planner, result recorder, cancellation path, and restart
path are all current and mounted.

## Document invariants

Every tool record fixes:

- an absolute executable path and SHA-256;
- an expectation of no Linux file capabilities;
- one bounded version/help probe;
- exact action-class, evidence-type, and risk mappings;
- a closed parameter schema with semantic types;
- a literal/parameter argv template;
- direct process spawning with `shell: false`;
- a fixed minimal environment (`HOME=/nonexistent`, `LANG=C.UTF-8`, and
  `LC_ALL=C.UTF-8`);
- a normalized logical engagement workspace parameter;
- authorized-scope-only network access;
- workspace-only filesystem writes;
- execution timeout, total output, and termination-grace limits;
- mandatory `NoNewPrivileges` compatibility.

Unknown fields, unknown canonical action/evidence IDs, duplicate routes,
duplicate parameters, unreferenced parameters, workspace interpolation into
argv, embedded URL credentials, option-shaped targets, unsafe paths, shell
execution, and secret-shaped values fail parsing.

The compiler returns direct argv plus the reviewed executable and binding
hashes. It always returns `authorizationGranted: false` and
`scopeEnforcementRequired: true`. Scope authorization remains a separate
action-time server decision.

## Workspace confinement

The supplied workspace template is
`deployment/runtime-config/engagement-workspace-mappings.v1.json`. It maps the
logical `/engagements` namespace into
`/var/lib/ti-scale/workspaces/engagements`. A compiled invocation retains the
logical path. The runtime must use `EngagementWorkspaceResolver` to produce and
recheck the contained physical path, and only that resolved path may become
the child process working directory.

The manifest cannot create a workspace or authorize a path. A missing,
ambiguous, symlinked, escaped, unavailable, or incorrectly owned mapping fails
closed before process creation.

## Target-free installation check

Pin the exact source document hash, then run:

```bash
MANIFEST=/absolute/release/deployment/runtime-config/local-tool-capabilities.v1.json
SHA256=$(sha256sum "$MANIFEST" | awk '{print $1}')

bun run scripts/local-tool-capability-preflight.ts \
  --manifest "$MANIFEST" \
  --trust-root /absolute/release/deployment/runtime-config \
  --sha256 "$SHA256"
```

The helper loads the document through the trusted-file boundary and inspects
only local executable metadata, bytes, hashes, ownership, mode, and Linux file
capabilities. It does not execute any declared tool, supply a target, contact a
provider, invoke MCP, or print executable paths or tool output. Its report
contains hashes, status codes, and complete accounting only.

Package upgrades can legitimately change executable hashes. A mismatch is a
review event, never a reason to bypass the check. Review the package, update
the template in a new release, and rerun validation.

## Runtime activation

An installation receipt explicitly grants no mission execution. A local tool
becomes available in the runtime projection only while all of these
manifest-bound, unexpired checks agree:

1. local executable installation integrity;
2. target-free version/help readiness from an isolated sealed snapshot;
3. direct-argv invocation adapter readiness;
4. action-time scope and policy enforcement;
5. workspace resolver confinement;
6. bounded output capture and result delivery;
7. cooperative cancellation and child-process cleanup.

The capability manifest projects local executable tools with no MCP servers.
MCP readiness counts therefore remain independent. Configuration drift,
expired receipts, binary drift, a missing adapter, or any failed enforcement
gate withdraws only the affected local tool.

### Reviewed local execution boundary

Enabled local tools use `ReviewedLocalToolExecutionPort`; they are not routed
through an MCP adapter and never create synthetic MCP attestations. The port
accepts only the exact canonical running action stored in SQLite. Immediately
before launch it repeats mission scope, control-plane lease, current
plan/step/assignment, agent health, per-agent tool policy, and either the exact
Guided decision or signed Autonomous contract check. Guided is the enabled
first-use path. An Autonomous action without a current matching contract fails
before a process or `tool_calls` receipt is created.

`DirectProcessLocalToolInvocationAdapter` recompiles the exact manifest argv;
it never accepts free-form arguments or a command string. HTTP targets must
match the represented URL exactly, DNS names may differ only by case or a
terminal dot, host-liveness targets match exactly, and TCP checks bind both the
host and explicit port in a `tcp://host:port` action target. Curl's reviewed
argv does not follow redirects.

At the last execution boundary, Ti-Scale:

- repeats root ownership, safe mode, execute permission, SHA-256, identity,
  and Linux file-capability checks for the sandbox helper and selected tool;
- copies the already verified bytes of both executables into sealed Linux
  `memfd` objects and executes the immutable sandbox snapshot directly;
- maps the tool snapshot read-only with bubblewrap `--ro-bind-data`;
- exposes host libraries and resolver/TLS files read-only, a disposable
  temporary filesystem, an empty `/proc`, and only the resolver-confirmed
  engagement workspace as persistent writable storage;
- clears the environment and supplies only the three manifest-fixed values;
- applies one combined stdout/stderr byte ceiling, timeout, termination grace,
  cooperative abort handling, and process-group cleanup; and
- refuses restart replay of an existing invocation. Recovery must create a new
  bounded action and attempt identity.

The adapter readiness receipt is target-free and identity-bound: it includes
the observed bubblewrap identity and hashes of fresh per-tool installation
receipts. It explicitly carries `grantsMissionExecution: false`; production
activation still combines it with the isolated target-free probe receipts,
policy gates, workspace mapping, result sink, and cancellation readiness.

Terminal `tool_calls` state is committed before the result reaches mission
evaluation. Cancellation marks any still-running local tool call terminal, so
a killed process cannot remain ghost-active. Bounded, sanitized stdout and
stderr are retained as a private Engagement Log record only. This adapter
creates no observation, evidence candidate, verified evidence, artifact, or
finding; those require a separate typed parser and promotion workflow.

Normal reconnaissance can produce a useful negative answer. The runtime uses
the reviewed executable's narrow exit contract instead of treating every
non-zero exit as a failed action. A refused ncat connection, ping with no
reply, DNS NXDOMAIN/no-record response, or curl HTTP error response completes
as a `negative_observation`. It is stored as a notice-level Engagement Log and
the Guided step may advance, but it is not automatically promoted to evidence.
Unrecognised exit codes, resolver/runtime faults, spawn errors, signals,
runtime timeouts, and output-limit termination remain execution failures.

The complete local execution configuration is all-or-nothing:

- `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_PATH`
- `TI_SCALE_LOCAL_TOOL_TRUSTED_CONFIG_ROOT`
- `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256`
- `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_PATH`
- `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_SHA256`
- `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_PATH`
- `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_SHA256`

Every path and the shared trust root are absolute. Each SHA-256 pins the exact
reviewed file bytes. Partial configuration fails rather than falling back to
PATH discovery, an unreviewed sandbox helper, or an arbitrary host path.

### Isolated recurring probe

The target-free version/help probe uses the separately pinned descriptor at
`deployment/runtime-config/bubblewrap-probe-sandbox.v1.json`. The helper is the
absolute `/usr/bin/bwrap` executable with its own reviewed hash and a strict
no-file-capabilities expectation.

Ti-Scale places the already hashed tool bytes in a Linux `memfd`, applies every
write/grow/shrink/seal seal, and passes that descriptor to bubblewrap. The
sandbox copies it into a read-only bind-data mount inside a new network
namespace. It exposes `/usr` read-only, provides only disposable write areas,
provides an empty `/proc` rather than host process metadata, clears the
environment, and invokes exactly one reviewed version/help argument. Avoiding
a nested procfs mount preserves the production unit's `ProtectKernel*` and
`ProtectHostname` hardening. Source identity is checked again afterwards. This
is stricter than executing an ordinary copied inode, which its owner could
still change.

Bubblewrap configures loopback inside that isolated probe namespace through a
short-lived `AF_NETLINK` route socket. The reviewed systemd drop-in therefore
limits the Ti-Scale service to `AF_UNIX`, `AF_INET`, `AF_INET6`, and
`AF_NETLINK`; it does not add capabilities, expose a host interface to the
probe, or permit packet/raw-socket families.

The readiness coordinator performs its initial bounded wave before exposing a
capability snapshot and refreshes before half of the shortest receipt lifetime.
Projection and API reads consume only the synchronous stored snapshot; they
never execute probes inline. Expiry withdraws the affected tool.

## Evidence semantics

Captured stdout and stderr begin as Engagement Log records. A DNS answer,
response header, ping response, successful TCP connection, or bounded parsed
port/service result may create an unverified Observation. The staged Nmap
normalizer never promotes its raw output or parsed Observation automatically.
None is automatically Verified Evidence, and none verifies a finding merely
because a process printed a matching string.

## Validation

Run the focused production-boundary suite with:

```bash
bun test server/local-tools/__tests__
```

The suite exercises all four enabled executables and the staged capability-free
Nmap candidate against loopback or the host-local resolver only, plus target
drift, sealed execution, hash and file-capability failure, output semantics,
result ordering, duplicate-safe recovery, cancellation cleanup, exact Guided
authorization, and Autonomous contract rejection. It does not contact an
engagement target.
