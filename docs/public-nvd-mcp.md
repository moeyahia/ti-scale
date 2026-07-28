# Public NVD MCP Connector

The Public NVD MCP Connector is a small, stateless service that exposes one reviewed read-only operation: `get_cve_details`. It retrieves a single CVE record from the official NIST National Vulnerability Database (NVD), normalizes the result into a typed contract, and marks every external text field as untrusted and quarantined.

The connector listens only on `127.0.0.1:43142/mcp`. It does not accept target addresses, execute assessment tools, read operational databases, read knowledge vaults, or write persistent state.

## Architecture

```text
Trusted local MCP client
       │
       │ Streamable HTTP + bearer credential
       ▼
127.0.0.1:43142/mcp
Public NVD MCP Connector
       │
       │ HTTPS GET; fixed NVD API origin and path
       ▼
services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-…
```

The runtime boundary consists of four independently enforced controls:

1. The HTTP server is hard-coded to IPv4 loopback and the fixed `/mcp` route.
2. Every request requires the bearer token supplied through the service manager's credential store.
3. The MCP server advertises exactly one read-only, non-destructive tool with strict uppercase CVE input validation.
4. The outbound client constructs the official NVD URL internally, rejects redirects, bounds time and response size, and never accepts a target URL.

## Trust boundary

NVD is authoritative public vulnerability intelligence, but its returned text is still external input. The connector therefore treats the complete normalized payload as `external_untrusted` and marks description text as:

- `lifecycle: quarantined`
- `promptEligible: false`
- content-hashed and control-character filtered
- unsuitable for direct model context until a separate local review approves it

The human summary intentionally excludes the raw external description. Provenance records the official API URL, NVD record URL, retrieval time, and HTTP status.

NVD's metrics registry can include non-CVSS families such as SSVC. The
connector bounds the number and size of metric families, validates each CVSS
entry independently, and omits every non-CVSS or malformed metric entry from
the normalized result. An additional metric family therefore cannot invalidate
an otherwise valid NVD record or be mistaken for a CVSS score.

The service account has no access to persistent application data. The supplied
unit makes `/etc/ti-scale` and `/var/lib/ti-scale` inaccessible, including
database, artifact, and Vault content beneath those roots. Ti-Scale retains no
backup or rollback store. The root-owned source credential directory is also
hidden after PID 1 has copied `mcp-token` into the service's private read-only
credential mount.

## Production files

```text
deployment/systemd/ti-scale-mcp-nvd.service
deployment/systemd/ti-scale.service.d/20-public-nvd-mcp.conf
deployment/sysusers.d/ti-scale-mcp-nvd.conf
scripts/install-public-nvd-mcp-credential.sh
scripts/smoke-public-nvd-mcp.ts
```

Expected deployment paths:

```text
/opt/ti-scale/                                  reviewed release
/usr/local/bin/bun                             Bun runtime
/etc/ti-scale-mcp-nvd/mcp-token               root-owned source credential
/etc/systemd/system/ti-scale-mcp-nvd.service   service unit
/etc/systemd/system/ti-scale.service.d/20-public-nvd-mcp.conf  Ti-Scale credential drop-in
/usr/lib/sysusers.d/ti-scale-mcp-nvd.conf      dedicated-account declaration
```

The connector needs no state directory. Its only writable filesystem is the service-private temporary directory created by `PrivateTmp=yes`.

## Installation

Perform installation as root during an approved maintenance window. Review every file before copying it.

```bash
install -D -m 0644 \
  deployment/sysusers.d/ti-scale-mcp-nvd.conf \
  /usr/lib/sysusers.d/ti-scale-mcp-nvd.conf
systemd-sysusers /usr/lib/sysusers.d/ti-scale-mcp-nvd.conf

scripts/install-public-nvd-mcp-credential.sh

install -D -m 0644 \
  deployment/systemd/ti-scale-mcp-nvd.service \
  /etc/systemd/system/ti-scale-mcp-nvd.service
install -D -m 0644 \
  deployment/systemd/ti-scale.service.d/20-public-nvd-mcp.conf \
  /etc/systemd/system/ti-scale.service.d/20-public-nvd-mcp.conf

systemd-analyze verify \
  /etc/systemd/system/ti-scale-mcp-nvd.service \
  /etc/systemd/system/ti-scale.service
systemctl daemon-reload
systemctl enable --now ti-scale-mcp-nvd.service
systemctl restart ti-scale.service
```

The Ti-Scale restart is required: systemd materializes `LoadCredential=` only
when it starts a service process. Installing the drop-in beside an already
running process does not add the credential to that process. Start the sidecar
first, restart Ti-Scale inside the approved maintenance window, and then run
the authenticated contract check below. If the Ti-Scale restart cannot be
performed, leave the connector unadvertised rather than copying the bearer
value into an environment variable.

The credential helper creates 256 random bits with OpenSSL, writes through a private temporary file, atomically installs mode `0600` ownership `root:root`, and never displays the value. It refuses symbolic-link traversal, unsafe ownership or permissions, an existing token without `--rotate`, and destinations inside a Git working tree.

The supplied Ti-Scale drop-in loads the source token as credential ID `public-nvd-mcp-token`. Ti-Scale reads the non-secret `CREDENTIALS_DIRECTORY` path supplied by systemd and refuses to obtain this bearer value from an environment variable, command-line argument, connection descriptor, log, issue, shell history, or repository.

Ti-Scale uses one shared client for the sidecar's exact live identity, inventory,
and schema attestation and for the narrowly reviewed mission-read route. The
client cannot authorize a mission action by itself. A successful check
advertises the one read-only public-intelligence capability and its real check
time; it does not create an agent heartbeat, specialist assignment, generic MCP
execution path, Guided execution path, Autonomous permission, or assessed-
target network authority.

The application exposes the reviewed read boundary at:

```text
GET /api/v2/missions/:missionId/runs/:runId/steps/:stepId/intelligence/cves/:recordId/nvd-detail
```

The route is authenticated and accepts no query parameters or request body. It
does not accept a caller-supplied CVE ID, URL, target, command, MCP tool name, or
provider instruction. `recordId` must be the opaque ID of a canonical CVE
applicability record. Before the sidecar is called, Ti-Scale verifies all of the
following from the canonical database and host policy:

- the run belongs to the mission;
- the step belongs to the run's current plan;
- both mission and run are owned by the `ti_scale` control plane;
- mission authorization is currently `verified`;
- the reviewed CVE record belongs to that mission and exact run; and
- the authenticated actor is permitted to use the fixed
  `read_public_nvd_detail` capability.

The route then invokes only the attested `get_cve_details` binding with the CVE
ID resolved from that reviewed record. It validates the result and invocation
receipt, reconstructs the public NVD record link locally, omits the upstream API
URL, returns only the count of external references, and never returns the raw
external description. A successful result is withheld unless the invocation
provenance can be appended to the canonical hash-linked audit trail. Rejections
after canonical mission context is established are also audited on a best-
effort basis with fixed, secret-free reasons.

This route is an operator-initiated public-intelligence read. It does not mutate
the plan or CVE applicability record, contact the assessed target, produce
verified evidence, grant a run lease, or authorize any subsequent attack step.
Mission agents and execution controllers remain unable to invoke generic MCP
tools through this boundary.

## Service hardening

The production unit applies:

- a dedicated `ti-scale-mcp-nvd` account with no login shell or home directory;
- empty capability and ambient-capability sets;
- `NoNewPrivileges`, namespace, device, kernel, process, home, and filesystem protections;
- a read-only application release and explicit denial of operational data roots;
- a native `@system-service` syscall allowlist;
- only `AF_UNIX`, `AF_INET`, and `AF_INET6` socket families;
- permission to bind only IPv4 TCP port `43142`;
- denial of private, carrier-grade NAT, link-local, metadata, benchmark, documentation, and multicast network ranges, while allowing loopback;
- bounded CPU, memory, process, file-descriptor, and task use;
- rate-limited journal output and bounded startup/shutdown behavior.

`MemoryDenyWriteExecute` is intentionally not enabled because the Bun JavaScript runtime uses executable JIT memory. The empty capability set, syscall filter, immutable filesystem, bind filter, fixed outbound URL, request limits, and resource controls provide the compensating boundaries.

NVD may use changing public CDN addresses, so the unit does not pin public egress IPs. Deployments requiring domain-level egress enforcement should route HTTPS through a separately reviewed proxy that permits only `services.nvd.nist.gov:443`. Keep redirects disabled in the connector. When local DNS does not use a loopback or public resolver, the private-range network denials may require an approved local resolver exception.

## Health and smoke checks

There is deliberately no unauthenticated health route. Health is the authenticated MCP initialize/list-tools exchange.

Confirm service and listener state:

```bash
systemctl is-active ti-scale-mcp-nvd.service
systemctl show ti-scale-mcp-nvd.service \
  -p MainPID -p SubState -p NRestarts -p MemoryCurrent -p TasksCurrent
ss -ltnp '( sport = :43142 )'
```

The listener must be `127.0.0.1:43142`, never `0.0.0.0`, `[::]`, or an external interface.

Verify that unauthenticated access is rejected without exposing a credential:

```bash
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  http://127.0.0.1:43142/mcp
```

The expected status is `401`.

Run the authenticated contract check as root. This reads the token directly into process memory but never prints it:

```bash
/usr/local/bin/bun run scripts/smoke-public-nvd-mcp.ts
```

This proves initialize and list-tools without contacting NVD. To verify the complete public-intelligence path, perform one deliberate live lookup:

```bash
/usr/local/bin/bun run scripts/smoke-public-nvd-mcp.ts --cve CVE-2021-44228
```

The live check must report that external text remains quarantined and target interaction is disabled. A rate-limited or unavailable NVD response is a degraded upstream state, not permission to bypass the connector.

After deploying the matching Ti-Scale application build and completing its
database preflight, verify the application boundary separately with an
authenticated session and a disposable, reviewed mission fixture. Use the
fixture's canonical mission, run, current-plan step, and opaque CVE applicability
IDs; do not substitute a CVE identifier in the URL. Require all of the
following:

- the response has `Cache-Control: no-store`;
- `targetInteraction` is `false` and `executionAuthority` is `none`;
- the returned tool name is exactly `get_cve_details`;
- no description text, upstream API URL, external reference URL, credential, or
  provider error body appears in the response;
- a matching `cve.nvd_detail.retrieved` audit record exists; and
- adding a query parameter, using a stale step, changing the run, or removing
  verified mission authorization fails before the MCP invocation.

Do not treat the sidecar smoke check alone as proof that this application route
is deployed. Conversely, a `503 nvd_dependency_not_ready` response from the
application is the correct fail-closed behavior until the shared client has a
fresh exact attestation.

## Browser contract validation

The browser suite validates the operator-facing mission-scoped control with a
deterministic HTTP fixture at the application boundary. The Playwright fixture
does not start the systemd-credential MCP sidecar, and its redacted receipt is
not evidence that a deployed sidecar was authenticated or attested. Adapter,
router, MCP-client, schema-attestation, audit-persistence, and fail-closed tests
cover those server boundaries independently. A release environment must still
pass the authenticated sidecar and disposable-mission checks described above.

The focused browser matrix currently exercises the successful redacted receipt
and the dependency-error/retry path across all 13 configured browser and
viewport projects. The recorded run passed 26 of 26 cases without retries,
skips, or failures. It verifies that the control names the public-only behavior,
never represents target interaction or execution authority, preserves an exact
current-step scope, excludes raw NVD description text and external reference
URLs, and renders precise remediation when the dependency is unavailable.

Inspect bounded logs without printing credential files:

```bash
journalctl -u ti-scale-mcp-nvd.service --since '-15 minutes' --no-pager
```

The connector logs only generic startup or failure information. Treat any bearer value, authorization header, raw upstream response, or target data in the journal as a security defect.

## Credential rotation

Rotation is an atomic source-file replacement followed by a coordinated restart of credential consumers. The current process retains its in-memory credential until it exits.

1. Confirm that all authorized local clients can be restarted in the same window.
2. Generate the replacement without displaying it:

   ```bash
   scripts/install-public-nvd-mcp-credential.sh --rotate
   ```

3. Restart the connector and Ti-Scale so both receive the same new credential generation from PID 1.
4. Run the authenticated list-tools smoke check.
5. Confirm unauthorized requests still return `401` and inspect the journal for bounded errors.

Do not preserve plaintext token backups. If coordination fails, generate a new credential and repeat the controlled restart; never copy a token into a shell command to repair access.

## Graceful shutdown

`SIGTERM` begins graceful shutdown. The sidecar stops accepting requests, closes active MCP transports, closes the listener, destroys remaining idle sockets, and clears its mutable token buffer. The unit allows 20 seconds before applying `SIGKILL` to remaining processes.

For a planned stop:

```bash
systemctl stop ti-scale-mcp-nvd.service
```

After stopping, verify that port `43142` is closed. The connector has no persistent queues or state to reconcile.

## Troubleshooting

### Service fails before listening

- Confirm `/usr/local/bin/bun` and `/opt/ti-scale/server/mcp-public-nvd/http.ts` are present and root-owned.
- Confirm `ti-scale-mcp-nvd` exists and has `/usr/sbin/nologin` as its shell.
- Confirm the credential source is a regular non-symlink file, owner `root:root`, mode `0600`, 32–512 bytes, and one line.
- Run `systemd-analyze verify` against the installed unit.

### Authentication returns 401

- Verify the connector and client loaded the same credential generation.
- Restart both consumers after rotation; changing the source file does not update a running process.
- Do not log, print, or compare the token manually.

### NVD lookup is rate limited

The connector honors a bounded `Retry-After` value and performs at most one retry by default. Preserve the mission state and retry later. Increasing concurrency or looping immediately will extend the upstream limit.

### NVD cannot be reached

- Confirm DNS resolution and HTTPS egress to `services.nvd.nist.gov:443`.
- Check whether the configured DNS resolver is inside a network range denied by the unit.
- Confirm the official service is available before changing local policy.
- Never broaden filesystem access, listener scope, or tool input to work around an upstream outage.

## Forward replacement

The connector is stateless, but its deployment still moves forward only.

1. Stop the connector.
2. Publish the newly reviewed code and unit definition in place without
   retaining the superseded release.
3. Run `systemd-analyze verify` on the new unit.
4. Reload the service manager and start the connector.
5. Run the authenticated list-tools smoke check, then optionally one live CVE
   lookup.
6. Confirm the listener, journal, filesystem denial, and resource limits.

The bearer credential may remain valid when there is no exposure concern.
Rotate it when the replacement addresses suspected credential exposure or an
authentication-boundary failure. The connector must never restore or modify
the Ti-Scale database, Vault, artifact store, or schema.

Retain only content-free deployment metadata: the reviewed release hash, unit
verification result, smoke-check result, timestamp, and operator decision. Do
not retain prior code, unit bytes, credentials, database content, or any other
restorable payload. If the Ti-Scale application has committed a schema
migration, an older application release cannot be used as recovery.
