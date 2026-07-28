# Local tool readiness

Ti-Scale treats the runtime capability manifest as the authoritative inventory. A local readiness registry may attest only tools that the runtime already declares; it cannot add a tool, change its action classes, supply mission/provider/MCP arguments, or authorize execution. The absence of target-shaped arguments is not treated as proof that an executable made no external contact.

Remote and MCP-backed tools use separate, expiring inventory and health attestations. MCP inventories use exact fully-qualified IDs in the form `mcp:<server-id>/<tool-id>`; duplicate IDs, bare names, extra tools, missing tools, and server-prefix mismatches fail closed. Server IDs that normalize to the same namespace, such as `public-nvd` and `mcp:public-nvd`, are conflicting owners and withdraw both inventories. A mission-scoped read-only adapter may be ready without enabling generic MCP execution, and the UI must state that distinction.

Local executable tools use a versioned JSON registry supplied through `TI_SCALE_TOOL_BINDING_REGISTRY_PATH`. The path must be absolute, non-symlinked, no larger than 512 KiB, owned by root or the service user, and not writable by group or world. Ti-Scale opens it with no-follow semantics and rejects identity or metadata changes while reading.

Each local binding contains:

- the exact runtime tool ID;
- an absolute executable path;
- exactly one reviewed version or help argument;
- explicit accepted exit codes;
- a timeout of at most five seconds;
- an output limit of at most 32 KiB;
- a receipt lifetime of at most five minutes.

Startup checks run sequentially and single-flight, then refresh before the shortest registered receipt lifetime expires. The initial gate requires every registered binding to have been attempted and accounted for in that wave. A check supplies only the exact executable and reviewed version/help argument, without a shell or mission/provider/MCP arguments. The receipt digest covers the tool identity, display label, executable, argument, working directory, exit codes, timeout, output bound, and lifetime; a mismatched worker response is converted to an unavailable runner error. A check can produce a `ready` receipt only when its worker technically enforces network-egress isolation, disposable filesystem writes, and execution from a sealed immutable snapshot of the hashed bytes. The standalone production process currently owns no such executor, so its default boundary refuses before starting the executable. A registry alone cannot change that state.

Before any eligible isolated invocation, Ti-Scale rejects symlinks, non-regular files, unsafe owners, group/world-writable executables, excessive size, and missing execute permission. It hashes the opened source and binds device, inode, size, mode, owner, and SHA-256 into the receipt. An ordinary opened descriptor is not accepted as an immutable execution source: the underlying inode can be modified and restored. The injected worker must attest sealed-snapshot execution, and any source or executed-snapshot identity mismatch discards the result. Public receipts retain bounded metadata and output hashes; stdout and stderr are not returned. A readiness receipt explicitly grants no execution authority.

An available local runtime tool without a reviewed binding fails startup composition. The server awaits the complete first readiness wave before creating application services or listening. Mission intake, action-class policy, and capability self-tests consume a reconciled manifest where a local tool is available only when registry alignment and a fresh isolated identity-bound receipt agree. Missing, failed, expired, or manifest-drifted receipts withdraw the tool and its autonomous enforcement readiness.

A missing executable, timeout, excessive output, unexpected exit code, empty response, missing isolation, identity change, unsafe permissions, or observed Linux `NoNewPrivs` capability conflict marks that binding unavailable. Ti-Scale does not copy binaries, strip capabilities, invoke `sudo`, or weaken the worker boundary to make a check pass.

During graceful shutdown, the runner completes only its current bounded probe and does not start another binding. MCP dispatch also recomputes the capability-attestation manifest hash before reserving any durable side effect; a modified inventory or schema carrying a stale plausible hash is rejected. Mission execution remains independently gated by authorization scope, a signed Autonomous contract or exact Guided decision, tool policy, specialist ownership, a control-plane lease, and action-time preflight.

Example registry:

```json
{
  "schemaVersion": "ti-scale.tool-binding-registry.v1",
  "registryVersion": "reviewed-2026.07.18",
  "bindings": [
    {
      "toolId": "kali:curl",
      "executablePath": "/usr/bin/curl",
      "probeArguments": ["--version"],
      "expectedExitCodes": [0],
      "timeoutMs": 2000,
      "maximumOutputBytes": 16384,
      "ttlMs": 60000
    }
  ]
}
```

The example is illustrative. It becomes eligible only when the same stable local tool ID is present in the current runtime manifest and a separately reviewed worker provides all three technical isolation guarantees, including sealed immutable-snapshot execution. The current production source declares zero local executable tools and owns no immutable-snapshot probe executor, so the normal result is `0/0` checked and no local tool capability. Tools must not be hand-registered merely because a binary exists on the host.
