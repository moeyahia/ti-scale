# Tool readiness registry

Ti-Scale's local tool readiness boundary is a versioned registry aligned to
the current runtime tool manifest. It cannot add a capability, supply a mission
target, provider, or MCP argument, or grant mission execution. External contact
is recorded as `not_measured` unless the probe worker technically enforces
network isolation.

Each registry record contains only a stable runtime tool ID, an absolute local
executable, one reviewed version/help argument, expected exit codes, and
explicit timeout, output, and receipt-TTL limits. Unknown fields are rejected.
The registry never accepts shell fragments, PATH-resolved executables, target
arguments, environment overrides, or implicit probe defaults.

`ToolBindingReadinessRunner` executes the records sequentially and uses a
single-flight guard for concurrent startup calls. Its cached receipts contain
only hashes, sizes, public status, bounded timestamps, and operator-readable
diagnostics; stdout and stderr are never returned. Receipt accounting remains
complete when a binding fails, while expired receipts make the snapshot
non-current.

The runner rejects a worker response unless its embedded tool ID and canonical
probe digest match the full reviewed binding, its timestamps match the binding
TTL, its fixed no-target boundary is intact, and a ready result carries all
three isolation attestations plus an executable identity. The runner exposes
`readToolExecutionPreflight(toolId)` as the narrow adapter
expected by `CapabilitySelfTestService`. Composition should inject it as:

```ts
const registry = new ToolBindingRegistry(document, runtimeManifests);
const readiness = new ToolBindingReadinessRunner(registry);
const initial = await readiness.startMonitoring();
// Refuse incomplete first-wave accounting before application startup/listen.

const selfTests = new CapabilitySelfTestService({
  repository,
  readRuntimeProjection,
  readToolExecutionPreflight: (toolId) =>
    readiness.readToolExecutionPreflight(toolId),
});
```

That composition is mounted by the standalone server. It reads the optional
absolute registry path from `TI_SCALE_TOOL_BINDING_REGISTRY_PATH`, runs the
argument-bounded checks before creating the application or listening,
refreshes them before the shortest receipt expires, and drains the current
bounded probe during graceful shutdown. The canonical manifest projection used
by intake and action-class readiness withdraws every local tool without a
current registry-aligned receipt from a worker that enforced network isolation,
disposable writes, and immutable hashed-snapshot execution.

Registry and executable paths are opened with no-follow checks, trusted-owner
and mode validation, and before/after identity comparison. Receipts bind the
source executable SHA-256, device, inode, size, mode, user, and group. An open
descriptor to an ordinary filesystem inode is not treated as immutable because
the inode can still be changed and restored. A worker may execute the probe only
when it separately attests that it executes a sealed immutable snapshot of the
hashed bytes, as well as enforcing network and disposable-write isolation.

The current production process owns no such executor. Its default boundary
inspects the reviewed source but refuses before starting it. Supplying a
registry alone therefore cannot make a local executable ready.

The default runtime manifest currently declares no local executable tools, so
the normal no-registry result is a truthful `0/0` readiness snapshot—not a
usable tool fleet. When a runtime adapter declares local tools, every available
local tool must have a reviewed binding from the same release or server
composition fails closed.

Remote MCP tools never enter this local registry. Each server inventory must be
a closed, duplicate-free set exactly equal to the runtime tools assigned to
that server, and every ID must use the server's fully-qualified
`mcp:<server-id>/<tool-id>` prefix. A missing, extra, duplicate, bare, or
foreign-prefix entry withdraws every tool assigned to that server. Two server
IDs that normalize to the same `mcp:<server-id>/` namespace are conflicting
owners and both fail closed.

See [Tool readiness](tool-readiness.md) for the exact JSON format and limits.
