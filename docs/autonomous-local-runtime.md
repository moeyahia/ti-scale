# Local Autonomous runtime activation contract

## Status

Ti-Scale contains a production-shaped, provider-free Autonomous DNS slice:

- `LocalAutonomousContractPlanner` creates a bounded plan from the confirmed mission contract, exact target scope, a reviewed local binding policy, a scoped Second Brain Context Pack, and the current live capability projection.
- `LocalVerifiedEvidenceOutcomeEvaluator` evaluates explicit mission success criteria from eligible verified evidence and verified finding support only.
- `AutonomousDnsLocalProcessExecutionFactory` dispatches one exact `kali:host-dns-query` envelope through the reviewed direct-argv adapter and returns normalized, evidence-linked results to the mission runtime.

The planner and evaluator never call a model, target, MCP server, tool, shell, or network endpoint. The execution factory is separate: after every live activation gate passes, it may invoke only the reviewed local `host` binding. Optional MCP inventory is advisory and cannot grant or block this local route.

## Planner boundary

Every locally planned tool step must resolve through one reviewed binding containing all of the following stable values:

- action class and compatible target kinds;
- specialist agent and capability IDs;
- enforcing provider, exact model, and immutable model-configuration hash used by the specialist;
- one exact execution binding: either a reviewed local tool ID or, for a different route, an MCP server and tool name;
- one declared target parameter plus bounded, secret-free static parameters;
- risk, reversibility, idempotency, evidence requirements, and success checks.

The planner rejects unsupported classes, contradictory scope, missing success criteria, stale or mismatched contracts, public-provider Context Pack envelopes, unavailable agents, stale worker heartbeats, unapproved tools, non-enforcing provider/model routes, and manifest drift. An MCP health gate applies only to an actual MCP execution binding. It never guesses a command, tool schema, model, or alternate target.

The produced plan is deterministic for the same canonical contract, policy, Context Pack, and live projection. Reconstructing the adapter after restart produces the same plan. A failure safe-stops the run, persists a structured local-planning diagnosis and checkpoint, and preserves the exact code; it does not create `waiting_guided_decision`.

## Outcome boundary

Each mission criterion has a stable ID derived from its normalized text. Eligible evidence must:

- satisfy the canonical verified-evidence query;
- not be raw `command_output`;
- reference the criterion through `ti-scale.success-criterion-reference.v1` provenance;
- declare `achieved` or `not_applicable`; and
- be linked to a succeeded completed action, or support a verified finding.

No evidence, unverified evidence, raw output, unsupported provenance, and conflicting outcomes all fail conservatively. `not_applicable` is explicit and does not masquerade as `satisfied`; it may count as a resolved criterion only in the evaluator's final all-criteria decision.

## Production activation gates

The local adapters may be mounted by `createProductionAutonomousRuntime` only after all of these conditions are true at the same readiness observation:

1. A root/operator-reviewed `LocalAutonomousPlanningPolicy` is loaded from a versioned trusted configuration source and its policy hash is retained with deployment evidence.
2. Every policy binding exactly matches the live action-class, tool, execution kind, specialist, provider/model, evidence, and risk manifests.
3. The specialist worker has a fresh heartbeat and its runtime configuration requires exact persisted bindings, bound result delivery, no shell interpolation, and no public-provider tool execution.
4. The specialist tool policy explicitly allows the tool, does not deny it, and does not require a routine runtime approval.
5. Every pinned provider/model route has a fresh enforcing attestation and exact model-configuration hash. Local planning does not weaken specialist model readiness.
6. A real result-aware execution factory is mounted. For `reviewed_local_process`, it must attest direct argv, no shell, bounded cancellation, and a bound result sink. For an actual MCP binding, the MCP policy and exact inventory gates additionally apply.
7. The local capability manifest and fresh executable/preflight receipts are the source of truth for direct local execution. An unrelated MCP server or tools-list receipt is never required.
8. The verified-evidence schema and promotion policy are active before outcome evaluation.
9. `inspectAutonomousRuntimeComposition` returns `ready` with the intended action-class IDs. Flags or configured counts alone cannot satisfy this gate.
10. Release tests cover safe stop, unsupported action classes, no evidence, insufficient evidence, restart determinism, no routine wait state, exact policy denial, and execution-result correlation.

Until those gates pass against the installed local dependencies, Ti-Scale advertises Autonomous execution as blocked. It does not fall back to Guided execution, a public-model tool path, manual actions, heuristic arguments, or an unverified success result.

## Disposable activation proof

`server/app/__tests__/AutonomousRuntimeActivationFixture.integration.test.ts` preserves the compatibility proof for an MCP execution binding. The direct-local DNS route is separately covered by the Autonomous DNS coordinator, production-configuration, reviewed-local execution, and terminal-run integration suites.

1. the confirmed contract and reviewed local policy produce one deterministic exact specialist binding;
2. production composition inspection accepts the internally consistent fixture projection, while the production server remains unchanged and fail-closed;
3. `SpecialistToolDispatchService` revalidates the canonical run, contract, target, specialist, MCP policy, exact attestation, and JSON input schema;
4. a result-aware cooperative transport accepts exactly one dispatch and returns through its bound runtime result sink;
5. immutable action-linked evidence records the exact invocation, hashes, custody events, and stable success-criterion reference;
6. the local evaluator completes only after the action succeeds and the verified evidence is eligible;
7. cancellation reaches the transport and leaves no running action, tool call, assignment, provider turn, or Guided wait; and
8. a deliberate database-policy denial safe-stops before dispatch even when the previously inspected fixture projection remains optimistic; and
9. completed, failed, and cancelled runs clear stale execution instructions, while an Autonomous safe stop exposes a specific diagnosis/contract-amendment recovery direction.

The fixture opens no socket, starts no process, contacts no provider or MCP server, and uses no target. Its provider, model, MCP, tool, specialist, and evidence IDs are explicitly fixture-only. It is an activation proof, not an installed-tool declaration or live-readiness claim.

## Deployment-pinned local activation

The repository includes a no-secret, no-MCP activation set:

- `deployment/runtime-config/autonomous-dns-local-runtime.v1.json`
- `deployment/runtime-config/local-tool-capabilities.v1.json`
- `deployment/runtime-config/bubblewrap-probe-sandbox.v1.json`
- `deployment/runtime-config/engagement-workspace-mappings.v1.json`
- `deployment/systemd/ti-scale.service.d/50-autonomous-dns-local.conf`

Before enabling the drop-in, copy the four JSON files without modifying their bytes into `/etc/ti-scale/runtime`, owned by root with directory mode `0700` and file mode `0600`. Create `/var/lib/ti-scale/workspaces/engagements/autonomous-dns` for the Ti-Scale service account. Then run `systemd-analyze verify` against the assembled service and execute the source test/check gate before any restart. The checked-in drop-in pins every source SHA-256 and deliberately contains no MCP endpoint or credential.

Configuration still grants no mission authority. Startup performs target-free executable, sandbox, workspace, result-sink, cancellation, provider-policy, and specialist-heartbeat attestations. Failure or expiry withdraws the runtime and cancels in-flight local work.
