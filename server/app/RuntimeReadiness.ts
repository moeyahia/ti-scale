import type {
  AutonomousMissionRequest,
  ReadinessCheck,
  ReadinessCheckProvider,
  ReadinessContext,
} from "../missions";

export type ComponentHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface ProviderReadiness {
  readonly id: string;
  readonly health: ComponentHealth;
  readonly authenticated: boolean;
  /** True only after a fresh live provider/ACP route attestation. */
  readonly callable: boolean;
  readonly attestedAt?: string;
  readonly expiresAt?: string;
  readonly circuitState?: "closed" | "open" | "probing";
  readonly supportsGuided: boolean;
  readonly enforcesAutonomousBoundary: boolean;
  readonly reportsExactTokenUsage: boolean;
  readonly reportsExactCostUsage: boolean;
  readonly reason?: string;
}

export interface McpReadiness {
  readonly enabled: boolean;
  readonly executionMode: "disabled" | "dry-run" | "enabled";
  readonly startPermitted: boolean;
  readonly configuredServers: number;
  readonly runnableServers: number;
  /** Routes whose bounded live tools/list attestation is currently running. */
  readonly probingServers?: number;
  readonly missingDependencies: number;
  readonly missingSecrets: number;
}

export interface RuntimeReadinessSnapshot {
  readonly actionBoundaryActive: boolean;
  readonly delegationEnforced: boolean;
  readonly noHandsCommanderEnforced: boolean;
  readonly directCommanderToolsDenied: boolean;
  readonly specialistAssignmentRequired: boolean;
  readonly specialistsConfigured: number;
  readonly providers: readonly ProviderReadiness[];
  readonly mcp: McpReadiness;
  readonly eventStream: ComponentHealth;
  readonly secondBrain: ComponentHealth;
  /** True only during an explicit rollback window; production should keep this false. */
  readonly legacyExecutionEnabled: boolean;
}

function check(
  id: string,
  label: string,
  status: ReadinessCheck["status"],
  journeys: ReadinessCheck["journeys"],
  impact: string,
  remediation?: string,
): ReadinessCheck {
  return { id, label, status, journeys, impact, ...(remediation ? { remediation } : {}) };
}

function autonomousRequest(context: ReadinessContext): AutonomousMissionRequest | undefined {
  return context.request?.journey === "autonomous" ? context.request : undefined;
}

function requiresExecutionTools(context: ReadinessContext): boolean {
  const request = autonomousRequest(context);
  if (!request) return true;
  const advisoryOnly = new Set(["analysis", "planning", "reporting", "summarization", "documentation"]);
  return request.contract.allowedActionClasses.some(
    (actionClass) => !advisoryOnly.has(actionClass.trim().toLocaleLowerCase("en-US")),
  );
}

/**
 * Converts live runtime facts into fail-closed launch checks. The callback is
 * evaluated for every request so readiness never relies on a stale boot-time
 * credential, provider, MCP, or enforcement assumption.
 */
export function createRuntimeReadinessProviders(
  snapshot: () => RuntimeReadinessSnapshot,
): readonly ReadinessCheckProvider[] {
  return [
    {
      id: "authorization_scope",
      label: "Authorization and scope",
      journeys: ["autonomous", "guided"],
      evaluate(context) {
        const request = autonomousRequest(context);
        if (!request) {
          return check(
            "authorization_scope",
            "Authorization and scope",
            "warn",
            ["autonomous", "guided"],
            "Authorization is verified against the selected engagement and exact mission scope during creation.",
            "Select an authorized engagement and confirm the exact allowed targets before launch.",
          );
        }
        const valid = request.authorization.authorizationConfirmed
          && request.authorization.allowedTargets.length > 0;
        return valid
          ? check(
              "authorization_scope",
              "Authorization and scope",
              "pass",
              ["autonomous", "guided"],
              "The operator confirmed a non-empty allowed target scope for this contract.",
            )
          : check(
              "authorization_scope",
              "Authorization and scope",
              "fail",
              ["autonomous", "guided"],
              "The mission does not have a confirmed, executable target scope.",
              "Confirm authorization and add at least one allowed target.",
            );
      },
    },
    {
      id: "execution_boundary",
      label: "Journey execution boundary",
      journeys: ["autonomous", "guided"],
      evaluate() {
        const value = snapshot();
        const shared = value.delegationEnforced
          && value.noHandsCommanderEnforced
          && value.directCommanderToolsDenied
          && value.specialistAssignmentRequired;
        const autonomousStrong = value.actionBoundaryActive && shared;
        return [
          autonomousStrong
            ? check(
                "execution_boundary_autonomous",
                "Autonomous execution boundary",
                "pass",
                ["autonomous"],
                "Signed contracts, durable actions, specialist ownership, and the no-hands commander policy are enforceable.",
              )
            : check(
                "execution_boundary_autonomous",
                "Autonomous execution boundary",
                "fail",
                ["autonomous"],
                "At least one required Autonomous action or delegation boundary is not enforceable by the active runtime.",
                "Enable the durable MCP action boundary, specialist assignment, hard delegation, and no-hands commander policy.",
              ),
          shared
            ? check(
                "execution_boundary_guided",
                "Guided exact-step boundary",
                "pass",
                ["guided"],
                "Consequential work is bound to one represented decision; manual steps cannot be dispatched and agent-run steps require the exact fingerprint.",
              )
            : check(
                "execution_boundary_guided",
                "Guided exact-step boundary",
                "fail",
                ["guided"],
                "The exact-step, specialist-assignment, or no-hands Guided boundary is not fully enforced.",
                "Restore specialist assignment, hard delegation, direct-commander tool denial, and the exact Guided decision gate.",
              ),
        ];
      },
    },
    {
      id: "provider_execution",
      label: "Provider execution compatibility",
      journeys: ["autonomous", "guided"],
      evaluate() {
        const value = snapshot();
        const autonomous = value.providers.filter(
          (provider) => provider.authenticated
            && provider.callable
            && provider.enforcesAutonomousBoundary
            && provider.health === "healthy",
        );
        const guided = value.providers.filter(
          (provider) => provider.authenticated
            && provider.callable
            && provider.supportsGuided
            && provider.health === "healthy",
        );
        return [
          autonomous.length > 0
            ? check(
                "provider_execution_autonomous",
                "Autonomous provider enforcement",
                "pass",
                ["autonomous"],
                `${autonomous.length} authenticated provider path${autonomous.length === 1 ? " is" : "s are"} compatible with the enforceable Autonomous boundary.`,
              )
            : check(
                "provider_execution_autonomous",
                "Autonomous provider enforcement",
                "fail",
                ["autonomous"],
                "No authenticated provider path can currently execute behind the enforceable Autonomous boundary.",
                "Restore an enforcing Grok ACP, Codex, or compatible provider path and rerun readiness.",
              ),
          guided.length > 0
            ? check(
                "provider_execution_guided",
                "Guided provider connection",
                "pass",
                ["guided"],
                `${guided.length} authenticated provider path${guided.length === 1 ? " is" : "s are"} available for Guided explanation and interpretation.`,
              )
            : check(
                "provider_execution_guided",
                "Guided provider connection",
                "fail",
                ["guided"],
                "No authenticated Guided-capable provider is available.",
                "Restore a configured provider connection before starting a Guided mission.",
              ),
        ];
      },
    },
    {
      id: "provider_usage_accounting",
      label: "Provider budget accounting",
      journeys: ["autonomous"],
      evaluate(context) {
        const request = autonomousRequest(context);
        const enforcing = snapshot().providers.filter((provider) =>
          provider.authenticated && provider.callable
          && provider.enforcesAutonomousBoundary && provider.health === "healthy");
        const tokenRequired = (request?.contract.tokenBudget ?? 0) > 0;
        const costRequired = (request?.contract.costBudget ?? 0) > 0;
        const tokenSupported = enforcing.some((provider) => provider.reportsExactTokenUsage);
        const costSupported = enforcing.some((provider) => provider.reportsExactCostUsage);
        return [
          tokenRequired && !tokenSupported
            ? check(
                "provider_token_accounting_autonomous",
                "Exact token accounting",
                "fail",
                ["autonomous"],
                "The signed contract has a finite token budget, but no enforcing provider path reports exact token usage.",
                "Use an enforcing provider with exact token telemetry or leave the token budget unset.",
              )
            : check(
                "provider_token_accounting_autonomous",
                "Exact token accounting",
                "pass",
                ["autonomous"],
                tokenRequired
                  ? "An enforcing provider path reports exact token usage for the signed budget."
                  : "No finite token budget was requested; token values will still be retained only when reported exactly.",
              ),
          costRequired && !costSupported
            ? check(
                "provider_cost_accounting_autonomous",
                "Exact cost accounting",
                "fail",
                ["autonomous"],
                "The signed contract has a finite cost budget, but no enforcing provider path reports exact billed cost.",
                "Use an enforcing provider with exact billed-cost telemetry or leave the cost budget unset.",
              )
            : check(
                "provider_cost_accounting_autonomous",
                "Exact cost accounting",
                "pass",
                ["autonomous"],
                costRequired
                  ? "An enforcing provider path reports exact billed cost for the signed budget."
                  : "No finite cost budget was requested; cost will never be estimated locally.",
              ),
        ];
      },
    },
    {
      id: "specialist_fleet",
      label: "Specialist fleet",
      journeys: ["autonomous", "guided"],
      evaluate() {
        const count = snapshot().specialistsConfigured;
        return count > 0
          ? check(
              "specialist_fleet",
              "Specialist fleet",
              "pass",
              ["autonomous", "guided"],
              `${count} specialist${count === 1 ? " has" : "s have"} a fresh provider and MCP route attestation.`,
            )
          : check(
              "specialist_fleet",
              "Specialist fleet",
              "fail",
              ["autonomous", "guided"],
              "No specialist has both a fresh live provider route and a live-attested MCP capability.",
              "Restore provider authentication and the reviewed MCP tools/list routes before mission launch.",
            );
      },
    },
    {
      id: "mcp_execution",
      label: "MCP and tool execution",
      journeys: ["autonomous", "guided"],
      evaluate(context) {
        const value = snapshot().mcp;
        const usable = value.enabled
          && value.executionMode === "enabled"
          && value.startPermitted
          && value.runnableServers > 0;
        if (usable) {
          const degraded = value.missingDependencies > 0 || value.missingSecrets > 0;
          return [
            check(
              "mcp_execution_autonomous",
              "Autonomous MCP execution",
              degraded ? "warn" : "pass",
              ["autonomous"],
              `${value.runnableServers} of ${value.configuredServers} configured MCP servers are runnable behind the mission boundary.`,
              degraded ? "Repair MCP dependencies or credentials required by this mission." : undefined,
            ),
            check(
              "mcp_execution_guided",
              "Guided single-step execution",
              degraded ? "warn" : "pass",
              ["guided"],
              "Bounded agent-run steps can use the currently runnable MCP capabilities; manual Guided steps remain available.",
              degraded ? "Repair optional MCP dependencies needed for agent-run Guided steps." : undefined,
            ),
          ];
        }
        const required = requiresExecutionTools(context);
        return [
          check(
            "mcp_execution_autonomous",
            "Autonomous MCP execution",
            required ? "fail" : "warn",
            ["autonomous"],
            required
              ? "The requested action classes require tools, but no enabled runnable MCP execution path is available."
              : "No runnable MCP execution path is available; this contract is limited to advisory or reporting work.",
            "Enable the reviewed MCP arsenal, permit server startup, and repair required dependencies without exposing secrets.",
          ),
          check(
            "mcp_execution_guided",
            "Guided single-step execution",
            "warn",
            ["guided"],
            "Agent-run Guided steps are unavailable, but the operator can continue with explained manual steps.",
            "Enable the reviewed MCP arsenal to allow exact single-step agent execution.",
          ),
        ];
      },
    },
    {
      id: "legacy_execution_surface",
      label: "Two-journey execution surface",
      journeys: ["autonomous", "guided"],
      evaluate() {
        const enabled = snapshot().legacyExecutionEnabled;
        return check(
          "legacy_execution_surface",
          "Two-journey execution surface",
          enabled ? "warn" : "pass",
          ["autonomous", "guided"],
          enabled
            ? "The unversioned legacy execution compatibility window is active beside Autonomous and Guided."
            : "Unversioned mutations and chat/terminal execution are disabled; historical compatibility is read-only.",
          enabled
            ? "Disable ENABLE_LEGACY_EXECUTION_API after the time-bounded rollback task is complete."
            : undefined,
        );
      },
    },
    {
      id: "event_stream",
      label: "Operational event stream",
      journeys: ["autonomous", "guided"],
      evaluate() {
        const health = snapshot().eventStream;
        return check(
          "event_stream",
          "Operational event stream",
          health === "healthy" ? "pass" : "warn",
          ["autonomous", "guided"],
          health === "healthy"
            ? "Durable operational events are available for live replay and reconnect."
            : "Mission state remains durable, but live updates may be delayed until the event stream recovers.",
          health === "healthy" ? undefined : "Restore the local event outbox pump and SSE service.",
        );
      },
    },
    {
      id: "memory_policy",
      label: "Second Brain policy",
      journeys: ["autonomous", "guided"],
      evaluate(context) {
        const health = snapshot().secondBrain;
        const request = autonomousRequest(context);
        const requested = (request?.contract.memoryScopes.length ?? 0) > 0;
        const unavailable = health === "unhealthy" || health === "unknown";
        return check(
          "memory_policy",
          "Second Brain policy",
          requested && unavailable ? "fail" : health === "degraded" ? "warn" : "pass",
          ["autonomous", "guided"],
          requested && unavailable
            ? "The contract requests retained context, but the canonical memory service is unavailable."
            : requested
              ? "Requested memory scopes will be filtered to confirmed memories and verified lessons."
              : "The mission can run without retained personal context; memory use remains opt-in and inspectable.",
          requested && unavailable ? "Restore the canonical memory service or remove memory scopes from the contract." : undefined,
        );
      },
    },
    {
      id: "contract_controls",
      label: "Autonomous contract controls",
      journeys: ["autonomous"],
      evaluate(context) {
        const request = autonomousRequest(context);
        if (!request) {
          return check(
            "contract_controls",
            "Autonomous contract controls",
            "pass",
            ["autonomous"],
            "Preflight validates storage, notification, reporting, retention, provider, and tool policies against currently enforceable choices.",
          );
        }
        const supported = request.contract.notificationPolicy === "in_app_only"
          && request.contract.reportingFormat === "ti_scale_json"
          && request.contract.dataHandlingPolicy === "local_private"
          && request.contract.retentionPolicy === "operator_managed"
          && request.contract.providerPolicy === "automatic_enforcing_only"
          && request.contract.toolPolicy === "contract_allowlist"
          && request.contract.evidenceStorageBudgetBytes >= 1_024
          && request.contract.artifactStorageBudgetBytes >= 1_024;
        return supported
          ? check(
              "contract_controls",
              "Autonomous contract controls",
              "pass",
              ["autonomous"],
              "The selected delivery, data, provider, tool, and byte-budget controls map to active enforcement paths.",
            )
          : check(
              "contract_controls",
              "Autonomous contract controls",
              "fail",
              ["autonomous"],
              "At least one requested contract control cannot be enforced by the active runtime.",
              "Select only the supported policies shown by the Autonomous contract composer.",
            );
      },
    },
  ];
}
