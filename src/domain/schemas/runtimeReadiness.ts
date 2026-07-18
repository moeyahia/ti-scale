import type { ExecutionReadiness, RuntimeReadinessSnapshot } from "../types/runtimeReadiness";
import { boolean, nonEmpty, number, object, schema } from "./common";

function executionReadiness(value: unknown, label: string): ExecutionReadiness {
  if (value !== "ready" && value !== "unavailable") {
    throw new Error(`${label} must be ready or unavailable`);
  }
  return value;
}

function availability(value: unknown, label: string): "available" | "unavailable" {
  if (value !== "available" && value !== "unavailable") {
    throw new Error(`${label} must be available or unavailable`);
  }
  return value;
}

function mcpExecutionMode(value: unknown): "disabled" | "dry-run" | "enabled" {
  if (value !== "disabled" && value !== "dry-run" && value !== "enabled") {
    throw new Error("MCP execution mode is invalid");
  }
  return value;
}

export function parseRuntimeReadiness(payload: unknown): RuntimeReadinessSnapshot {
  const root = object(payload, "runtime readiness");
  schema(root);
  if (root.status !== "healthy" && root.status !== "degraded") {
    throw new Error("runtime readiness status is invalid");
  }
  const execution = object(root.execution, "runtime readiness execution");
  const dependencies = object(root.dependencies, "runtime readiness dependencies");
  const providers = object(dependencies.providers, "runtime readiness providers");
  const mcp = dependencies.mcp === undefined
    ? null
    : object(dependencies.mcp, "runtime readiness MCP");
  return {
    schemaVersion: "2.4",
    status: root.status,
    execution: {
      autonomous: executionReadiness(execution.autonomous, "autonomous execution"),
      guided: executionReadiness(execution.guided, "Guided execution"),
      guidedToolExecution: execution.guidedToolExecution === undefined
        ? "unavailable"
        : executionReadiness(execution.guidedToolExecution, "Guided tool execution"),
      actionBoundaryActive: boolean(execution.actionBoundaryActive, "actionBoundaryActive"),
      delegationEnforced: boolean(execution.delegationEnforced, "delegationEnforced"),
      noHandsCommanderEnforced: boolean(execution.noHandsCommanderEnforced, "noHandsCommanderEnforced"),
    },
    dependencies: {
      providers: {
        status: availability(providers.status, "provider availability"),
        initializing: providers.initializing === undefined
          ? false
          : boolean(providers.initializing, "providers.initializing"),
        probing: providers.probing === undefined
          ? 0
          : number(providers.probing, "providers.probing"),
        reason: providers.reason === undefined || providers.reason === null
          ? null
          : nonEmpty(providers.reason, "providers.reason"),
        declared: number(providers.declared, "providers.declared"),
        callable: number(providers.callable, "providers.callable"),
        enforcing: number(providers.enforcing, "providers.enforcing"),
        guidedCapable: number(providers.guidedCapable, "providers.guidedCapable"),
      },
      mcp: mcp === null
        ? {
            status: "unavailable",
            initializing: false,
            probingServers: 0,
            reason: null,
            configuredServers: 0,
            runnableServers: 0,
            executionMode: "disabled",
          }
        : {
            status: availability(mcp.status, "MCP availability"),
            initializing: mcp.initializing === undefined
              ? false
              : boolean(mcp.initializing, "mcp.initializing"),
            probingServers: mcp.probingServers === undefined
              ? 0
              : number(mcp.probingServers, "mcp.probingServers"),
            reason: mcp.reason === undefined || mcp.reason === null
              ? null
              : nonEmpty(mcp.reason, "mcp.reason"),
            configuredServers: number(mcp.configuredServers, "mcp.configuredServers"),
            runnableServers: number(mcp.runnableServers, "mcp.runnableServers"),
            executionMode: mcpExecutionMode(mcp.executionMode),
          },
    },
    checkedAt: nonEmpty(root.checkedAt, "readiness checkedAt"),
  };
}
