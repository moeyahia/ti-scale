import type { SqliteDatabase } from "../db";
import { productAgentIdForActionClass } from "./ProductAgentRegistry";

interface AgentBindingRow {
  readonly status: string;
  readonly configuration_json: string;
}

function parseConfiguration(value: string): Readonly<Record<string, unknown>> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Readonly<Record<string, unknown>>
      : null;
  } catch {
    return null;
  }
}

function isExecutableStatus(status: string): boolean {
  return status !== "offline" && status !== "quarantined";
}

/**
 * Product agents remain the durable plan and audit owner while an internal
 * runtime adapter performs the exact reviewed action. This boundary accepts
 * the split identity only when the canonical product-agent projection names
 * the exact internal binding and both rows remain executable.
 */
export function agentAssignmentBindsRuntimeAgent(
  database: SqliteDatabase,
  assignedAgentId: string | null,
  runtimeAgentId: string,
): boolean {
  if (!assignedAgentId || !runtimeAgentId) return false;
  if (assignedAgentId === runtimeAgentId) return true;

  const assigned = database.prepare(`
    SELECT status, configuration_json
    FROM agents
    WHERE id = ?
  `).get(assignedAgentId) as AgentBindingRow | undefined;
  if (!assigned || !isExecutableStatus(assigned.status)) return false;

  const configuration = parseConfiguration(assigned.configuration_json);
  if (
    !configuration
    || configuration.userFacing !== true
    || configuration.productAgent !== true
    || !Array.isArray(configuration.runtimeBindingAgentIds)
  ) return false;

  const runtimeBindingAgentIds = configuration.runtimeBindingAgentIds
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.trim())
    .filter(Boolean);
  if (!runtimeBindingAgentIds.includes(runtimeAgentId)) return false;

  const runtime = database.prepare(`
    SELECT status, configuration_json
    FROM agents
    WHERE id = ?
  `).get(runtimeAgentId) as AgentBindingRow | undefined;
  return Boolean(runtime && isExecutableStatus(runtime.status));
}

/**
 * Signed contracts and durable plan/assignment rows must name the canonical
 * product owner of the action class. The internal adapter ID is accepted only
 * as that product owner's current executable runtime binding.
 */
export function canonicalProductOwnerBindsRuntimeAgent(
  database: SqliteDatabase,
  input: Readonly<{
    actionClassId: string;
    planAgentId: string | null;
    assignmentAgentId: string | null;
    signedSpecialistAgentIds: readonly unknown[];
    runtimeAgentId: string;
  }>,
): boolean {
  const productAgentId = productAgentIdForActionClass(input.actionClassId);
  if (
    !productAgentId
    || input.planAgentId !== productAgentId
    || input.assignmentAgentId !== productAgentId
    || !input.signedSpecialistAgentIds.includes(productAgentId)
  ) return false;
  return agentAssignmentBindsRuntimeAgent(
    database,
    productAgentId,
    input.runtimeAgentId,
  );
}
