export const SPECIALIST_MCP_EXECUTION_AUTHORIZATION =
  "signed_contract_specialist_action" as const;

/**
 * Exact server-side policy required before a specialist adapter may invoke an
 * MCP tool. Capability discovery remains authorization-free; this policy is
 * re-read with the current signed mission contract and assignment at dispatch.
 */
export interface SpecialistMcpExecutionPolicy {
  readonly schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1";
  readonly enabled: true;
  readonly startPermitted: true;
  readonly executionAuthorization: typeof SPECIALIST_MCP_EXECUTION_AUTHORIZATION;
  readonly autonomousExecution: true;
  readonly exactInventoryRequired: true;
  readonly directCommanderToolsAllowed: false;
  readonly assignedAgents: readonly string[];
}

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

export function isSpecialistMcpExecutionPolicy(
  value: unknown,
): value is SpecialistMcpExecutionPolicy {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Readonly<Record<string, unknown>>;
  const expected = [
    "assignedAgents",
    "autonomousExecution",
    "directCommanderToolsAllowed",
    "enabled",
    "exactInventoryRequired",
    "executionAuthorization",
    "schemaVersion",
    "startPermitted",
  ].sort();
  const keys = Object.keys(record).sort();
  return keys.length === expected.length
    && keys.every((key, index) => key === expected[index])
    && record.schemaVersion === "ti-scale.specialist-mcp-execution-policy.v1"
    && record.enabled === true
    && record.startPermitted === true
    && record.executionAuthorization === SPECIALIST_MCP_EXECUTION_AUTHORIZATION
    && record.autonomousExecution === true
    && record.exactInventoryRequired === true
    && record.directCommanderToolsAllowed === false
    && Array.isArray(record.assignedAgents)
    && record.assignedAgents.length > 0
    && record.assignedAgents.every((agentId) =>
      typeof agentId === "string" && PUBLIC_ID.test(agentId))
    && new Set(record.assignedAgents).size === record.assignedAgents.length;
}
