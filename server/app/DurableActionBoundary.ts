/**
 * Live inputs required before Ti-Scale may advertise a durable specialist
 * action boundary. All enforcement switches must be explicitly true (or, for
 * direct commander tools, explicitly false) on every evaluation.
 */
export interface DurableActionBoundaryPolicy {
  readonly routingEnabled?: boolean;
  readonly delegationEnforced?: boolean;
  readonly noHandsCommanderEnforced?: boolean;
  readonly directCommanderToolsAllowed?: boolean;
  readonly specialistAssignmentRequired?: boolean;
}

export interface DurableActionBoundaryInventoryItem {
  readonly agentId?: string;
  readonly mcpServer?: string;
  readonly toolNames?: readonly string[];
}

export interface DurableActionBoundaryInput {
  readonly runtimeCoordinatorReady?: boolean;
  readonly policy?: DurableActionBoundaryPolicy | null;
  readonly specialistInventory?: readonly DurableActionBoundaryInventoryItem[] | null;
}

function nonBlank(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasCallableSpecialist(
  inventory: readonly DurableActionBoundaryInventoryItem[] | null | undefined,
): boolean {
  if (!Array.isArray(inventory)) return false;
  return inventory.some((item) => nonBlank(item?.agentId)
    && nonBlank(item?.mcpServer)
    && Array.isArray(item?.toolNames)
    && item.toolNames.some(nonBlank));
}

/**
 * Re-evaluates the durable action boundary from current runtime facts.
 *
 * This function is intentionally pure and fail-closed: missing, stale, or
 * partially populated inputs return false, and no startup result is cached.
 */
export function deriveCommandOsDurableActionBoundary(
  input: DurableActionBoundaryInput,
): boolean {
  const policy = input.policy;
  return input.runtimeCoordinatorReady === true
    && policy?.routingEnabled === true
    && policy.delegationEnforced === true
    && policy.noHandsCommanderEnforced === true
    && policy.directCommanderToolsAllowed === false
    && policy.specialistAssignmentRequired === true
    && hasCallableSpecialist(input.specialistInventory);
}
