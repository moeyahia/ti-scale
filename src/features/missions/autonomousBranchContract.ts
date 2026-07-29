import type { AutonomousMissionRequest } from "../../domain/types/commandOs";
import type { ActionPolicyState, IntakeRegistrySnapshot } from "../../domain/types/intake";

export interface AutonomousBranchRegistryFields {
  readonly actionPolicyStates: Readonly<Record<string, ActionPolicyState>>;
  readonly unmatchedAllowedActionClasses: readonly string[];
  readonly unmatchedProhibitedActionClasses: readonly string[];
  readonly evidenceTypeIds: readonly string[];
  readonly unmatchedEvidenceRequirements: readonly string[];
  readonly optionalSafeStopIds: readonly string[];
  readonly unmatchedSafeStopConditions: readonly string[];
  readonly deliverableIds: readonly string[];
  readonly unmatchedDeliverables: readonly string[];
}

interface RegistryEntry {
  readonly id: string;
  readonly label: string;
}

function unique(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

function matchKey(value: string): string {
  return value.trim().toLocaleLowerCase("en-US").replace(/[^a-z0-9]+/gu, "_").replace(/^_+|_+$/gu, "");
}

function registryLookup(entries: readonly RegistryEntry[]): ReadonlyMap<string, string> {
  const lookup = new Map<string, string>();
  for (const entry of entries) {
    lookup.set(matchKey(entry.id), entry.id);
    lookup.set(matchKey(entry.label), entry.id);
  }
  return lookup;
}

function reconcile(values: readonly string[], entries: readonly RegistryEntry[]): {
  readonly matchedIds: readonly string[];
  readonly unmatchedValues: readonly string[];
} {
  const lookup = registryLookup(entries);
  const matchedIds: string[] = [];
  const unmatchedValues: string[] = [];
  for (const value of unique(values)) {
    const id = lookup.get(matchKey(value));
    if (id) matchedIds.push(id);
    else unmatchedValues.push(value);
  }
  return { matchedIds: unique(matchedIds), unmatchedValues };
}

function actionEntries(registry: IntakeRegistrySnapshot): RegistryEntry[] {
  return Object.values(registry.actionClasses.classes).map(({ id, label }) => ({ id, label }));
}

function evidenceEntries(registry: IntakeRegistrySnapshot): RegistryEntry[] {
  return Object.values(registry.evidenceTypes.types).map(({ id, label }) => ({ id, label }));
}

function safeStopEntries(registry: IntakeRegistrySnapshot): RegistryEntry[] {
  return registry.safeStops.optional.map(({ id, label }) => ({ id, label }));
}

function deliverableEntries(registry: IntakeRegistrySnapshot): RegistryEntry[] {
  return Object.values(registry.deliverables.deliverables).map(({ id, label }) => ({ id, label }));
}

export function registryFieldsFromAutonomousRequest(
  request: AutonomousMissionRequest,
  registry: IntakeRegistrySnapshot,
): AutonomousBranchRegistryFields {
  const allowed = reconcile(request.contract.allowedActionClasses, actionEntries(registry));
  const prohibited = reconcile(request.contract.prohibitedActionClasses, actionEntries(registry));
  const allowedIds = new Set(allowed.matchedIds);
  const prohibitedIds = new Set(prohibited.matchedIds);
  const actionPolicyStates = Object.fromEntries(Object.keys(registry.actionClasses.classes).map((id) => [
    id,
    allowedIds.has(id) ? "pre_authorized" : prohibitedIds.has(id) ? "prohibited" : "inherited_default",
  ])) as Record<string, ActionPolicyState>;
  const evidence = reconcile(request.contract.evidenceRequirements, evidenceEntries(registry));
  const safeStops = reconcile(request.contract.safeStopConditions, safeStopEntries(registry));
  const deliverables = reconcile(request.contract.deliverables, deliverableEntries(registry));
  return {
    actionPolicyStates,
    unmatchedAllowedActionClasses: allowed.unmatchedValues,
    unmatchedProhibitedActionClasses: prohibited.unmatchedValues,
    evidenceTypeIds: evidence.matchedIds,
    unmatchedEvidenceRequirements: evidence.unmatchedValues,
    optionalSafeStopIds: safeStops.matchedIds,
    unmatchedSafeStopConditions: safeStops.unmatchedValues,
    deliverableIds: deliverables.matchedIds,
    unmatchedDeliverables: deliverables.unmatchedValues,
  };
}

export function projectAutonomousRegistryFields(
  fields: AutonomousBranchRegistryFields,
  registry: IntakeRegistrySnapshot,
): Pick<AutonomousMissionRequest["contract"],
  "allowedActionClasses" | "prohibitedActionClasses" | "evidenceRequirements" | "safeStopConditions" | "deliverables"
> {
  const allowedActionClasses: string[] = [];
  const prohibitedActionClasses: string[] = [];
  for (const action of Object.values(registry.actionClasses.classes)) {
    const selected = fields.actionPolicyStates[action.id] ?? "inherited_default";
    const resolved = selected === "inherited_default" ? action.policyState : selected;
    if (resolved === "pre_authorized") allowedActionClasses.push(action.id);
    else prohibitedActionClasses.push(action.id);
  }
  const allowed = unique([...allowedActionClasses, ...fields.unmatchedAllowedActionClasses]);
  const allowedSet = new Set(allowed);
  return {
    allowedActionClasses: allowed,
    prohibitedActionClasses: unique([
      ...prohibitedActionClasses,
      ...fields.unmatchedProhibitedActionClasses,
    ]).filter((value) => !allowedSet.has(value)),
    evidenceRequirements: unique([...fields.evidenceTypeIds, ...fields.unmatchedEvidenceRequirements]),
    safeStopConditions: unique([...fields.optionalSafeStopIds, ...fields.unmatchedSafeStopConditions]),
    deliverables: unique([...fields.deliverableIds, ...fields.unmatchedDeliverables]),
  };
}
