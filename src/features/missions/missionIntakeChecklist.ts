import type {
  ActionPolicyState,
  IntakeRegistrySnapshot,
  ResolvedMissionIntake,
} from "../../domain/types/intake";

export type ChecklistValueSource = "recommended_default" | "operator_selection" | "platform_invariant";

export interface ResolvedChecklistItem {
  readonly id: string;
  readonly label: string;
}

export interface ResolvedActionPolicyGroup {
  readonly state: Exclude<ActionPolicyState, "inherited_default">;
  readonly label: string;
  readonly items: readonly ResolvedChecklistItem[];
}

export interface ResolvedContractChecklist {
  readonly actionPolicy: {
    readonly source: ChecklistValueSource;
    readonly groups: readonly ResolvedActionPolicyGroup[];
  };
  readonly deliverables: {
    readonly source: ChecklistValueSource;
    readonly items: readonly ResolvedChecklistItem[];
  };
  readonly evidence: {
    readonly source: ChecklistValueSource;
    readonly items: readonly ResolvedChecklistItem[];
  };
  readonly optionalSafeStops: {
    readonly source: ChecklistValueSource;
    readonly items: readonly ResolvedChecklistItem[];
  };
  readonly mandatorySafeStops: {
    readonly source: "platform_invariant";
    readonly items: readonly ResolvedChecklistItem[];
  };
  readonly budget: {
    readonly source: ChecklistValueSource;
    readonly label: string;
  };
}

type ResolvedChecklistInput = Pick<
  ResolvedMissionIntake,
  | "policyMatrix"
  | "deliverableIds"
  | "evidenceTypeIds"
  | "mandatorySafeStopIds"
  | "optionalSafeStopIds"
  | "budget"
  | "inferredFields"
>;

type RegistryChecklistInput = Pick<
  IntakeRegistrySnapshot,
  "deliverables" | "evidenceTypes" | "safeStops"
>;

const ACTION_GROUPS = [
  ["pre_authorized", "Pre-authorized"],
  ["guided_only", "Guided only / not autonomous"],
  ["prohibited", "Prohibited"],
] as const;

function inferredSource(
  resolved: ResolvedChecklistInput,
  field: string,
): Exclude<ChecklistValueSource, "platform_invariant"> {
  return resolved.inferredFields.includes(field) ? "recommended_default" : "operator_selection";
}

function registryItems(
  ids: readonly string[],
  definitions: Readonly<Record<string, { readonly label: string }>>,
): ResolvedChecklistItem[] {
  return ids.map((id) => ({ id, label: definitions[id]?.label ?? id }));
}

/**
 * Builds the exact human-readable checklist shown at final review. It consumes
 * the server-normalized result, never the draft form, so inferred values and
 * operator edits cannot be represented differently from what launch receives.
 */
export function buildResolvedContractChecklist(
  resolved: ResolvedChecklistInput,
  registry: RegistryChecklistInput,
): ResolvedContractChecklist {
  const actionClasses = Object.values(resolved.policyMatrix.classes);
  const actionPolicyEdited = actionClasses.some(({ policySource }) => policySource === "operator_override");
  const optionalStops = Object.fromEntries(registry.safeStops.optional.map((item) => [item.id, item]));
  const mandatoryStops = Object.fromEntries(registry.safeStops.mandatory.map((item) => [item.id, item]));

  return {
    actionPolicy: {
      source: actionPolicyEdited ? "operator_selection" : "recommended_default",
      groups: ACTION_GROUPS.map(([state, label]) => ({
        state,
        label,
        items: actionClasses
          .filter((item) => item.policyState === state)
          .map((item) => ({ id: item.id, label: item.label })),
      })),
    },
    deliverables: {
      source: inferredSource(resolved, "deliverables"),
      items: registryItems(resolved.deliverableIds, registry.deliverables.deliverables),
    },
    evidence: {
      source: inferredSource(resolved, "evidenceRequirements"),
      items: registryItems(resolved.evidenceTypeIds, registry.evidenceTypes.types),
    },
    optionalSafeStops: {
      source: inferredSource(resolved, "optionalSafeStops"),
      items: registryItems(resolved.optionalSafeStopIds, optionalStops),
    },
    mandatorySafeStops: {
      source: "platform_invariant",
      items: registryItems(resolved.mandatorySafeStopIds, mandatoryStops),
    },
    budget: {
      source: inferredSource(resolved, "budget"),
      label: `${resolved.budget.label} · ${resolved.budget.timeBudgetMinutes} min · ${resolved.budget.toolCallBudget} tool calls`,
    },
  };
}

export function checklistSourceLabel(source: ChecklistValueSource): string {
  if (source === "operator_selection") return "Operator selected";
  if (source === "platform_invariant") return "Always enforced";
  return "Recommended default";
}
