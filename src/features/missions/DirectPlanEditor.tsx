import { type FormEvent, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { fetchMissionIntakeRegistry } from "../../data/api/commandOs";
import { operationsApi } from "../../data/api/operations";
import { planChangesApi } from "../../data/api/planChanges";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type { IntakeActionClass } from "../../domain/types/intake";
import type { AgentRecord } from "../../domain/types/operations";
import type {
  PlanChangeJson,
  PlanChangeOperation,
  PlanChangeRequest,
  PlanStepActionKind,
  PlanStepRepresentationInput,
} from "../../domain/types/planChanges";
import type { PlanStep, RunPlan, RuntimeRun } from "../../domain/types/runtimeV2";

type EditorMode = "add" | "update" | "dependencies" | "reorder" | "remove" | "represented_action";

interface StepDraft {
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly successCriteriaText: string;
  readonly actionClass: string;
  readonly assignedAgentId: string;
}

interface RepresentationDraft {
  readonly actionType: string;
  readonly target: string;
  readonly argumentsJson: string;
  readonly intentSummary: string;
  readonly kind: PlanStepActionKind;
  readonly idempotent: boolean;
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
}

interface AddStepDraft extends StepDraft, RepresentationDraft {
  readonly clientStepId: string;
  readonly afterStepId: string;
  readonly dependencyStepIds: readonly string[];
}

const MODES: ReadonlyArray<{ readonly id: EditorMode; readonly label: string }> = [
  { id: "add", label: "Add an exact step" },
  { id: "update", label: "Edit step details or ownership" },
  { id: "dependencies", label: "Change dependencies" },
  { id: "reorder", label: "Reorder steps" },
  { id: "remove", label: "Remove a step" },
  { id: "represented_action", label: "Amend the exact represented action" },
];

const ACTION_KINDS: ReadonlyArray<{ readonly id: PlanStepActionKind; readonly label: string }> = [
  { id: "manual", label: "Manual procedure" },
  { id: "tool", label: "Tool call" },
  { id: "provider_turn", label: "Provider reasoning turn" },
  { id: "delegation", label: "Specialist delegation" },
  { id: "replan", label: "Bounded replan" },
];

function lines(value: string): string[] {
  return [...new Set(value.split(/\r?\n/u).map((entry) => entry.trim()).filter(Boolean))];
}

function makeClientStepId(): string {
  return `draft-step-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
}

function makeStepDraft(step: PlanStep): StepDraft {
  return {
    phase: step.phase,
    title: step.title,
    objective: step.objective,
    successCriteriaText: step.successCriteria.join("\n"),
    actionClass: step.action.actionClass,
    assignedAgentId: step.assignedAgentId,
  };
}

function makeRepresentationDraft(step: PlanStep): RepresentationDraft {
  return {
    actionType: step.action.actionType,
    target: step.action.target,
    argumentsJson: JSON.stringify(step.action.arguments, null, 2) ?? "{}",
    intentSummary: step.action.intentSummary,
    kind: step.action.kind,
    idempotent: step.action.idempotent,
    explanation: step.explanation,
    rationale: step.rationale,
    reversibility: step.reversibility,
  };
}

function initialAddStep(steps: readonly PlanStep[]): AddStepDraft {
  const last = steps.at(-1);
  return {
    clientStepId: makeClientStepId(),
    afterStepId: last?.id ?? "",
    phase: last?.phase ?? "Assessment",
    title: "",
    objective: "",
    successCriteriaText: "",
    dependencyStepIds: last ? [last.id] : [],
    actionClass: "",
    assignedAgentId: "",
    actionType: "",
    target: "",
    argumentsJson: "{}",
    intentSummary: "",
    kind: "manual",
    idempotent: false,
    explanation: "",
    rationale: "",
    reversibility: "",
  };
}

function modeForOperation(operation: PlanChangeOperation | undefined): EditorMode {
  switch (operation?.kind) {
    case "add_step": return "add";
    case "update_step": return "update";
    case "set_dependencies": return "dependencies";
    case "reorder_steps": return "reorder";
    case "remove_step": return "remove";
    case "set_represented_action": return "represented_action";
    default: return "add";
  }
}

function stepIdForOperation(operation: PlanChangeOperation | undefined, fallback: string): string {
  switch (operation?.kind) {
    case "update_step":
    case "set_dependencies":
    case "remove_step":
    case "set_represented_action": return operation.stepId;
    default: return fallback;
  }
}

function draftForUpdateOperation(step: PlanStep | undefined, operation: PlanChangeOperation | undefined): StepDraft {
  const base = step
    ? makeStepDraft(step)
    : { phase: "", title: "", objective: "", successCriteriaText: "", actionClass: "", assignedAgentId: "" };
  if (operation?.kind !== "update_step") return base;
  return {
    phase: operation.phase ?? base.phase,
    title: operation.title ?? base.title,
    objective: operation.objective ?? base.objective,
    successCriteriaText: operation.successCriteria?.join("\n") ?? base.successCriteriaText,
    actionClass: operation.actionClass !== undefined ? operation.actionClass ?? "" : base.actionClass,
    assignedAgentId: operation.assignedAgentId !== undefined ? operation.assignedAgentId ?? "" : base.assignedAgentId,
  };
}

function draftForAddOperation(steps: readonly PlanStep[], operation: PlanChangeOperation | undefined): AddStepDraft {
  if (operation?.kind !== "add_step") return initialAddStep(steps);
  return {
    clientStepId: operation.clientStepId,
    afterStepId: operation.afterStepId ?? "",
    phase: operation.phase,
    title: operation.title,
    objective: operation.objective,
    successCriteriaText: operation.successCriteria.join("\n"),
    dependencyStepIds: operation.dependencyStepIds,
    actionClass: operation.actionClass,
    assignedAgentId: operation.assignedAgentId,
    actionType: operation.representation.action.actionType,
    target: operation.representation.action.target,
    argumentsJson: JSON.stringify(operation.representation.action.arguments, null, 2) ?? "{}",
    intentSummary: operation.representation.action.intentSummary,
    kind: operation.representation.action.kind,
    idempotent: operation.representation.action.idempotent,
    explanation: operation.representation.explanation,
    rationale: operation.representation.rationale,
    reversibility: operation.representation.reversibility,
  };
}

function draftForRepresentationOperation(step: PlanStep | undefined, operation: PlanChangeOperation | undefined): RepresentationDraft {
  if (operation?.kind === "set_represented_action") {
    return {
      actionType: operation.representation.action.actionType,
      target: operation.representation.action.target,
      argumentsJson: JSON.stringify(operation.representation.action.arguments, null, 2) ?? "{}",
      intentSummary: operation.representation.action.intentSummary,
      kind: operation.representation.action.kind,
      idempotent: operation.representation.action.idempotent,
      explanation: operation.representation.explanation,
      rationale: operation.representation.rationale,
      reversibility: operation.representation.reversibility,
    };
  }
  return step ? makeRepresentationDraft(step) : initialAddStep([]);
}

function parseArgumentsJson(value: string): Readonly<Record<string, PlanChangeJson>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "the JSON parser rejected the value";
    throw new Error(`Action arguments are not valid JSON: ${detail}. Use an object such as {"timeoutSeconds":30}.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Action arguments must be a JSON object. Use {} when this represented action has no arguments.");
  }
  return parsed as Readonly<Record<string, PlanChangeJson>>;
}

function riskClass(actionClass: IntakeActionClass): "low" | "medium" | "high" | "critical" {
  return actionClass.riskBand === "moderate" ? "medium" : actionClass.riskBand;
}

function representation(
  draft: RepresentationDraft,
  destructive: boolean,
): PlanStepRepresentationInput {
  return {
    action: {
      actionType: draft.actionType.trim(),
      target: draft.target.trim(),
      arguments: parseArgumentsJson(draft.argumentsJson),
      intentSummary: draft.intentSummary.trim(),
      kind: draft.kind,
      idempotent: draft.idempotent,
      destructive,
    },
    explanation: draft.explanation.trim(),
    rationale: draft.rationale.trim(),
    reversibility: draft.reversibility.trim(),
  };
}

async function fetchCanonicalAgents(signal: AbortSignal): Promise<readonly AgentRecord[]> {
  const records: AgentRecord[] = [];
  const seenIds = new Set<string>();
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  do {
    const page = await operationsApi.agents({ limit: 100, cursor }, signal);
    for (const item of page.items) {
      if (!seenIds.has(item.id)) records.push(item);
      seenIds.add(item.id);
    }
    if (page.nextCursor === null) break;
    if (seenCursors.has(page.nextCursor)) throw new Error("The canonical agent catalog repeated a pagination cursor.");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  } while (!signal.aborted);
  return records;
}

function sortedSteps(plan: RunPlan): PlanStep[] {
  return [...plan.steps].sort((left, right) => left.ordinal - right.ordinal || left.id.localeCompare(right.id));
}

function firstSafeActionClass(classes: readonly IntakeActionClass[]): IntakeActionClass | undefined {
  return classes.filter((item) =>
    !item.destructiveOrDisruptive &&
    item.policyState !== "prohibited" &&
    item.capability.availability === "supported" &&
    item.launchBlockingReasons.length === 0,
  ).sort((left, right) => {
    const score = (value: IntakeActionClass) =>
      (value.destructiveOrDisruptive ? 100 : 0) +
      (value.policyState === "pre_authorized" ? 0 : value.policyState === "guided_only" ? 10 : 50) +
      (value.capability.availability === "supported" ? 0 : 25) +
      ({ low: 0, moderate: 1, high: 2, critical: 3 }[value.riskBand]);
    return score(left) - score(right) || left.label.localeCompare(right.label);
  })[0];
}

function agentOptionsFor(
  actionClass: IntakeActionClass | undefined,
  agents: readonly AgentRecord[],
): AgentRecord[] {
  const mapped = new Set(actionClass?.capability.agentIds ?? []);
  const available = new Set(actionClass?.capability.availableAgentIds ?? []);
  return [...agents].sort((left, right) => {
    const score = (agent: AgentRecord) =>
      (available.has(agent.id) ? 0 : mapped.has(agent.id) ? 10 : 20) + (agent.status === "available" ? 0 : 1);
    return score(left) - score(right) || left.displayName.localeCompare(right.displayName);
  });
}

function defaultAgentId(actionClass: IntakeActionClass | undefined, agents: readonly AgentRecord[]): string {
  const options = agentOptionsFor(actionClass, agents);
  return options.find((agent) => actionClass?.capability.availableAgentIds.includes(agent.id))?.id
    ?? options.find((agent) => actionClass?.capability.agentIds.includes(agent.id))?.id
    ?? "";
}

function sameValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function canonicalDependencies(ids: readonly string[], steps: readonly PlanStep[]): string[] {
  const selected = new Set(ids);
  const known = new Set(steps.map((step) => step.id));
  return [
    ...steps.filter((step) => selected.has(step.id)).map((step) => step.id),
    ...[...selected].filter((id) => !known.has(id)).sort(),
  ];
}

function reordered(orderedIds: readonly string[], stepId: string, delta: -1 | 1): string[] {
  const next = [...orderedIds];
  const index = next.indexOf(stepId);
  const destination = index + delta;
  if (index < 0 || destination < 0 || destination >= next.length) return next;
  [next[index], next[destination]] = [next[destination]!, next[index]!];
  return next;
}

function orderIssues(orderedIds: readonly string[], steps: readonly PlanStep[]): string[] {
  const position = new Map(orderedIds.map((id, index) => [id, index]));
  const issues: string[] = [];
  for (const step of steps) {
    for (const dependencyId of step.dependencyStepIds) {
      const stepIndex = position.get(step.id);
      const dependencyIndex = position.get(dependencyId);
      if (stepIndex === undefined || dependencyIndex === undefined || dependencyIndex >= stepIndex) {
        issues.push(`${step.title} must remain after dependency ${dependencyId}.`);
      }
    }
  }
  return issues;
}

function classOptionLabel(actionClass: IntakeActionClass): string {
  return `${actionClass.label} · ${actionClass.policyState.replaceAll("_", " ")} · ${actionClass.capability.availability}`;
}

function ActionClassSelect({
  id,
  controlId,
  value,
  currentValue,
  classes,
  disabled,
  onChange,
}: {
  readonly id: string;
  readonly controlId: string;
  readonly value: string;
  readonly currentValue?: string;
  readonly classes: readonly IntakeActionClass[];
  readonly disabled?: boolean;
  readonly onChange: (value: string) => void;
}) {
  const currentIsMissing = Boolean(currentValue && !classes.some((item) => item.id === currentValue));
  return <label htmlFor={id}>Action class
    <TitaniumSelect id={id} data-control-id={controlId} value={value} disabled={disabled} required onChange={(event) => onChange(event.target.value)}>
      <option value="" disabled>Select from the live action-class registry</option>
      {currentIsMissing && <option value={currentValue} disabled>{currentValue} · not present in the live registry</option>}
      {classes.map((item) => <option key={item.id} value={item.id}>{classOptionLabel(item)}</option>)}
    </TitaniumSelect>
    <span>Values, policy state, capability mapping, and availability come from the runtime intake registry.</span>
  </label>;
}

function AgentSelect({
  id,
  controlId,
  value,
  currentValue,
  agents,
  actionClass,
  disabled,
  onChange,
}: {
  readonly id: string;
  readonly controlId: string;
  readonly value: string;
  readonly currentValue?: string;
  readonly agents: readonly AgentRecord[];
  readonly actionClass?: IntakeActionClass;
  readonly disabled?: boolean;
  readonly onChange: (value: string) => void;
}) {
  const currentIsMissing = Boolean(currentValue && !agents.some((agent) => agent.id === currentValue));
  const mapped = new Set(actionClass?.capability.agentIds ?? []);
  return <label htmlFor={id}>Assigned specialist
    <TitaniumSelect id={id} data-control-id={controlId} value={value} disabled={disabled} required onChange={(event) => onChange(event.target.value)}>
      <option value="" disabled>Select from the canonical agent fleet</option>
      {currentIsMissing && <option value={currentValue} disabled>{currentValue} · not present in the canonical fleet</option>}
      {agentOptionsFor(actionClass, agents).map((agent) => <option key={agent.id} value={agent.id}>
        {agent.displayName} · {agent.status}{mapped.has(agent.id) ? " · mapped capability" : ""}
      </option>)}
    </TitaniumSelect>
    <span>Fleet status is live. The server performs the authoritative capability and readiness check on the proposal.</span>
  </label>;
}

function ActionClassEvidence({ actionClass }: { readonly actionClass?: IntakeActionClass }) {
  if (!actionClass) return <div className="os-registry-source" role="status"><StatusPill status="unresolved" /><span><strong>No registered action class selected</strong><small>Select a live registry value before creating this proposal.</small></span></div>;
  return <div className="os-registry-source" role="status">
    <StatusPill status={actionClass.capability.enforcementReady ? "enforcement_ready" : actionClass.capability.availability} />
    <span>
      <strong>{actionClass.label} · {actionClass.riskBand} risk</strong>
      <small>{actionClass.plainLanguageDescription}</small>
      <small>{actionClass.policyState.replaceAll("_", " ")} · {actionClass.capability.availability} · {actionClass.capability.availableAgentIds.length} available mapped specialists · enforcement {actionClass.capability.enforcementReady ? "ready" : "not verified"}</small>
      {actionClass.launchBlockingReasons.length > 0 && <small>{actionClass.launchBlockingReasons.join(" ")}</small>}
    </span>
  </div>;
}

function RepresentationFields({
  prefix,
  draft,
  destructive,
  disabled,
  onChange,
}: {
  readonly prefix: string;
  readonly draft: RepresentationDraft;
  readonly destructive: boolean;
  readonly disabled?: boolean;
  readonly onChange: (next: RepresentationDraft) => void;
}) {
  const set = <K extends keyof RepresentationDraft>(key: K, value: RepresentationDraft[K]) => onChange({ ...draft, [key]: value });
  return <fieldset>
    <legend>Exact represented action</legend>
    <p className="os-field-intro">This is the exact method, target, and normalized argument object that a later reviewed plan version would represent. Creating the proposal does not execute it.</p>
    <div className="os-field-grid">
      <label htmlFor={`${prefix}-action-type`}>Action type <small>Required</small>
        <input id={`${prefix}-action-type`} data-control-id={`${prefix}-action-type`} disabled={disabled} required minLength={2} maxLength={120} value={draft.actionType} onChange={(event) => set("actionType", event.target.value)} placeholder="Example: http_endpoint_discovery" />
        <span>Use the bounded runtime action identifier, not a shell command.</span>
      </label>
      <label htmlFor={`${prefix}-kind`}>Execution kind
        <TitaniumSelect id={`${prefix}-kind`} data-control-id={`${prefix}-kind`} disabled={disabled} value={draft.kind} onChange={(event) => set("kind", event.target.value as PlanStepActionKind)}>
          {ACTION_KINDS.map((kind) => <option key={kind.id} value={kind.id}>{kind.label}</option>)}
        </TitaniumSelect>
        <span>This declares how the represented action is routed; it does not grant execution permission.</span>
      </label>
    </div>
    <label htmlFor={`${prefix}-target`}>Exact target <small>Required</small>
      <input id={`${prefix}-target`} data-control-id={`${prefix}-target`} disabled={disabled} required minLength={1} maxLength={2000} value={draft.target} onChange={(event) => set("target", event.target.value)} placeholder="Example: https://portal.example.test/login" />
      <span>The server rechecks this value against normalized mission scope.</span>
    </label>
    <label htmlFor={`${prefix}-arguments`}>Normalized action arguments <small>Required JSON object</small>
      <textarea id={`${prefix}-arguments`} data-control-id={`${prefix}-arguments`} disabled={disabled} required spellCheck={false} value={draft.argumentsJson} onChange={(event) => set("argumentsJson", event.target.value)} placeholder={'{"timeoutSeconds": 30, "path": "/login"}'} />
      <span>Use an object only. Never paste credentials, tokens, cookies, private keys, or raw confidential payloads.</span>
    </label>
    <label htmlFor={`${prefix}-intent`}>Human-readable intent <small>Required</small>
      <textarea id={`${prefix}-intent`} data-control-id={`${prefix}-intent`} disabled={disabled} required minLength={3} maxLength={1000} value={draft.intentSummary} onChange={(event) => set("intentSummary", event.target.value)} placeholder="Example: Enumerate authorized application endpoints while retaining attributable response metadata." />
      <span>Explain what this one action is trying to learn or accomplish.</span>
    </label>
    <label className="os-check-field" htmlFor={`${prefix}-idempotent`}>
      <input id={`${prefix}-idempotent`} data-control-id={`${prefix}-idempotent`} type="checkbox" disabled={disabled} checked={draft.idempotent} onChange={(event) => set("idempotent", event.target.checked)} />
      <span><strong>This exact action is idempotent</strong><small>Off is the conservative default. Enable only when repeating the same normalized action cannot create additional side effects.</small></span>
    </label>
    <div className="os-registry-source" role="status"><StatusPill status={destructive ? "destructive" : "non_destructive"} /><span><strong>Destructive classification is registry-derived</strong><small>{destructive ? "The selected action class is marked destructive or service-disruptive." : "The selected action class is not marked destructive or service-disruptive."} This value is not accepted as free-form operator input.</small></span></div>
    <label htmlFor={`${prefix}-explanation`}>Layman explanation <small>Required</small>
      <textarea id={`${prefix}-explanation`} data-control-id={`${prefix}-explanation`} disabled={disabled} required minLength={3} maxLength={2000} value={draft.explanation} onChange={(event) => set("explanation", event.target.value)} placeholder="Example: Check which approved web paths respond so the next step is based on observed application behavior." />
    </label>
    <label htmlFor={`${prefix}-rationale`}>Technical rationale <small>Required</small>
      <textarea id={`${prefix}-rationale`} data-control-id={`${prefix}-rationale`} disabled={disabled} required minLength={3} maxLength={2000} value={draft.rationale} onChange={(event) => set("rationale", event.target.value)} placeholder="Example: Structured endpoint discovery reduces uncertainty before version-aware vulnerability analysis." />
    </label>
    <label htmlFor={`${prefix}-reversibility`}>Reversibility and rollback <small>Required</small>
      <textarea id={`${prefix}-reversibility`} data-control-id={`${prefix}-reversibility`} disabled={disabled} required minLength={3} maxLength={2000} value={draft.reversibility} onChange={(event) => set("reversibility", event.target.value)} placeholder="Example: Read-only requests only; stop on instability and retain the last safe checkpoint." />
    </label>
  </fieldset>;
}

export function DirectPlanEditor({
  run,
  plan,
  onProposalCreated,
  editRequest,
  editOperationIndex = 0,
  onEditCancelled,
  onEditCompleted,
}: {
  readonly run: RuntimeRun;
  readonly plan: RunPlan;
  readonly onProposalCreated?: () => void | Promise<void>;
  readonly editRequest?: PlanChangeRequest;
  readonly editOperationIndex?: number;
  readonly onEditCancelled?: () => void;
  readonly onEditCompleted?: (request: PlanChangeRequest) => void;
}) {
  const steps = useMemo(() => sortedSteps(plan), [plan]);
  const firstStep = steps[0];
  const editOperation = editRequest?.normalizedChange.operations[editOperationIndex];
  const initialSelectedStepId = stepIdForOperation(editOperation, firstStep?.id ?? "");
  const initialSelectedStep = steps.find((step) => step.id === initialSelectedStepId) ?? firstStep;
  const [mode, setMode] = useState<EditorMode>(() => modeForOperation(editOperation));
  const [selectedStepId, setSelectedStepId] = useState(initialSelectedStepId);
  const [changeReason, setChangeReason] = useState(editRequest?.requestText ?? "");
  const [stepDraft, setStepDraft] = useState<StepDraft>(() => draftForUpdateOperation(initialSelectedStep, editOperation));
  const [dependencyIds, setDependencyIds] = useState<readonly string[]>(() => editOperation?.kind === "set_dependencies" ? editOperation.dependencyStepIds : initialSelectedStep?.dependencyStepIds ?? []);
  const [orderedStepIds, setOrderedStepIds] = useState<readonly string[]>(() => editOperation?.kind === "reorder_steps" ? editOperation.orderedStepIds : steps.map((step) => step.id));
  const [removalReason, setRemovalReason] = useState(() => editOperation?.kind === "remove_step" ? editOperation.reason : "");
  const [actionDraft, setActionDraft] = useState<RepresentationDraft>(() => draftForRepresentationOperation(initialSelectedStep, editOperation));
  const [addDraft, setAddDraft] = useState<AddStepDraft>(() => draftForAddOperation(steps, editOperation));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<Error>();
  const [confirmation, setConfirmation] = useState<string>();
  const headingRef = useRef<HTMLHeadingElement>(null);

  const registry = useQuery(
    `plan-direct-action-registry:${run.journey}:custom`,
    (signal) => fetchMissionIntakeRegistry(run.journey, "custom", signal),
    { staleTime: 30_000 },
  );
  const fleet = useQuery(
    "plan-direct-canonical-agents",
    fetchCanonicalAgents,
    { staleTime: 15_000 },
  );
  const actionClasses = useMemo(
    () => Object.values(registry.data?.actionClasses.classes ?? {}).sort((left, right) => left.label.localeCompare(right.label)),
    [registry.data],
  );
  const actionClassById = useMemo(() => new Map(actionClasses.map((item) => [item.id, item])), [actionClasses]);
  const agents = useMemo(() => [...(fleet.data ?? [])], [fleet.data]);
  const selectedStep = steps.find((step) => step.id === selectedStepId) ?? firstStep;
  const updateActionClass = actionClassById.get(stepDraft.actionClass);
  const addActionClass = actionClassById.get(addDraft.actionClass);
  const representedActionClass = selectedStep ? actionClassById.get(selectedStep.action.actionClass) : undefined;
  const registryIsLive = registry.data?.source.status === "live";
  const addAfterStep = steps.find((step) => step.id === addDraft.afterStepId);
  const addDependencyCandidates = addAfterStep
    ? steps.filter((step) => step.ordinal <= addAfterStep.ordinal)
    : steps;

  useEffect(() => {
    if (addDraft.actionClass || actionClasses.length === 0) return;
    const selected = firstSafeActionClass(actionClasses);
    if (!selected) return;
    setAddDraft((current) => ({
      ...current,
      actionClass: selected.id,
      assignedAgentId: defaultAgentId(selected, agents),
    }));
  }, [actionClasses, addDraft.actionClass, agents]);

  useEffect(() => {
    if (!addDraft.actionClass || addDraft.assignedAgentId || agents.length === 0) return;
    setAddDraft((current) => ({
      ...current,
      assignedAgentId: defaultAgentId(actionClassById.get(current.actionClass), agents),
    }));
  }, [actionClassById, addDraft.actionClass, addDraft.assignedAgentId, agents]);

  useLayoutEffect(() => {
    if (!editRequest) return;
    headingRef.current?.focus();
  }, [editOperationIndex, editRequest?.id, editRequest?.version]);

  function chooseStep(stepId: string) {
    const step = steps.find((candidate) => candidate.id === stepId);
    if (!step) return;
    setSelectedStepId(step.id);
    setStepDraft(makeStepDraft(step));
    setDependencyIds(canonicalDependencies(step.dependencyStepIds, steps));
    setRemovalReason("");
    setActionDraft(makeRepresentationDraft(step));
    setError(undefined);
    setConfirmation(undefined);
  }

  async function persistProposal(operation: PlanChangeOperation): Promise<boolean> {
    if (changeReason.trim().length < 3) {
      setError(new Error("Explain why this structured plan amendment is needed using at least three characters."));
      return false;
    }
    setSubmitting(true);
    setError(undefined);
    setConfirmation(undefined);
    try {
      const result = editRequest
        ? await planChangesApi.edit(run.id, editRequest.id, {
          expectedRequestVersion: editRequest.version,
          expectedRunVersion: run.version,
          expectedPlanVersion: plan.version,
          requestText: changeReason.trim(),
          operations: editRequest.normalizedChange.operations.map((candidate, index) => index === editOperationIndex ? operation : candidate),
        })
        : await planChangesApi.create(run.id, {
          basePlanId: plan.id,
          expectedRunVersion: run.version,
          expectedPlanVersion: plan.version,
          requestText: changeReason.trim(),
          operations: [operation],
        });
      setConfirmation(editRequest
        ? `Proposal ${result.request.id} was saved as version ${result.request.version} with status ${result.request.status}. The active plan and execution state were not changed.`
        : `Proposal ${result.request.id} was created with status ${result.request.status}. The active plan and execution state were not changed.`);
      if (!editRequest) setChangeReason("");
      try {
        await onProposalCreated?.();
      } catch (refreshError) {
        setError(new Error(
          `Proposal ${result.request.id} was committed, but the canonical proposal list could not be refreshed. Refresh it before taking another action.`,
          { cause: refreshError },
        ));
      }
      if (editRequest) onEditCompleted?.(result.request);
      return true;
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("The structured plan proposal could not be created."));
      return false;
    } finally {
      setSubmitting(false);
    }
  }

  async function submitAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!registryIsLive || !addActionClass) {
      setError(new Error("The add-step proposal needs a live registered action class. Retry the registry connection before submitting."));
      return;
    }
    if (!agents.some((agent) => agent.id === addDraft.assignedAgentId)) {
      setError(new Error("Choose a specialist from the current canonical agent fleet before adding this step."));
      return;
    }
    try {
      const created = await persistProposal({
        kind: "add_step",
        clientStepId: addDraft.clientStepId.trim(),
        afterStepId: addDraft.afterStepId || null,
        phase: addDraft.phase.trim(),
        title: addDraft.title.trim(),
        objective: addDraft.objective.trim(),
        successCriteria: lines(addDraft.successCriteriaText),
        dependencyStepIds: canonicalDependencies(addDraft.dependencyStepIds, steps),
        actionClass: addActionClass.id,
        riskClass: riskClass(addActionClass),
        assignedAgentId: addDraft.assignedAgentId,
        representation: representation(addDraft, addActionClass.destructiveOrDisruptive),
      });
      if (created && !editRequest) setAddDraft((current) => ({ ...initialAddStep(steps), actionClass: current.actionClass, assignedAgentId: current.assignedAgentId }));
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("The exact add-step values are invalid."));
    }
  }

  async function submitUpdate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedStep) return;
    const operation: Extract<PlanChangeOperation, { readonly kind: "update_step" }> = { kind: "update_step", stepId: selectedStep.id };
    const mutable: {
      phase?: string; title?: string; objective?: string; successCriteria?: readonly string[];
      actionClass?: string; riskClass?: string; assignedAgentId?: string;
    } = {};
    const criteria = lines(stepDraft.successCriteriaText);
    if (stepDraft.phase.trim() !== selectedStep.phase) mutable.phase = stepDraft.phase.trim();
    if (stepDraft.title.trim() !== selectedStep.title) mutable.title = stepDraft.title.trim();
    if (stepDraft.objective.trim() !== selectedStep.objective) mutable.objective = stepDraft.objective.trim();
    if (!sameValues(criteria, selectedStep.successCriteria)) mutable.successCriteria = criteria;
    if (stepDraft.actionClass !== selectedStep.action.actionClass) {
      if (!registryIsLive || !updateActionClass) {
        setError(new Error("Choose the replacement action class from the live runtime registry."));
        return;
      }
      mutable.actionClass = updateActionClass.id;
      mutable.riskClass = riskClass(updateActionClass);
    }
    if (stepDraft.assignedAgentId !== selectedStep.assignedAgentId) {
      if (!agents.some((agent) => agent.id === stepDraft.assignedAgentId)) {
        setError(new Error("Choose the replacement specialist from the current canonical agent fleet."));
        return;
      }
      mutable.assignedAgentId = stepDraft.assignedAgentId;
    }
    if (Object.keys(mutable).length === 0) {
      setError(new Error("Change at least one step field, action class, or specialist before creating a proposal."));
      return;
    }
    await persistProposal({ ...operation, ...mutable });
  }

  async function submitDependencies(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedStep) return;
    const normalizedDependencies = canonicalDependencies(dependencyIds, steps);
    if (sameValues(normalizedDependencies, canonicalDependencies(selectedStep.dependencyStepIds, steps))) {
      setError(new Error("Choose a different dependency set before creating a proposal."));
      return;
    }
    await persistProposal({ kind: "set_dependencies", stepId: selectedStep.id, dependencyStepIds: normalizedDependencies });
  }

  async function submitReorder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const issues = orderIssues(orderedStepIds, steps);
    if (issues.length > 0) {
      setError(new Error(`The proposed order violates the dependency graph: ${issues.join(" ")}`));
      return;
    }
    if (sameValues(orderedStepIds, steps.map((step) => step.id))) {
      setError(new Error("Move at least one step before creating a reorder proposal."));
      return;
    }
    await persistProposal({ kind: "reorder_steps", orderedStepIds });
  }

  async function submitRemove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedStep) return;
    await persistProposal({ kind: "remove_step", stepId: selectedStep.id, reason: removalReason.trim() });
  }

  async function submitRepresentedAction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedStep || !registryIsLive || !representedActionClass) {
      setError(new Error("The exact-action proposal needs the selected step's action class from the live runtime registry."));
      return;
    }
    try {
      await persistProposal({
        kind: "set_represented_action",
        stepId: selectedStep.id,
        representation: representation(actionDraft, representedActionClass.destructiveOrDisruptive),
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("The represented action values are invalid."));
    }
  }

  const currentOrder = steps.map((step) => step.id);
  const reorderIssues = orderIssues(orderedStepIds, steps);
  const updateChanged = selectedStep ? (
    stepDraft.phase.trim() !== selectedStep.phase ||
    stepDraft.title.trim() !== selectedStep.title ||
    stepDraft.objective.trim() !== selectedStep.objective ||
    !sameValues(lines(stepDraft.successCriteriaText), selectedStep.successCriteria) ||
    stepDraft.actionClass !== selectedStep.action.actionClass ||
    stepDraft.assignedAgentId !== selectedStep.assignedAgentId
  ) : false;
  const actionChanged = selectedStep ? (
    actionDraft.actionType.trim() !== selectedStep.action.actionType ||
    actionDraft.target.trim() !== selectedStep.action.target ||
    actionDraft.argumentsJson !== (JSON.stringify(selectedStep.action.arguments, null, 2) ?? "{}") ||
    actionDraft.intentSummary.trim() !== selectedStep.action.intentSummary ||
    actionDraft.kind !== selectedStep.action.kind ||
    actionDraft.idempotent !== selectedStep.action.idempotent ||
    representedActionClass?.destructiveOrDisruptive !== selectedStep.action.destructive ||
    actionDraft.explanation.trim() !== selectedStep.explanation ||
    actionDraft.rationale.trim() !== selectedStep.rationale ||
    actionDraft.reversibility.trim() !== selectedStep.reversibility
  ) : false;

  const initialEditStepDraft = draftForUpdateOperation(initialSelectedStep, editOperation);
  const initialEditAddDraft = draftForAddOperation(steps, editOperation);
  const initialEditActionDraft = draftForRepresentationOperation(initialSelectedStep, editOperation);
  const editDirty = !editRequest || (
    changeReason.trim() !== (editRequest.requestText ?? "").trim() ||
    selectedStepId !== initialSelectedStepId ||
    (mode === "add" && JSON.stringify(addDraft) !== JSON.stringify(initialEditAddDraft)) ||
    (mode === "update" && JSON.stringify(stepDraft) !== JSON.stringify(initialEditStepDraft)) ||
    (mode === "dependencies" && !sameValues(canonicalDependencies(dependencyIds, steps), canonicalDependencies(editOperation?.kind === "set_dependencies" ? editOperation.dependencyStepIds : initialSelectedStep?.dependencyStepIds ?? [], steps))) ||
    (mode === "reorder" && !sameValues(orderedStepIds, editOperation?.kind === "reorder_steps" ? editOperation.orderedStepIds : currentOrder)) ||
    (mode === "remove" && removalReason !== (editOperation?.kind === "remove_step" ? editOperation.reason : "")) ||
    (mode === "represented_action" && JSON.stringify(actionDraft) !== JSON.stringify(initialEditActionDraft))
  );
  const submitControlId = (creationControlId: string) => editRequest ? "plan-change-direct-edit-submit" : creationControlId;
  const submitLabel = (creationLabel: string) => editRequest ? `Save and revalidate proposal ${editRequest.id}` : creationLabel;

  return <Card className="os-direct-plan-editor" aria-labelledby="direct-plan-editor-heading">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">{editRequest ? `Proposal ${editRequest.id} · version ${editRequest.version}` : "Direct structured amendment"}</p><h3 id="direct-plan-editor-heading" ref={headingRef} tabIndex={editRequest ? -1 : undefined}>{editRequest ? "Revise this structured proposal without applying it" : "Edit the plan graph without executing it"}</h3></div>
      <StatusPill status={editRequest ? "revalidation_draft" : "proposal_only"} />
    </div>
    <p>{editRequest
      ? "The canonical operation and audit reason are prefilled from this open request. Saving creates a new request version and reruns diff, dependency, policy, readiness, budget, and in-flight validation; it never applies the proposal or executes work."
      : <>Choose one exact graph change. Ti-Scale creates a versioned <span className="os-mono">PlanChangeRequest</span> with optimistic run and plan versions; the active plan changes only after a separate valid review and apply action.</>}</p>

    {editRequest && <div className="os-plan-change-actions">
      <p><strong>Operation under revision:</strong> {MODES.find((option) => option.id === mode)?.label ?? mode}. The operation kind remains fixed so a revision cannot silently become a different amendment.</p>
      <Button type="button" variant="quiet" data-control-id="plan-change-direct-edit-cancel" aria-label={`Cancel structured edit for ${editRequest.id}`} disabled={submitting || !onEditCancelled} onClick={onEditCancelled}>Cancel structured edit</Button>
    </div>}

    <div className="os-field-grid">
      {!editRequest && <label htmlFor="plan-direct-editor-mode">Structured operation
        <TitaniumSelect id="plan-direct-editor-mode" data-control-id="plan-direct-editor-mode" value={mode} onChange={(event) => { setMode(event.target.value as EditorMode); setError(undefined); setConfirmation(undefined); }}>
          {MODES.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}
        </TitaniumSelect>
        <span>Each submission proposes one bounded operation so its exact diff and impact remain reviewable.</span>
      </label>}
      <label htmlFor="plan-direct-change-reason">Reason for this structured amendment <small>Required</small>
        <textarea id="plan-direct-change-reason" data-control-id="plan-direct-change-reason" value={changeReason} minLength={3} maxLength={4000} required onChange={(event) => setChangeReason(event.target.value)} placeholder="Example: Verified HTTPS evidence invalidated the prior dependency, so change this one part of the plan before any further work." />
        <span>State the new fact or operator intent. This explanation is retained in the immutable proposal audit.</span>
      </label>
    </div>

    {mode !== "add" && mode !== "reorder" && <label htmlFor="plan-direct-step">Plan step
      <TitaniumSelect id="plan-direct-step" data-control-id="plan-direct-step" value={selectedStep?.id ?? ""} disabled={steps.length === 0} onChange={(event) => chooseStep(event.target.value)}>
        {steps.map((step) => <option key={step.id} value={step.id}>{step.ordinal}. {step.title} · {step.phase}</option>)}
      </TitaniumSelect>
      <span>Stable step IDs and current values come from plan {plan.id}, version {plan.version}.</span>
    </label>}

    {(registry.isLoading || fleet.isLoading) && <LoadingPanel label="Loading live action classes and canonical agents" />}
    {registry.error && <ErrorPanel title="Live action classes are unavailable" error={registry.error} onRetry={registry.refresh} />}
    {fleet.error && <ErrorPanel title="The canonical agent fleet is unavailable" error={fleet.error} onRetry={fleet.refresh} />}
    {registry.data && <div className="os-registry-source" role="status"><StatusPill status={registry.data.source.status} /><span><strong>{registry.data.source.status === "live" ? "Live ActionClassRegistry" : "Action classes are degraded"}</strong><small>{registry.data.source.explanation}</small></span></div>}

    {mode === "add" && <form data-control-id="plan-direct-add-form" onSubmit={submitAdd}>
      <fieldset><legend>Add one fully represented step</legend>
        <p className="os-field-intro">All fields are review data. The new step remains a proposal until the server validates policy, graph order, exact target, specialist readiness, and in-flight safety.</p>
        <div className="os-field-grid">
          <label htmlFor="plan-direct-add-id">Draft step ID <small>Required</small>
            <input id="plan-direct-add-id" data-control-id="plan-direct-add-id" required pattern={"draft-[a-z0-9][a-z0-9._\\-]{0,79}"} value={addDraft.clientStepId} onChange={(event) => setAddDraft((current) => ({ ...current, clientStepId: event.target.value }))} placeholder="draft-cve-applicability" />
            <span>Use the <span className="os-mono">draft-</span> namespace. A stable canonical step ID is created only if the proposal is applied.</span>
          </label>
          <label htmlFor="plan-direct-add-after">Place after
            <TitaniumSelect id="plan-direct-add-after" data-control-id="plan-direct-add-after" value={addDraft.afterStepId} onChange={(event) => {
              const nextAfterStep = steps.find((step) => step.id === event.target.value);
              const validDependencies = new Set(nextAfterStep ? steps.filter((step) => step.ordinal <= nextAfterStep.ordinal).map((step) => step.id) : steps.map((step) => step.id));
              setAddDraft((current) => ({ ...current, afterStepId: event.target.value, dependencyStepIds: canonicalDependencies(current.dependencyStepIds.filter((id) => validDependencies.has(id)), steps) }));
            }}>
              <option value="">End of plan</option>
              {steps.map((step) => <option key={step.id} value={step.id}>{step.ordinal}. {step.title}</option>)}
            </TitaniumSelect>
            <span>The server recomputes the final ordinal and dependency validity.</span>
          </label>
        </div>
        <div className="os-field-grid">
          <label htmlFor="plan-direct-add-phase">Phase <small>Required</small><input id="plan-direct-add-phase" data-control-id="plan-direct-add-phase" required minLength={2} maxLength={200} value={addDraft.phase} onChange={(event) => setAddDraft((current) => ({ ...current, phase: event.target.value }))} placeholder="Example: Vulnerability analysis" /></label>
          <label htmlFor="plan-direct-add-title">Step title <small>Required</small><input id="plan-direct-add-title" data-control-id="plan-direct-add-title" required minLength={3} maxLength={500} value={addDraft.title} onChange={(event) => setAddDraft((current) => ({ ...current, title: event.target.value }))} placeholder="Example: Classify version-aware CVE candidates" /></label>
        </div>
        <label htmlFor="plan-direct-add-objective">Bounded objective <small>Required</small><textarea id="plan-direct-add-objective" data-control-id="plan-direct-add-objective" required minLength={3} maxLength={4000} value={addDraft.objective} onChange={(event) => setAddDraft((current) => ({ ...current, objective: event.target.value }))} placeholder="Example: Compare verified product versions with authoritative advisories and record explicit applicability states." /></label>
        <label htmlFor="plan-direct-add-criteria">Success criteria <small>Required · one per line</small><textarea id="plan-direct-add-criteria" data-control-id="plan-direct-add-criteria" required value={addDraft.successCriteriaText} onChange={(event) => setAddDraft((current) => ({ ...current, successCriteriaText: event.target.value }))} placeholder="Every candidate has an explicit applicability state&#10;Every conclusion links version evidence and an authoritative source" /></label>
        <ActionClassSelect id="plan-direct-add-action-class" controlId="plan-direct-add-action-class" value={addDraft.actionClass} classes={actionClasses} disabled={!registryIsLive} onChange={(value) => {
          const nextClass = actionClassById.get(value);
          setAddDraft((current) => ({ ...current, actionClass: value, assignedAgentId: defaultAgentId(nextClass, agents) }));
        }} />
        <ActionClassEvidence actionClass={addActionClass} />
        <AgentSelect id="plan-direct-add-agent" controlId="plan-direct-add-agent" value={addDraft.assignedAgentId} agents={agents} actionClass={addActionClass} disabled={fleet.isLoading || Boolean(fleet.error)} onChange={(value) => setAddDraft((current) => ({ ...current, assignedAgentId: value }))} />
        <fieldset className="os-registry-checklist"><legend>Dependencies <span>Optional · existing earlier steps only</span></legend>
          {addDependencyCandidates.map((step, index) => <label className="os-check-field" htmlFor={`plan-direct-add-dependency-${index}`} key={step.id}>
            <input id={`plan-direct-add-dependency-${index}`} data-control-id={`plan-direct-add-dependency-${step.id}`} type="checkbox" checked={addDraft.dependencyStepIds.includes(step.id)} onChange={(event) => setAddDraft((current) => ({ ...current, dependencyStepIds: canonicalDependencies(event.target.checked ? [...current.dependencyStepIds, step.id] : current.dependencyStepIds.filter((id) => id !== step.id), steps) }))} />
            <span><strong>{step.title}</strong><small>{step.id} · current ordinal {step.ordinal}</small></span>
          </label>)}
        </fieldset>
        <RepresentationFields prefix="plan-direct-add-action" draft={addDraft} destructive={addActionClass?.destructiveOrDisruptive ?? false} disabled={!registryIsLive || !addActionClass} onChange={(next) => setAddDraft((current) => ({ ...current, ...next }))} />
        <Button data-control-id={submitControlId("plan-direct-add-submit")} type="submit" disabled={submitting || !editDirty || changeReason.trim().length < 3 || !registryIsLive || !addActionClass || !addDraft.assignedAgentId || lines(addDraft.successCriteriaText).length === 0}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose exact new step")}</Button>
      </fieldset>
    </form>}

    {mode === "update" && selectedStep && <form data-control-id="plan-direct-update-form" onSubmit={submitUpdate}>
      <fieldset><legend>Edit step metadata, ownership, or action class</legend>
        <p className="os-field-intro">Only changed fields enter the operation. Changing an action class preserves the current exact represented action; use the separate exact-action operation when its method, target, or arguments must also change.</p>
        <div className="os-field-grid">
          <label htmlFor="plan-direct-update-phase">Phase <small>Required</small><input id="plan-direct-update-phase" data-control-id="plan-direct-update-phase" required minLength={2} maxLength={200} value={stepDraft.phase} onChange={(event) => setStepDraft((current) => ({ ...current, phase: event.target.value }))} /></label>
          <label htmlFor="plan-direct-update-title">Step title <small>Required</small><input id="plan-direct-update-title" data-control-id="plan-direct-update-title" required minLength={3} maxLength={500} value={stepDraft.title} onChange={(event) => setStepDraft((current) => ({ ...current, title: event.target.value }))} /></label>
        </div>
        <label htmlFor="plan-direct-update-objective">Bounded objective <small>Required</small><textarea id="plan-direct-update-objective" data-control-id="plan-direct-update-objective" required minLength={3} maxLength={4000} value={stepDraft.objective} onChange={(event) => setStepDraft((current) => ({ ...current, objective: event.target.value }))} /></label>
        <label htmlFor="plan-direct-update-criteria">Success criteria <small>Required · one per line</small><textarea id="plan-direct-update-criteria" data-control-id="plan-direct-update-criteria" required value={stepDraft.successCriteriaText} onChange={(event) => setStepDraft((current) => ({ ...current, successCriteriaText: event.target.value }))} /></label>
        <ActionClassSelect id="plan-direct-update-action-class" controlId="plan-direct-update-action-class" value={stepDraft.actionClass} currentValue={selectedStep.action.actionClass} classes={actionClasses} disabled={!registryIsLive} onChange={(value) => setStepDraft((current) => ({ ...current, actionClass: value, assignedAgentId: defaultAgentId(actionClassById.get(value), agents) || current.assignedAgentId }))} />
        <ActionClassEvidence actionClass={updateActionClass} />
        <AgentSelect id="plan-direct-update-agent" controlId="plan-direct-update-agent" value={stepDraft.assignedAgentId} currentValue={selectedStep.assignedAgentId} agents={agents} actionClass={updateActionClass} disabled={fleet.isLoading || Boolean(fleet.error)} onChange={(value) => setStepDraft((current) => ({ ...current, assignedAgentId: value }))} />
        <Button data-control-id={submitControlId("plan-direct-update-submit")} type="submit" disabled={submitting || !editDirty || changeReason.trim().length < 3 || !updateChanged || lines(stepDraft.successCriteriaText).length === 0}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose step changes")}</Button>
      </fieldset>
    </form>}

    {mode === "dependencies" && selectedStep && <form data-control-id="plan-direct-dependencies-form" onSubmit={submitDependencies}>
      <fieldset className="os-registry-checklist"><legend>Set prerequisites for {selectedStep.title}</legend>
        <p>Only earlier steps can be selected. The service repeats dependency and cycle validation before the proposal can be applied.</p>
        {steps.filter((step) => step.ordinal < selectedStep.ordinal).map((step, index) => <label className="os-check-field" htmlFor={`plan-direct-dependency-${index}`} key={step.id}>
          <input id={`plan-direct-dependency-${index}`} data-control-id={`plan-direct-dependency-${step.id}`} type="checkbox" checked={dependencyIds.includes(step.id)} onChange={(event) => setDependencyIds((current) => canonicalDependencies(event.target.checked ? [...current, step.id] : current.filter((id) => id !== step.id), steps))} />
          <span><strong>{step.title}</strong><small>{step.id} · ordinal {step.ordinal}</small></span>
        </label>)}
        {steps.filter((step) => step.ordinal < selectedStep.ordinal).length === 0 && <p>This is the first step, so its only valid dependency set is empty.</p>}
        <Button data-control-id={submitControlId("plan-direct-dependencies-submit")} type="submit" disabled={submitting || !editDirty || changeReason.trim().length < 3 || sameValues(canonicalDependencies(dependencyIds, steps), canonicalDependencies(selectedStep.dependencyStepIds, steps))}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose dependency change")}</Button>
      </fieldset>
    </form>}

    {mode === "reorder" && <form data-control-id="plan-direct-reorder-form" onSubmit={submitReorder}>
      <fieldset><legend>Reorder the complete step graph</legend><p className="os-field-intro">Move controls prevent an order that places a step before one of its current prerequisites. The complete stable-ID order is still revalidated by the service.</p>
        <ol className="os-compact-list">
          {orderedStepIds.map((stepId, index) => {
            const step = steps.find((candidate) => candidate.id === stepId);
            if (!step) return null;
            const up = reordered(orderedStepIds, stepId, -1);
            const down = reordered(orderedStepIds, stepId, 1);
            return <li key={step.id}><span><strong>{index + 1}. {step.title}</strong><small>{step.id} · dependencies {step.dependencyStepIds.length ? step.dependencyStepIds.join(", ") : "none"}</small></span><span className="os-plan-reorder-actions">
              <Button type="button" variant="quiet" data-control-id={`plan-direct-reorder-up-${step.id}`} aria-label={`Move ${step.title} earlier`} disabled={submitting || index === 0 || orderIssues(up, steps).length > 0} onClick={() => setOrderedStepIds(up)}>Move earlier</Button>
              <Button type="button" variant="quiet" data-control-id={`plan-direct-reorder-down-${step.id}`} aria-label={`Move ${step.title} later`} disabled={submitting || index === orderedStepIds.length - 1 || orderIssues(down, steps).length > 0} onClick={() => setOrderedStepIds(down)}>Move later</Button>
            </span></li>;
          })}
        </ol>
        {reorderIssues.length > 0 && <div className="os-plan-change-blockers" role="alert"><strong>The current draft order is invalid</strong><ul>{reorderIssues.map((issue) => <li key={issue}>{issue}</li>)}</ul></div>}
        <Button data-control-id="plan-direct-reorder-reset" type="button" variant="quiet" disabled={submitting || sameValues(orderedStepIds, currentOrder)} onClick={() => setOrderedStepIds(currentOrder)}>Reset current order</Button>
        <Button data-control-id={submitControlId("plan-direct-reorder-submit")} type="submit" disabled={submitting || !editDirty || changeReason.trim().length < 3 || reorderIssues.length > 0 || sameValues(orderedStepIds, currentOrder)}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose complete step order")}</Button>
      </fieldset>
    </form>}

    {mode === "remove" && selectedStep && <form data-control-id="plan-direct-remove-form" onSubmit={submitRemove}>
      <fieldset><legend>Remove {selectedStep.title}</legend>
        <p className="os-policy-note">This creates a review proposal only. The service blocks an empty plan and reports dependencies that would become unresolved; it does not cancel or skip live work.</p>
        <label htmlFor="plan-direct-remove-reason">Why should this step leave the plan? <small>Required</small><textarea id="plan-direct-remove-reason" data-control-id="plan-direct-remove-reason" required minLength={3} maxLength={1000} value={removalReason} onChange={(event) => setRemovalReason(event.target.value)} placeholder="Example: Two attributable observations disproved this hypothesis, so retaining the step would repeat work without reducing uncertainty." /></label>
        <Button data-control-id={submitControlId("plan-direct-remove-submit")} type="submit" variant="danger" disabled={submitting || !editDirty || changeReason.trim().length < 3 || removalReason.trim().length < 3 || steps.length <= 1}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose step removal")}</Button>
        {steps.length <= 1 && <p role="status">The only remaining step cannot be removed because a plan must retain at least one bounded step.</p>}
      </fieldset>
    </form>}

    {mode === "represented_action" && selectedStep && <form data-control-id="plan-direct-action-form" onSubmit={submitRepresentedAction}>
      <ActionClassEvidence actionClass={representedActionClass} />
      <RepresentationFields prefix="plan-direct-existing-action" draft={actionDraft} destructive={representedActionClass?.destructiveOrDisruptive ?? false} disabled={!registryIsLive || !representedActionClass} onChange={setActionDraft} />
      <Button data-control-id={submitControlId("plan-direct-action-submit")} type="submit" disabled={submitting || !editDirty || changeReason.trim().length < 3 || !registryIsLive || !representedActionClass || !actionChanged}>{submitting ? (editRequest ? "Saving and revalidating…" : "Creating proposal…") : submitLabel("Propose exact represented action")}</Button>
    </form>}

    {confirmation && <div className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Review proposal created.</strong> {confirmation}</div>}
    {error && <ErrorPanel title="Structured plan proposal was not created" error={error} />}
  </Card>;
}
