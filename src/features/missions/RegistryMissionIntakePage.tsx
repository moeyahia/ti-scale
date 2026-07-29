import { memo, type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import {
  createMission,
  fetchMissionIntakeRegistry,
  preflightAutonomousMission,
  resolveMissionIntake,
} from "../../data/api/commandOs";
import { fetchRuntimeReadiness } from "../../data/api/runtimeReadiness";
import { fetchModelCatalog } from "../../data/api/modelConfiguration";
import { ApiError } from "../../data/api/client";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import {
  Button,
  ButtonLink,
  Card,
  ErrorPanel,
  LoadingPanel,
  PageHeader,
  StatusPill,
} from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type {
  AutonomousContextCandidate,
  AutonomousAgentModelAssignment,
  AutonomousMissionRequest,
  AutonomousMissionPreflight,
  AutonomousPlanningSelection,
  GuidedMissionRequest,
  GuidedReconnaissanceSelection,
  GuidedTcpPortPresetId,
  Journey,
  MissionEnvironmentClassification,
} from "../../domain/types/commandOs";
import { AUTONOMOUS_LOCAL_PLANNING_SELECTION } from "../../domain/types/commandOs";
import type {
  ActionPolicyState,
  BudgetPresetId,
  DestructiveActionPolicy,
  IntakeFieldDefinition,
  IntakeEvidenceType,
  IntakeRegistrySnapshot,
  MissionIntakeRequest,
  MissionTemplateId,
  ResolvedMissionIntake,
} from "../../domain/types/intake";
import { isAutonomousResolved } from "../../domain/types/intake";
import type { RuntimeReadinessSnapshot } from "../../domain/types/runtimeReadiness";
import { lines, requestKey, safeNextUrl } from "./formUtils";
import { AutonomousReadinessReview } from "./AutonomousReadinessReview";
import {
  MissionAgentModelAssignmentReview,
  MissionAgentModelAssignments,
} from "./MissionAgentModelAssignments";
import { filterAgentModelAssignments } from "./missionModelAssignmentState";
import { actionCapabilityPresentation } from "./actionCapabilityPresentation";
import {
  AutonomousPlanningSelectionEditor,
  AutonomousPlanningSelectionReview,
} from "./AutonomousPlanningSelection";
import { samePlanningSelection } from "./autonomousPlanningSelectionState";
import {
  buildResolvedContractChecklist,
  checklistSourceLabel,
  type ChecklistValueSource,
  type ResolvedChecklistItem,
} from "./missionIntakeChecklist";
import {
  runtimeReadinessChanged,
  runtimeReadinessVersion,
  type RuntimeReadinessVersion,
} from "./runtimeReadinessVersion";

const AUTONOMOUS_STEPS = ["Scope", "Outcome", "Contract", "Team", "Context", "Review"] as const;
const GUIDED_STEPS = ["Scope", "Outcome", "Contract", "Review"] as const;

const INFERRED_FIELD_LABELS: Readonly<Record<string, string>> = Object.freeze({
  title: "Mission title",
  objective: "Authorized objective",
  successCriteria: "Success criteria",
  deliverables: "Final deliverables",
  evidenceRequirements: "Evidence requirements",
  optionalSafeStops: "Mission-specific safe stops",
  budget: "Operational budget",
  specialistAgentIds: "Specialist team",
  agentModelAssignments: "Exact specialist model assignments",
  planningSelection: "Plan-construction route",
  memoryScopes: "Second Brain memory scopes",
});

function inferredFieldLabels(fields: readonly string[]): string {
  return fields.map((field) => {
    const known = INFERRED_FIELD_LABELS[field];
    if (known) return known;
    const readable = field
      .replace(/([a-z0-9])([A-Z])/gu, "$1 $2")
      .replace(/[_-]+/gu, " ")
      .trim()
      .toLocaleLowerCase("en-US");
    return readable ? `${readable[0]!.toLocaleUpperCase("en-US")}${readable.slice(1)}` : "Recommended setting";
  }).join(", ");
}

interface IntakeFormState {
  readonly templateId: MissionTemplateId;
  readonly targets: string;
  readonly excludedTargets: string;
  readonly authorizationAcknowledged: boolean;
  readonly title: string;
  readonly objective: string;
  readonly engagementId: string;
  readonly environmentClassification: MissionEnvironmentClassification;
  readonly successCriteria?: readonly string[];
  readonly customSuccessCriteria: string;
  readonly deliverableIds?: readonly string[];
  readonly evidenceTypeIds?: readonly string[];
  readonly optionalSafeStopIds?: readonly string[];
  readonly budgetPresetId?: BudgetPresetId;
  readonly destructivePolicy: DestructiveActionPolicy;
  readonly boundedDestructiveTargetIds: readonly string[];
  readonly actionPolicyOverrides: Readonly<Record<string, ActionPolicyState>>;
  readonly specialistAgentIds?: readonly string[];
  readonly agentModelAssignments?: readonly AutonomousAgentModelAssignment[];
  readonly planningSelection: AutonomousPlanningSelection;
  readonly memoryScopes?: readonly string[];
  readonly contextNodeIds?: readonly string[];
  readonly explanationDepth: "concise" | "balanced" | "deep";
  readonly executionPreference: "manual" | "single_step_agent";
  readonly guidedReconChoice: "recommended" | "host_liveness" | "tcp_service_scan";
  readonly guidedTcpPortPresetId: GuidedTcpPortPresetId | "custom";
  readonly guidedCustomTcpPorts: string;
  readonly guidedWindowsIdentityOperation?: NonNullable<
    GuidedMissionRequest["guidedWindowsIdentity"]
  >["operation"];
  readonly guidedWindowsIdentityAuthenticationMode: NonNullable<
    GuidedMissionRequest["guidedWindowsIdentity"]
  >["authenticationMode"];
  readonly guidedWindowsIdentityCredentialReference: string;
  readonly guidedLocalExploitQueryKind?: NonNullable<
    GuidedMissionRequest["guidedLocalExploitIntelligence"]
  >["query"]["kind"];
  readonly guidedLocalExploitCveId: string;
  readonly guidedLocalExploitProduct: string;
  readonly guidedLocalExploitVersion: string;
  readonly guidedLocalExploitPlatform: string;
  readonly guidedLocalExploitMaximumResults: string;
}

const INITIAL_FORM: IntakeFormState = {
  templateId: "safe_recon",
  targets: "",
  excludedTargets: "",
  authorizationAcknowledged: false,
  title: "",
  objective: "",
  engagementId: "",
  environmentClassification: "client_or_public",
  customSuccessCriteria: "",
  destructivePolicy: "prohibited",
  boundedDestructiveTargetIds: [],
  actionPolicyOverrides: {},
  planningSelection: AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  explanationDepth: "balanced",
  executionPreference: "manual",
  guidedReconChoice: "recommended",
  guidedTcpPortPresetId: "focused_services",
  guidedCustomTcpPorts: "22, 80, 443",
  guidedWindowsIdentityAuthenticationMode: "anonymous",
  guidedWindowsIdentityCredentialReference: "",
  guidedLocalExploitCveId: "",
  guidedLocalExploitProduct: "",
  guidedLocalExploitVersion: "",
  guidedLocalExploitPlatform: "",
  guidedLocalExploitMaximumResults: "20",
};

function looksLikeSingleHost(value: string): boolean {
  const target = value.trim();
  if (!target || /^(?:https?:|[a-z]+:)/iu.test(target) || target.includes("/")) return false;
  if (/^[0-9A-Fa-f:]+$/u.test(target) && target.includes(":")) return true;
  return target.length <= 253 && target.split(".").every((part) =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part));
}

function parseCustomTcpPorts(value: string, maximum: number): { readonly ports?: number[]; readonly issue?: string } {
  const normalized = value.trim();
  if (!normalized) return { issue: "Enter at least one TCP port, for example 22, 80, 443." };
  if (!/^\d+(?:\s*,\s*\d+)*$/u.test(normalized)) {
    return { issue: "Use comma-separated individual port numbers only, such as 22, 80, 443. Remove ranges, service names, spaces without commas, and command options." };
  }
  const values = normalized.split(",").map((item) => Number(item.trim()));
  const invalid = values.find((port) => !Number.isSafeInteger(port) || port < 1 || port > 65_535);
  if (invalid !== undefined) return { issue: `${invalid} is not a valid TCP port. Use whole numbers from 1 through 65535.` };
  const ports = [...new Set(values)].sort((left, right) => left - right);
  if (ports.length > maximum) return { issue: `Choose no more than ${maximum} individual TCP ports. Use a reviewed preset or remove ports from the custom list.` };
  return { ports };
}

const GUIDED_LOCAL_EXPLOIT_CVE_ID = /^CVE-[12][0-9]{3}-[0-9]{4,10}$/u;
const GUIDED_LOCAL_EXPLOIT_TECHNOLOGY_TEXT =
  /^[\p{L}\p{N}][\p{L}\p{N} ._+/:()#-]*$/u;

function guidedLocalExploitTextIssue(
  value: string,
  label: string,
  minimum: number,
  maximum: number,
  optional = false,
): string | undefined {
  if (optional && value.length === 0) return undefined;
  if (
    value !== value.trim()
    || value.length < minimum
    || value.length > maximum
    || !GUIDED_LOCAL_EXPLOIT_TECHNOLOGY_TEXT.test(value)
  ) {
    return `${label} must use ${minimum} through ${maximum} readable technology characters. Remove command options, shell syntax, secrets, and leading or trailing spaces.`;
  }
  return undefined;
}

function listToggle(current: readonly string[], value: string, checked: boolean): string[] {
  return checked ? [...new Set([...current, value])] : current.filter((item) => item !== value);
}

function field(registry: IntakeRegistrySnapshot | undefined, id: string): IntakeFieldDefinition | undefined {
  return registry?.fields.find((candidate) => candidate.id === id);
}

function FieldHelp({ definition }: { readonly definition?: IntakeFieldDefinition }) {
  if (!definition) return null;
  return <details className="os-field-help"><summary>Why is this needed?</summary><p>{definition.purpose}</p><p><strong>Example:</strong> {definition.example}</p></details>;
}

function bytes(value: number): string {
  return new Intl.NumberFormat(undefined, { style: "unit", unit: "megabyte", maximumFractionDigits: 0 }).format(value / 1024 ** 2);
}

function selectedOrDefault(explicit: readonly string[] | undefined, defaults: readonly string[]): readonly string[] {
  return explicit ?? defaults;
}

function evidenceAvailabilityExplanation(
  item: IntakeEvidenceType,
  journey: Journey,
): string {
  if (item.capability.availability === "supported") {
    return "Supported now by the connected runtime and eligible for recommended defaults.";
  }
  if (journey === "guided") {
    return item.capability.availability === "unavailable"
      ? "A producer is registered but is not ready now. Guided keeps the proof requirement visible and selected so the operator can capture or upload the result."
      : "No connected runtime producer declares this type. Guided keeps the proof requirement selected so a manual result can still be captured and attributed.";
  }
  if (item.capability.availability === "unavailable") {
    return "A producer is registered but is not ready now. Recommended defaults leave this unchecked until readiness returns.";
  }
  return "No connected runtime evidence kind or producer declares this type. It remains visible for review but is not selected by recommended defaults.";
}

function ReviewChecklistItems({
  items,
  emptyLabel,
}: {
  readonly items: readonly ResolvedChecklistItem[];
  readonly emptyLabel: string;
}) {
  if (items.length === 0) return <p className="os-contract-review-empty">{emptyLabel}</p>;
  return <ul>{items.map((item) => <li key={item.id}>{item.label}</li>)}</ul>;
}

function ChecklistSource({ source }: { readonly source: ChecklistValueSource }) {
  return <span className={`os-checklist-source os-checklist-source--${source}`}>{checklistSourceLabel(source)}</span>;
}

function LiveAutonomousReadinessReview({
  preflight,
  runtime,
  runtimePending,
  preflightRefreshing,
  preflightRefreshFailed,
}: {
  readonly preflight: AutonomousMissionPreflight;
  readonly runtime?: RuntimeReadinessSnapshot;
  readonly runtimePending: boolean;
  readonly preflightRefreshing: boolean;
  readonly preflightRefreshFailed: boolean;
}) {
  return <AutonomousReadinessReview
    preflight={preflight}
    runtime={runtime}
    runtimePending={runtimePending}
    preflightRefreshing={preflightRefreshing}
    preflightRefreshFailed={preflightRefreshFailed}
  />;
}

type IntakeActionClass = IntakeRegistrySnapshot["actionClasses"]["classes"][string];

const ActionPolicyRow = memo(function ActionPolicyRow({
  action,
  journey,
  state,
  onPolicyChange,
}: {
  readonly action: IntakeActionClass;
  readonly journey: Journey;
  readonly state: ActionPolicyState;
  readonly onPolicyChange: (actionId: string, state: ActionPolicyState) => void;
}) {
  const presentation = actionCapabilityPresentation(action, journey);
  return (
    <article className="os-policy-row">
      <div>
        <strong>{action.label}</strong>
        <p>{action.plainLanguageDescription}</p>
        <small>{action.capability.availableAgentIds.length} ready agents · {action.capability.availableToolIds.length} ready tools · {action.capability.enforcedProviderModelRefs.length} enforcing models</small>
        <small><strong>{presentation.label}:</strong> {presentation.explanation}</small>
        {action.capability.readinessReasons.length > 0 && <small>{action.capability.readinessReasons.join(" ")}</small>}
      </div>
      <StatusPill status={action.capability.availability}>{presentation.label}</StatusPill>
      <label>
        <span>Mission state</span>
        <TitaniumSelect
          aria-label={`${action.label} policy`}
          value={state}
          onChange={(event) => onPolicyChange(action.id, event.target.value as ActionPolicyState)}
        >
          <option value="pre_authorized">Pre-authorized</option>
          <option value="guided_only">Guided only / not autonomous</option>
          <option value="prohibited">Prohibited</option>
          <option value="inherited_default">Inherited default</option>
        </TitaniumSelect>
      </label>
      {action.launchBlockingReasons.length > 0 && (
        <ul>{action.launchBlockingReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
      )}
    </article>
  );
});

interface StampedAutonomousPreflight {
  readonly preflight: AutonomousMissionPreflight;
  readonly runtimeVersion: RuntimeReadinessVersion;
}

/**
 * Bind a server preflight to the process-level capability state observed on
 * both sides of it. If readiness changes during the request, run the review
 * once more against the settled state rather than publishing a mixed-era
 * score.
 */
async function requestStampedAutonomousPreflight(
  request: AutonomousMissionRequest,
): Promise<StampedAutonomousPreflight> {
  const before = await fetchRuntimeReadiness();
  let preflight = await preflightAutonomousMission(request);
  let after = await fetchRuntimeReadiness();

  if (runtimeReadinessChanged(runtimeReadinessVersion(before), after)) {
    preflight = await preflightAutonomousMission(request);
    const settled = await fetchRuntimeReadiness();
    if (runtimeReadinessChanged(runtimeReadinessVersion(after), settled)) {
      throw new Error(
        "Runtime readiness changed repeatedly during the Autonomous review. Wait for capability checks to settle, then run the review again.",
      );
    }
    after = settled;
  }

  return { preflight, runtimeVersion: runtimeReadinessVersion(after) };
}

export function RegistryMissionIntakePage({ journey }: { readonly journey: Journey }) {
  const isAutonomous = journey === "autonomous";
  const steps = isAutonomous ? AUTONOMOUS_STEPS : GUIDED_STEPS;
  const reviewStep = steps.length - 1;
  const navigation = useNavigation();
  const cache = useQueryCache();
  const idempotencyKey = useRef(requestKey());
  const [form, setForm] = useState<IntakeFormState>(INITIAL_FORM);
  const [step, setStep] = useState(0);
  const [resolved, setResolved] = useState<ResolvedMissionIntake>();
  const [normalizedTargetOptions, setNormalizedTargetOptions] = useState<ResolvedMissionIntake["normalizedTargets"]>([]);
  const [preflight, setPreflight] = useState<AutonomousMissionPreflight>();
  const [preflightRuntimeVersion, setPreflightRuntimeVersion] = useState<RuntimeReadinessVersion>();
  const [preflightRefreshState, setPreflightRefreshState] = useState<"idle" | "refreshing" | "failed">("idle");
  const [preflightStale, setPreflightStale] = useState(true);
  const [error, setError] = useState<Error>();
  const [validation, setValidation] = useState<string[]>([]);
  const [working, setWorking] = useState(false);
  const registryRequest = useQuery(
    `mission-intake:${journey}:${form.templateId}`,
    (signal) => fetchMissionIntakeRegistry(journey, form.templateId, signal),
    { staleTime: 30_000 },
  );
  const runtimeReadinessRequest = useQuery(
    "runtime-readiness",
    (signal) => fetchRuntimeReadiness(signal),
    { staleTime: 5_000 },
  );
  const modelCatalogRequest = useQuery(
    "model-catalog",
    fetchModelCatalog,
    { staleTime: 5_000 },
  );
  const refreshRuntimeReadinessRef = useRef(runtimeReadinessRequest.refresh);
  refreshRuntimeReadinessRef.current = runtimeReadinessRequest.refresh;
  // Template changes start a new registry request. Retain the last verified
  // snapshot while that request settles so the form and its focused selector
  // do not unmount into a full-page loading state between ordinary choices.
  const registrySnapshot = useRef(registryRequest.data);
  if (registryRequest.data) registrySnapshot.current = registryRequest.data;
  const registry = {
    ...registryRequest,
    data: registryRequest.data ?? registrySnapshot.current,
    isLoading: !registryRequest.data && !registrySnapshot.current && registryRequest.isLoading,
    isRefreshing: registryRequest.isRefreshing || Boolean(!registryRequest.data && registrySnapshot.current),
  };
  const template = registry.data?.templates.templates[form.templateId];
  const successCriteria = selectedOrDefault(form.successCriteria, template?.successCriteria ?? []);
  const deliverableIds = selectedOrDefault(form.deliverableIds, template?.recommendedDeliverableIds ?? []);
  const evidenceTypeIds = selectedOrDefault(form.evidenceTypeIds, template?.recommendedEvidenceTypeIds ?? []);
  const optionalSafeStopIds = selectedOrDefault(form.optionalSafeStopIds, template?.recommendedOptionalSafeStops ?? []);
  const selectedSpecialistIds = form.specialistAgentIds ?? preflight?.execution.team.selectedAgentIds ?? [];
  const selectedContextIds = form.contextNodeIds ?? [];
  const selectedMemoryScopes = form.memoryScopes
    ?? (resolved?.request.journey === "autonomous" ? resolved.request.contract.memoryScopes : []);
  const firstAllowedTarget = lines(form.targets)[0] ?? "";
  const disposableEnvironment = isAutonomous
    ? (
        form.environmentClassification === "htb"
        || form.environmentClassification === "ctf"
        || form.environmentClassification === "local_disposable_lab"
      )
    : normalizedTargetOptions.some(
        (target) => !target.excluded && target.type === "lab_environment",
      );
  const boundedTargetOptions = disposableEnvironment
    ? normalizedTargetOptions.filter(
        (target) => !target.excluded && (target.type === "host" || target.type === "lab_environment"),
      )
    : [];
  const guidedReconEligible = !isAutonomous && looksLikeSingleHost(firstAllowedTarget);
  const selectedGuidedReconMode = registry.data?.guidedReconnaissance.modes.find(
    ({ id }) => id === form.guidedReconChoice,
  );
  const selectedGuidedWindowsIdentityMode =
    registry.data?.guidedWindowsIdentity.modes.find(
      ({ id }) => id === form.guidedWindowsIdentityOperation,
    );
  const selectedGuidedLocalExploitQueryKind =
    registry.data?.guidedLocalExploitIntelligence.queryKinds.find(
      ({ id }) => id === form.guidedLocalExploitQueryKind,
    );
  const resolvedGuidedRequest =
    resolved?.request.journey === "guided" ? resolved.request : undefined;
  const resolvedGuidedWindowsIdentityMode =
    registry.data?.guidedWindowsIdentity.modes.find(
      ({ id }) => id === resolvedGuidedRequest?.guidedWindowsIdentity?.operation,
    );
  const resolvedGuidedLocalExploitQuery =
    resolvedGuidedRequest?.guidedLocalExploitIntelligence?.query;
  const resolvedGuidedLocalExploitQueryKind =
    registry.data?.guidedLocalExploitIntelligence.queryKinds.find(
      ({ id }) => id === resolvedGuidedLocalExploitQuery?.kind,
    );
  const resolvedGuidedReconPresetId = resolved?.request.journey === "guided"
    && resolved.request.guidedReconnaissance?.mode === "tcp_service_scan"
    && resolved.request.guidedReconnaissance.portSelection.source === "preset"
    ? resolved.request.guidedReconnaissance.portSelection.presetId
    : undefined;
  const resolvedGuidedReconPreset = registry.data?.guidedReconnaissance.tcpPortPresets.find(
    ({ id }) => id === resolvedGuidedReconPresetId,
  );
  const resolvedGuidedFirstStepLabel =
    resolved?.request.journey === "guided"
      ? resolved.request.guidedLocalExploitIntelligence
        ? resolvedGuidedLocalExploitQueryKind?.label
          ?? "Selected local ExploitDB lookup"
        : resolved.request.guidedWindowsIdentity
          ? resolvedGuidedWindowsIdentityMode?.label
            ?? "Selected Windows or identity metadata read"
          : resolved.request.guidedReconnaissance?.mode === "tcp_service_scan"
            ? "Selected TCP service scan"
            : resolved.request.guidedReconnaissance?.mode === "host_liveness"
              ? "Selected host reachability check"
              : "Recommended target-based behavior"
      : undefined;
  const currentGuidedFirstStepLabel = form.guidedLocalExploitQueryKind
    ? selectedGuidedLocalExploitQueryKind?.label ?? "Local ExploitDB lookup"
    : form.guidedWindowsIdentityOperation
      ? selectedGuidedWindowsIdentityMode?.label ?? "Windows or identity metadata read"
      : form.guidedReconChoice === "recommended"
        ? "Target-based default"
        : form.guidedReconChoice === "host_liveness"
          ? "Host reachability"
          : "Selected TCP services";
  const contractCustomized = form.deliverableIds !== undefined
    || form.evidenceTypeIds !== undefined
    || form.optionalSafeStopIds !== undefined
    || form.budgetPresetId !== undefined
    || form.destructivePolicy !== "prohibited"
    || form.boundedDestructiveTargetIds.length > 0
    || Object.keys(form.actionPolicyOverrides).length > 0;
  const resolvedChecklist = useMemo(
    () => resolved && registry.data
      ? buildResolvedContractChecklist(resolved, registry.data)
      : undefined,
    [registry.data, resolved],
  );
  const autonomousOutcome = preflight?.outcome ?? resolved?.autonomousOutcome;

  const set = <K extends keyof IntakeFormState>(key: K, value: IntakeFormState[K]) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    if (key === "targets" || key === "excludedTargets") setNormalizedTargetOptions([]);
    setForm((current) => ({
      ...current,
      [key]: value,
      ...(
        key === "targets"
        || key === "excludedTargets"
        || key === "environmentClassification"
          ? { boundedDestructiveTargetIds: [] }
          : {}
      ),
    }));
  };

  const selectGuidedReconChoice = (
    choice: IntakeFormState["guidedReconChoice"],
  ) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      guidedReconChoice: choice,
      guidedWindowsIdentityOperation: undefined,
      guidedWindowsIdentityCredentialReference: "",
      guidedLocalExploitQueryKind: undefined,
    }));
  };

  const selectGuidedWindowsIdentityOperation = (
    operation: NonNullable<
      GuidedMissionRequest["guidedWindowsIdentity"]
    >["operation"],
  ) => {
    const mode = registry.data?.guidedWindowsIdentity.modes.find(
      (candidate) => candidate.id === operation,
    );
    const authenticationMode =
      mode?.readyAuthenticationModes[0]
      ?? form.guidedWindowsIdentityAuthenticationMode;
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      guidedReconChoice: "recommended",
      guidedWindowsIdentityOperation: operation,
      guidedWindowsIdentityAuthenticationMode: authenticationMode,
      guidedWindowsIdentityCredentialReference:
        authenticationMode === "credential_reference"
          ? current.guidedWindowsIdentityCredentialReference
          : "",
      guidedLocalExploitQueryKind: undefined,
      executionPreference: "single_step_agent",
    }));
  };

  const selectGuidedLocalExploitQueryKind = (
    queryKind: NonNullable<
      GuidedMissionRequest["guidedLocalExploitIntelligence"]
    >["query"]["kind"],
  ) => {
    const definition =
      registry.data?.guidedLocalExploitIntelligence.queryKinds.find(
        ({ id }) => id === queryKind,
      );
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      guidedReconChoice: "recommended",
      guidedWindowsIdentityOperation: undefined,
      guidedWindowsIdentityCredentialReference: "",
      guidedLocalExploitQueryKind: queryKind,
      guidedLocalExploitMaximumResults:
        current.guidedLocalExploitMaximumResults
        || String(definition?.example.maximumResults ?? 20),
      executionPreference: "single_step_agent",
    }));
  };

  const clearGuidedLocalExploitQuery = () => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      guidedLocalExploitQueryKind: undefined,
    }));
  };

  const setActionPolicy = useCallback((actionId: string, state: ActionPolicyState) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      actionPolicyOverrides: { ...current.actionPolicyOverrides, [actionId]: state },
    }));
  }, []);

  const setSelectedSpecialists = useCallback((agentIds: readonly string[]) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      specialistAgentIds: [...agentIds],
      agentModelAssignments: filterAgentModelAssignments(
        current.agentModelAssignments,
        agentIds,
      ),
    }));
  }, []);

  const setAgentModelAssignments = useCallback((
    assignments: readonly AutonomousAgentModelAssignment[] | undefined,
  ) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      agentModelAssignments: assignments
        ? assignments.map((assignment) => ({ ...assignment }))
        : undefined,
    }));
  }, []);

  const setPlanningSelection = useCallback((
    planningSelection: AutonomousPlanningSelection,
  ) => {
    setResolved(undefined);
    setPreflightStale(true);
    setPreflightRefreshState("idle");
    setError(undefined);
    setForm((current) => ({
      ...current,
      planningSelection,
    }));
  }, []);

  const restoreRecommendedContract = useCallback(() => {
    setResolved(undefined);
    setPreflight(undefined);
    setPreflightRuntimeVersion(undefined);
    setPreflightRefreshState("idle");
    setPreflightStale(true);
    setError(undefined);
    setValidation([]);
    setForm((current) => ({
      ...current,
      deliverableIds: undefined,
      evidenceTypeIds: undefined,
      optionalSafeStopIds: undefined,
      budgetPresetId: undefined,
      destructivePolicy: "prohibited",
      boundedDestructiveTargetIds: [],
      actionPolicyOverrides: {},
    }));
  }, []);

  const templateOptions = useMemo(
    () => Object.values(registry.data?.templates.templates ?? {}).filter((candidate) => candidate.supportedJourneys.includes(journey)),
    [journey, registry.data],
  );

  const guidedReconnaissanceRequest = (): GuidedReconnaissanceSelection | undefined => {
    if (
      journey !== "guided"
      || form.guidedWindowsIdentityOperation
      || form.guidedLocalExploitQueryKind
      || form.guidedReconChoice === "recommended"
    ) return undefined;
    if (form.guidedReconChoice === "host_liveness") return { mode: "host_liveness" };
    if (form.guidedTcpPortPresetId === "custom") {
      const parsed = parseCustomTcpPorts(
        form.guidedCustomTcpPorts,
        registry.data!.guidedReconnaissance.customPorts.maximumIndividualPorts,
      );
      return parsed.ports
        ? { mode: "tcp_service_scan", portSelection: { source: "custom", ports: parsed.ports } }
        : undefined;
    }
    const preset = registry.data!.guidedReconnaissance.tcpPortPresets.find(
      ({ id }) => id === form.guidedTcpPortPresetId,
    );
    return preset ? {
      mode: "tcp_service_scan",
      portSelection: {
        source: "preset",
        presetId: preset.id,
        presetVersion: preset.version,
        ports: [...preset.ports],
      },
    } : undefined;
  };

  const guidedWindowsIdentityRequest = (
  ): GuidedMissionRequest["guidedWindowsIdentity"] | undefined => {
    if (
      journey !== "guided"
      || form.guidedLocalExploitQueryKind
      || !form.guidedWindowsIdentityOperation
    ) return undefined;
    return {
      operation: form.guidedWindowsIdentityOperation,
      authenticationMode: form.guidedWindowsIdentityAuthenticationMode,
      credentialReference:
        form.guidedWindowsIdentityAuthenticationMode === "credential_reference"
          ? {
              kind: "systemd_credential_bundle",
              id: form.guidedWindowsIdentityCredentialReference.trim(),
            }
          : null,
    };
  };

  const guidedLocalExploitIntelligenceRequest = (
  ): GuidedMissionRequest["guidedLocalExploitIntelligence"] | undefined => {
    if (journey !== "guided" || !form.guidedLocalExploitQueryKind) {
      return undefined;
    }
    const maximumResults = Number(form.guidedLocalExploitMaximumResults);
    return form.guidedLocalExploitQueryKind === "cve"
      ? {
          query: {
            kind: "cve",
            cveId: form.guidedLocalExploitCveId.trim().toLocaleUpperCase("en-US"),
            maximumResults,
          },
        }
      : {
          query: {
            kind: "technology",
            product: form.guidedLocalExploitProduct.trim(),
            version: form.guidedLocalExploitVersion.trim() || null,
            platform: form.guidedLocalExploitPlatform.trim() || null,
            maximumResults,
          },
        };
  };

  const intakeRequest = (): MissionIntakeRequest => ({
    journey,
    authorizationAcknowledged: form.authorizationAcknowledged,
    targets: [
      ...lines(form.targets).map((value) => ({ value })),
      ...lines(form.excludedTargets).map((value) => ({ value, excluded: true })),
    ],
    templateId: form.templateId,
    ...(form.title.trim() ? { title: form.title.trim() } : {}),
    ...(form.objective.trim() ? { objective: form.objective.trim() } : {}),
    ...(form.engagementId.trim() ? { engagementId: form.engagementId.trim() } : {}),
    ...(journey === "autonomous" ? {
      environmentClassification: form.environmentClassification,
    } : {}),
    ...(form.successCriteria !== undefined || lines(form.customSuccessCriteria).length > 0 ? {
      successCriteria: [...successCriteria, ...lines(form.customSuccessCriteria)],
    } : {}),
    ...(form.deliverableIds !== undefined ? { deliverableIds: [...deliverableIds] } : {}),
    ...(form.evidenceTypeIds !== undefined ? { evidenceTypeIds: [...evidenceTypeIds] } : {}),
    ...(form.optionalSafeStopIds !== undefined ? { optionalSafeStopIds: [...optionalSafeStopIds] } : {}),
    ...(form.budgetPresetId ? { budgetPresetId: form.budgetPresetId } : {}),
    destructivePolicy: form.destructivePolicy,
    boundedDestructiveTargetIds: [...form.boundedDestructiveTargetIds],
    actionPolicyOverrides: { ...form.actionPolicyOverrides },
    ...(journey === "autonomous" && form.specialistAgentIds !== undefined ? {
      specialistAgentIds: [...form.specialistAgentIds],
    } : {}),
    ...(journey === "autonomous" && form.agentModelAssignments !== undefined ? {
      agentModelAssignments: [...form.agentModelAssignments],
    } : {}),
    ...(journey === "autonomous" ? {
      planningSelection: form.planningSelection,
    } : {}),
    ...(journey === "autonomous" && (form.contextNodeIds !== undefined || form.memoryScopes !== undefined) ? {
      contextNodeIds: [...(form.contextNodeIds ?? [])],
      memoryScopes: [...selectedMemoryScopes],
    } : {}),
    ...(journey === "guided" ? {
      explanationDepth: form.explanationDepth,
      executionPreference: form.executionPreference,
      ...(guidedReconnaissanceRequest() ? {
        guidedReconnaissance: guidedReconnaissanceRequest(),
      } : {}),
      ...(guidedWindowsIdentityRequest() ? {
        guidedWindowsIdentity: guidedWindowsIdentityRequest(),
      } : {}),
      ...(guidedLocalExploitIntelligenceRequest() ? {
        guidedLocalExploitIntelligence:
          guidedLocalExploitIntelligenceRequest(),
      } : {}),
    } : {}),
  });

  const resolveCurrent = async (): Promise<ResolvedMissionIntake | undefined> => {
    const issues: string[] = [];
    if (lines(form.targets).length === 0) issues.push("Add at least one authorized target or environment reference.");
    if (!form.authorizationAcknowledged) issues.push("Confirm that you are authorized to assess the supplied target scope.");
    if (
      journey === "guided"
      && (
        form.guidedReconChoice !== "recommended"
        || form.guidedWindowsIdentityOperation
      )
      && !guidedReconEligible
    ) {
      issues.push("The selected first step needs one host, IP address, or hostname as the first target. Use recommended target-based behavior, or replace the first target with one host without a scheme, port, CIDR, or range.");
    }
    if (journey === "guided" && form.guidedReconChoice === "tcp_service_scan" && form.guidedTcpPortPresetId === "custom") {
      const parsed = parseCustomTcpPorts(form.guidedCustomTcpPorts, registry.data!.guidedReconnaissance.customPorts.maximumIndividualPorts);
      if (parsed.issue) issues.push(parsed.issue);
    }
    if (journey === "guided" && form.guidedWindowsIdentityOperation) {
      if (
        !selectedGuidedWindowsIdentityMode
        || selectedGuidedWindowsIdentityMode.readiness !== "ready"
      ) {
        issues.push("The selected Windows or identity read is not ready. Choose a ready operation or restore its reviewed runtime dependency.");
      } else if (!selectedGuidedWindowsIdentityMode.readyAuthenticationModes.includes(
        form.guidedWindowsIdentityAuthenticationMode,
      )) {
        issues.push("Choose one authentication mode that has a current runtime readiness receipt.");
      }
      if (form.executionPreference !== "single_step_agent") {
        issues.push("Windows and identity reads require the single represented agent-step preference.");
      }
      if (
        form.guidedWindowsIdentityAuthenticationMode === "credential_reference"
        && !/^[A-Za-z0-9._:@/-]{1,200}$/u.test(
          form.guidedWindowsIdentityCredentialReference.trim(),
        )
      ) {
        issues.push("Enter the opaque systemd credential bundle ID. Use only letters, numbers, period, underscore, colon, at sign, slash, or hyphen; do not enter a password or secret.");
      }
    }
    if (journey === "guided" && form.guidedLocalExploitQueryKind) {
      if (registry.data!.guidedLocalExploitIntelligence.readiness !== "ready") {
        issues.push(
          "The local ExploitDB lookup is not ready. Restore its pinned catalog and reviewed local runtime, then refresh the mission controls.",
        );
      }
      if (form.executionPreference !== "single_step_agent") {
        issues.push(
          "Local ExploitDB intelligence requires the single represented agent-step preference.",
        );
      }
      if (
        form.guidedReconChoice !== "recommended"
        || form.guidedWindowsIdentityOperation
      ) {
        issues.push(
          "Choose exactly one first Guided action: reconnaissance, Windows or identity metadata, or local ExploitDB intelligence.",
        );
      }
      if (
        !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(
          form.guidedLocalExploitMaximumResults,
        )
      ) {
        issues.push(
          "Set the local ExploitDB result limit to a whole number from 1 through 100.",
        );
      }
      if (form.guidedLocalExploitQueryKind === "cve") {
        const cveId = form.guidedLocalExploitCveId.trim()
          .toLocaleUpperCase("en-US");
        if (!GUIDED_LOCAL_EXPLOIT_CVE_ID.test(cveId)) {
          issues.push(
            "Enter one canonical CVE ID, for example CVE-2021-44228.",
          );
        }
      } else {
        const productIssue = guidedLocalExploitTextIssue(
          form.guidedLocalExploitProduct,
          "Product",
          2,
          120,
        );
        const versionIssue = guidedLocalExploitTextIssue(
          form.guidedLocalExploitVersion,
          "Version",
          1,
          80,
          true,
        );
        const platformIssue = guidedLocalExploitTextIssue(
          form.guidedLocalExploitPlatform,
          "Platform",
          1,
          80,
          true,
        );
        if (productIssue) issues.push(productIssue);
        if (versionIssue) issues.push(versionIssue);
        if (platformIssue) issues.push(platformIssue);
      }
    }
    if (issues.length > 0) {
      setValidation(issues);
      return undefined;
    }
    setWorking(true);
    setError(undefined);
    try {
      const result = await resolveMissionIntake(intakeRequest());
      if (
        result.request.journey === "autonomous"
        && !samePlanningSelection(
          result.request.contract.planningSelection,
          form.planningSelection,
        )
      ) {
        throw new Error(
          "The mission resolver did not preserve the selected planning route. Refresh the application after the planning-contract service is updated; Ti-Scale will not silently fall back to another planner.",
        );
      }
      setResolved(result);
      setNormalizedTargetOptions(result.normalizedTargets);
      setValidation([]);
      return result;
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Mission defaults could not be resolved"));
      return undefined;
    } finally {
      setWorking(false);
    }
  };

  const advance = async () => {
    const result = await resolveCurrent();
    if (!result) return;
    if (journey === "autonomous" && step >= 2 && step < reviewStep) {
      if (!isAutonomousResolved(result)) return;
      setWorking(true);
      try {
        const checked = await requestStampedAutonomousPreflight(result.request);
        setPreflight(checked.preflight);
        setPreflightRuntimeVersion(checked.runtimeVersion);
        setPreflightRefreshState("idle");
        setPreflightStale(false);
        refreshRuntimeReadinessRef.current();
        if (step === 2) {
          const recommendedSpecialists = checked.preflight.execution.team.recommendedAgentIds;
          const seededSpecialists = form.specialistAgentIds ?? recommendedSpecialists;
          // The preview may contain hundreds of eligible memories. Eligibility is
          // not relevance, so never opt every candidate into a public-provider
          // Context Pack. Preserve only server-selected IDs; the operator can add
          // individual memories on the explicit Context step.
          const seededContext = form.contextNodeIds ?? checked.preflight.context.selectedNodeIds;
          const seededMemoryScopes = form.memoryScopes ?? result.request.contract.memoryScopes;
          const defaultsChanged = form.specialistAgentIds === undefined
            || form.contextNodeIds === undefined
            || form.memoryScopes === undefined;
          if (defaultsChanged) {
            setForm((current) => ({
              ...current,
              specialistAgentIds: current.specialistAgentIds ?? seededSpecialists,
              contextNodeIds: current.contextNodeIds ?? seededContext,
              memoryScopes: current.memoryScopes ?? seededMemoryScopes,
            }));
            setPreflightStale(true);
          }
        }
      } catch (reason) {
        setError(reason instanceof Error ? reason : new Error("Autonomous readiness could not be verified"));
        return;
      } finally {
        setWorking(false);
      }
    }
    setStep((current) => Math.min(reviewStep, current + 1));
  };

  const currentRuntimeSignature = runtimeReadinessRequest.data
    ? runtimeReadinessVersion(runtimeReadinessRequest.data).signature
    : undefined;
  const preflightRuntimeChanged = runtimeReadinessChanged(
    preflightRuntimeVersion,
    runtimeReadinessRequest.data,
  );

  // A visible, current Autonomous review samples the process-level runtime on
  // a bounded interval. This replaces a stale score without turning intake
  // into a high-frequency polling surface.
  useEffect(() => {
    if (!isAutonomous || !preflight || preflightStale) return;
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") refreshRuntimeReadinessRef.current();
    };
    const interval = window.setInterval(refreshWhenVisible, 5_000);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [isAutonomous, preflight, preflightStale]);

  // Retire an old review as soon as a material readiness field changes. The
  // old score never remains actionable while its replacement is in flight.
  useEffect(() => {
    if (
      !isAutonomous
      || !preflight
      || preflightStale
      || !preflightRuntimeVersion
      || !runtimeReadinessRequest.data
      || !resolved
      || !isAutonomousResolved(resolved)
      || !runtimeReadinessChanged(preflightRuntimeVersion, runtimeReadinessRequest.data)
    ) return;

    let cancelled = false;
    setPreflightRefreshState("refreshing");
    setError(undefined);
    void requestStampedAutonomousPreflight(resolved.request)
      .then((checked) => {
        if (cancelled) return;
        setPreflight(checked.preflight);
        setPreflightRuntimeVersion(checked.runtimeVersion);
        setPreflightStale(false);
        setPreflightRefreshState("idle");
        refreshRuntimeReadinessRef.current();
      })
      .catch((reason) => {
        if (cancelled) return;
        setPreflightRefreshState("failed");
        setError(reason instanceof Error ? reason : new Error("Autonomous readiness could not be refreshed"));
      });
    return () => { cancelled = true; };
  }, [
    currentRuntimeSignature,
    isAutonomous,
    preflight,
    preflightRuntimeVersion?.signature,
    preflightStale,
    resolved,
  ]);

  const launch = async (event: FormEvent) => {
    event.preventDefault();
    const current = resolved ?? await resolveCurrent();
    if (!current) return;
    let request = current.request;
    if (journey === "autonomous") {
      if (
        !isAutonomousResolved(current)
        || !preflight
        || preflightStale
        || preflightRuntimeChanged
        || preflightRefreshState !== "idle"
        || preflight.readiness.status === "blocked"
      ) {
        setValidation(["Autonomous launch remains blocked until the current contract has a passing server readiness review."]);
        return;
      }
      request = { ...current.request, contractReview: preflight.contract };
    }
    setWorking(true);
    setError(undefined);
    try {
      const created = await createMission(request, idempotencyKey.current);
      cache.invalidate("ti-scale-overview");
      navigation.navigate(safeNextUrl(
        created.nextUrl,
        journey === "guided"
          ? `/guided/${encodeURIComponent(created.mission.id)}`
          : `/missions/${encodeURIComponent(created.mission.id)}`,
      ));
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Mission could not be created"));
    } finally {
      setWorking(false);
    }
  };

  if (registry.isLoading) return <div className="os-page"><LoadingPanel label="Loading runtime-derived mission controls" /></div>;
  if (registry.error || !registry.data || !template) {
    return <div className="os-page"><ErrorPanel title="Mission controls are unavailable" error={registry.error ?? new Error("The selected mission template is unavailable.")} onRetry={registry.refresh} /></div>;
  }

  const launchBlocked = isAutonomous && (
    !preflight
    || preflightStale
    || preflightRuntimeChanged
    || preflightRefreshState !== "idle"
    || preflight.readiness.status === "blocked"
  );
  const title = isAutonomous ? "Launch from a clear boundary, not a blank contract" : "Begin with one authorized target";
  const description = isAutonomous
    ? "Authorization and a target are the only operator-authored requirements. Ti-Scale resolves safe defaults, shows every inference, and blocks execution when runtime enforcement is unavailable."
    : "Ti-Scale resolves a durable Guided mission from authorization and one target, then explains one represented step at a time.";

  return <div className="os-page os-form-page">
    <PageHeader eyebrow={isAutonomous ? "Go Autonomous" : "Start Guided Mission"} title={title} description={description} actions={<ButtonLink href="/missions/new" variant="quiet">Change journey</ButtonLink>} />
    <div className="os-registry-source" role="status"><StatusPill status={registry.data.source.status === "live" ? "ready" : "degraded"} /><span><strong>{registry.data.source.status === "live" ? "Live runtime registry" : "Runtime registry unavailable"}</strong><small>{registry.data.source.explanation}</small></span></div>
    <div className="os-step-layout os-step-layout--summary">
      <ol className="os-stepper" aria-label={`${isAutonomous ? "Autonomous" : "Guided"} intake steps`}>
        {steps.map((label, index) => <li key={label} className={index === step ? "is-current" : index < step ? "is-complete" : ""} aria-current={index === step ? "step" : undefined}><button type="button" disabled={index > step} onClick={() => index < step && setStep(index)}><span>{index + 1}</span>{label}</button></li>)}
      </ol>
      <form onSubmit={launch} className="os-contract-form">
        <Card>
          {step === 0 && <fieldset><legend>Authorization and exact scope</legend><p className="os-field-intro">Templates configure behavior only inside the targets you supply. They never expand authorization.</p>
            <label>Mission template<TitaniumSelect value={form.templateId} onChange={(event) => {
              setResolved(undefined); setPreflight(undefined); setPreflightRuntimeVersion(undefined); setPreflightRefreshState("idle"); setPreflightStale(true); setForm((current) => ({ ...current, templateId: event.target.value as MissionTemplateId, successCriteria: undefined, deliverableIds: undefined, evidenceTypeIds: undefined, optionalSafeStopIds: undefined, budgetPresetId: undefined, actionPolicyOverrides: {}, destructivePolicy: "prohibited", boundedDestructiveTargetIds: [] }));
            }}>{templateOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</TitaniumSelect><span>{template.summary}</span></label>
            <label>Authorized targets or environment references<textarea required rows={5} value={form.targets} onChange={(event) => set("targets", event.target.value)} placeholder="https://portal.example.test&#10;10.10.10.0/24" /><span>One host, CIDR, URL, domain, cloud reference, or named lab per line.</span></label>
            <FieldHelp definition={field(registry.data, "targets")} />
            {isAutonomous && <label>Environment classification<TitaniumSelect
              data-control-id="autonomous-intake-environment-classification"
              value={form.environmentClassification}
              onChange={(event) => set(
                "environmentClassification",
                event.target.value as MissionEnvironmentClassification,
              )}
            >
              <option value="client_or_public">Client or public environment — not disposable</option>
              <option value="internal">Internal environment — not disposable</option>
              <option value="htb">Hack The Box — disposable lab</option>
              <option value="ctf">CTF — disposable lab</option>
              <option value="local_disposable_lab">Local disposable lab</option>
            </TitaniumSelect><span>This classifies the environment around the target; an IP remains an exact host. Only an explicitly disposable environment can enable exact-host lab-only execution.</span></label>}
            <details className="os-advanced-section"><summary>Excluded targets and engagement boundary</summary><div className="os-details-content"><label>Explicitly excluded targets <span>Optional · one per line</span><textarea rows={3} value={form.excludedTargets} onChange={(event) => set("excludedTargets", event.target.value)} placeholder="admin.portal.example.test" /></label><label>Existing engagement ID <span>Optional</span><input value={form.engagementId} onChange={(event) => set("engagementId", event.target.value)} placeholder="eng_customer-portal_q3" /></label><FieldHelp definition={field(registry.data, "engagementId")} /></div></details>
            <label className="os-check-field"><input type="checkbox" checked={form.authorizationAcknowledged} onChange={(event) => set("authorizationAcknowledged", event.target.checked)} /><span><strong>I confirm these targets and the selected action policy are authorized</strong><small>Authorization is required for every mission and is never inferred from prior work.</small></span></label>
          </fieldset>}

          {step === 1 && <fieldset><legend>Outcome and collaboration</legend><p className="os-field-intro">Recommended defaults are complete and editable. Optional blank fields do not block launch.</p>
            <label>Mission title <span>Optional · generated from template, target, and date</span><input value={form.title} onChange={(event) => set("title", event.target.value)} placeholder="Q3 External Web Assessment — Customer Portal" /></label><FieldHelp definition={field(registry.data, "title")} />
            <label>Authorized objective <span>Optional · generated conservatively inside supplied scope</span><textarea rows={7} value={form.objective} onChange={(event) => set("objective", event.target.value)} placeholder={template.objectivePattern} /></label><FieldHelp definition={field(registry.data, "objective")} />
            <fieldset className="os-registry-checklist"><legend>Recommended success criteria <span>Optional</span></legend>{template.successCriteria.map((criterion) => <label className="os-check-field" key={criterion}><input type="checkbox" checked={successCriteria.includes(criterion)} onChange={(event) => set("successCriteria", listToggle(successCriteria, criterion, event.target.checked))} /><span><strong>{criterion}</strong><small>Used by completion evaluation; partial and not-applicable outcomes remain visible.</small></span></label>)}</fieldset>
            <label>Additional success criteria <span>Optional · one per line</span><textarea rows={3} value={form.customSuccessCriteria} onChange={(event) => set("customSuccessCriteria", event.target.value)} placeholder="At least one safe authorized attack path is validated when prerequisites exist." /></label>
            {!isAutonomous && <>
              <label>Explanation depth<TitaniumSelect value={form.explanationDepth} onChange={(event) => set("explanationDepth", event.target.value as IntakeFormState["explanationDepth"])}><option value="concise">Concise</option><option value="balanced">Balanced</option><option value="deep">Deep</option></TitaniumSelect></label>
              <fieldset className="os-choice-group"><legend>Execution preference</legend><label className="os-radio-card"><input type="radio" name="execution-preference" disabled={Boolean(form.guidedWindowsIdentityOperation || form.guidedLocalExploitQueryKind)} checked={form.executionPreference === "manual"} onChange={() => set("executionPreference", "manual")} /><span><strong>I run commands manually</strong><small>{form.guidedWindowsIdentityOperation ? "Remove the selected Windows or identity operation to return to manual execution." : form.guidedLocalExploitQueryKind ? "Remove the local ExploitDB lookup to return to manual execution." : "Ti-Scale explains and interprets the result you provide."}</small></span></label><label className="os-radio-card"><input type="radio" name="execution-preference" checked={form.executionPreference === "single_step_agent"} onChange={() => set("executionPreference", "single_step_agent")} /><span><strong>Allow one represented agent step</strong><small>Each exact action and normalized parameter set still requires a deliberate decision.</small></span></label></fieldset>
              <fieldset className="os-choice-group" aria-describedby="guided-first-recon-help">
                <legend>First represented reconnaissance step <span>Optional</span></legend>
                <p id="guided-first-recon-help" className="os-policy-note">Choose what the first Guided card should establish. This is not another journey and does not authorize a chain of actions; the exact represented step still waits for your decision.</p>
                <label className="os-radio-card"><input data-control-id="guided-intake-recon-recommended" type="radio" name="guided-recon-choice" checked={form.guidedReconChoice === "recommended" && !form.guidedWindowsIdentityOperation && !form.guidedLocalExploitQueryKind} onChange={() => selectGuidedReconChoice("recommended")} /><span><strong>Use recommended target-based behavior</strong><small>Keep the existing safe default: Ti-Scale chooses a reachability, DNS, or web metadata baseline from the target type.</small></span></label>
                <label className="os-radio-card"><input data-control-id="guided-intake-recon-host-liveness" type="radio" name="guided-recon-choice" disabled={!guidedReconEligible} checked={form.guidedReconChoice === "host_liveness"} onChange={() => selectGuidedReconChoice("host_liveness")} /><span><strong>Check host reachability</strong><small>{registry.data.guidedReconnaissance.modes.find(({ id }) => id === "host_liveness")?.description}</small></span></label>
                <label className="os-radio-card"><input data-control-id="guided-intake-recon-tcp-service-scan" type="radio" name="guided-recon-choice" disabled={!guidedReconEligible} checked={form.guidedReconChoice === "tcp_service_scan"} onChange={() => selectGuidedReconChoice("tcp_service_scan")} /><span><strong>Scan selected TCP services</strong><small>{registry.data.guidedReconnaissance.modes.find(({ id }) => id === "tcp_service_scan")?.description}</small></span></label>
                {!guidedReconEligible && <p className="os-policy-note">This optional override is available when the first target is one host, IP address, or hostname. The current URL, CIDR, environment, or other reference keeps recommended target-based behavior.</p>}
                {form.guidedReconChoice === "tcp_service_scan" && guidedReconEligible && <div className="os-details-content">
                  <label>TCP port selection<TitaniumSelect data-control-id="guided-intake-recon-port-preset" value={form.guidedTcpPortPresetId} onChange={(event) => set("guidedTcpPortPresetId", event.target.value as IntakeFormState["guidedTcpPortPresetId"])}>{registry.data.guidedReconnaissance.tcpPortPresets.map((preset) => <option key={preset.id} value={preset.id}>{preset.label} · {preset.ports.length} ports</option>)}<option value="custom">Custom individual ports</option></TitaniumSelect></label>
                  {form.guidedTcpPortPresetId === "custom" ? <label>Custom TCP ports<input data-control-id="guided-intake-recon-custom-ports" inputMode="numeric" value={form.guidedCustomTcpPorts} onChange={(event) => set("guidedCustomTcpPorts", event.target.value)} placeholder={registry.data.guidedReconnaissance.customPorts.example} /><span>{registry.data.guidedReconnaissance.customPorts.explanation}</span></label> : <p className="os-policy-note">{registry.data.guidedReconnaissance.tcpPortPresets.find(({ id }) => id === form.guidedTcpPortPresetId)?.description} Exact normalized ports: <code>{registry.data.guidedReconnaissance.tcpPortPresets.find(({ id }) => id === form.guidedTcpPortPresetId)?.ports.join(",")}</code></p>}
                </div>}
                {form.guidedReconChoice !== "recommended" && selectedGuidedReconMode && <div className="os-guided-contract"><StatusPill status={selectedGuidedReconMode.readiness === "ready" ? "ready" : "unavailable"} /><div><strong>{selectedGuidedReconMode.readinessExplanation}</strong><p>{selectedGuidedReconMode.readiness === "ready" ? "Agent execution still requires one exact represented decision." : selectedGuidedReconMode.remediation}</p></div></div>}
              </fieldset>
              <fieldset className="os-choice-group" aria-describedby="guided-windows-identity-help">
                <legend>Windows and identity metadata read <span>Optional</span></legend>
                <p id="guided-windows-identity-help" className="os-policy-note">Choose one bounded read when the first target is a Windows, SMB, RPC, or LDAP host. These operations list advertised metadata only; they do not try passwords, open files, change directory objects, or execute commands.</p>
                <label className="os-radio-card">
                  <input
                    data-control-id="guided-intake-identity-none"
                    type="radio"
                    name="guided-identity-operation"
                    checked={!form.guidedWindowsIdentityOperation}
                    onChange={() => {
                      set("guidedWindowsIdentityOperation", undefined);
                      set("guidedWindowsIdentityCredentialReference", "");
                    }}
                  />
                  <span><strong>No Windows or identity override</strong><small>Use the selected reconnaissance step or the recommended target-based first action.</small></span>
                </label>
                {registry.data.guidedWindowsIdentity.modes.map((mode) => (
                  <label className="os-radio-card" key={mode.id}>
                    <input
                      data-control-id={`guided-intake-identity-${mode.id}`}
                      type="radio"
                      name="guided-identity-operation"
                      disabled={!guidedReconEligible || mode.readiness !== "ready"}
                      checked={form.guidedWindowsIdentityOperation === mode.id}
                      onChange={() => selectGuidedWindowsIdentityOperation(mode.id)}
                    />
                    <span>
                      <strong>{mode.label}</strong>
                      <small>{mode.description}</small>
                      <small>{mode.readiness === "ready" ? `Ready · ${mode.readyAuthenticationModes.map((item) => item === "anonymous" ? "anonymous read" : "private credential reference").join(" or ")}` : `Unavailable · ${mode.readinessExplanation}`}</small>
                    </span>
                  </label>
                ))}
                {!guidedReconEligible && <p className="os-policy-note">Supply one IP address or hostname as the first target to choose a Windows or identity read.</p>}
                {selectedGuidedWindowsIdentityMode && <div className="os-details-content">
                  <p className="os-policy-note"><strong>Expected result:</strong> {selectedGuidedWindowsIdentityMode.expectedResult}</p>
                  {selectedGuidedWindowsIdentityMode.readyAuthenticationModes.length > 1
                    ? <label>Authentication mode
                        <TitaniumSelect
                          data-control-id="guided-intake-identity-authentication-mode"
                          value={form.guidedWindowsIdentityAuthenticationMode}
                          onChange={(event) => {
                            const value = event.target.value as IntakeFormState["guidedWindowsIdentityAuthenticationMode"];
                            set("guidedWindowsIdentityAuthenticationMode", value);
                            if (value === "anonymous") set("guidedWindowsIdentityCredentialReference", "");
                          }}
                        >
                          {selectedGuidedWindowsIdentityMode.readyAuthenticationModes.map((mode) => <option key={mode} value={mode}>{mode === "anonymous" ? "Anonymous metadata read" : "Private credential reference"}</option>)}
                        </TitaniumSelect>
                      </label>
                    : <p className="os-policy-note">Authentication: {form.guidedWindowsIdentityAuthenticationMode === "anonymous" ? "anonymous metadata read" : "private credential reference"}.</p>}
                  {form.guidedWindowsIdentityAuthenticationMode === "credential_reference" && <label>Credential bundle reference
                    <input
                      data-control-id="guided-intake-identity-credential-reference"
                      value={form.guidedWindowsIdentityCredentialReference}
                      onChange={(event) => set("guidedWindowsIdentityCredentialReference", event.target.value)}
                      placeholder="lab-ad-credential"
                      autoComplete="off"
                    />
                    <span>Enter only the opaque systemd credential bundle ID. Do not enter a username, password, hash, ticket, token, or key.</span>
                  </label>}
                  <div className="os-guided-contract"><StatusPill status={selectedGuidedWindowsIdentityMode.readiness === "ready" ? "ready" : "unavailable"} /><div><strong>{selectedGuidedWindowsIdentityMode.readinessExplanation}</strong><p>{selectedGuidedWindowsIdentityMode.remediation}</p></div></div>
                </div>}
              </fieldset>
              <fieldset className="os-choice-group" aria-describedby="guided-local-exploit-help">
                <legend>Local ExploitDB intelligence <span>Optional</span></legend>
                <p id="guided-local-exploit-help" className="os-policy-note">
                  Search the pinned ExploitDB catalog already installed on this system for one CVE or observed technology. This helps identify leads worth checking; it does not contact the approved target, send data to an AI provider, execute an exploit, or prove that a vulnerability applies.
                </p>
                <label className="os-radio-card">
                  <input
                    data-control-id="guided-intake-local-exploit-none"
                    type="radio"
                    name="guided-local-exploit-query-kind"
                    checked={!form.guidedLocalExploitQueryKind}
                    onChange={clearGuidedLocalExploitQuery}
                  />
                  <span>
                    <strong>No local ExploitDB override</strong>
                    <small>Use the selected reconnaissance or Windows/identity step, or retain recommended target-based behavior.</small>
                  </span>
                </label>
                {registry.data.guidedLocalExploitIntelligence.queryKinds.map((queryKind) => (
                  <label className="os-radio-card" key={queryKind.id}>
                    <input
                      data-control-id={`guided-intake-local-exploit-${queryKind.id}`}
                      type="radio"
                      name="guided-local-exploit-query-kind"
                      disabled={registry.data!.guidedLocalExploitIntelligence.readiness !== "ready"}
                      checked={form.guidedLocalExploitQueryKind === queryKind.id}
                      onChange={() => selectGuidedLocalExploitQueryKind(queryKind.id)}
                    />
                    <span>
                      <strong>{queryKind.label}</strong>
                      <small>{queryKind.purpose}</small>
                      <small>{queryKind.expectedResult}</small>
                    </span>
                  </label>
                ))}
                {form.guidedLocalExploitQueryKind && selectedGuidedLocalExploitQueryKind && <div className="os-details-content">
                  {form.guidedLocalExploitQueryKind === "cve"
                    ? <label>
                        CVE ID
                        <input
                          data-control-id="guided-intake-local-exploit-cve-id"
                          value={form.guidedLocalExploitCveId}
                          onChange={(event) => set(
                            "guidedLocalExploitCveId",
                            event.target.value,
                          )}
                          placeholder={selectedGuidedLocalExploitQueryKind.example.kind === "cve"
                            ? selectedGuidedLocalExploitQueryKind.example.cveId
                            : "CVE-2021-44228"}
                          autoComplete="off"
                        />
                        <span>Enter one canonical CVE identifier. The local result is a lead for version-aware applicability review, not evidence by itself.</span>
                      </label>
                    : <>
                        <label>
                          Product
                          <input
                            data-control-id="guided-intake-local-exploit-product"
                            value={form.guidedLocalExploitProduct}
                            onChange={(event) => set(
                              "guidedLocalExploitProduct",
                              event.target.value,
                            )}
                            placeholder={selectedGuidedLocalExploitQueryKind.example.kind === "technology"
                              ? selectedGuidedLocalExploitQueryKind.example.product
                              : "Apache HTTP Server"}
                            autoComplete="off"
                          />
                          <span>Use the product name observed during reconnaissance, not a command or a general attack request.</span>
                        </label>
                        <label>
                          Version <span>Optional</span>
                          <input
                            data-control-id="guided-intake-local-exploit-version"
                            value={form.guidedLocalExploitVersion}
                            onChange={(event) => set(
                              "guidedLocalExploitVersion",
                              event.target.value,
                            )}
                            placeholder={selectedGuidedLocalExploitQueryKind.example.kind === "technology"
                              ? selectedGuidedLocalExploitQueryKind.example.version ?? "2.4.49"
                              : "2.4.49"}
                            autoComplete="off"
                          />
                          <span>Add an observed version when available to narrow the catalog leads.</span>
                        </label>
                        <label>
                          Platform <span>Optional</span>
                          <input
                            data-control-id="guided-intake-local-exploit-platform"
                            value={form.guidedLocalExploitPlatform}
                            onChange={(event) => set(
                              "guidedLocalExploitPlatform",
                              event.target.value,
                            )}
                            placeholder={selectedGuidedLocalExploitQueryKind.example.kind === "technology"
                              ? selectedGuidedLocalExploitQueryKind.example.platform ?? "linux"
                              : "linux"}
                            autoComplete="off"
                          />
                          <span>Use an observed platform such as Linux or Windows when it materially improves matching.</span>
                        </label>
                      </>}
                  <label>
                    Maximum catalog matches
                    <input
                      data-control-id="guided-intake-local-exploit-maximum-results"
                      type="number"
                      inputMode="numeric"
                      min={1}
                      max={100}
                      step={1}
                      value={form.guidedLocalExploitMaximumResults}
                      onChange={(event) => set(
                        "guidedLocalExploitMaximumResults",
                        event.target.value,
                      )}
                    />
                    <span>Return between 1 and 100 local entries. The default 20 keeps the represented result focused.</span>
                  </label>
                  <div className="os-guided-contract">
                    <StatusPill status={registry.data.guidedLocalExploitIntelligence.readiness === "ready" ? "ready" : "unavailable"} />
                    <div>
                      <strong>{registry.data.guidedLocalExploitIntelligence.readinessExplanation}</strong>
                      <p>Exact local binding: <code>{registry.data.guidedLocalExploitIntelligence.toolId}</code>. No target or provider contact. Raw output is retained in the Engagement Log and parsed matches remain unverified observations; nothing is promoted to evidence automatically.</p>
                    </div>
                  </div>
                </div>}
                {!form.guidedLocalExploitQueryKind && <div className="os-guided-contract">
                  <StatusPill status={registry.data.guidedLocalExploitIntelligence.readiness === "ready" ? "ready" : "unavailable"} />
                  <div>
                    <strong>{registry.data.guidedLocalExploitIntelligence.readinessExplanation}</strong>
                    <p>{registry.data.guidedLocalExploitIntelligence.readiness === "ready"
                      ? "Choose one lookup above to make it the first represented Guided step."
                      : registry.data.guidedLocalExploitIntelligence.remediation}</p>
                  </div>
                </div>}
              </fieldset>
            </>}
          </fieldset>}

          {step === 2 && <fieldset><legend>{isAutonomous ? "Autonomous operating contract" : "Guided proposal boundaries"}</legend><p className="os-field-intro">Structured registries replace policy prose. Advanced controls remain optional and resolve from the selected template.</p>
            <section className="os-contract-checklist-overview" aria-label="Operating contract checklists">
              <header>
                <div><p className="os-eyebrow">Operating contract</p><h3>Four registry-backed checklists</h3><p>Review each list below or keep the recommended values. The runtime receives IDs from these registries—not unvalidated policy prose.</p></div>
                <Button
                  type="button"
                  variant="quiet"
                  data-control-id={`${journey}-intake-contract-recommended-defaults`}
                  disabled={!contractCustomized}
                  onClick={restoreRecommendedContract}
                >Use recommended defaults</Button>
              </header>
              <dl>
                <div><dt>Action classes</dt><dd>{Object.keys(registry.data.actionClasses.classes).length} resolved states</dd></div>
                <div><dt>Final deliverables</dt><dd>{deliverableIds.length} selected</dd></div>
                <div><dt>Evidence requirements</dt><dd>{evidenceTypeIds.length} selected</dd></div>
                <div><dt>Safe stops</dt><dd>{registry.data.safeStops.mandatory.length} mandatory · {optionalSafeStopIds.length} optional</dd></div>
              </dl>
            </section>
            <label>Budget preset<TitaniumSelect value={form.budgetPresetId ?? template.budgetPreset} onChange={(event) => set("budgetPresetId", event.target.value as BudgetPresetId)}>{Object.values(registry.data.budgets).map((budget) => <option key={budget.id} value={budget.id}>{budget.label} — {budget.timeBudgetMinutes} min</option>)}</TitaniumSelect><span>{registry.data.budgets[(form.budgetPresetId === "custom" ? "standard" : form.budgetPresetId) ?? (template.budgetPreset === "custom" ? "standard" : template.budgetPreset)].description}</span></label>
            <label>Destructive-action policy<TitaniumSelect value={form.destructivePolicy} onChange={(event) => set("destructivePolicy", event.target.value as DestructiveActionPolicy)}><option value="prohibited">Prohibited</option><option value="validate_without_executing">Validate the path without executing it</option><option value="bounded_lab_only">Named disposable lab targets only</option></TitaniumSelect><span>Destructive and service-disruptive work defaults to prohibited.</span></label>
            {form.destructivePolicy === "bounded_lab_only" && <fieldset className="os-registry-checklist"><legend>Named disposable lab targets</legend>{boundedTargetOptions.map((target) => <label className="os-check-field" key={target.id}><input type="checkbox" checked={form.boundedDestructiveTargetIds.includes(target.id)} onChange={(event) => set("boundedDestructiveTargetIds", listToggle(form.boundedDestructiveTargetIds, target.id, event.target.checked))} /><span><strong>{target.value}</strong><small>{target.type === "host" ? "Exact authorized host" : "Named lab reference"} · {form.environmentClassification === "htb" ? "Hack The Box" : form.environmentClassification === "ctf" ? "CTF" : "local disposable lab"} · exact bounded target</small></span></label>)}{!disposableEnvironment && <p>Lab-only execution is unavailable because this mission is classified as a non-disposable environment. Return to Scope and explicitly choose Hack The Box, CTF, or Local disposable lab.</p>}{disposableEnvironment && boundedTargetOptions.length === 0 && <p>No exact host is available to bind. Supply one host or IP address; CIDRs, URLs, domains, cloud accounts, and engagement references cannot be destructive target bounds.</p>}</fieldset>}
            <details className="os-advanced-section"><summary>Action-class policy matrix · {Object.keys(registry.data.actionClasses.classes).length} classes</summary><div className="os-policy-matrix">{Object.values(registry.data.actionClasses.classes).map((action) => (
              <ActionPolicyRow
                key={action.id}
                action={action}
                journey={journey}
                state={form.actionPolicyOverrides[action.id] ?? action.policyState}
                onPolicyChange={setActionPolicy}
              />
            ))}</div></details>
            <details className="os-advanced-section"><summary>Final deliverables · {deliverableIds.length} selected</summary><div className="os-registry-checklist">{Object.values(registry.data.deliverables.deliverables).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={deliverableIds.includes(item.id)} onChange={(event) => set("deliverableIds", listToggle(deliverableIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.purpose}</small><small>{item.capability.availability} · {item.formats.join(", ")}</small></span></label>)}</div></details>
            <details className="os-advanced-section"><summary>Evidence requirements · {evidenceTypeIds.length} selected</summary><div className="os-registry-checklist"><p className="os-policy-note">{isAutonomous ? "Recommended defaults select only evidence the connected runtime can produce now. Unsupported types remain visible" : "Recommended defaults preserve the attributable proof this Guided assessment should capture, including results the operator may run or upload manually. Runtime availability remains visible"}, and mission preferences never weaken the immutable evidence required to verify a finding.</p>{Object.values(registry.data.evidenceTypes.types).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={evidenceTypeIds.includes(item.id)} onChange={(event) => set("evidenceTypeIds", listToggle(evidenceTypeIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.proves}</small><small>{evidenceAvailabilityExplanation(item, journey)}</small><small>Integrity: hash {item.immutableHashRequired ? "required" : "optional"} · chain of custody {item.chainOfCustodyRequired ? "required" : "optional"}</small></span></label>)}</div></details>
            <details className="os-advanced-section"><summary>Safe-stop behavior · {optionalSafeStopIds.length} mission stops</summary><div className="os-registry-checklist"><p className="os-policy-note">A safe stop preserves the checkpoint and explains why the mission cannot continue safely. Mandatory platform stops cannot be removed.</p>{registry.data.safeStops.optional.map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={optionalSafeStopIds.includes(item.id)} onChange={(event) => set("optionalSafeStopIds", listToggle(optionalSafeStopIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></label>)}<h3>Always enforced</h3>{registry.data.safeStops.mandatory.map((item) => <div className="os-mandatory-stop" key={item.id}><StatusPill status="enforced" /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></div>)}</div></details>
          </fieldset>}

          {isAutonomous && step === 3 && <fieldset>
            <legend>Specialist team and execution readiness</legend>
            <p className="os-field-intro">Choose the specialists allowed to receive work. Recommendations come from live agent, tool, MCP, provider, and model readiness—not a hard-coded UI roster.</p>
            {preflight ? <>
              <div className="os-inline-actions">
                <Button
                  type="button"
                  variant="quiet"
                  onClick={() => setSelectedSpecialists(preflight.execution.team.recommendedAgentIds)}
                >
                  Use recommended team
                </Button>
                <span>{selectedSpecialistIds.length} selected</span>
              </div>
              <div className="os-registry-checklist">
                {preflight.execution.team.candidates.map((agent) => <label className="os-check-field" key={agent.id}>
                  <input
                    type="checkbox"
                    disabled={!agent.compatible}
                    checked={selectedSpecialistIds.includes(agent.id)}
                    onChange={(event) => setSelectedSpecialists(
                      listToggle(selectedSpecialistIds, agent.id, event.target.checked),
                    )}
                  />
                  <span>
                    <strong>{agent.displayName}</strong>
                    <small>{agent.role}</small>
                    <small>{agent.capabilities.join(", ") || "No declared capabilities"}</small>
                    <small>{agent.runnableTools.length} reviewed tools · {agent.mcpServerIds.length} MCP servers · provider {agent.providerPolicy.defaultProvider ?? "runtime-selected"}</small>
                    {agent.incompatibilityReasons.map((reason) => <small key={reason}>{reason}</small>)}
                  </span>
                  <StatusPill status={agent.compatible ? agent.status : "unavailable"} />
                </label>)}
              </div>
              <MissionAgentModelAssignments
                idPrefix="autonomous-intake-team"
                agents={preflight.execution.team.candidates}
                selectedAgentIds={selectedSpecialistIds}
                receipts={preflight.execution.team.modelAssignments}
                explicitAssignments={form.agentModelAssignments}
                catalog={modelCatalogRequest.data}
                catalogUpdatedAt={modelCatalogRequest.updatedAt}
                catalogLoading={modelCatalogRequest.isLoading}
                catalogError={modelCatalogRequest.error}
                readinessStale={preflightStale}
                restoreLabel="Restore recommended models"
                restoreControlId="autonomous-intake-team-model-restore-recommended"
                onAssignmentsChange={setAgentModelAssignments}
                onRestore={() => setAgentModelAssignments(undefined)}
                onRetryCatalog={modelCatalogRequest.refresh}
              />
              <AutonomousPlanningSelectionEditor
                idPrefix="autonomous-intake-team"
                selection={form.planningSelection}
                agents={preflight.execution.team.candidates}
                catalog={modelCatalogRequest.data}
                catalogUpdatedAt={modelCatalogRequest.updatedAt}
                catalogLoading={modelCatalogRequest.isLoading}
                catalogError={modelCatalogRequest.error}
                readinessCheck={preflight.readiness.checks.find(
                  ({ id }) => id === "contract_planning_selection",
                )}
                readinessStale={preflightStale}
                onChange={setPlanningSelection}
                onRetryCatalog={modelCatalogRequest.refresh}
              />
              <h3>Provider enforcement paths</h3>
              <ul className="os-review-list">
                {preflight.execution.providers.map((provider) => <li key={provider.id}>
                  <StatusPill status={provider.compatible ? provider.status : "unavailable"} />
                  <span>
                    <strong>{provider.id}</strong>
                    <small>{provider.reason}</small>
                    <small>{provider.enforcesAutonomousBoundary ? "Local runtime enforcement available" : "Advisor/observe-only for this contract"}</small>
                  </span>
                </li>)}
              </ul>
            </> : <LoadingPanel label="Checking specialist, provider, and model readiness" />}
          </fieldset>}

          {isAutonomous && step === 4 && <fieldset><legend>Second Brain context</legend><p className="os-field-intro">Choose which reviewed memory domains the core agent may search. Ti-Scale retrieves only the smallest relevant set for each lifecycle hook, records every result in a Context Pack, and never treats historical reports as verified proof.</p>
            <fieldset className="os-registry-checklist"><legend>Memory scopes allowed for this mission</legend><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("confirmed_preferences")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "confirmed_preferences", event.target.checked))} /><span><strong>Confirmed operator preferences</strong><small>May adjust explanation depth, pace, and presentation; never authorization or safety policy.</small></span></label><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("verified_lessons")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "verified_lessons", event.target.checked))} /><span><strong>Verified operational lessons</strong><small>May inform planning, routing, evidence strategy, and bounded recovery.</small></span></label><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("confirmed_attack_knowledge")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "confirmed_attack_knowledge", event.target.checked))} /><span><strong>Confirmed historical attack knowledge</strong><small>May suggest matching technologies, procedures, failed paths, and recovery patterns. Reported outcomes remain clearly labeled and cannot prove success.</small></span></label><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("verified_attack_knowledge")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "verified_attack_knowledge", event.target.checked))} /><span><strong>Verified attack safety knowledge</strong><small>May enforce exact known-hazard gates and proven recovery constraints before a represented attack attempt.</small></span></label><label className="os-check-field"><input type="checkbox" disabled={!form.engagementId.trim()} checked={selectedMemoryScopes.includes("engagement_memory")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "engagement_memory", event.target.checked))} /><span><strong>Engagement-isolated knowledge</strong><small>{form.engagementId.trim() ? `Limited to ${form.engagementId.trim()}.` : "Add an existing engagement ID on Scope to enable this isolated memory domain."}</small></span></label></fieldset>
            {preflight ? <><div className="os-inline-actions"><Button type="button" variant="quiet" onClick={() => set("contextNodeIds", [])}>Use no retained context</Button><span>{selectedContextIds.length} selected</span></div>{preflight.context.candidates.length > 0 ? <div className="os-registry-checklist">{preflight.context.candidates.map((candidate: AutonomousContextCandidate) => <label className="os-check-field" key={candidate.id}><input type="checkbox" checked={selectedContextIds.includes(candidate.id)} onChange={(event) => set("contextNodeIds", listToggle(selectedContextIds, candidate.id, event.target.checked))} /><span><strong>{candidate.title}</strong><small>{candidate.summary}</small><small>{candidate.nodeType} · {candidate.lifecycleStatus} · {candidate.scope.kind}{candidate.scope.engagementId ? ` ${candidate.scope.engagementId}` : ""} · {candidate.sensitivity}</small><small>{Math.round(candidate.confidence * 100)}% confidence · {candidate.provenanceExplanation}</small></span></label>)}</div> : <p>No eligible confirmed memory or verified lesson was found. The run will record an empty Context Pack instead of inventing remembered context.</p>}{preflight.context.invalidSelectedNodeIds.length > 0 && <div className="os-validation-summary" role="alert"><strong>Unavailable memory was excluded</strong><p>{preflight.context.invalidSelectedNodeIds.join(", ")}</p></div>}<p className="os-policy-note">Memory may influence wording, planning, and tool preference; it can never expand authorization, weaken policy, or expose private context to an incompatible provider.</p></> : <LoadingPanel label="Loading scope-safe Second Brain context" />}
          </fieldset>}

          {step === reviewStep && <fieldset><legend>Review the resolved mission</legend><p className="os-field-intro">This is the exact server-normalized result. Inferred values are identified, and unsupported runtime paths remain launch blockers.</p>
            {resolved ? <>
              <dl className="os-review-grid"><div><dt>Journey</dt><dd>{resolved.request.journey === "autonomous" ? "Autonomous" : "Guided"}</dd></div>{autonomousOutcome && <div><dt>Completion promise</dt><dd>{autonomousOutcome.label}</dd></div>}<div><dt>Mission</dt><dd>{resolved.request.title}</dd></div><div><dt>Objective</dt><dd>{resolved.request.objective}</dd></div><div><dt>Targets</dt><dd>{resolved.normalizedTargets.filter((target) => !target.excluded).map((target) => target.value).join(", ")}</dd></div>{resolved.request.journey === "autonomous" && <div><dt>Environment</dt><dd>{resolved.request.authorization.environmentClassification === "htb" ? "Hack The Box — disposable lab" : resolved.request.authorization.environmentClassification === "ctf" ? "CTF — disposable lab" : resolved.request.authorization.environmentClassification === "local_disposable_lab" ? "Local disposable lab" : resolved.request.authorization.environmentClassification === "internal" ? "Internal environment — not disposable" : "Client or public environment — not disposable"}</dd></div>}<div><dt>Template</dt><dd>{template.label} v{resolved.template.version}</dd></div><div><dt>Budget</dt><dd>{resolved.budget.label} · {resolved.budget.timeBudgetMinutes} min · {resolved.budget.toolCallBudget} tool calls</dd></div><div><dt>Evidence storage</dt><dd>{bytes(resolved.budget.evidenceStorageBudgetBytes)}</dd></div><div><dt>Artifact storage</dt><dd>{bytes(resolved.budget.artifactStorageBudgetBytes)}</dd></div><div><dt>Evidence requirements</dt><dd>{resolved.evidenceTypeIds.length}</dd></div><div><dt>Deliverables</dt><dd>{resolved.deliverableIds.length}</dd></div>{resolved.request.journey === "guided" && <div><dt>First represented step</dt><dd>{resolvedGuidedFirstStepLabel}</dd></div>}{resolved.request.journey === "guided" && resolved.request.guidedLocalExploitIntelligence && resolvedGuidedLocalExploitQuery && <><div><dt>Local catalog query</dt><dd>{resolvedGuidedLocalExploitQuery.kind === "cve" ? resolvedGuidedLocalExploitQuery.cveId : [resolvedGuidedLocalExploitQuery.product, resolvedGuidedLocalExploitQuery.version, resolvedGuidedLocalExploitQuery.platform].filter(Boolean).join(" · ")}</dd></div><div><dt>Maximum catalog matches</dt><dd>{resolvedGuidedLocalExploitQuery.maximumResults}</dd></div><div><dt>Exact local binding</dt><dd><code>{registry.data.guidedLocalExploitIntelligence.toolId}</code></dd></div></>}{resolved.request.journey === "guided" && resolved.request.guidedWindowsIdentity && <><div><dt>Authentication</dt><dd>{resolved.request.guidedWindowsIdentity.authenticationMode === "anonymous" ? "Anonymous metadata read" : "Private credential reference"}</dd></div><div><dt>Exact local binding</dt><dd><code>{resolvedGuidedWindowsIdentityMode?.toolId ?? resolved.request.guidedWindowsIdentity.operation}</code></dd></div></>}{resolved.request.journey === "guided" && resolved.request.guidedReconnaissance?.mode === "tcp_service_scan" && <><div><dt>TCP port source</dt><dd>{resolved.request.guidedReconnaissance.portSelection.source === "preset" ? `${resolvedGuidedReconPreset?.label ?? resolved.request.guidedReconnaissance.portSelection.presetId} · ${resolved.request.guidedReconnaissance.portSelection.presetId} v${resolved.request.guidedReconnaissance.portSelection.presetVersion}` : "Custom operator list"}</dd></div><div><dt>Exact normalized TCP ports</dt><dd><code>{resolved.request.guidedReconnaissance.portSelection.ports.join(",")}</code></dd></div></>}</dl>
              {autonomousOutcome && <div className="os-guided-contract"><StatusPill status={autonomousOutcome.id === "complete_engagement" ? "enforced" : "ready"} /><div><strong>{autonomousOutcome.concisePromise}</strong><p>{autonomousOutcome.completionMeaning}</p>{autonomousOutcome.requiredTerminalSuccessCriteria.length > 0 && <small>{autonomousOutcome.requiredTerminalSuccessCriteria.length} mandatory terminal proofs · {autonomousOutcome.requiredActionClassIds.length} required execution classes</small>}</div></div>}
              {resolved.request.journey === "autonomous" && preflight && <MissionAgentModelAssignmentReview
                assignments={resolved.request.contract.agentModelAssignments}
                receipts={preflight.execution.team.modelAssignments}
                agents={preflight.execution.team.candidates}
              />}
              {resolved.request.journey === "autonomous" && <AutonomousPlanningSelectionReview
                selection={resolved.request.contract.planningSelection}
                catalog={modelCatalogRequest.data}
                readinessCheck={preflight?.readiness.checks.find(
                  ({ id }) => id === "contract_planning_selection",
                )}
              />}
              {resolved.request.journey === "guided" && resolved.request.guidedReconnaissance && selectedGuidedReconMode && <div className="os-guided-contract"><StatusPill status={selectedGuidedReconMode.readiness === "ready" ? "ready" : "unavailable"} /><div><strong>{selectedGuidedReconMode.readinessExplanation}</strong><p>{selectedGuidedReconMode.readiness === "ready" ? "If you allow agent execution, Ti-Scale will create one exact decision whose target and normalized ports cannot change after approval." : `${selectedGuidedReconMode.remediation} Launching now preserves this selection as the represented manual fallback.`}</p></div></div>}
              {resolved.request.journey === "guided" && resolved.request.guidedWindowsIdentity && resolvedGuidedWindowsIdentityMode && <div className="os-guided-contract"><StatusPill status={resolvedGuidedWindowsIdentityMode.readiness === "ready" ? "ready" : "unavailable"} /><div><strong>{resolvedGuidedWindowsIdentityMode.readinessExplanation}</strong><p>Ti-Scale will create one exact decision for this host, operation, authentication mode, and opaque reference. Any material change requires another decision. Raw output remains an Engagement Log record until explicitly promoted and verified.</p></div></div>}
              {resolved.request.journey === "guided" && resolved.request.guidedLocalExploitIntelligence && <div className="os-guided-contract"><StatusPill status={registry.data.guidedLocalExploitIntelligence.readiness === "ready" ? "ready" : "unavailable"} /><div><strong>{registry.data.guidedLocalExploitIntelligence.readinessExplanation}</strong><p>Ti-Scale will create one exact decision for this local catalog query. The binding contacts neither the approved target nor a public provider. Raw output remains in the Engagement Log, parsed matches remain unverified observations, and no evidence or finding is created automatically.</p></div></div>}
              <h3>Inferred by recommended defaults</h3><p>{resolved.inferredFields.length > 0 ? inferredFieldLabels(resolved.inferredFields) : "No values were inferred."}</p>
              {resolvedChecklist && <section className="os-resolved-contract-checklist" aria-label="Resolved operating contract checklist">
                <header><div><p className="os-eyebrow">Exact launch values</p><h3>Operating contract checklist</h3></div><p>These are the server-normalized values—not draft counts. Every source label identifies whether the operator changed the value.</p></header>
                <article className="os-contract-review-block os-contract-review-block--wide">
                  <div className="os-contract-review-heading"><h4>Action classes</h4><ChecklistSource source={resolvedChecklist.actionPolicy.source} /></div>
                  <div className="os-contract-review-policy-groups">{resolvedChecklist.actionPolicy.groups.map((group) => <div key={group.state}><strong>{group.label} · {group.items.length}</strong><ReviewChecklistItems items={group.items} emptyLabel="None" /></div>)}</div>
                </article>
                <article className="os-contract-review-block">
                  <div className="os-contract-review-heading"><h4>Final deliverables · {resolvedChecklist.deliverables.items.length}</h4><ChecklistSource source={resolvedChecklist.deliverables.source} /></div>
                  <ReviewChecklistItems items={resolvedChecklist.deliverables.items} emptyLabel="No optional deliverables selected." />
                </article>
                <article className="os-contract-review-block">
                  <div className="os-contract-review-heading"><h4>Evidence requirements · {resolvedChecklist.evidence.items.length}</h4><ChecklistSource source={resolvedChecklist.evidence.source} /></div>
                  <ReviewChecklistItems items={resolvedChecklist.evidence.items} emptyLabel="No optional evidence preferences selected; immutable finding evidence still applies." />
                </article>
                <article className="os-contract-review-block">
                  <div className="os-contract-review-heading"><h4>Mission-specific safe stops · {resolvedChecklist.optionalSafeStops.items.length}</h4><ChecklistSource source={resolvedChecklist.optionalSafeStops.source} /></div>
                  <ReviewChecklistItems items={resolvedChecklist.optionalSafeStops.items} emptyLabel="No optional mission-specific safe stops selected." />
                </article>
                <article className="os-contract-review-block">
                  <div className="os-contract-review-heading"><h4>Mandatory platform stops · {resolvedChecklist.mandatorySafeStops.items.length}</h4><ChecklistSource source={resolvedChecklist.mandatorySafeStops.source} /></div>
                  <ReviewChecklistItems items={resolvedChecklist.mandatorySafeStops.items} emptyLabel="No mandatory platform stop was returned; launch must remain blocked." />
                </article>
                <article className="os-contract-review-block os-contract-review-block--wide">
                  <div className="os-contract-review-heading"><h4>Operational budget</h4><ChecklistSource source={resolvedChecklist.budget.source} /></div><p>{resolvedChecklist.budget.label}</p>
                </article>
              </section>}
              {resolved.limitations.length > 0 && <><h3>Current limitations</h3><ul className="os-review-list">{resolved.limitations.map((limitation) => <li key={limitation}><StatusPill status="blocked" /><span><strong>{limitation}</strong></span></li>)}</ul></>}
            </> : <LoadingPanel label="Resolving the mission contract" />}
            {preflight && <LiveAutonomousReadinessReview
              preflight={preflight}
              runtime={runtimeReadinessRequest.data}
              runtimePending={runtimeReadinessRequest.isLoading || runtimeReadinessRequest.isRefreshing}
              preflightRefreshing={preflightRuntimeChanged && preflightRefreshState !== "failed"}
              preflightRefreshFailed={preflightRefreshState === "failed"}
            />}
            {!isAutonomous && <div className="os-guided-contract"><StatusPill status="guided" /><div><strong>Explain → recommend → choose → observe → interpret → record → advance</strong><p>Every consequential agent-run step requires one exact represented decision.</p></div></div>}
          </fieldset>}

          {validation.length > 0 && <div className="os-validation-summary" role="alert"><strong>Resolve before continuing</strong><ul>{validation.map((item) => <li key={item}>{item}</li>)}</ul></div>}
          {error && <ErrorPanel title={error instanceof ApiError && error.status === 409 ? "Mission is not ready" : "Mission intake could not complete"} error={error} />}
          <div className="os-form-actions">{step > 0 ? <Button type="button" variant="quiet" onClick={() => { setValidation([]); setStep((current) => current - 1); }}>Back</Button> : <ButtonLink href="/missions/new" variant="quiet">Back</ButtonLink>}<span />{step < reviewStep ? <Button type="button" disabled={working} onClick={() => void advance()}>{working ? "Resolving defaults…" : "Continue"}</Button> : <Button data-control-id={isAutonomous ? "autonomous-intake-review-launch" : "guided-intake-review-launch"} type="submit" disabled={working || launchBlocked}>{working ? "Creating mission…" : isAutonomous ? autonomousOutcome?.id === "complete_engagement" ? "Launch Complete Autonomous Engagement" : "Launch Autonomous Assessment" : "Start Guided Mission"}</Button>}</div>
        </Card>
      </form>
      <aside className="os-intake-summary" aria-label="Current mission contract summary"><p className="os-eyebrow">Contract summary</p><h2>{form.title.trim() || resolved?.request.title || template.label}</h2><dl><div><dt>Journey</dt><dd>{isAutonomous ? "Autonomous" : "Guided"}</dd></div><div><dt>Authorized targets</dt><dd>{lines(form.targets).length}</dd></div><div><dt>Template</dt><dd>{template.label}</dd></div>{!isAutonomous && <div><dt>First represented step</dt><dd>{currentGuidedFirstStepLabel}</dd></div>}{isAutonomous && <div><dt>Planning route</dt><dd>{form.planningSelection.route === "local_deterministic" ? "Local deterministic" : `Provider advisory · ${form.planningSelection.agentId}`}</dd></div>}{isAutonomous && <div><dt>Specialist models</dt><dd>{form.agentModelAssignments?.length ? `${form.agentModelAssignments.length} mission overrides` : "Recommended or inherited"}</dd></div>}<div><dt>Action policy</dt><dd>{Object.keys(form.actionPolicyOverrides).length ? `${Object.keys(form.actionPolicyOverrides).length} overrides` : "Recommended defaults"}</dd></div><div><dt>Evidence</dt><dd>{evidenceTypeIds.length} types</dd></div><div><dt>Deliverables</dt><dd>{deliverableIds.length}</dd></div><div><dt>Safe stops</dt><dd>{registry.data.safeStops.mandatory.length} mandatory · {optionalSafeStopIds.length} optional</dd></div><div><dt>Runtime source</dt><dd>{registry.data.source.status}</dd></div></dl>{resolved?.inferredFields.length ? <p><strong>Inferred:</strong> {inferredFieldLabels(resolved.inferredFields)}</p> : <p>Use recommended defaults to resolve the full mission contract.</p>}</aside>
    </div>
  </div>;
}
