import { type FormEvent, useMemo, useRef, useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import {
  createMission,
  fetchMissionIntakeRegistry,
  preflightAutonomousMission,
  resolveMissionIntake,
} from "../../data/api/commandOs";
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
import type {
  AutonomousContextCandidate,
  AutonomousMissionPreflight,
  Journey,
} from "../../domain/types/commandOs";
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
import { lines, requestKey, safeNextUrl } from "./formUtils";

const AUTONOMOUS_STEPS = ["Scope", "Outcome", "Contract", "Team", "Context", "Review"] as const;
const GUIDED_STEPS = ["Scope", "Outcome", "Contract", "Review"] as const;

interface IntakeFormState {
  readonly templateId: MissionTemplateId;
  readonly targets: string;
  readonly excludedTargets: string;
  readonly authorizationAcknowledged: boolean;
  readonly title: string;
  readonly objective: string;
  readonly engagementId: string;
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
  readonly memoryScopes?: readonly string[];
  readonly contextNodeIds?: readonly string[];
  readonly explanationDepth: "concise" | "balanced" | "deep";
  readonly executionPreference: "manual" | "single_step_agent";
}

const INITIAL_FORM: IntakeFormState = {
  templateId: "safe_recon",
  targets: "",
  excludedTargets: "",
  authorizationAcknowledged: false,
  title: "",
  objective: "",
  engagementId: "",
  customSuccessCriteria: "",
  destructivePolicy: "prohibited",
  boundedDestructiveTargetIds: [],
  actionPolicyOverrides: {},
  explanationDepth: "balanced",
  executionPreference: "manual",
};

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

function evidenceAvailabilityExplanation(item: IntakeEvidenceType): string {
  if (item.capability.availability === "supported") {
    return "Supported now by the connected runtime and eligible for recommended defaults.";
  }
  if (item.capability.availability === "unavailable") {
    return "A producer is registered but is not ready now. Recommended defaults leave this unchecked until readiness returns.";
  }
  return "No connected runtime evidence kind or producer declares this type. It remains visible for review but is not selected by recommended defaults.";
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
  const [preflightStale, setPreflightStale] = useState(true);
  const [error, setError] = useState<Error>();
  const [validation, setValidation] = useState<string[]>([]);
  const [working, setWorking] = useState(false);
  const registry = useQuery(
    `mission-intake:${journey}:${form.templateId}`,
    (signal) => fetchMissionIntakeRegistry(journey, form.templateId, signal),
    { staleTime: 30_000 },
  );
  const template = registry.data?.templates.templates[form.templateId];
  const successCriteria = selectedOrDefault(form.successCriteria, template?.successCriteria ?? []);
  const deliverableIds = selectedOrDefault(form.deliverableIds, template?.recommendedDeliverableIds ?? []);
  const evidenceTypeIds = selectedOrDefault(form.evidenceTypeIds, template?.recommendedEvidenceTypeIds ?? []);
  const optionalSafeStopIds = selectedOrDefault(form.optionalSafeStopIds, template?.recommendedOptionalSafeStops ?? []);
  const selectedSpecialistIds = form.specialistAgentIds ?? preflight?.execution.team.selectedAgentIds ?? [];
  const selectedContextIds = form.contextNodeIds ?? [];
  const selectedMemoryScopes = form.memoryScopes
    ?? (resolved?.request.journey === "autonomous" ? resolved.request.contract.memoryScopes : []);

  const set = <K extends keyof IntakeFormState>(key: K, value: IntakeFormState[K]) => {
    setResolved(undefined);
    setPreflightStale(true);
    setError(undefined);
    if (key === "targets" || key === "excludedTargets") setNormalizedTargetOptions([]);
    setForm((current) => ({ ...current, [key]: value }));
  };

  const templateOptions = useMemo(
    () => Object.values(registry.data?.templates.templates ?? {}).filter((candidate) => candidate.supportedJourneys.includes(journey)),
    [journey, registry.data],
  );

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
    successCriteria: [...successCriteria, ...lines(form.customSuccessCriteria)],
    deliverableIds: [...deliverableIds],
    evidenceTypeIds: [...evidenceTypeIds],
    optionalSafeStopIds: [...optionalSafeStopIds],
    ...(form.budgetPresetId ? { budgetPresetId: form.budgetPresetId } : {}),
    destructivePolicy: form.destructivePolicy,
    boundedDestructiveTargetIds: [...form.boundedDestructiveTargetIds],
    actionPolicyOverrides: { ...form.actionPolicyOverrides },
    ...(journey === "autonomous" && form.specialistAgentIds !== undefined ? {
      specialistAgentIds: [...form.specialistAgentIds],
    } : {}),
    ...(journey === "autonomous" && (form.contextNodeIds !== undefined || form.memoryScopes !== undefined) ? {
      contextNodeIds: [...(form.contextNodeIds ?? [])],
      memoryScopes: [...selectedMemoryScopes],
    } : {}),
    ...(journey === "guided" ? {
      explanationDepth: form.explanationDepth,
      executionPreference: form.executionPreference,
    } : {}),
  });

  const resolveCurrent = async (): Promise<ResolvedMissionIntake | undefined> => {
    const issues: string[] = [];
    if (lines(form.targets).length === 0) issues.push("Add at least one authorized target or environment reference.");
    if (!form.authorizationAcknowledged) issues.push("Confirm that you are authorized to assess the supplied target scope.");
    if (issues.length > 0) {
      setValidation(issues);
      return undefined;
    }
    setWorking(true);
    setError(undefined);
    try {
      const result = await resolveMissionIntake(intakeRequest());
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
        const checked = await preflightAutonomousMission(result.request);
        setPreflight(checked);
        setPreflightStale(false);
        if (step === 2) {
          const recommendedSpecialists = checked.execution.team.recommendedAgentIds;
          const seededSpecialists = form.specialistAgentIds ?? recommendedSpecialists;
          // The preview may contain hundreds of eligible memories. Eligibility is
          // not relevance, so never opt every candidate into a public-provider
          // Context Pack. Preserve only server-selected IDs; the operator can add
          // individual memories on the explicit Context step.
          const seededContext = form.contextNodeIds ?? checked.context.selectedNodeIds;
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

  const launch = async (event: FormEvent) => {
    event.preventDefault();
    const current = resolved ?? await resolveCurrent();
    if (!current) return;
    let request = current.request;
    if (journey === "autonomous") {
      if (!isAutonomousResolved(current) || !preflight || preflightStale || preflight.readiness.status === "blocked") {
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

  const launchBlocked = isAutonomous && (!preflight || preflightStale || preflight.readiness.status === "blocked");
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
            <label>Mission template<select value={form.templateId} onChange={(event) => {
              setResolved(undefined); setPreflight(undefined); setForm((current) => ({ ...current, templateId: event.target.value as MissionTemplateId, successCriteria: undefined, deliverableIds: undefined, evidenceTypeIds: undefined, optionalSafeStopIds: undefined, budgetPresetId: undefined, actionPolicyOverrides: {}, destructivePolicy: "prohibited", boundedDestructiveTargetIds: [] }));
            }}>{templateOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select><span>{template.summary}</span></label>
            <label>Authorized targets or environment references<textarea required rows={5} value={form.targets} onChange={(event) => set("targets", event.target.value)} placeholder="https://portal.example.test&#10;10.10.10.0/24" /><span>One host, CIDR, URL, domain, cloud reference, or named lab per line.</span></label>
            <FieldHelp definition={field(registry.data, "targets")} />
            <details className="os-advanced-section"><summary>Excluded targets and engagement boundary</summary><div className="os-details-content"><label>Explicitly excluded targets <span>Optional · one per line</span><textarea rows={3} value={form.excludedTargets} onChange={(event) => set("excludedTargets", event.target.value)} placeholder="admin.portal.example.test" /></label><label>Existing engagement ID <span>Optional</span><input value={form.engagementId} onChange={(event) => set("engagementId", event.target.value)} placeholder="eng_customer-portal_q3" /></label><FieldHelp definition={field(registry.data, "engagementId")} /></div></details>
            <label className="os-check-field"><input type="checkbox" checked={form.authorizationAcknowledged} onChange={(event) => set("authorizationAcknowledged", event.target.checked)} /><span><strong>I confirm these targets and the selected action policy are authorized</strong><small>Authorization is required for every mission and is never inferred from prior work.</small></span></label>
          </fieldset>}

          {step === 1 && <fieldset><legend>Outcome and collaboration</legend><p className="os-field-intro">Recommended defaults are complete and editable. Optional blank fields do not block launch.</p>
            <label>Mission title <span>Optional · generated from template, target, and date</span><input value={form.title} onChange={(event) => set("title", event.target.value)} placeholder="Q3 External Web Assessment — Customer Portal" /></label><FieldHelp definition={field(registry.data, "title")} />
            <label>Authorized objective <span>Optional · generated conservatively inside supplied scope</span><textarea rows={7} value={form.objective} onChange={(event) => set("objective", event.target.value)} placeholder={template.objectivePattern} /></label><FieldHelp definition={field(registry.data, "objective")} />
            <fieldset className="os-registry-checklist"><legend>Recommended success criteria <span>Optional</span></legend>{template.successCriteria.map((criterion) => <label className="os-check-field" key={criterion}><input type="checkbox" checked={successCriteria.includes(criterion)} onChange={(event) => set("successCriteria", listToggle(successCriteria, criterion, event.target.checked))} /><span><strong>{criterion}</strong><small>Used by completion evaluation; partial and not-applicable outcomes remain visible.</small></span></label>)}</fieldset>
            <label>Additional success criteria <span>Optional · one per line</span><textarea rows={3} value={form.customSuccessCriteria} onChange={(event) => set("customSuccessCriteria", event.target.value)} placeholder="At least one safe authorized attack path is validated when prerequisites exist." /></label>
            {!isAutonomous && <><label>Explanation depth<select value={form.explanationDepth} onChange={(event) => set("explanationDepth", event.target.value as IntakeFormState["explanationDepth"])}><option value="concise">Concise</option><option value="balanced">Balanced</option><option value="deep">Deep</option></select></label><fieldset className="os-choice-group"><legend>Execution preference</legend><label className="os-radio-card"><input type="radio" name="execution-preference" checked={form.executionPreference === "manual"} onChange={() => set("executionPreference", "manual")} /><span><strong>I run commands manually</strong><small>Ti-Scale explains and interprets the result you provide.</small></span></label><label className="os-radio-card"><input type="radio" name="execution-preference" checked={form.executionPreference === "single_step_agent"} onChange={() => set("executionPreference", "single_step_agent")} /><span><strong>Allow one represented agent step</strong><small>Each exact action and normalized parameter set still requires a deliberate decision.</small></span></label></fieldset></>}
          </fieldset>}

          {step === 2 && <fieldset><legend>{isAutonomous ? "Autonomous operating contract" : "Guided proposal boundaries"}</legend><p className="os-field-intro">Structured registries replace policy prose. Advanced controls remain optional and resolve from the selected template.</p>
            <label>Budget preset<select value={form.budgetPresetId ?? template.budgetPreset} onChange={(event) => set("budgetPresetId", event.target.value as BudgetPresetId)}>{Object.values(registry.data.budgets).map((budget) => <option key={budget.id} value={budget.id}>{budget.label} — {budget.timeBudgetMinutes} min</option>)}</select><span>{registry.data.budgets[(form.budgetPresetId === "custom" ? "standard" : form.budgetPresetId) ?? (template.budgetPreset === "custom" ? "standard" : template.budgetPreset)].description}</span></label>
            <label>Destructive-action policy<select value={form.destructivePolicy} onChange={(event) => set("destructivePolicy", event.target.value as DestructiveActionPolicy)}><option value="prohibited">Prohibited</option><option value="validate_without_executing">Validate the path without executing it</option><option value="bounded_lab_only">Named disposable lab targets only</option></select><span>Destructive and service-disruptive work defaults to prohibited.</span></label>
            {form.destructivePolicy === "bounded_lab_only" && <fieldset className="os-registry-checklist"><legend>Named disposable lab targets</legend>{normalizedTargetOptions.filter((target) => !target.excluded && target.type === "lab_environment").map((target) => <label className="os-check-field" key={target.id}><input type="checkbox" checked={form.boundedDestructiveTargetIds.includes(target.id)} onChange={(event) => set("boundedDestructiveTargetIds", listToggle(form.boundedDestructiveTargetIds, target.id, event.target.checked))} /><span><strong>{target.value}</strong><small>Disposable lab environment · exact bounded target</small></span></label>)}{normalizedTargetOptions.filter((target) => !target.excluded && target.type === "lab_environment").length === 0 && <p>No disposable lab target is present. Add a target such as <code>lab:customer-portal-sandbox</code>, resolve the scope, then select it here.</p>}</fieldset>}
            <details className="os-advanced-section"><summary>Action-class policy matrix · {Object.keys(registry.data.actionClasses.classes).length} classes</summary><div className="os-policy-matrix">{Object.values(registry.data.actionClasses.classes).map((action) => {
              const state = form.actionPolicyOverrides[action.id] ?? action.policyState;
              return <article key={action.id} className="os-policy-row"><div><strong>{action.label}</strong><p>{action.plainLanguageDescription}</p><small>{action.capability.availableAgentIds.length} ready agents · {action.capability.availableToolIds.length} ready tools · {action.capability.enforcedProviderModelRefs.length} enforcing models</small></div><StatusPill status={action.capability.availability} /><label><span>Mission state</span><select aria-label={`${action.label} policy`} value={state} onChange={(event) => set("actionPolicyOverrides", { ...form.actionPolicyOverrides, [action.id]: event.target.value as ActionPolicyState })}><option value="pre_authorized">Pre-authorized</option><option value="guided_only">Guided only / not autonomous</option><option value="prohibited">Prohibited</option><option value="inherited_default">Inherited default</option></select></label>{action.launchBlockingReasons.length > 0 && <ul>{action.launchBlockingReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}</article>;
            })}</div></details>
            <details className="os-advanced-section"><summary>Final deliverables · {deliverableIds.length} selected</summary><div className="os-registry-checklist">{Object.values(registry.data.deliverables.deliverables).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={deliverableIds.includes(item.id)} onChange={(event) => set("deliverableIds", listToggle(deliverableIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.purpose}</small><small>{item.capability.availability} · {item.formats.join(", ")}</small></span></label>)}</div></details>
            <details className="os-advanced-section"><summary>Evidence requirements · {evidenceTypeIds.length} selected</summary><div className="os-registry-checklist"><p className="os-policy-note">Recommended defaults select only evidence the connected runtime can produce now. Unsupported types remain visible, and mission preferences never weaken the immutable evidence required to verify a finding.</p>{Object.values(registry.data.evidenceTypes.types).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={evidenceTypeIds.includes(item.id)} onChange={(event) => set("evidenceTypeIds", listToggle(evidenceTypeIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.proves}</small><small>{evidenceAvailabilityExplanation(item)}</small><small>Integrity: hash {item.immutableHashRequired ? "required" : "optional"} · chain of custody {item.chainOfCustodyRequired ? "required" : "optional"}</small></span></label>)}</div></details>
            <details className="os-advanced-section"><summary>Safe-stop behavior · {optionalSafeStopIds.length} mission stops</summary><div className="os-registry-checklist"><p className="os-policy-note">A safe stop preserves the checkpoint and explains why the mission cannot continue safely. Mandatory platform stops cannot be removed.</p>{registry.data.safeStops.optional.map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" checked={optionalSafeStopIds.includes(item.id)} onChange={(event) => set("optionalSafeStopIds", listToggle(optionalSafeStopIds, item.id, event.target.checked))} /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></label>)}<h3>Always enforced</h3>{registry.data.safeStops.mandatory.map((item) => <div className="os-mandatory-stop" key={item.id}><StatusPill status="enforced" /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></div>)}</div></details>
          </fieldset>}

          {isAutonomous && step === 3 && <fieldset><legend>Specialist team and execution readiness</legend><p className="os-field-intro">Choose the specialists allowed to receive work. Recommendations come from live agent, tool, MCP, and provider readiness—not a hard-coded UI roster.</p>
            {preflight ? <><div className="os-inline-actions"><Button type="button" variant="quiet" onClick={() => set("specialistAgentIds", preflight.execution.team.recommendedAgentIds)}>Use recommended team</Button><span>{selectedSpecialistIds.length} selected</span></div><div className="os-registry-checklist">{preflight.execution.team.candidates.map((agent) => <label className="os-check-field" key={agent.id}><input type="checkbox" disabled={!agent.compatible} checked={selectedSpecialistIds.includes(agent.id)} onChange={(event) => set("specialistAgentIds", listToggle(selectedSpecialistIds, agent.id, event.target.checked))} /><span><strong>{agent.displayName}</strong><small>{agent.role}</small><small>{agent.capabilities.join(", ") || "No declared capabilities"}</small><small>{agent.runnableTools.length} reviewed tools · {agent.mcpServerIds.length} MCP servers · provider {agent.providerPolicy.defaultProvider ?? "runtime-selected"}</small>{agent.incompatibilityReasons.map((reason) => <small key={reason}>{reason}</small>)}</span><StatusPill status={agent.compatible ? agent.status : "unavailable"} /></label>)}</div><h3>Provider enforcement paths</h3><ul className="os-review-list">{preflight.execution.providers.map((provider) => <li key={provider.id}><StatusPill status={provider.compatible ? provider.status : "unavailable"} /><span><strong>{provider.id}</strong><small>{provider.reason}</small><small>{provider.enforcesAutonomousBoundary ? "Local runtime enforcement available" : "Advisor/observe-only for this contract"}</small></span></li>)}</ul></> : <LoadingPanel label="Checking specialist and provider readiness" />}
          </fieldset>}

          {isAutonomous && step === 4 && <fieldset><legend>Second Brain context</legend><p className="os-field-intro">Select the smallest useful set of confirmed preferences and verified lessons. Eligible memories are not selected automatically, and local-only sensitivity remains visible.</p>
            <fieldset className="os-registry-checklist"><legend>Memory scopes allowed for this mission</legend><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("confirmed_preferences")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "confirmed_preferences", event.target.checked))} /><span><strong>Confirmed operator preferences</strong><small>May adjust explanation depth, pace, and presentation; never authorization or safety policy.</small></span></label><label className="os-check-field"><input type="checkbox" checked={selectedMemoryScopes.includes("verified_lessons")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "verified_lessons", event.target.checked))} /><span><strong>Verified operational lessons</strong><small>May inform planning, routing, evidence strategy, and bounded recovery.</small></span></label><label className="os-check-field"><input type="checkbox" disabled={!form.engagementId.trim()} checked={selectedMemoryScopes.includes("engagement_memory")} onChange={(event) => set("memoryScopes", listToggle(selectedMemoryScopes, "engagement_memory", event.target.checked))} /><span><strong>Engagement-isolated knowledge</strong><small>{form.engagementId.trim() ? `Limited to ${form.engagementId.trim()}.` : "Add an existing engagement ID on Scope to enable this isolated memory domain."}</small></span></label></fieldset>
            {preflight ? <><div className="os-inline-actions"><Button type="button" variant="quiet" onClick={() => set("contextNodeIds", [])}>Use no retained context</Button><span>{selectedContextIds.length} selected</span></div>{preflight.context.candidates.length > 0 ? <div className="os-registry-checklist">{preflight.context.candidates.map((candidate: AutonomousContextCandidate) => <label className="os-check-field" key={candidate.id}><input type="checkbox" checked={selectedContextIds.includes(candidate.id)} onChange={(event) => set("contextNodeIds", listToggle(selectedContextIds, candidate.id, event.target.checked))} /><span><strong>{candidate.title}</strong><small>{candidate.summary}</small><small>{candidate.nodeType} · {candidate.lifecycleStatus} · {candidate.scope.kind}{candidate.scope.engagementId ? ` ${candidate.scope.engagementId}` : ""} · {candidate.sensitivity}</small><small>{Math.round(candidate.confidence * 100)}% confidence · {candidate.provenanceExplanation}</small></span></label>)}</div> : <p>No eligible confirmed memory or verified lesson was found. The run will record an empty Context Pack instead of inventing remembered context.</p>}{preflight.context.invalidSelectedNodeIds.length > 0 && <div className="os-validation-summary" role="alert"><strong>Unavailable memory was excluded</strong><p>{preflight.context.invalidSelectedNodeIds.join(", ")}</p></div>}<p className="os-policy-note">Memory may influence wording, planning, and tool preference; it can never expand authorization, weaken policy, or expose private context to an incompatible provider.</p></> : <LoadingPanel label="Loading scope-safe Second Brain context" />}
          </fieldset>}

          {step === reviewStep && <fieldset><legend>Review the resolved mission</legend><p className="os-field-intro">This is the exact server-normalized result. Inferred values are identified, and unsupported runtime paths remain launch blockers.</p>
            {resolved ? <><dl className="os-review-grid"><div><dt>Journey</dt><dd>{resolved.request.journey === "autonomous" ? "Autonomous" : "Guided"}</dd></div><div><dt>Mission</dt><dd>{resolved.request.title}</dd></div><div><dt>Objective</dt><dd>{resolved.request.objective}</dd></div><div><dt>Targets</dt><dd>{resolved.normalizedTargets.filter((target) => !target.excluded).map((target) => target.value).join(", ")}</dd></div><div><dt>Template</dt><dd>{template.label} v{resolved.template.version}</dd></div><div><dt>Budget</dt><dd>{resolved.budget.label} · {resolved.budget.timeBudgetMinutes} min · {resolved.budget.toolCallBudget} tool calls</dd></div><div><dt>Evidence storage</dt><dd>{bytes(resolved.budget.evidenceStorageBudgetBytes)}</dd></div><div><dt>Artifact storage</dt><dd>{bytes(resolved.budget.artifactStorageBudgetBytes)}</dd></div><div><dt>Evidence requirements</dt><dd>{resolved.evidenceTypeIds.length}</dd></div><div><dt>Deliverables</dt><dd>{resolved.deliverableIds.length}</dd></div></dl><h3>Inferred by recommended defaults</h3><p>{resolved.inferredFields.length > 0 ? resolved.inferredFields.join(", ") : "No values were inferred."}</p>{resolved.limitations.length > 0 && <><h3>Current limitations</h3><ul className="os-review-list">{resolved.limitations.map((limitation) => <li key={limitation}><StatusPill status="blocked" /><span><strong>{limitation}</strong></span></li>)}</ul></>}</> : <LoadingPanel label="Resolving the mission contract" />}
            {preflight && <><div className="os-readiness-summary"><span><strong>{preflight.readiness.score}</strong>/100</span><div><h3>{preflight.readiness.status}</h3><p>{preflight.readiness.checks.filter((check) => check.status === "fail").length} launch blockers</p></div><StatusPill status={preflight.readiness.status} /></div><ul className="os-review-list">{preflight.readiness.checks.map((check) => <li key={check.id}><StatusPill status={check.status} /><span><strong>{check.label}</strong><small>{check.impact}</small>{check.remediation && check.status !== "pass" && <small>{check.remediation}</small>}</span></li>)}</ul><dl className="os-review-grid"><div><dt>Contract version</dt><dd>{preflight.contract.version}</dd></div><div><dt>Contract SHA-256</dt><dd className="os-mono">{preflight.contract.hash}</dd></div><div><dt>Compatible providers</dt><dd>{preflight.execution.providers.filter((provider) => provider.compatible).length}</dd></div><div><dt>Signed specialists</dt><dd>{preflight.execution.team.effectiveAgentIds.length}</dd></div></dl></>}
            {!isAutonomous && <div className="os-guided-contract"><StatusPill status="guided" /><div><strong>Explain → recommend → choose → observe → interpret → record → advance</strong><p>Every consequential agent-run step requires one exact represented decision.</p></div></div>}
          </fieldset>}

          {validation.length > 0 && <div className="os-validation-summary" role="alert"><strong>Resolve before continuing</strong><ul>{validation.map((item) => <li key={item}>{item}</li>)}</ul></div>}
          {error && <ErrorPanel title={error instanceof ApiError && error.status === 409 ? "Mission is not ready" : "Mission intake could not complete"} error={error} />}
          <div className="os-form-actions">{step > 0 ? <Button type="button" variant="quiet" onClick={() => { setValidation([]); setStep((current) => current - 1); }}>Back</Button> : <ButtonLink href="/missions/new" variant="quiet">Back</ButtonLink>}<span />{step < reviewStep ? <Button type="button" disabled={working} onClick={() => void advance()}>{working ? "Resolving defaults…" : "Continue"}</Button> : <Button type="submit" disabled={working || launchBlocked}>{working ? "Creating mission…" : isAutonomous ? "Launch Autonomous Mission" : "Start Guided Mission"}</Button>}</div>
        </Card>
      </form>
      <aside className="os-intake-summary" aria-label="Current mission contract summary"><p className="os-eyebrow">Contract summary</p><h2>{form.title.trim() || resolved?.request.title || template.label}</h2><dl><div><dt>Journey</dt><dd>{isAutonomous ? "Autonomous" : "Guided"}</dd></div><div><dt>Authorized targets</dt><dd>{lines(form.targets).length}</dd></div><div><dt>Template</dt><dd>{template.label}</dd></div><div><dt>Action policy</dt><dd>{Object.keys(form.actionPolicyOverrides).length ? `${Object.keys(form.actionPolicyOverrides).length} overrides` : "Recommended defaults"}</dd></div><div><dt>Evidence</dt><dd>{evidenceTypeIds.length} types</dd></div><div><dt>Deliverables</dt><dd>{deliverableIds.length}</dd></div><div><dt>Safe stops</dt><dd>{registry.data.safeStops.mandatory.length} mandatory · {optionalSafeStopIds.length} optional</dd></div><div><dt>Runtime source</dt><dd>{registry.data.source.status}</dd></div></dl>{resolved?.inferredFields.length ? <p><strong>Inferred:</strong> {resolved.inferredFields.join(", ")}</p> : <p>Use recommended defaults to resolve the full mission contract.</p>}</aside>
    </div>
  </div>;
}
