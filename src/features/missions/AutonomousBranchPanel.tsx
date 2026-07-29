import { type FormEvent, useEffect, useRef, useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import {
  createAutonomousBranch,
  fetchAutonomousBranchContext,
  fetchMissionIntakeRegistry,
  preflightAutonomousBranch,
} from "../../data/api/commandOs";
import { fetchModelCatalog } from "../../data/api/modelConfiguration";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import { runtimeV2Api } from "../../data/api/runtimeV2";
import type {
  AutonomousBranchMode,
  AutonomousBranchPreflight,
  AutonomousAgentModelAssignment,
  AutonomousMissionRequest,
  AutonomousPlanningSelection,
} from "../../domain/types/commandOs";
import type { ActionPolicyState, IntakeRegistrySnapshot } from "../../domain/types/intake";
import type { RuntimeRun } from "../../domain/types/runtimeV2";
import { Button, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import {
  MissionAgentModelAssignmentReview,
  MissionAgentModelAssignments,
} from "./MissionAgentModelAssignments";
import {
  AutonomousPlanningSelectionEditor,
  AutonomousPlanningSelectionReview,
} from "./AutonomousPlanningSelection";
import { resolvedPlanningSelection } from "./autonomousPlanningSelectionState";
import { filterAgentModelAssignments } from "./missionModelAssignmentState";
import { KeyValueGrid, useActionState } from "../runs/OperationalSurface";
import {
  projectAutonomousRegistryFields,
  registryFieldsFromAutonomousRequest,
  type AutonomousBranchRegistryFields,
} from "./autonomousBranchContract";
import { lines, requestKey, safeNextUrl } from "./formUtils";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

interface AmendmentForm {
  title: string;
  objective: string;
  successCriteria: string;
  engagementId: string;
  allowedTargets: string;
  prohibitedTargets: string;
  timeWindow: string;
  dataHandling: string;
  destructivePolicy: "prohibited" | "validate_without_executing" | "bounded_lab_only";
  boundedDestructiveTargets: readonly string[];
  timeBudgetMinutes: string;
  tokenBudget: string;
  costBudget: string;
  retryBudget: string;
  replanBudget: string;
  concurrencyLimit: string;
  evidenceStorageBudgetMb: string;
  artifactStorageBudgetMb: string;
  specialistAgentIds: string;
  agentModelAssignments: readonly AutonomousAgentModelAssignment[];
  planningSelection: AutonomousPlanningSelection;
  memoryScopes: string;
  contextNodeIds: string;
  registryFields: AutonomousBranchRegistryFields;
}

function formFromRequest(request: AutonomousMissionRequest, registry: IntakeRegistrySnapshot): AmendmentForm {
  return {
    title: request.title,
    objective: request.objective,
    successCriteria: request.successCriteria.join("\n"),
    engagementId: request.authorization.engagementId ?? "",
    allowedTargets: request.authorization.allowedTargets.join("\n"),
    prohibitedTargets: request.authorization.prohibitedTargets.join("\n"),
    timeWindow: request.authorization.timeWindow ?? "",
    dataHandling: request.authorization.dataHandling ?? "",
    destructivePolicy: request.contract.destructivePolicy,
    boundedDestructiveTargets: request.contract.boundedDestructiveTargets ?? [],
    timeBudgetMinutes: String(request.contract.timeBudgetMinutes),
    tokenBudget: request.contract.tokenBudget === undefined ? "" : String(request.contract.tokenBudget),
    costBudget: request.contract.costBudget === undefined ? "" : String(request.contract.costBudget),
    retryBudget: String(request.contract.retryBudget),
    replanBudget: String(request.contract.replanBudget),
    concurrencyLimit: String(request.contract.concurrencyLimit),
    evidenceStorageBudgetMb: String(request.contract.evidenceStorageBudgetBytes / (1024 * 1024)),
    artifactStorageBudgetMb: String(request.contract.artifactStorageBudgetBytes / (1024 * 1024)),
    specialistAgentIds: request.contract.specialistAgentIds.join("\n"),
    agentModelAssignments: request.contract.agentModelAssignments.map((assignment) => ({
      ...assignment,
    })),
    planningSelection: resolvedPlanningSelection(
      request.contract.planningSelection,
    ),
    memoryScopes: request.contract.memoryScopes.join("\n"),
    contextNodeIds: request.contract.contextNodeIds.join("\n"),
    registryFields: registryFieldsFromAutonomousRequest(request, registry),
  };
}

function numberValue(value: string): number {
  return Number(value.trim());
}

function requestFromForm(
  base: AutonomousMissionRequest,
  form: AmendmentForm,
  registry: IntakeRegistrySnapshot,
): AutonomousMissionRequest {
  const tokenBudget = form.tokenBudget.trim() ? numberValue(form.tokenBudget) : undefined;
  const costBudget = form.costBudget.trim() ? numberValue(form.costBudget) : undefined;
  const registryContract = projectAutonomousRegistryFields(form.registryFields, registry);
  return {
    ...base,
    title: form.title.trim(),
    objective: form.objective.trim(),
    successCriteria: lines(form.successCriteria),
    authorization: {
      ...base.authorization,
      allowedTargets: lines(form.allowedTargets),
      prohibitedTargets: lines(form.prohibitedTargets),
      authorizationConfirmed: true,
      ...(form.engagementId.trim() ? { engagementId: form.engagementId.trim() } : {}),
      ...(form.timeWindow.trim() ? { timeWindow: form.timeWindow.trim() } : {}),
      ...(form.dataHandling.trim() ? { dataHandling: form.dataHandling.trim() } : {}),
    },
    contract: {
      ...base.contract,
      ...registryContract,
      destructivePolicy: form.destructivePolicy,
      boundedDestructiveTargets: [...form.boundedDestructiveTargets],
      timeBudgetMinutes: numberValue(form.timeBudgetMinutes),
      ...(tokenBudget === undefined ? {} : { tokenBudget }),
      ...(costBudget === undefined ? {} : { costBudget }),
      retryBudget: numberValue(form.retryBudget),
      replanBudget: numberValue(form.replanBudget),
      concurrencyLimit: numberValue(form.concurrencyLimit),
      evidenceStorageBudgetBytes: numberValue(form.evidenceStorageBudgetMb) * 1024 * 1024,
      artifactStorageBudgetBytes: numberValue(form.artifactStorageBudgetMb) * 1024 * 1024,
      specialistAgentIds: lines(form.specialistAgentIds),
      agentModelAssignments: form.agentModelAssignments.map((assignment) => ({
        ...assignment,
      })),
      planningSelection: form.planningSelection,
      memoryScopes: lines(form.memoryScopes),
      contextNodeIds: lines(form.contextNodeIds),
    },
  };
}

function listToggle(current: readonly string[], value: string, checked: boolean): string[] {
  return checked ? [...new Set([...current, value])] : current.filter((item) => item !== value);
}

function UnmappedRegistryValues({ label, values }: { readonly label: string; readonly values: readonly string[] }) {
  if (values.length === 0) return null;
  return <div className="os-validation-summary" role="status"><strong>{label}</strong><p>These historical contract values are not present in the current runtime registry. They remain preserved for server readiness reconciliation and cannot be newly selected here.</p><ul>{values.map((value) => <li key={value} className="os-mono">{value}</li>)}</ul></div>;
}

function ReadinessReview({
  review,
  agents,
  catalog,
}: {
  readonly review: AutonomousBranchPreflight;
  readonly agents: readonly { id: string; displayName: string; role: string }[];
  readonly catalog?: import("../../domain/types/modelConfiguration").ModelCatalog;
}) {
  return <Card className="os-branch-review">
    <div className="os-card-heading"><div><p className="os-eyebrow">Server-issued review</p><h3>Contract v{review.contract.version}</h3></div><StatusPill status={review.preflight.readiness.status} /></div>
    <p className="os-mono os-branch-hash">SHA-256 {review.contract.hash}</p>
    <KeyValueGrid items={[
      { label: "Contract state", value: review.contract.state },
      { label: "Source run version", value: review.sourceRunVersion },
      { label: "Specialist pool", value: review.preflight.execution.team.effectiveAgentIds.join(", ") || "None" },
      { label: "Context selected", value: review.preflight.context.selectedNodeIds.length },
    ]} />
    <ul className="os-compact-list">{review.preflight.readiness.checks.map((check) => <li key={check.id}><span><strong>{check.label}</strong><small>{check.impact}{check.remediation ? ` · ${check.remediation}` : ""}</small></span><StatusPill status={check.status} /></li>)}</ul>
    <MissionAgentModelAssignmentReview
      title="Exact branch model assignments"
      assignments={review.request.contract.agentModelAssignments}
      receipts={review.preflight.execution.team.modelAssignments}
      agents={agents}
    />
    <AutonomousPlanningSelectionReview
      selection={review.request.contract.planningSelection}
      catalog={catalog}
      readinessCheck={review.preflight.readiness.checks.find(
        ({ id }) => id === "contract_planning_selection",
      )}
    />
  </Card>;
}

export function AutonomousBranchPanel({ missionId, selectedRun }: { missionId: string; selectedRun: RuntimeRun }) {
  const navigation = useNavigation();
  const cache = useQueryCache();
  const context = useQuery(
    `autonomous-branch-context:${missionId}:${selectedRun.id}`,
    (signal) => fetchAutonomousBranchContext(missionId, selectedRun.id, signal),
    { staleTime: 0 },
  );
  const registry = useQuery(
    "mission-intake:autonomous:custom",
    (signal) => fetchMissionIntakeRegistry("autonomous", "custom", signal),
    { staleTime: 30_000 },
  );
  const modelCatalog = useQuery(
    "model-catalog",
    fetchModelCatalog,
    { staleTime: 5_000 },
  );
  const control = useActionState();
  const [mode, setMode] = useState<AutonomousBranchMode>("unchanged_contract");
  const [reason, setReason] = useState("");
  const [stopReason, setStopReason] = useState("");
  const [form, setForm] = useState<AmendmentForm>();
  const [initializedRunId, setInitializedRunId] = useState<string>();
  const [review, setReview] = useState<AutonomousBranchPreflight>();
  const [reviewError, setReviewError] = useState<Error>();
  const [reviewPending, setReviewPending] = useState(false);
  const [deliberatelyConfirmed, setDeliberatelyConfirmed] = useState(false);
  const [createError, setCreateError] = useState<Error>();
  const [createPending, setCreatePending] = useState(false);
  const preflightKey = useRef(requestKey());
  const createKey = useRef(requestKey());

  useEffect(() => {
    if (!context.data || !registry.data || initializedRunId === context.data.sourceRun.id) return;
    setForm(formFromRequest(context.data.request, registry.data));
    setInitializedRunId(context.data.sourceRun.id);
  }, [context.data, initializedRunId, registry.data]);

  const invalidateReview = () => {
    setReview(undefined);
    setReviewError(undefined);
    setCreateError(undefined);
    setDeliberatelyConfirmed(false);
    preflightKey.current = requestKey();
    createKey.current = requestKey();
  };
  const updateForm = <K extends keyof AmendmentForm>(key: K, value: AmendmentForm[K]) => {
    invalidateReview();
    setForm((current) => current ? { ...current, [key]: value } : current);
  };
  const updateRegistryFields = (fields: AutonomousBranchRegistryFields) => updateForm("registryFields", fields);
  const updateSpecialistIds = (value: string) => {
    invalidateReview();
    const selectedAgentIds = lines(value);
    setForm((current) => current ? {
      ...current,
      specialistAgentIds: value,
      agentModelAssignments: filterAgentModelAssignments(
        current.agentModelAssignments,
        selectedAgentIds,
      ) ?? [],
    } : current);
  };
  const refreshRuntime = () => {
    cache.invalidatePrefix("mission-runtime:");
    cache.invalidatePrefix("run:");
    cache.invalidate("ti-scale-overview");
    context.refresh();
  };
  const runControl = (command: "pause" | "cancel") => {
    void control.run(
      () => runtimeV2Api.controlRun(
        selectedRun.id,
        { command, reason: stopReason },
        requestKey(),
      ).then(() => { refreshRuntime(); }),
      command === "pause"
        ? "Run paused at a durable checkpoint. Refreshing branch readiness."
        : "Run cancelled safely. Refreshing branch readiness.",
    );
  };

  const runPreflight = async (event: FormEvent) => {
    event.preventDefault();
    if (!context.data) return;
    if (mode === "contract_amendment" && (!form || !registry.data)) {
      setReviewError(new Error("The live runtime registry must load before an amended contract can be reviewed."));
      return;
    }
    setReviewPending(true);
    setReviewError(undefined);
    setCreateError(undefined);
    setDeliberatelyConfirmed(false);
    try {
      const result = await preflightAutonomousBranch(missionId, {
        sourceRunId: context.data.sourceRun.id,
        sourceRunVersion: context.data.sourceRun.version,
        mode,
        reason,
        ...(mode === "contract_amendment" && form && registry.data
          ? { request: requestFromForm(context.data.request, form, registry.data) }
          : {}),
      }, preflightKey.current);
      setReview(result);
    } catch (cause) {
      setReviewError(cause instanceof Error ? cause : new Error("Autonomous branch preflight failed"));
    } finally {
      setReviewPending(false);
    }
  };

  const create = async () => {
    if (!context.data || !review || !deliberatelyConfirmed) return;
    setCreatePending(true);
    setCreateError(undefined);
    try {
      const result = await createAutonomousBranch(missionId, {
        sourceRunId: review.sourceRunId,
        sourceRunVersion: review.sourceRunVersion,
        mode: review.mode,
        reason,
        ...(review.contract.id && review.mode === "contract_amendment"
          ? { draftContractId: review.contract.id }
          : {}),
        review: { version: review.contract.version, hash: review.contract.hash },
      }, createKey.current);
      cache.invalidate("ti-scale-overview");
      cache.invalidate(`run:${result.run.id}`);
      // Establish the exact mission projection before handing the same query
      // key from the source route to the successor route. A failed projection
      // must not repeat the already-successful branch mutation; the successor
      // workspace performs its own bounded authoritative retry.
      await cache.reconcile(
        `mission-runtime:${missionId}`,
        (signal) => runtimeV2Api.mission(missionId, signal),
        0,
      ).catch(() => undefined);
      navigation.navigate(safeNextUrl(
        result.nextUrl,
        `/missions/${encodeURIComponent(missionId)}/runs/${encodeURIComponent(result.run.id)}`,
      ));
    } catch (cause) {
      setCreateError(cause instanceof Error ? cause : new Error("Autonomous branch creation failed"));
    } finally {
      setCreatePending(false);
    }
  };

  if (context.isLoading) return <LoadingPanel label="Loading signed Autonomous contract history" />;
  if (context.error && !context.data) return <ErrorPanel title="Contract branch controls are unavailable" error={context.error} onRetry={context.refresh} />;
  if (!context.data) return null;
  const branchContext = context.data;
  const source = branchContext.sourceRun;
  const branchAgentIds = lines(form?.specialistAgentIds ?? branchContext.request.contract.specialistAgentIds.join("\n"));
  const branchAgents = branchAgentIds.map((agentId) => {
    const candidate = review?.preflight.execution.team.candidates.find((item) => item.id === agentId);
    return {
      id: agentId,
      displayName: candidate?.displayName ?? agentId,
      role: candidate?.role ?? "Selected specialist",
    };
  });
  const canPause = !TERMINAL.has(source.status) && source.status !== "blocked";
  const canCancel = !TERMINAL.has(source.status);
  const readinessReady = Boolean(review && review.preflight.readiness.status !== "blocked" && !review.preflight.readiness.checks.some((check) => check.status === "fail"));
  const reviewPersisted = Boolean(review && (review.mode === "unchanged_contract" ? review.contract.state === "confirmed" : review.contract.state === "draft"));
  const canCreate = source.safeToBranch && readinessReady && reviewPersisted && deliberatelyConfirmed && !createPending;

  return <section className="os-autonomous-branch" aria-labelledby="autonomous-branch-title">
    <Card>
      <div className="os-card-heading"><div><p className="os-eyebrow">Versioned journey amendment</p><h2 id="autonomous-branch-title">Create a separate Autonomous execution attempt</h2></div><StatusPill status={source.safeToBranch ? "safe_to_branch" : "must_stop"}>{source.safeToBranch ? "Safe to branch" : "Pause or cancel first"}</StatusPill></div>
      <p>The active contract is never edited in place. A new run either reuses its exact signed authority or confirms a fully readiness-checked successor contract.</p>
      <KeyValueGrid items={[
        { label: "Source run", value: <span className="os-mono">{source.id}</span> },
        { label: "Run state / version", value: `${source.status} · v${source.version}` },
        { label: "Signed contract", value: `v${context.data.contract.version} · ${context.data.contract.state}` },
        { label: "Branch safety", value: source.safeToBranchReason },
      ]} />
      {!source.safeToBranch && <form className="os-review-form" onSubmit={(event) => { event.preventDefault(); runControl("pause"); }}>
        <label><span>Operator stop reason (audited)</span><input required minLength={3} value={stopReason} onChange={(event) => setStopReason(event.target.value)} placeholder="Why must this run stop before branching?" /></label>
        <div className="os-branch-actions">
          <Button variant="secondary" disabled={!canPause || control.pending || stopReason.trim().length < 3}>Pause at durable checkpoint</Button>
          <Button type="button" variant="danger" disabled={!canCancel || control.pending || stopReason.trim().length < 3} onClick={() => runControl("cancel")}>Cancel source run</Button>
        </div>
      </form>}
      {control.error && <ErrorPanel title="Run control failed" error={control.error} />}
      {control.message && <p role="status" className="os-success-note">{control.message}</p>}
    </Card>

    <form className="os-review-form os-branch-composer" onSubmit={runPreflight}>
      <Card>
        <fieldset><legend>Choose the authority for the new run</legend>
          <div className="os-branch-mode">
            <label><input type="radio" name="branch-mode" checked={mode === "unchanged_contract"} onChange={() => { setMode("unchanged_contract"); invalidateReview(); }} /><span><strong>Unchanged signed contract</strong><small>Branch under the same version and SHA-256. Objective, scope, tools, budgets, specialists, and memory authority remain identical.</small></span></label>
            <label><input type="radio" name="branch-mode" checked={mode === "contract_amendment"} onChange={() => { setMode("contract_amendment"); invalidateReview(); }} /><span><strong>Versioned contract amendment</strong><small>Create a new draft, rerun full readiness, then deliberately confirm it. The prior contract remains in immutable history.</small></span></label>
          </div>
        </fieldset>
        <label><span>Branch or amendment reason (audited)</span><textarea required minLength={3} rows={3} value={reason} onChange={(event) => { setReason(event.target.value); invalidateReview(); }} placeholder="Why is a new execution attempt necessary?" /></label>
      </Card>

      {mode === "contract_amendment" && registry.isLoading && <Card><LoadingPanel label="Loading live contract registries" /></Card>}
      {mode === "contract_amendment" && registry.error && !registry.data && <Card><ErrorPanel title="Structured contract controls are unavailable" error={registry.error} onRetry={registry.refresh} /></Card>}
      {mode === "contract_amendment" && registry.data && form && <Card className="os-branch-fields">
        <p className="os-eyebrow">Full successor contract</p><h3>Amend explicit authority</h3>
        <p className="os-muted">Unchanged fields remain copied from contract v{context.data.contract.version}; every submitted field is revalidated by the live readiness gate.</p>
        <div className="os-registry-source" role="status"><StatusPill status={registry.data.source.status === "live" ? "ready" : "degraded"} /><span><strong>{registry.data.source.status === "live" ? "Live runtime registry" : "Runtime registry unavailable"}</strong><small>{registry.data.source.explanation}</small></span></div>
        <div className="os-branch-field-grid">
          <label><span>Mission title</span><input required value={form.title} onChange={(event) => updateForm("title", event.target.value)} /></label>
          <label className="is-wide"><span>Authorized objective</span><textarea required rows={3} value={form.objective} onChange={(event) => updateForm("objective", event.target.value)} /></label>
          <label><span>Success criteria · one per line</span><textarea required rows={4} value={form.successCriteria} onChange={(event) => updateForm("successCriteria", event.target.value)} /></label>
          <label><span>Engagement ID</span><input value={form.engagementId} onChange={(event) => updateForm("engagementId", event.target.value)} /></label>
          <label><span>Allowed targets · one per line</span><textarea required rows={4} value={form.allowedTargets} onChange={(event) => updateForm("allowedTargets", event.target.value)} /></label>
          <label><span>Prohibited targets · one per line</span><textarea rows={4} value={form.prohibitedTargets} onChange={(event) => updateForm("prohibitedTargets", event.target.value)} /></label>
          <label><span>Authorization time window</span><input value={form.timeWindow} onChange={(event) => updateForm("timeWindow", event.target.value)} /></label>
          <label><span>Data-handling constraint</span><input value={form.dataHandling} onChange={(event) => updateForm("dataHandling", event.target.value)} /></label>
          <label><span>Destructive-action policy</span><TitaniumSelect value={form.destructivePolicy} onChange={(event) => updateForm("destructivePolicy", event.target.value as AmendmentForm["destructivePolicy"])}><option value="prohibited">Prohibited</option><option value="validate_without_executing">Validate the path without executing</option><option value="bounded_lab_only">Named disposable lab targets only</option></TitaniumSelect></label>
          {form.destructivePolicy === "bounded_lab_only" && <fieldset className="os-registry-checklist is-wide"><legend>Named bounded destructive targets</legend><p className="os-policy-note">Only exact targets already present in this signed authorization boundary can be selected.</p>{lines(form.allowedTargets).map((target) => <label className="os-check-field" key={target}><input type="checkbox" aria-label={`Bound destructive activity to ${target}`} checked={form.boundedDestructiveTargets.includes(target)} onChange={(event) => updateForm("boundedDestructiveTargets", listToggle(form.boundedDestructiveTargets, target, event.target.checked))} /><span><strong>{target}</strong><small>Exact authorized target · bounded lab-only policy</small></span></label>)}</fieldset>}
          <label><span>Time budget · minutes</span><input type="number" min="1" required value={form.timeBudgetMinutes} onChange={(event) => updateForm("timeBudgetMinutes", event.target.value)} /></label>
          <label><span>Token budget · optional</span><input type="number" min="0" value={form.tokenBudget} onChange={(event) => updateForm("tokenBudget", event.target.value)} /></label>
          <label><span>Cost budget · optional</span><input type="number" min="0" step="0.01" value={form.costBudget} onChange={(event) => updateForm("costBudget", event.target.value)} /></label>
          <label><span>Retry budget</span><input type="number" min="0" required value={form.retryBudget} onChange={(event) => updateForm("retryBudget", event.target.value)} /></label>
          <label><span>Replan budget</span><input type="number" min="0" required value={form.replanBudget} onChange={(event) => updateForm("replanBudget", event.target.value)} /></label>
          <label><span>Concurrency limit</span><input type="number" min="1" required value={form.concurrencyLimit} onChange={(event) => updateForm("concurrencyLimit", event.target.value)} /></label>
          <label><span>Evidence storage · MiB</span><input type="number" min="1" required value={form.evidenceStorageBudgetMb} onChange={(event) => updateForm("evidenceStorageBudgetMb", event.target.value)} /></label>
          <label><span>Artifact storage · MiB</span><input type="number" min="1" required value={form.artifactStorageBudgetMb} onChange={(event) => updateForm("artifactStorageBudgetMb", event.target.value)} /></label>
          <label><span>Signed specialist IDs · one per line</span><textarea required rows={4} value={form.specialistAgentIds} onChange={(event) => updateSpecialistIds(event.target.value)} /></label>
          <label><span>Allowed memory scopes · one per line</span><textarea rows={4} value={form.memoryScopes} onChange={(event) => updateForm("memoryScopes", event.target.value)} /></label>
          <label><span>Exact context-node IDs · one per line</span><textarea rows={4} value={form.contextNodeIds} onChange={(event) => updateForm("contextNodeIds", event.target.value)} /></label>
        </div>
        <MissionAgentModelAssignments
          idPrefix="autonomous-branch"
          agents={branchAgents}
          selectedAgentIds={branchAgentIds}
          receipts={review?.preflight.execution.team.modelAssignments ?? []}
          explicitAssignments={form.agentModelAssignments}
          baselineAssignments={branchContext.request.contract.agentModelAssignments}
          baselineSourceLabel="Source signed contract"
          changedSourceLabel="Branch amendment pending review"
          catalog={modelCatalog.data}
          catalogUpdatedAt={modelCatalog.updatedAt}
          catalogLoading={modelCatalog.isLoading}
          catalogError={modelCatalog.error}
          readinessStale={!review}
          restoreLabel="Restore signed models"
          restoreControlId="autonomous-branch-model-restore-signed"
          onAssignmentsChange={(assignments) => updateForm(
            "agentModelAssignments",
            assignments ?? [],
          )}
          onRestore={() => updateForm(
            "agentModelAssignments",
            filterAgentModelAssignments(
              branchContext.request.contract.agentModelAssignments,
              branchAgentIds,
            ) ?? [],
          )}
          onRetryCatalog={modelCatalog.refresh}
        />
        <AutonomousPlanningSelectionEditor
          idPrefix="autonomous-branch"
          selection={form.planningSelection}
          baselineSelection={resolvedPlanningSelection(
            branchContext.request.contract.planningSelection,
          )}
          agents={review?.preflight.execution.team.candidates ?? branchAgents}
          catalog={modelCatalog.data}
          catalogUpdatedAt={modelCatalog.updatedAt}
          catalogLoading={modelCatalog.isLoading}
          catalogError={modelCatalog.error}
          readinessCheck={review?.preflight.readiness.checks.find(
            ({ id }) => id === "contract_planning_selection",
          )}
          readinessStale={!review}
          onChange={(planningSelection) => updateForm(
            "planningSelection",
            planningSelection,
          )}
          onRestore={() => updateForm(
            "planningSelection",
            resolvedPlanningSelection(
              branchContext.request.contract.planningSelection,
            ),
          )}
          onRetryCatalog={modelCatalog.refresh}
        />
        <details className="os-advanced-section"><summary>Action-class policy matrix · {Object.keys(registry.data.actionClasses.classes).length} classes</summary><div className="os-policy-matrix">{Object.values(registry.data.actionClasses.classes).map((action) => {
          const state = form.registryFields.actionPolicyStates[action.id] ?? "inherited_default";
          return <article key={action.id} className="os-policy-row"><div><strong>{action.label}</strong><p>{action.plainLanguageDescription}</p><small>{action.capability.availableAgentIds.length} ready agents · {action.capability.availableToolIds.length} ready tools · {action.capability.enforcedProviderModelRefs.length} enforcing models</small></div><StatusPill status={action.capability.availability} /><label><span>Mission state</span><TitaniumSelect aria-label={`${action.label} branch policy`} value={state} onChange={(event) => updateRegistryFields({ ...form.registryFields, actionPolicyStates: { ...form.registryFields.actionPolicyStates, [action.id]: event.target.value as ActionPolicyState } })}><option value="pre_authorized">Pre-authorized</option><option value="guided_only">Guided only / not autonomous</option><option value="prohibited">Prohibited</option><option value="inherited_default">Inherited default</option></TitaniumSelect></label>{action.launchBlockingReasons.length > 0 && <ul>{action.launchBlockingReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}</article>;
        })}<UnmappedRegistryValues label="Unmapped allowed action classes" values={form.registryFields.unmatchedAllowedActionClasses} /><UnmappedRegistryValues label="Unmapped prohibited action classes" values={form.registryFields.unmatchedProhibitedActionClasses} /></div></details>
        <details className="os-advanced-section"><summary>Final deliverables · {form.registryFields.deliverableIds.length} selected</summary><div className="os-registry-checklist">{Object.values(registry.data.deliverables.deliverables).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" aria-label={`Require ${item.label} deliverable`} checked={form.registryFields.deliverableIds.includes(item.id)} onChange={(event) => updateRegistryFields({ ...form.registryFields, deliverableIds: listToggle(form.registryFields.deliverableIds, item.id, event.target.checked) })} /><span><strong>{item.label}</strong><small>{item.purpose}</small><small>{item.capability.availability} · {item.formats.join(", ")}</small></span></label>)}<UnmappedRegistryValues label="Unmapped historical deliverables" values={form.registryFields.unmatchedDeliverables} /></div></details>
        <details className="os-advanced-section"><summary>Evidence requirements · {form.registryFields.evidenceTypeIds.length} selected</summary><div className="os-registry-checklist">{Object.values(registry.data.evidenceTypes.types).map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" aria-label={`Require ${item.label} evidence`} checked={form.registryFields.evidenceTypeIds.includes(item.id)} onChange={(event) => updateRegistryFields({ ...form.registryFields, evidenceTypeIds: listToggle(form.registryFields.evidenceTypeIds, item.id, event.target.checked) })} /><span><strong>{item.label}</strong><small>{item.proves}</small><small>{item.capability.availability} · hash {item.immutableHashRequired ? "required" : "optional"} · custody {item.chainOfCustodyRequired ? "required" : "optional"}</small></span></label>)}<UnmappedRegistryValues label="Unmapped historical evidence requirements" values={form.registryFields.unmatchedEvidenceRequirements} /></div></details>
        <details className="os-advanced-section"><summary>Safe-stop behavior · {form.registryFields.optionalSafeStopIds.length} mission stops</summary><div className="os-registry-checklist"><p className="os-policy-note">A safe stop preserves the checkpoint and explains why the mission cannot continue safely. Mandatory platform stops are always enforced and cannot be removed.</p>{registry.data.safeStops.optional.map((item) => <label className="os-check-field" key={item.id}><input type="checkbox" aria-label={`Enable ${item.label} safe stop`} checked={form.registryFields.optionalSafeStopIds.includes(item.id)} onChange={(event) => updateRegistryFields({ ...form.registryFields, optionalSafeStopIds: listToggle(form.registryFields.optionalSafeStopIds, item.id, event.target.checked) })} /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></label>)}<UnmappedRegistryValues label="Unmapped historical safe-stop conditions" values={form.registryFields.unmatchedSafeStopConditions} /><h3>Always enforced</h3>{registry.data.safeStops.mandatory.map((item) => <div className="os-mandatory-stop" key={item.id}><StatusPill status="enforced" /><span><strong>{item.label}</strong><small>{item.explanation}</small></span></div>)}</div></details>
      </Card>}

      <div className="os-branch-actions"><Button disabled={!source.safeToBranch || reason.trim().length < 3 || reviewPending || (mode === "contract_amendment" && (!form || !registry.data))}>{reviewPending ? "Checking live readiness…" : mode === "contract_amendment" ? "Draft and review amended contract" : "Review unchanged signed contract"}</Button></div>
    </form>

    {reviewError && <ErrorPanel title="Branch preflight did not pass" error={reviewError} />}
    {review && <ReadinessReview
      review={review}
      agents={branchAgents}
      catalog={modelCatalog.data}
    />}
    {review && <Card className="os-branch-confirmation">
      <label className="os-check"><input type="checkbox" checked={deliberatelyConfirmed} onChange={(event) => setDeliberatelyConfirmed(event.target.checked)} /><span>I reviewed contract v{review.contract.version}, its SHA-256 digest, live readiness, scope, budgets, specialist pool, and safe-stop behavior. Create one separate Autonomous run without routine user-wait states.</span></label>
      <div className="os-branch-actions"><Button type="button" disabled={!canCreate} onClick={() => void create()}>{createPending ? "Creating durable run…" : mode === "contract_amendment" ? `Confirm contract v${review.contract.version} and create run` : `Create run under contract v${review.contract.version}`}</Button></div>
    </Card>}
    {createError && <ErrorPanel title="New Autonomous run was not created" error={createError} />}

    <Card><p className="os-eyebrow">Immutable lineage</p><h3>Contract history</h3><ul className="os-compact-list">{context.data.history.map((item) => <li key={item.id}><span><strong>Contract v{item.version}</strong><small className="os-mono">{item.hash} · source {item.sourceContractId ?? "initial"}</small></span><StatusPill status={item.state} /></li>)}</ul></Card>
  </section>;
}
