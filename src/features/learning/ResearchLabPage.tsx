import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import { useAuth } from "../../app/providers/AuthProvider";
import { ApiError } from "../../data/api/client";
import {
  researchApi,
  serializeResearchPromotionRequest,
} from "../../data/api/research";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type {
  HumanResearchPromotionAction,
  ResearchCampaignRecord,
  ResearchCampaignSetupPreview,
  ResearchExperimentRunRecord,
  ResearchLabSnapshot,
  ResearchPromotionLifecycleRecord,
} from "../../domain/types/research";
import { formatTime, JsonDetails, KeyValueGrid } from "../runs/OperationalSurface";
import {
  availableResearchPromotionStorage,
  classifyResearchPromotionOutcomeAttribution,
  classifyResearchPromotionFailure,
  clearResearchPromotionAttempt,
  createResearchPromotionAttempt,
  loadResearchPromotionAttempt,
  researchPromotionAttemptMatchesProjection,
  RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION,
  saveResearchPromotionAttempt,
  withResearchPromotionFailure,
  type ResearchPromotionAttempt,
} from "./researchPromotionRetry";
import {
  availableResearchExperimentStorage,
  classifyResearchExperimentFailure,
  clearResearchExperimentAttempt,
  createResearchExperimentCancelAttempt,
  createResearchExperimentStartAttempt,
  loadResearchExperimentAttempt,
  researchExperimentAttemptMatchesProjection,
  researchExperimentAttemptOutcomeReached,
  saveResearchExperimentAttempt,
  withResearchExperimentFailure,
  type ResearchExperimentAttempt,
  type ResearchExperimentProjection,
} from "./researchExperimentRetry";

interface CreateCampaignIntent {
  readonly catalogId: ResearchLabSnapshot["catalog"][number]["id"];
  readonly idempotencyKey: string;
}

interface StopCampaignIntent {
  readonly campaignId: string;
  readonly expectedUpdatedAt: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

interface SetupCampaignIntent {
  readonly campaignId: string;
  readonly expectedUpdatedAt: string;
  readonly candidatePresetId: string;
  readonly idempotencyKey: string;
}

interface MutationFailure<TIntent> {
  readonly error: Error;
  readonly intent: TIntent;
  readonly retryable?: boolean;
}

interface PromotionIntent {
  readonly experimentId: string;
  readonly expectedVersion: number;
  readonly action: HumanResearchPromotionAction;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly targetStrategyVersionId?: string;
  readonly canaryBounds?: {
    readonly maxMissions: number;
    readonly maxWallClockMs: number;
  };
  readonly idempotencyKey: string;
}

function toError(cause: unknown, fallback: string): Error {
  return cause instanceof Error ? cause : new Error(fallback);
}

function ResearchMutationFailure({
  title,
  failure,
  onRetry,
  onRefresh,
  onResolved,
  refreshLabel = "Refresh campaign state",
}: {
  readonly title: string;
  readonly failure: MutationFailure<unknown>;
  readonly onRetry: () => void;
  readonly onRefresh: () => Promise<void>;
  readonly onResolved: () => void;
  readonly refreshLabel?: string;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<Error>();
  const actionBoundary = useRef<HTMLDivElement>(null);
  const retryable = failure.retryable
    ?? (failure.error instanceof ApiError && failure.error.retryable);
  useEffect(() => {
    actionBoundary.current?.querySelector<HTMLButtonElement>("button")?.focus();
  }, [failure]);
  const refresh = async () => {
    setRefreshing(true); setRefreshError(undefined);
    try {
      await onRefresh();
      onResolved();
    } catch (cause) {
      setRefreshError(toError(cause, "Research campaign state could not be refreshed"));
    } finally {
      setRefreshing(false);
    }
  };
  return <div ref={actionBoundary} className="os-research-mutation-failure">
    <ErrorPanel title={title} error={failure.error} onRetry={retryable ? onRetry : undefined} />
    {retryable
      ? <p className="os-state-remediation">No new outcome is assumed. Try again resubmits the exact represented request with its original idempotency key.</p>
      : <p className="os-state-remediation">This result must be reconciled against canonical Research Lab state before another change is submitted.</p>}
    {!retryable && <Button type="button" variant="secondary" disabled={refreshing} onClick={() => void refresh()}>
      {refreshing ? "Refreshing Research Lab state…" : refreshLabel}
    </Button>}
    {refreshError && <ErrorPanel
      title="Campaign state could not be refreshed"
      error={refreshError}
    />}
  </div>;
}

export default function ResearchLabPage() {
  const auth = useAuth();
  const actorId = auth.session.actorId ?? "";
  const query = useQuery("research-lab", (signal) => researchApi.snapshot(signal), { staleTime: 10_000 });
  const cache = useQueryCache();
  const [ownerAcknowledged, setOwnerAcknowledged] = useState(false);
  const [pendingId, setPendingId] = useState<string>();
  const [createFailure, setCreateFailure] = useState<MutationFailure<CreateCampaignIntent>>();
  const [message, setMessage] = useState<string>();
  const executeCreate = async (intent: CreateCampaignIntent) => {
    setPendingId(intent.catalogId); setCreateFailure(undefined); setMessage(undefined);
    try {
      await researchApi.createCampaign(intent.catalogId, intent.idempotencyKey);
      setMessage("Draft campaign created. Execution remains blocked until its trusted charter, benchmark, lab, worker, and integrity signer are ready.");
      cache.invalidate("research-lab");
    } catch (cause) {
      setCreateFailure({ error: toError(cause, "Research campaign could not be created"), intent });
    }
    finally { setPendingId(undefined); }
  };
  const create = (catalogId: ResearchLabSnapshot["catalog"][number]["id"]) => void executeCreate({
    catalogId,
    idempotencyKey: `research-create-${crypto.randomUUID()}`,
  });
  if (query.isLoading) return <LoadingPanel label="Loading bounded Research Lab state" />;
  if (query.error && !query.data) return <ErrorPanel
    title="Research Lab state is unavailable"
    error={query.error}
    onRetry={query.refresh}
    retryControlId="research-initial-read-retry"
  />;
  const data = query.data!;
  return <div className="os-research-lab">
    <section className="os-research-principle"><StatusPill status={data.readiness.status} /><div><strong>{data.readiness.status === "ready" ? "Local research harness ready" : "Research execution is safely blocked"}</strong><p>{data.governingPrinciple}</p></div></section>
    <div className="os-research-layout"><section><Card><div className="os-card-heading"><div><p className="os-eyebrow">Immutable local boundary</p><h2>Readiness gate</h2></div><StatusPill status={data.readiness.status} /></div><ul className="os-review-list">{data.readiness.checks.map((check) => <li key={check.id}><StatusPill status={check.status} /><span><strong>{check.label}</strong><small>{check.impact}</small>{check.remediation && check.status === "fail" && <small>{check.remediation}</small>}</span></li>)}</ul></Card>
      <div className="os-section-heading"><div><p className="os-eyebrow">First campaigns</p><h2>Safety and reliability tracks</h2></div></div>
      <label className="os-check-field os-research-owner"><input type="checkbox" checked={ownerAcknowledged} onChange={(event) => setOwnerAcknowledged(event.target.checked)} /><span><strong>I own this campaign and its promotion decisions</strong><small>Creating a draft does not approve a charter, start an experiment, or deploy a strategy.</small></span></label>
      {createFailure && <ResearchMutationFailure
        title="Research campaign was not created"
        failure={createFailure}
        onRetry={() => void executeCreate(createFailure.intent)}
        onRefresh={query.reconcile}
        onResolved={() => setCreateFailure(undefined)}
      />}{message && <p role="status" className="os-success-note">{message}</p>}
      <div className="os-research-campaigns">{data.catalog.map((catalog) => {
        const existing = data.campaigns.filter(({ catalogId }) => catalogId === catalog.id);
        const active = existing.find(({ status }) => ["draft", "approved", "running", "paused"].includes(status));
        return <Card key={catalog.id}><div className="os-card-heading"><div><h3>{catalog.title}</h3><p>{catalog.purpose}</p></div>{active && <StatusPill status={active.status} />}</div><KeyValueGrid items={[{ label: "Primary metric", value: catalog.primaryMetric.replaceAll("_", " ") }, { label: "Mutable dimensions", value: catalog.mutablePaths.length }, { label: "Prior campaigns", value: existing.length }]} /><JsonDetails label="Allowed strategy paths" value={catalog.mutablePaths} />{active ? <CampaignControl campaign={active} setup={catalog.setup} onChanged={() => cache.invalidate("research-lab")} onReconcile={query.reconcile} /> : <Button disabled={!ownerAcknowledged || Boolean(pendingId) || Boolean(createFailure)} onClick={() => create(catalog.id)}>{pendingId === catalog.id ? "Creating draft…" : "Create bounded draft"}</Button>}</Card>;
      })}</div>
      <div className="os-section-heading"><div><p className="os-eyebrow">Experiment history</p><h2>Measured candidates and near misses</h2></div></div>{data.experiments.length === 0 ? <Card><EmptyState title="No experiments have run" description="This is an honest empty state: no trusted benchmark run, metric, receipt, or performance claim exists yet." /></Card> : <div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Hypothesis</th><th>Dimension</th><th>Status</th><th>Updated</th><th>Bounded run</th></tr></thead><tbody>{data.experiments.map((experiment) => <tr key={experiment.id}><th scope="row">{experiment.hypothesis}<small>{experiment.candidateStrategyId}</small></th><td>{experiment.dimensionId}</td><td><StatusPill status={experiment.status} /></td><td>{formatTime(experiment.updatedAt)}</td><td><ExperimentControl experiment={experiment} actorId={actorId} onChanged={() => cache.invalidate("research-lab")} /></td></tr>)}</tbody></table></div>}
      <div className="os-section-heading"><div><p className="os-eyebrow">Promotion inbox</p><h2>Human-owned strategy decisions</h2></div></div>
      {data.promotions.length === 0
        ? <Card><EmptyState title="No candidates await promotion" description="A candidate appears only after a typed experiment is bound to an immutable benchmark and durable strategy version." /></Card>
        : <div className="os-research-promotions">{data.promotions.map((promotion) =>
            <PromotionControl
              key={promotion.experimentId}
              promotion={promotion}
              actorId={actorId}
              onChanged={() => cache.invalidate("research-lab")}
              onReconcile={query.reconcile}
            />)}
          </div>}
      </section>
      <aside><Card><p className="os-eyebrow">Public-provider trust boundary</p><h2>Proposal only</h2><ul className="os-policy-list"><li>Raw client evidence: prohibited</li><li>Direct experiment tools: prohibited</li><li>Authoritative scoring: local evaluator only</li><li>Automatic promotion: prohibited</li></ul></Card><Card><p className="os-eyebrow">Private holdout</p><h2>Operator descriptor required</h2><p>No hidden holdout cases are shipped in this public application. A development result can be benchmarked, but it cannot become promotion-ready until a private operator-owned holdout descriptor is connected and independently evaluated.</p></Card><Card><p className="os-eyebrow">Promotion path</p><ol className="os-promotion-path">{data.promotionPath.map((stage, index) => <li key={stage}><span>{index + 1}</span>{stage.replaceAll("_", " ")}</li>)}</ol></Card><Card><p className="os-eyebrow">Integrity records</p><KeyValueGrid items={[{ label: "Benchmark families", value: data.integrity.benchmarkFamilies }, { label: "Frozen snapshots", value: data.integrity.benchmarkSnapshots }, { label: "Approved charters", value: data.integrity.approvedCharters }, { label: "Signed receipts", value: data.integrity.integrityReceipts }, { label: "Exposure receipts", value: data.integrity.providerExposureReceipts }, { label: "Blocked exposures", value: data.integrity.blockedProviderExposures }]} /></Card></aside></div>
  </div>;
}

function CampaignControl({ campaign, setup, onChanged, onReconcile }: {
  readonly campaign: ResearchCampaignRecord;
  readonly setup: ResearchCampaignSetupPreview;
  readonly onChanged: () => void;
  readonly onReconcile: () => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [failure, setFailure] = useState<MutationFailure<StopCampaignIntent>>();
  const [approvedSetupKey, setApprovedSetupKey] = useState<string>();
  const [setupPending, setSetupPending] = useState(false);
  const [setupFailure, setSetupFailure] =
    useState<MutationFailure<SetupCampaignIntent>>();
  const [setupMessage, setSetupMessage] = useState<string>();
  const setupApprovalRef = useRef<HTMLInputElement>(null);
  const setupReviewKey = JSON.stringify({
    campaignId: campaign.id,
    campaignUpdatedAt: campaign.updatedAt,
    candidatePresetId: setup.candidatePresetId,
    developmentScenarioId: setup.developmentScenarioId,
    baselineBundleHash: setup.baselineBundleHash,
    candidateBundleHash: setup.candidateBundleHash,
    evaluatorHash: setup.evaluatorHash,
    toolManifestHash: setup.toolManifestHash,
    executionEnvironmentIdentityHash: setup.executionEnvironmentIdentityHash,
    patch: setup.patch,
  });
  const setupApproved = approvedSetupKey === setupReviewKey;
  const executeSetup = async (intent: SetupCampaignIntent) => {
    setSetupPending(true);
    setSetupFailure(undefined);
    setSetupMessage(undefined);
    try {
      const result = await researchApi.approveAndQueueCampaign(intent);
      setSetupMessage(
        `Candidate ${result.setup.candidateStrategyId} is queued against the public development fixture. It is not promotion-ready and cannot deploy.`,
      );
      setApprovedSetupKey(undefined);
      onChanged();
    } catch (cause) {
      setSetupFailure({
        error: toError(cause, "Research campaign setup could not be approved"),
        intent,
      });
    } finally {
      setSetupPending(false);
    }
  };
  const approveSetup = () => void executeSetup({
    campaignId: campaign.id,
    expectedUpdatedAt: campaign.updatedAt,
    candidatePresetId: setup.candidatePresetId,
    idempotencyKey: `research-setup-${crypto.randomUUID()}`,
  });
  const executeStop = async (intent: StopCampaignIntent) => {
    setPending(true); setFailure(undefined);
    try {
      await researchApi.stopCampaign(
        intent.campaignId,
        intent.expectedUpdatedAt,
        intent.reason,
        intent.idempotencyKey,
      );
      onChanged();
    } catch (cause) {
      setFailure({ error: toError(cause, "Campaign could not be stopped"), intent });
    }
    finally { setPending(false); }
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void executeStop({
      campaignId: campaign.id,
      expectedUpdatedAt: campaign.updatedAt,
      reason: reason.trim(),
      idempotencyKey: `research-stop-${crypto.randomUUID()}`,
    });
  };
  const changeReason = (nextReason: string) => {
    // A failed mutation remains bound to its exact represented request until
    // the operator retries it or reconciles canonical state. Editing text must
    // never dismiss a non-retryable optimistic-concurrency conflict.
    setReason(nextReason);
  };
  return <div className="os-research-control">
    {campaign.status === "draft" && <details className="os-advanced-section" open>
      <summary>Review exact bounded experiment</summary>
      <div className="os-details-content">
        <p>{setup.hypothesis}</p>
        <KeyValueGrid items={[
          { label: "Candidate preset", value: setup.candidatePresetId },
          { label: "Development fixture", value: setup.developmentScenarioId },
          { label: "Mutable path", value: setup.path },
          { label: "Execution boundary", value: setup.executionReadiness === "ready" ? "Attested local bwrap" : "Not ready" },
          { label: "Private holdout", value: "Operator descriptor required" },
        ]} />
        <JsonDetails label="Exact one-operation strategy patch" value={setup.patch} />
        <JsonDetails label="Immutable execution hashes" value={{
          baselineBundleHash: setup.baselineBundleHash,
          candidateBundleHash: setup.candidateBundleHash,
          evaluatorHash: setup.evaluatorHash,
          toolManifestHash: setup.toolManifestHash,
          executionEnvironmentIdentityHash:
            setup.executionEnvironmentIdentityHash,
        }} />
        <ul className="os-policy-list">
          <li>Target: synthetic fixture only</li>
          <li>Outbound network: disabled</li>
          <li>Public provider execution: disabled</li>
          <li>Automatic promotion or deployment: disabled</li>
        </ul>
        <label className="os-check-field">
          <input
            ref={setupApprovalRef}
            type="checkbox"
            checked={setupApproved}
            onChange={(event) => {
              setApprovedSetupKey(
                event.target.checked ? setupReviewKey : undefined,
              );
            }}
          />
          <span>
            <strong>I approve this exact charter, patch, fixture, and budget</strong>
            <small>This queues one development experiment. It does not authorize validation, private holdout, shadow, canary, or production deployment.</small>
          </span>
        </label>
        {setupFailure && <ResearchMutationFailure
          title="Research setup was not approved"
          failure={setupFailure}
          onRetry={() => void executeSetup(setupFailure.intent)}
          onRefresh={onReconcile}
          onResolved={() => {
            setSetupFailure(undefined);
            setApprovedSetupKey(undefined);
            window.requestAnimationFrame(() => setupApprovalRef.current?.focus());
          }}
          refreshLabel="Refresh exact setup bindings"
        />}
        {setupMessage && <p role="status" className="os-success-note">{setupMessage}</p>}
        <Button
          type="button"
          disabled={
            setup.executionReadiness !== "ready"
            || !setupApproved
            || setupPending
            || Boolean(setupFailure)
          }
          onClick={approveSetup}
        >
          {setupPending ? "Binding exact setup…" : "Approve and queue candidate"}
        </Button>
      </div>
    </details>}
    <details className="os-advanced-section"><summary>Stop campaign</summary><div className="os-details-content"><p>Stopping preserves immutable audit and experiment history.</p><form onSubmit={submit}><label>Reason for stopping<textarea required minLength={3} value={reason} onChange={(event) => changeReason(event.target.value)} placeholder="The benchmark fixture requires revision before experiments begin." /></label>{failure && <ResearchMutationFailure
    title="Campaign was not stopped"
    failure={failure}
    onRetry={() => void executeStop(failure.intent)}
    onRefresh={onReconcile}
    onResolved={() => setFailure(undefined)}
  />}<Button variant="danger" disabled={pending || Boolean(failure) || reason.trim().length < 3}>{pending ? "Stopping…" : "Stop campaign"}</Button></form></div></details>
  </div>;
}

type ResearchExperimentSummary =
  ResearchLabSnapshot["experiments"][number];

function retainedResearchRunError(
  attempt: ResearchExperimentAttempt,
): Error {
  const action = attempt.action === "start"
    ? "run start"
    : "cancellation";
  return Object.assign(
    new Error(`The exact Research ${action} has an unconfirmed outcome.`),
    {
      humanMessage:
        `The exact Research ${action} has an unconfirmed outcome.`,
      remediation:
        "Retry the retained request, refresh canonical run state, or explicitly discard it before changing the represented input.",
    },
  );
}

function ResearchExperimentMutationFailure({
  failure,
  canRetry,
  refreshing,
  refreshError,
  onRetry,
  onRefresh,
  onDiscard,
}: {
  readonly failure: MutationFailure<ResearchExperimentAttempt>;
  readonly canRetry: boolean;
  readonly refreshing: boolean;
  readonly refreshError?: Error;
  readonly onRetry: () => void;
  readonly onRefresh: () => void;
  readonly onDiscard: () => void;
}) {
  const actionBoundary = useRef<HTMLDivElement>(null);
  useEffect(() => {
    actionBoundary.current?.querySelector<HTMLButtonElement>("button")?.focus();
  }, [failure]);
  return <div
    ref={actionBoundary}
    className="os-research-mutation-failure"
  >
    <ErrorPanel
      title={failure.intent.action === "start"
        ? "Research development run did not start"
        : "Research run control failed"}
      error={failure.error}
      onRetry={canRetry ? onRetry : undefined}
      retryControlId="research-experiment-mutation-retry"
    />
    <p className="os-state-remediation">
      {canRetry
        ? "Try again resubmits the exact represented request body with its original idempotency key. Refreshing checks canonical state without assuming an outcome."
        : "This retained request no longer matches the visible canonical run. Refresh it or explicitly discard it; Ti-Scale will not silently submit changed input."}
    </p>
    <div className="os-inline-actions">
      <Button
        type="button"
        variant="secondary"
        data-control-id="research-experiment-canonical-refresh"
        disabled={refreshing}
        onClick={onRefresh}
      >
        {refreshing
          ? "Refreshing canonical run state…"
          : "Refresh canonical run state"}
      </Button>
      <Button
        type="button"
        variant="secondary"
        data-control-id="research-experiment-discard-retained-request"
        disabled={refreshing}
        onClick={onDiscard}
      >
        Discard retained request
      </Button>
    </div>
    {refreshError && <ErrorPanel
      title="Canonical run state could not be refreshed"
      error={refreshError}
    />}
  </div>;
}

function experimentProjection(
  experiment: ResearchExperimentSummary,
  latestRun: ResearchExperimentRunRecord | undefined,
): ResearchExperimentProjection {
  return {
    experimentId: experiment.id,
    scenarioId: experiment.scenarioId,
    experimentStatus: experiment.status,
    latestRunId: latestRun?.id ?? null,
    latestRunStatus: latestRun?.status ?? null,
  };
}

function ExperimentControl({
  experiment,
  actorId,
  onChanged,
}: {
  readonly experiment: ResearchExperimentSummary;
  readonly actorId: string;
  readonly onChanged: () => void;
}) {
  const [run, setRun] = useState<ResearchExperimentRunRecord>();
  const [seed, setSeed] = useState(
    `development-${new Date().toISOString().slice(0, 10)}`,
  );
  const [pending, setPending] = useState(false);
  const [representing, setRepresenting] = useState(false);
  const [restoringAttempt, setRestoringAttempt] = useState(true);
  const [cancelReason, setCancelReason] = useState("");
  const [attempt, setAttempt] = useState<ResearchExperimentAttempt>();
  const [failure, setFailure] =
    useState<MutationFailure<ResearchExperimentAttempt>>();
  const [pollError, setPollError] = useState<Error>();
  const [preflightError, setPreflightError] = useState<Error>();
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<Error>();
  const [message, setMessage] = useState<string>();
  const storage = availableResearchExperimentStorage();
  const activeRun = run
    ?? (experiment.latestRun
      ? {
          ...experiment.latestRun,
          experimentId: experiment.id,
          scenarioId: experiment.scenarioId,
          seed: "",
          workerId: experiment.latestRun.status === "queued"
            ? "pending"
            : "local-isolated-worker",
          createdAt: experiment.updatedAt,
        }
      : undefined);
  const isActive = activeRun?.status === "queued"
    || activeRun?.status === "running";
  const projection = experimentProjection(experiment, activeRun);
  const canRetryAttempt = Boolean(
    attempt
    && failure?.retryable
    && researchExperimentAttemptMatchesProjection(attempt, projection),
  );
  const discardAttempt = (notice?: string) => {
    clearResearchExperimentAttempt(storage, actorId, experiment.id);
    setAttempt(undefined);
    setFailure(undefined);
    setRefreshError(undefined);
    if (notice) setMessage(notice);
  };
  useEffect(() => {
    let active = true;
    setRestoringAttempt(true);
    setAttempt(undefined);
    setFailure(undefined);
    setRefreshError(undefined);
    if (!actorId) {
      setRestoringAttempt(false);
      return () => { active = false; };
    }
    void loadResearchExperimentAttempt(
      storage,
      actorId,
      experiment.id,
    ).then((restored) => {
      if (!active || !restored) return;
      setAttempt(restored);
      if (restored.action === "start") setSeed(restored.seed);
      else setCancelReason(restored.reason);
      setFailure({
        error: retainedResearchRunError(restored),
        intent: restored,
        retryable: restored.disposition !== "reconcile",
      });
    }).finally(() => {
      if (active) setRestoringAttempt(false);
    });
    return () => { active = false; };
  }, [actorId, experiment.id]);
  useEffect(() => {
    // A retained mutation represents an outcome the client cannot yet prove.
    // Let the explicit canonical-reconciliation control own that interval:
    // background polling can otherwise replace the failure surface while its
    // refresh button is being activated and make the operator's click a no-op.
    if (!activeRun || !isActive || attempt) return;
    let stopped = false;
    const poll = async () => {
      try {
        const result = await researchApi.experimentRun(
          experiment.id,
          activeRun.id,
        );
        if (stopped) return;
        setRun(result.run);
        setPollError(undefined);
        if (!["queued", "running"].includes(result.run.status)) onChanged();
      } catch (cause) {
        if (!stopped) {
          setPollError(
            toError(cause, "Research run status could not be refreshed"),
          );
        }
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 750);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [
    activeRun?.id,
    actorId,
    attempt?.action,
    attempt?.idempotencyKey,
    experiment.id,
    isActive,
    onChanged,
  ]);
  const execute = async (retained: ResearchExperimentAttempt) => {
    setPending(true);
    setFailure(undefined);
    if (
      !researchExperimentAttemptMatchesProjection(
        retained,
        experimentProjection(experiment, activeRun),
      )
    ) {
      const reconcileError = Object.assign(
        new Error(
          "The retained Research request no longer matches the canonical run.",
        ),
        {
          remediation:
            "Refresh canonical run state, then explicitly discard the retained request if you intend to represent a different seed or cancellation reason.",
        },
      );
      const reconciled = withResearchExperimentFailure(
        retained,
        "reconcile",
        reconcileError,
      );
      await saveResearchExperimentAttempt(storage, reconciled);
      setAttempt(reconciled);
      setFailure({
        error: reconcileError,
        intent: reconciled,
        retryable: false,
      });
      setPending(false);
      return;
    }
    const dispatching: ResearchExperimentAttempt = {
      ...retained,
      disposition: "dispatching",
      failureCode: null,
    };
    if (!await saveResearchExperimentAttempt(storage, dispatching)) {
      setAttempt(dispatching);
      setFailure({
        error: Object.assign(
          new Error(
            "The exact Research request could not be retained before dispatch.",
          ),
          {
            remediation:
              "Restore this tab's session storage, then explicitly discard and represent the request again.",
          },
        ),
        intent: dispatching,
        retryable: false,
      });
      setPending(false);
      return;
    }
    setAttempt(dispatching);
    setPreflightError(undefined);
    setRefreshError(undefined);
    setMessage(undefined);
    try {
      const result = retained.action === "start"
        ? await researchApi.startExperiment({
            experimentId: retained.experimentId,
            scenarioId: retained.scenarioId,
            seed: retained.seed,
            idempotencyKey: retained.idempotencyKey,
          })
        : await researchApi.cancelExperiment({
            experimentId: retained.experimentId,
            runId: retained.runId,
            reason: retained.reason,
            idempotencyKey: retained.idempotencyKey,
          });
      clearResearchExperimentAttempt(
        storage,
        actorId,
        experiment.id,
      );
      setAttempt(undefined);
      setFailure(undefined);
      setRun(result.run);
      setPollError(undefined);
      setMessage(retained.action === "start"
        ? "The isolated development fixture was accepted."
        : "The bounded run cancellation was recorded.");
      onChanged();
    } catch (cause) {
      const error = toError(
        cause,
        retained.action === "start"
          ? "Research development run could not start"
          : "Research development run could not be cancelled",
      );
      const disposition = classifyResearchExperimentFailure(error);
      const failed = withResearchExperimentFailure(
        dispatching,
        disposition,
        error,
      );
      await saveResearchExperimentAttempt(storage, failed);
      setAttempt(failed);
      setFailure({
        error,
        intent: failed,
        retryable: disposition !== "reconcile",
      });
    } finally {
      setPending(false);
    }
  };
  const start = async () => {
    setRepresenting(true);
    try {
      const retained = await createResearchExperimentStartAttempt({
        actorId,
        experimentId: experiment.id,
        scenarioId: experiment.scenarioId,
        seed: seed.trim(),
        idempotencyKey: `research-run-${crypto.randomUUID()}`,
      });
      await execute(retained);
    } catch (cause) {
      setPreflightError(
        toError(cause, "The exact Research run could not be retained"),
      );
    } finally {
      setRepresenting(false);
    }
  };
  const cancel = async () => {
    if (!activeRun) return;
    setRepresenting(true);
    try {
      const retained = await createResearchExperimentCancelAttempt({
        actorId,
        experimentId: experiment.id,
        runId: activeRun.id,
        reason: cancelReason.trim(),
        idempotencyKey: `research-cancel-${crypto.randomUUID()}`,
      });
      await execute(retained);
    } catch (cause) {
      setPreflightError(
        toError(cause, "The exact Research cancellation could not be retained"),
      );
    } finally {
      setRepresenting(false);
    }
  };
  const refreshCanonicalState = async (
    retained: ResearchExperimentAttempt,
  ) => {
    setRefreshing(true);
    setRefreshError(undefined);
    try {
      let canonicalProjection: ResearchExperimentProjection;
      if (retained.action === "cancel") {
        const result = await researchApi.experimentRun(
          retained.experimentId,
          retained.runId,
        );
        setRun(result.run);
        setPollError(undefined);
        canonicalProjection = experimentProjection(experiment, result.run);
      } else {
        const snapshot = await researchApi.snapshot();
        const canonical = snapshot.experiments.find(
          ({ id }) => id === retained.experimentId,
        );
        if (!canonical) {
          throw new Error(
            "The retained experiment is absent from canonical Research Lab state.",
          );
        }
        const canonicalRun = canonical.latestRun
          ? {
              ...canonical.latestRun,
              experimentId: canonical.id,
              scenarioId: canonical.scenarioId,
              seed: retained.seed,
              workerId: canonical.latestRun.status === "queued"
                ? "pending"
                : "local-isolated-worker",
              createdAt: canonical.updatedAt,
            }
          : undefined;
        if (canonicalRun) setRun(canonicalRun);
        setPollError(undefined);
        canonicalProjection = experimentProjection(canonical, canonicalRun);
      }
      if (
        researchExperimentAttemptOutcomeReached(
          retained,
          canonicalProjection,
        )
      ) {
        discardAttempt(
          retained.action === "start"
            ? "Canonical state contains the bounded run. The start request was not repeated."
            : "Canonical state confirms the run ended. The cancellation request was not repeated.",
        );
      } else if (
        researchExperimentAttemptMatchesProjection(
          retained,
          canonicalProjection,
        )
      ) {
        const retryReady: ResearchExperimentAttempt = {
          ...retained,
          disposition: "retryable",
          failureCode: null,
        };
        await saveResearchExperimentAttempt(storage, retryReady);
        setAttempt(retryReady);
        setFailure({
          error: Object.assign(
            new Error(
              "Canonical state is unchanged and the exact request remains available.",
            ),
            {
              remediation:
                "Use Try again to resubmit the original request and idempotency key, or explicitly discard it.",
            },
          ),
          intent: retryReady,
          retryable: true,
        });
        setMessage(
          "Canonical state is unchanged. No new outcome was assumed.",
        );
      } else {
        const reconcileError = Object.assign(
          new Error(
            "Canonical state changed while this exact request was retained.",
          ),
          {
            remediation:
              "Review the current run, then explicitly discard the retained request before representing different input.",
          },
        );
        const reconciled = withResearchExperimentFailure(
          retained,
          "reconcile",
          reconcileError,
        );
        await saveResearchExperimentAttempt(storage, reconciled);
        setAttempt(reconciled);
        setFailure({
          error: reconcileError,
          intent: reconciled,
          retryable: false,
        });
      }
      onChanged();
    } catch (cause) {
      setRefreshError(
        toError(cause, "Canonical Research run state could not be refreshed"),
      );
    } finally {
      setRefreshing(false);
    }
  };
  const failurePanel = failure && <ResearchExperimentMutationFailure
    failure={failure}
    canRetry={canRetryAttempt}
    refreshing={refreshing}
    refreshError={refreshError}
    onRetry={() => void execute(failure.intent)}
    onRefresh={() => void refreshCanonicalState(failure.intent)}
    onDiscard={() => discardAttempt(
      "The retained request was discarded. No outcome was inferred.",
    )}
  />;
  if (isActive) {
    return <div className="os-research-run-control">
      <StatusPill status={activeRun.status} />
      <small>{activeRun.status === "queued"
        ? "Waiting for the isolated local worker"
        : "Trusted local evaluator is processing typed decisions"}</small>
      <label>
        Cancellation reason
        <input
          value={cancelReason}
          disabled={
            restoringAttempt
            || representing
            || Boolean(attempt)
          }
          onChange={(event) => {
            setCancelReason(event.target.value);
            setPreflightError(undefined);
          }}
          placeholder="The fixture or candidate needs review."
        />
      </label>
      <Button
        type="button"
        variant="danger"
        disabled={
          pending
          || representing
          || restoringAttempt
          || Boolean(attempt)
          || cancelReason.trim().length < 3
        }
        onClick={() => void cancel()}
      >
        {pending || representing
          ? "Cancelling exact worker…"
          : "Cancel bounded run"}
      </Button>
      {failurePanel}
      {preflightError && <ErrorPanel
        title="Research cancellation could not be represented"
        error={preflightError}
      />}
      {pollError && <ErrorPanel
        title="Research run status could not be refreshed"
        error={pollError}
      />}
      {message && <p role="status" className="os-success-note">{message}</p>}
    </div>;
  }
  if (activeRun) {
    return <div className="os-research-run-control">
      <StatusPill status={activeRun.status} />
      <small>
        {activeRun.status === "completed"
          ? "Development evaluated locally. Private holdout is still unavailable, so this result cannot promote."
          : "The bounded run ended without a promotable result."}
      </small>
      {failurePanel}
      {pollError && <ErrorPanel
        title="Research run status could not be refreshed"
        error={pollError}
      />}
      {message && <p role="status" className="os-success-note">{message}</p>}
    </div>;
  }
  return <div className="os-research-run-control">
    <label>
      Reproducible seed
      <input
        value={seed}
        disabled={
          restoringAttempt
          || representing
          || Boolean(attempt)
        }
        onChange={(event) => {
          setSeed(event.target.value);
          setPreflightError(undefined);
        }}
        pattern={"[A-Za-z0-9._:\\-]{1,160}"}
      />
    </label>
    <Button
      type="button"
      disabled={
        pending
        || representing
        || restoringAttempt
        || Boolean(attempt)
        || experiment.status !== "queued"
        || !/^[A-Za-z0-9._:-]{1,160}$/u.test(seed.trim())
      }
      onClick={() => void start()}
    >
      {pending || representing
        ? "Starting isolated fixture…"
        : "Run development fixture"}
    </Button>
    {failurePanel}
    {preflightError && <ErrorPanel
      title="Research run could not be represented"
      error={preflightError}
    />}
    {pollError && <ErrorPanel
      title="Research run status could not be refreshed"
      error={pollError}
    />}
    {message && <p role="status" className="os-success-note">{message}</p>}
  </div>;
}

const PROMOTION_ACTION_LABELS: Readonly<
  Record<HumanResearchPromotionAction, string>
> = {
  approve_human_review: "Approve for isolated shadow",
  reject_human_review: "Reject after human review",
  start_shadow: "Start isolated shadow",
  approve_canary: "Approve bounded canary",
  start_canary: "Start bounded canary",
  verify: "Verify strategy",
  reject: "Reject candidate",
  mark_stale: "Mark strategy stale",
  supersede: "Supersede strategy",
  rollback: "Roll back by forward activation",
};

function PromotionControl({
  promotion,
  actorId,
  onChanged,
  onReconcile,
}: {
  readonly promotion: ResearchPromotionLifecycleRecord;
  readonly actorId: string;
  readonly onChanged: () => void;
  readonly onReconcile: () => Promise<void>;
}) {
  const [rationale, setRationale] = useState("");
  const [evidence, setEvidence] = useState(
    promotion.latestIntegrityReceiptId ?? "",
  );
  const [rollbackTarget, setRollbackTarget] = useState(
    promotion.rollbackTargets[0]?.strategyVersionId ?? "",
  );
  const [maxMissions, setMaxMissions] = useState(1);
  const [maxMinutes, setMaxMinutes] = useState(60);
  const [draftVersion, setDraftVersion] = useState(promotion.version);
  const [pendingAction, setPendingAction] =
    useState<HumanResearchPromotionAction>();
  const [failure, setFailure] =
    useState<MutationFailure<ResearchPromotionAttempt>>();
  const [attempt, setAttempt] = useState<ResearchPromotionAttempt>();
  const [reconciliationReady, setReconciliationReady] = useState(false);
  const [message, setMessage] = useState<string>();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const rationaleRef = useRef<HTMLTextAreaElement>(null);
  const evidenceInputId = useId();
  const evidenceHelpId = useId();
  const focusAfterLifecycleAdvance = useRef(false);
  const storage = availableResearchPromotionStorage();
  const rollbackTargetSignature = promotion.rollbackTargets
    .map(({ strategyVersionId }) => strategyVersionId)
    .join("|");
  const rollbackTargetValid = promotion.rollbackTargets.some(({ strategyVersionId }) =>
    strategyVersionId === rollbackTarget);
  const evidenceRefs = evidence
    .split(/[\n,]/u)
    .map((item) => item.trim())
    .filter(Boolean);
  const focusDecisionReview = () => {
    window.requestAnimationFrame(() => {
      const activeElement = document.activeElement;
      const currentCard = headingRef.current?.closest<HTMLElement>(".os-card");
      // A lifecycle refresh can reorder promotion cards. Restore focus only
      // while the operator is still in this card (or nowhere interactive);
      // never steal typing that has already moved to another decision.
      if (
        activeElement
        && activeElement !== document.body
        && activeElement !== document.documentElement
        && !currentCard?.contains(activeElement)
      ) {
        return;
      }
      rationaleRef.current?.focus();
      if (document.activeElement !== rationaleRef.current) {
        headingRef.current?.focus();
      }
    });
  };
  const discardAttempt = (notice?: string) => {
    clearResearchPromotionAttempt(
      storage,
      actorId,
      promotion.experimentId,
    );
    setAttempt(undefined);
    setFailure(undefined);
    setReconciliationReady(false);
    if (notice) setMessage(notice);
  };
  const retryError = (
    text: string,
    remediation: string,
  ): Error => Object.assign(new Error(text), {
    humanMessage: text,
    remediation,
  });
  const execute = async (retained: ResearchPromotionAttempt) => {
    const dispatching: ResearchPromotionAttempt = {
      ...retained,
      disposition: "dispatching",
      failureCode: null,
    };
    if (!await saveResearchPromotionAttempt(storage, dispatching)) {
      setFailure({
        error: retryError(
          "The exact Research decision could not be retained before dispatch.",
          "Restore this tab's session storage, then review and submit the decision again.",
        ),
        intent: dispatching,
        retryable: false,
      });
      return;
    }
    setAttempt(dispatching);
    setPendingAction(dispatching.action);
    setFailure(undefined);
    setMessage(undefined);
    try {
      await researchApi.transitionPromotionSerialized(
        dispatching.experimentId,
        dispatching.serializedBody,
        dispatching.idempotencyKey,
      );
      clearResearchPromotionAttempt(
        storage,
        dispatching.actorId,
        dispatching.experimentId,
      );
      setAttempt(undefined);
      setMessage(
        `${PROMOTION_ACTION_LABELS[dispatching.action]} recorded. No production deployment was created.`,
      );
      focusAfterLifecycleAdvance.current = true;
      onChanged();
    } catch (cause) {
      const error = toError(
        cause,
        "Promotion decision could not be recorded",
      );
      const disposition = classifyResearchPromotionFailure(error);
      if (disposition === "fresh_review") {
        clearResearchPromotionAttempt(
          storage,
          dispatching.actorId,
          dispatching.experimentId,
        );
        setAttempt(undefined);
        setFailure({ error, intent: dispatching, retryable: false });
        return;
      }
      const failed = withResearchPromotionFailure(
        dispatching,
        disposition,
        error,
      );
      if (!await saveResearchPromotionAttempt(storage, failed)) {
        clearResearchPromotionAttempt(
          storage,
          dispatching.actorId,
          dispatching.experimentId,
        );
        setAttempt(undefined);
        setFailure({
          error: retryError(
            "The Research response was not confirmed and its retry record could not be retained.",
            "Refresh canonical lifecycle state. Do not submit a different decision until the original result is reconciled.",
          ),
          intent: dispatching,
          retryable: false,
        });
        return;
      }
      setAttempt(failed);
      setFailure({
        error,
        intent: failed,
        retryable: disposition === "retryable",
      });
    } finally {
      setPendingAction(undefined);
    }
  };
  const activate = async (action: HumanResearchPromotionAction) => {
    const intent: PromotionIntent = {
      experimentId: promotion.experimentId,
      expectedVersion: promotion.version,
      action,
      rationale: rationale.trim(),
      evidenceRefs,
      ...(action === "rollback"
        ? { targetStrategyVersionId: rollbackTarget }
        : {}),
      ...(action === "start_canary"
        ? {
            canaryBounds: {
              maxMissions,
              maxWallClockMs: maxMinutes * 60_000,
            },
          }
        : {}),
      idempotencyKey: `research-promotion-${crypto.randomUUID()}`,
    };
    try {
      const retained = await createResearchPromotionAttempt({
        actorId,
        experimentId: intent.experimentId,
        serializedBody: serializeResearchPromotionRequest(intent),
        idempotencyKey: intent.idempotencyKey,
      });
      await execute(retained);
    } catch (cause) {
      setFailure({
        error: toError(
          cause,
          "The Research decision could not be retained safely",
        ),
        intent: {
          schemaVersion: RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION,
          kind: "research_promotion_attempt",
          actorId,
          experimentId: intent.experimentId,
          expectedVersion: intent.expectedVersion,
          action: intent.action,
          idempotencyKey: intent.idempotencyKey,
          serializedBody: "",
          bodySha256: "",
          decisionFingerprint: "",
          disposition: "uncertain",
          failureCode: null,
          createdAt: new Date().toISOString(),
          expiresAt: new Date().toISOString(),
        },
        retryable: false,
      });
    }
  };
  useEffect(() => {
    if (draftVersion === promotion.version) return;
    setRationale("");
    setEvidence(promotion.latestIntegrityReceiptId ?? "");
    setRollbackTarget(
      promotion.rollbackTargets[0]?.strategyVersionId ?? "",
    );
    setMaxMissions(1);
    setMaxMinutes(60);
    setDraftVersion(promotion.version);
    if (focusAfterLifecycleAdvance.current) {
      focusAfterLifecycleAdvance.current = false;
      focusDecisionReview();
    }
  }, [
    draftVersion,
    promotion.latestIntegrityReceiptId,
    promotion.version,
    rollbackTargetSignature,
  ]);
  useEffect(() => {
    if (rollbackTargetValid || promotion.rollbackTargets.length === 0) {
      if (promotion.rollbackTargets.length === 0 && rollbackTarget) {
        setRollbackTarget("");
      }
      return;
    }
    setRollbackTarget(
      promotion.rollbackTargets[0]?.strategyVersionId ?? "",
    );
  }, [rollbackTargetSignature, rollbackTarget, rollbackTargetValid]);
  useEffect(() => {
    let active = true;
    setAttempt(undefined);
    setFailure(undefined);
    setReconciliationReady(false);
    if (!actorId) return () => { active = false; };
    void loadResearchPromotionAttempt(
      storage,
      actorId,
      promotion.experimentId,
    ).then((restored) => {
      if (!active || !restored) return;
      const attribution = classifyResearchPromotionOutcomeAttribution(
        restored,
        promotion,
      );
      if (attribution === "same_actor") {
        discardAttempt(
          "The earlier Research decision is already present in the canonical lifecycle under your reviewer identity.",
        );
        focusDecisionReview();
        return;
      }
      if (attribution === "other_actor") {
        discardAttempt(
          "A different authorized reviewer recorded the same lifecycle action. Your retained decision was not recorded under your identity; review the canonical transition.",
        );
        focusDecisionReview();
        return;
      }
      if (attribution === "other_decision") {
        discardAttempt(
          "Your reviewer identity recorded a different decision at this lifecycle version. The retained decision was not applied; review the canonical transition.",
        );
        focusDecisionReview();
        return;
      }
      if (!researchPromotionAttemptMatchesProjection(restored, promotion)) {
        discardAttempt("The retained Research decision no longer matches the canonical lifecycle and was discarded.");
        return;
      }
      const retryable = restored.disposition === "retryable"
        ? restored
        : { ...restored, disposition: "retryable" as const };
      void saveResearchPromotionAttempt(storage, retryable);
      setAttempt(retryable);
      setFailure({
        error: retryError(
          restored.disposition === "retryable"
            ? "A retryable Research decision is awaiting an exact replay."
            : "The previous response was lost; the freshly loaded lifecycle still matches the original decision.",
          "Retry only the retained body and original Idempotency-Key.",
        ),
        intent: retryable,
        retryable: true,
      });
    });
    return () => { active = false; };
  }, [actorId, promotion.experimentId]);
  useEffect(() => {
    if (!attempt || !reconciliationReady) return;
    setReconciliationReady(false);
    const attribution = classifyResearchPromotionOutcomeAttribution(
      attempt,
      promotion,
    );
    if (attribution === "same_actor") {
      discardAttempt(
        "Canonical lifecycle state confirms the earlier Research decision was recorded under your reviewer identity.",
      );
      focusDecisionReview();
      return;
    }
    if (attribution === "other_actor") {
      discardAttempt(
        "A different authorized reviewer recorded the same lifecycle action. Your retained decision was not recorded under your identity; review the canonical transition.",
      );
      focusDecisionReview();
      return;
    }
    if (attribution === "other_decision") {
      discardAttempt(
        "Your reviewer identity recorded a different decision at this lifecycle version. The retained decision was not applied; review the canonical transition.",
      );
      focusDecisionReview();
      return;
    }
    if (!researchPromotionAttemptMatchesProjection(attempt, promotion)) {
      discardAttempt("Canonical lifecycle state changed; review a fresh Research decision.");
      focusDecisionReview();
      return;
    }
    const retryable = {
      ...attempt,
      disposition: "retryable" as const,
      failureCode: null,
    };
    void saveResearchPromotionAttempt(storage, retryable);
    setAttempt(retryable);
    setFailure({
      error: retryError(
        "Canonical lifecycle state is unchanged and the original Research decision can be replayed exactly.",
        "Use Try again to resend the retained bytes and original Idempotency-Key.",
      ),
      intent: retryable,
      retryable: true,
    });
  }, [promotion.version, reconciliationReady]);
  useEffect(() => {
    if (!attempt) return;
    const delay = Math.max(0, Date.parse(attempt.expiresAt) - Date.now());
    const timeout = window.setTimeout(() => {
      discardAttempt("The retained Research decision expired. Review current lifecycle state before creating a fresh decision.");
    }, Math.min(delay, 2_147_483_647));
    return () => window.clearTimeout(timeout);
  }, [attempt?.expiresAt, actorId, promotion.experimentId]);
  const decisionInputChanged = () => {
    if (attempt || failure) {
      discardAttempt("The retained decision was discarded because its represented inputs changed.");
    }
  };
  const canSubmit =
    draftVersion === promotion.version
    && actorId.length > 0
    && rationale.trim().length >= 3
    && evidenceRefs.length > 0
    && !pendingAction
    && !failure;
  return <Card>
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">{promotion.stage.replaceAll("_", " ")}</p>
        <h3 ref={headingRef} tabIndex={-1}>
          Strategy {promotion.strategyVersionId}
        </h3>
        <p>
          Experiment {promotion.experimentId} · lifecycle version{" "}
          {promotion.version}
        </p>
      </div>
      <StatusPill status={promotion.state} />
    </div>
    <KeyValueGrid items={[
      {
        label: "Development",
        value: promotion.milestones.developmentPassed ? "passed" : "pending",
      },
      {
        label: "Validation",
        value: promotion.milestones.validationPassed ? "passed" : "pending",
      },
      {
        label: "Hidden holdout",
        value: promotion.milestones.hiddenHoldoutPassed ? "passed" : "pending",
      },
      {
        label: "Shadow",
        value: promotion.milestones.shadowPassed ? "passed" : "pending",
      },
      {
        label: "Bounded canary",
        value: promotion.milestones.canaryPassed ? "passed" : "pending",
      },
    ]} />
    <JsonDetails
      label="Immutable transition history"
      value={promotion.transitions}
    />
    {promotion.availableHumanActions.length === 0
      ? <p className="os-state-remediation">
          No human action is currently valid. The local evaluator must complete
          the represented stage, or this lifecycle is terminal.
        </p>
      : <div className="os-details-content">
          <label>
            Decision rationale
            <textarea
              ref={rationaleRef}
              required
              minLength={3}
              value={rationale}
              onChange={(event) => {
                decisionInputChanged();
                setRationale(event.target.value);
              }}
              placeholder="The signed holdout result passed every hard gate and preserved evidence quality."
            />
          </label>
          <div>
            <label htmlFor={evidenceInputId}>
              Evidence or receipt references
              <textarea
                id={evidenceInputId}
                aria-describedby={evidenceHelpId}
                required
                value={evidence}
                onChange={(event) => {
                  decisionInputChanged();
                  setEvidence(event.target.value);
                }}
                placeholder="integrity_receipt_id, evaluation_id"
              />
            </label>
            <small id={evidenceHelpId}>
              Enter stable IDs separated by commas or new lines. These become
              part of the immutable review record.
            </small>
          </div>
          {promotion.availableHumanActions.includes("start_canary")
            && <fieldset>
              <legend>Bounded canary limits</legend>
              <label>
                Maximum missions
                <input
                  type="number"
                  min={1}
                  max={10}
                  value={maxMissions}
                  onChange={(event) => {
                    decisionInputChanged();
                    setMaxMissions(Number(event.target.value));
                  }}
                />
              </label>
              <label>
                Maximum minutes
                <input
                  type="number"
                  min={1}
                  max={1_440}
                  value={maxMinutes}
                  onChange={(event) => {
                    decisionInputChanged();
                    setMaxMinutes(Number(event.target.value));
                  }}
                />
              </label>
            </fieldset>}
          {promotion.availableHumanActions.includes("rollback")
            && <fieldset>
              <legend>Previously verified rollback target</legend>
              {promotion.rollbackTargets.length === 0
                ? <p className="os-state-remediation">
                    No different verified strategy is available. Rollback stays
                    disabled; no bundle or database state will be copied.
                  </p>
                : promotion.rollbackTargets.map((target) =>
                    <label
                      key={target.strategyVersionId}
                      className="os-check-field"
                    >
                      <input
                        type="radio"
                        name={`rollback-${promotion.experimentId}`}
                        value={target.strategyVersionId}
                        checked={rollbackTarget === target.strategyVersionId}
                        onChange={() => {
                          decisionInputChanged();
                          setRollbackTarget(target.strategyVersionId);
                        }}
                      />
                      <span>
                        <strong>{target.strategyVersionId}</strong>
                        <small>{target.experimentId}</small>
                      </span>
                    </label>)}
            </fieldset>}
          {failure && <ResearchMutationFailure
            title="Promotion decision was not recorded"
            failure={failure}
            onRetry={() => void execute(failure.intent)}
            onRefresh={onReconcile}
            onResolved={() => {
              if (attempt?.disposition === "uncertain") {
                setReconciliationReady(true);
              } else {
                setFailure(undefined);
                focusDecisionReview();
              }
            }}
            refreshLabel="Refresh lifecycle state"
          />}
          {failure && attempt && <Button
            type="button"
            variant="secondary"
            onClick={() => {
              discardAttempt(
                "The retained Research decision was discarded. Review the current lifecycle before submitting another decision.",
              );
              focusDecisionReview();
            }}
          >
            Discard retained decision
          </Button>}
          {message && <p role="status" className="os-success-note">
            {message}
          </p>}
          <div className="os-form-actions">
            {promotion.availableHumanActions.map((action) =>
              <Button
                key={action}
                type="button"
                variant={
                  action.includes("reject")
                    || action === "rollback"
                    || action === "mark_stale"
                    || action === "supersede"
                    ? "danger"
                    : action.includes("approve") || action === "verify"
                      ? "primary"
                      : "secondary"
                }
                disabled={
                  !canSubmit
                  || (action === "rollback" && !rollbackTargetValid)
                  || (
                    action === "start_canary"
                    && (
                      !Number.isSafeInteger(maxMissions)
                      || maxMissions < 1
                      || maxMissions > 10
                      || !Number.isSafeInteger(maxMinutes)
                      || maxMinutes < 1
                      || maxMinutes > 1_440
                    )
                  )
                }
                onClick={() => void activate(action)}
              >
                {pendingAction === action
                  ? `${PROMOTION_ACTION_LABELS[action]}…`
                  : PROMOTION_ACTION_LABELS[action]}
              </Button>)}
          </div>
        </div>}
  </Card>;
}
