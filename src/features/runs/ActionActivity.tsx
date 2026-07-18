import { operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import type { ActionRecord } from "../../domain/types/operations";
import { ButtonLink, Card, StatusPill } from "../../design-system/components/Primitives";
import { ContextUsedDisclosure } from "../brain/ContextUsedDisclosure";
import { DegradedNotice, formatDuration, formatTime, JsonDetails, KeyValueGrid, QueryBoundary } from "./OperationalSurface";
import { formatOperatorCopy } from "../../lib/operatorLanguage";

function elapsedSeconds(action: ActionRecord): number | null {
  if (!action.startedAt) return null;
  const end = action.endedAt ? Date.parse(action.endedAt) : Date.now();
  const start = Date.parse(action.startedAt);
  return Number.isFinite(start) && Number.isFinite(end) && end >= start ? (end - start) / 1_000 : null;
}

type ActionActivityProps = ({ missionId: string; runId?: never } | { missionId?: never; runId: string }) & {
  title?: string;
  limit?: number;
};

export function ActionActivity({ missionId, runId, title = "Semantic action activity", limit = 50 }: ActionActivityProps) {
  const scope = runId ? { runId, limit } : { missionId, limit };
  const key = runId ?? missionId ?? "unscoped";
  const actions = useQuery(`actions:${key}:${limit}`, (signal) => operationsApi.actions(scope, signal), { staleTime: 0 });
  const evidence = useQuery(`action-evidence:${key}`, (signal) => operationsApi.evidence({ ...scope, limit: 100 }, signal), { staleTime: 10_000 });
  const artifacts = useQuery(`action-artifacts:${key}`, (signal) => operationsApi.artifacts({ ...scope, limit: 100 }, signal), { staleTime: 10_000 });
  const evidenceCounts = new Map<string, number>();
  const artifactCounts = new Map<string, number>();
  evidence.data?.items.forEach((item) => { if (item.actionId) evidenceCounts.set(item.actionId, (evidenceCounts.get(item.actionId) ?? 0) + 1); });
  artifacts.data?.items.forEach((item) => { if (item.actionId) artifactCounts.set(item.actionId, (artifactCounts.get(item.actionId) ?? 0) + 1); });

  return <section className="os-action-activity" aria-labelledby={`action-activity-${key}`}>
    <div className="os-card-heading"><div><p className="os-eyebrow">Durable execution record</p><h2 id={`action-activity-${key}`}>{title}</h2></div><StatusPill status={actions.data?.items.some((item) => item.status === "running") ? "live" : "recorded"} /></div>
    {(evidence.error || artifacts.error) && <DegradedNotice>Evidence or artifact deltas could not refresh. Action status and memory context remain canonical.</DegradedNotice>}
    <QueryBoundary data={actions.data?.items} error={actions.error} isLoading={actions.isLoading} onRetry={actions.refresh} emptyTitle="No durable actions" emptyDescription="The run has not created a policy-bound action record yet.">{(items) => <ol className="os-action-list">
      {items.map((action) => {
        const intent = formatOperatorCopy(action.intentSummary, { kind: "action_intent", agent: action.agentId, target: action.target });
        const actionResult = formatOperatorCopy(action.resultSummary, { kind: "action_result", agent: action.agentId, target: action.target });
        return <li key={action.id}><Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">{action.agentId ?? "Runtime supervisor"} · {action.actionClass}</p><h3>{intent.displayText}</h3></div><StatusPill status={action.status} /></div>
        <p>{actionResult.displayText || (action.status === "running" ? "The bounded action is still executing." : "No semantic result summary was persisted.")}</p>
        <KeyValueGrid items={[
          { label: "Phase / step", value: action.step ? `${action.step.phase} · ${action.step.title}` : "Run-level action" },
          { label: "Target", value: action.target ?? "Not reported" },
          { label: "Duration", value: formatDuration(elapsedSeconds(action)) },
          { label: "Retries", value: action.retryCount },
          { label: "Evidence delta", value: evidenceCounts.get(action.id) ?? 0 },
          { label: "Artifacts", value: artifactCounts.get(action.id) ?? 0 },
          { label: "Authority", value: action.guidedDecisionId ? "Exact Guided decision" : action.contractId ? "Signed Autonomous contract" : "Runtime policy" },
          { label: "Updated", value: formatTime(action.updatedAt) },
        ]} />
        <div className="os-action-links">
          {(evidenceCounts.get(action.id) ?? 0) > 0 && <ButtonLink href={`/intelligence/evidence?runId=${encodeURIComponent(action.runId)}`} variant="quiet">View evidence</ButtonLink>}
          {(artifactCounts.get(action.id) ?? 0) > 0 && <ButtonLink href={`/intelligence/artifacts?runId=${encodeURIComponent(action.runId)}`} variant="quiet">View artifacts</ButtonLink>}
        </div>
        {action.contextPackId ? <ContextUsedDisclosure packId={action.contextPackId} /> : <p className="os-muted">No persisted memory context pack influenced this action.</p>}
        <JsonDetails label="Technical action detail and original wording" value={{
          actionId: action.id, actionType: action.actionType, stepId: action.step?.id ?? null,
          rawIntentSummary: action.intentSummary, rawResultSummary: action.resultSummary,
          guidedDecisionId: action.guidedDecisionId, contractId: action.contractId,
          contextPackId: action.contextPackId, correlation: action.correlation,
          errorCategory: action.errorCategory, startedAt: action.startedAt, endedAt: action.endedAt,
        }} />
      </Card></li>;
      })}
    </ol>}</QueryBoundary>
  </section>;
}
