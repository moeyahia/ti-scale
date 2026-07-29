import { fetchRunModelAssignments } from "../../data/api/modelConfiguration";
import { useQuery } from "../../data/cache/QueryProvider";
import { Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type {
  ModelConfiguration,
  PinnedModelAssignmentReadback,
  RunModelAssignmentPage,
} from "../../domain/types/modelConfiguration";
import { formatTime, KeyValueGrid } from "../runs/OperationalSurface";
import "./run-model-assignments.css";

function readable(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/gu, (character) =>
    character.toUpperCase());
}

function configurationLabel(configuration: ModelConfiguration): string {
  const model = configuration.displayName === configuration.modelId
    ? configuration.displayName
    : `${configuration.displayName} · ${configuration.modelId}`;
  return `${configuration.providerId} · ${model}`;
}

function fallbackLabel(
  configuration: PinnedModelAssignmentReadback["fallbackConfiguration"],
): string {
  return configuration ? configurationLabel(configuration) : "No automatic fallback";
}

function sortedAssignments(
  items: readonly PinnedModelAssignmentReadback[],
): readonly PinnedModelAssignmentReadback[] {
  return [...items].sort((left, right) => {
    const purpose = left.assignment.purpose.localeCompare(right.assignment.purpose);
    return purpose || left.assignment.agentId.localeCompare(right.assignment.agentId);
  });
}

export function RunModelAssignmentReceiptList({
  page,
}: {
  readonly page: RunModelAssignmentPage;
}) {
  if (page.items.length === 0) {
    return <EmptyState
      title="No model assignment was pinned"
      description="This run has no canonical provider/model receipt. Ti-Scale does not infer a model from logs or current workspace defaults."
    />;
  }
  return <ol className="run-model-assignments__list">
    {sortedAssignments(page.items).map((item) => {
      const { assignment, primaryConfiguration, fallbackConfiguration } = item;
      const advisory = assignment.purpose === "planning";
      return <li
        key={assignment.id}
        className="run-model-assignment"
        aria-label={`${assignment.agentId} ${assignment.purpose} model configuration receipt`}
      >
        <header>
          <div>
            <p className="os-eyebrow">
              {readable(assignment.purpose)} configuration
            </p>
            <h3>{assignment.agentId}</h3>
            <p>{assignment.resolutionReason}</p>
          </div>
          <StatusPill status="pinned">
            {advisory ? "Advisory pin" : "Execution pin"}
          </StatusPill>
        </header>
        {advisory && (
          <p className="run-model-assignment__authority" role="note">
            <strong>No execution authority.</strong>{" "}
            This configuration may advise planning, explanation, and critique
            only; specialist execution remains separately pinned and enforced.
          </p>
        )}
        <KeyValueGrid items={[
          {
            label: "Primary provider and model",
            value: configurationLabel(primaryConfiguration),
          },
          {
            label: "Reasoning effort",
            value: primaryConfiguration.reasoningEffort
              ? readable(primaryConfiguration.reasoningEffort)
              : "Provider default",
          },
          {
            label: "Enforcement",
            value: readable(primaryConfiguration.enforcementMode),
          },
          {
            label: advisory ? "Provider boundary" : "Execution boundary",
            value: readable(primaryConfiguration.executionBoundary),
          },
          {
            label: "Data disclosure",
            value: readable(primaryConfiguration.disclosureClass),
          },
          {
            label: "Provider health at pin",
            value: readable(primaryConfiguration.healthState),
          },
          {
            label: "Fallback",
            value: fallbackLabel(fallbackConfiguration),
          },
          {
            label: "Inherited from",
            value: readable(assignment.inheritanceLevel),
          },
          {
            label: "Pinned at",
            value: formatTime(assignment.resolvedAt),
          },
          {
            label: "Configuration receipt",
            value: <span className="os-mono">{primaryConfiguration.id}</span>,
          },
        ]} />
        {fallbackConfiguration && <p className="run-model-assignment__fallback">
          <strong>Fallback boundary:</strong>{" "}
          {readable(fallbackConfiguration.enforcementMode)} ·{" "}
          {readable(fallbackConfiguration.executionBoundary)} ·{" "}
          {readable(fallbackConfiguration.disclosureClass)}
        </p>}
      </li>;
    })}
  </ol>;
}

export function RunModelAssignmentsPanel({
  runId,
}: {
  readonly runId: string;
}) {
  const query = useQuery(
    `run-model-assignments:${runId}`,
    (signal) => fetchRunModelAssignments(runId, signal),
    { staleTime: 5_000 },
  );
  return <Card
    className="run-model-assignments"
    aria-label="Current run model routing"
  >
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">Current run configuration</p>
        <h2>Pinned provider and model routes</h2>
        <p>
          These are the exact immutable receipts pinned when this run was
          created. Execution and advisory configurations remain distinct;
          workspace or agent changes apply only to future runs.
        </p>
      </div>
      <StatusPill status={query.data?.activeRunPinning ?? "loading"}>
        {query.data
          ? `${query.data.items.length} pinned`
          : "Reading pins"}
      </StatusPill>
    </div>
    {query.isLoading && <LoadingPanel label="Loading pinned provider and model assignments" />}
    {query.error && !query.data && <ErrorPanel
      title="Pinned model assignments are unavailable"
      error={query.error}
    />}
    {query.data && <RunModelAssignmentReceiptList page={query.data} />}
    <p className="run-model-assignments__policy">
      Change future defaults from Agent Fleet → LLM settings. To change an
      Autonomous mission, create a reviewed contract amendment and successor
      run; Ti-Scale never rewrites an active run’s provider/model configuration.
    </p>
  </Card>;
}
