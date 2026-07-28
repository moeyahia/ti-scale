import { useEffect, useRef } from "react";
import { useNavigation } from "../../app/router/navigation";
import { runtimeV2Api } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type {
  AutonomousActivationReceiptDetail,
  AutonomousActivationReceiptSummary,
} from "../../domain/types/runtimeV2";
import { formatTime, JsonDetails, KeyValueGrid } from "./OperationalSurface";

function planningRouteLabel(
  route: AutonomousActivationReceiptSummary["planningRoute"],
): string {
  return route === "provider_advisory"
    ? "Provider advisory plan selection"
    : "Local deterministic plan construction";
}

function integrityLabel(
  status: AutonomousActivationReceiptSummary["integrity"]["status"],
): string {
  if (status === "verified") return "Verified";
  if (status === "expired") return "Expired";
  return "Integrity failure";
}

function detailSearch(
  search: string,
  receiptId: string | null,
): string {
  const parameters = new URLSearchParams(search);
  if (receiptId) parameters.set("activationReceipt", receiptId);
  else parameters.delete("activationReceipt");
  return parameters.size ? `?${parameters.toString()}` : "";
}

export function AutonomousActivationProofPanel({
  runId,
  current,
  onRefresh,
}: {
  runId: string;
  current: AutonomousActivationReceiptSummary | null | undefined;
  onRefresh: () => void;
}) {
  const navigation = useNavigation();
  const selectedReceiptId = new URLSearchParams(navigation.search)
    .get("activationReceipt");
  const history = useQuery(
    `autonomous-activation-receipts:${runId}`,
    (signal) => runtimeV2Api.activationReceipts(runId, 100, signal),
    { staleTime: 0 },
  );
  const open = (receiptId: string) => {
    navigation.navigate(
      `${navigation.pathname}${detailSearch(navigation.search, receiptId)}`,
      { replace: false },
    );
  };
  const close = () => {
    navigation.navigate(
      `${navigation.pathname}${detailSearch(navigation.search, null)}`,
      { replace: false },
    );
    requestAnimationFrame(() => {
      document.getElementById("autonomous-activation-proof-review")?.focus();
    });
  };
  const refresh = () => {
    onRefresh();
    history.refresh();
  };

  if (current === undefined) {
    return <Card className="os-activation-proof" aria-label="Autonomous activation proof">
      <LoadingPanel label="Loading Autonomous activation proof" />
    </Card>;
  }

  return <Card className="os-activation-proof" aria-label="Autonomous activation proof">
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">Contract-bound execution proof</p>
        <h2>Autonomous Activation Proof</h2>
      </div>
      <StatusPill status={current?.integrity.status ?? "pending"}>
        {current ? integrityLabel(current.integrity.status) : "Not issued"}
      </StatusPill>
    </div>
    {!current
      ? <div className="os-activation-proof-message" role="status">
          <strong>Autonomous execution is not proven yet.</strong>
          <p>
            No aggregate activation receipt is attached to this run. Planning,
            model routes, tools, evidence producers, and Brain context must be
            sealed together before Autonomous dispatch.
          </p>
          <p className="os-muted">
            Complete readiness or resolve the launch blockers, then refresh this
            proof. The absence of a receipt is never treated as permission.
          </p>
        </div>
      : <>
          <p role="status" className={
            current.integrity.status === "verified"
              ? "os-success-note"
              : "os-degraded"
          }>
            {current.integrity.humanMessage}
          </p>
          {current.integrity.remediation && <p className="os-muted">
            <strong>Next:</strong> {current.integrity.remediation}
          </p>}
          <KeyValueGrid items={[
            { label: "Generation", value: current.generation },
            {
              label: "Action classes",
              value: `${current.activatedActionClassCount} activated / ${current.selectedActionClassCount} signed`,
            },
            { label: "Planning route", value: planningRouteLabel(current.planningRoute) },
            { label: "Planner", value: current.plannerId },
            { label: "Model routes", value: current.modelRouteCount },
            { label: "Tool routes", value: current.toolRouteCount },
            { label: "Bindings", value: current.bindingCount },
            { label: "Expires", value: formatTime(current.expiresAt) },
          ]} />
        </>}
    <div className="os-button-row">
      <Button
        id="autonomous-activation-proof-refresh"
        type="button"
        variant="secondary"
        onClick={refresh}
      >
        Refresh activation proof
      </Button>
      {current && <Button
        id="autonomous-activation-proof-review"
        type="button"
        onClick={() => open(current.id)}
      >
        Review activation proof
      </Button>}
    </div>
    {history.error && !history.data && <div className="os-degraded" role="alert">
      <strong>Activation proof history is unavailable.</strong>
      <span>{history.error.message} Use Refresh activation proof to retry the bounded read.</span>
    </div>}
    {history.data && history.data.items.length > 1 && <section
      className="os-activation-proof-history"
      aria-label="Activation proof history"
    >
      <h3>Prior generations</h3>
      <ol>
        {history.data.items.slice(1).map((item) => <li key={item.id}>
          <strong>Generation {item.generation}</strong>
          <span>{integrityLabel(item.integrity.status)} · issued {formatTime(item.issuedAt)}</span>
        </li>)}
      </ol>
    </section>}
    {selectedReceiptId && <ActivationReceiptDetailDrawer
      runId={runId}
      receiptId={selectedReceiptId}
      onClose={close}
    />}
  </Card>;
}

function ActivationReceiptDetailDrawer({
  runId,
  receiptId,
  onClose,
}: {
  runId: string;
  receiptId: string;
  onClose: () => void;
}) {
  const detailRegion = useRef<HTMLElement>(null);
  const detail = useQuery(
    `autonomous-activation-receipt:${runId}:${receiptId}`,
    (signal) => runtimeV2Api.activationReceipt(runId, receiptId, signal),
    { staleTime: 0 },
  );
  useEffect(() => {
    detailRegion.current?.focus();
  }, [receiptId]);
  return <section
    ref={detailRegion}
    className="os-activation-proof-detail"
    aria-label="Autonomous activation proof detail"
    aria-live="polite"
    tabIndex={-1}
  >
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">Immutable generation detail</p>
        <h3>Activation proof {receiptId}</h3>
      </div>
      <Button
        id="autonomous-activation-proof-close"
        type="button"
        variant="secondary"
        onClick={onClose}
      >
        Close activation proof
      </Button>
    </div>
    {detail.isLoading && <LoadingPanel label="Loading immutable activation proof" />}
    {detail.error && !detail.data && <div className="os-degraded" role="alert">
      <strong>Activation proof detail is unavailable.</strong>
      <span>{detail.error.message}</span>
      <Button
        id="autonomous-activation-proof-detail-retry"
        type="button"
        variant="secondary"
        onClick={detail.refresh}
      >
        Retry activation proof detail
      </Button>
    </div>}
    {detail.data && <ActivationReceiptDetailContent detail={detail.data} />}
  </section>;
}

function ActivationReceiptDetailContent({
  detail,
}: {
  detail: AutonomousActivationReceiptDetail;
}) {
  const { receipt, summary } = detail;
  return <>
    <KeyValueGrid items={[
      { label: "Integrity", value: integrityLabel(summary.integrity.status) },
      { label: "Planning route", value: planningRouteLabel(summary.planningRoute) },
      { label: "Planning model pin", value: summary.planningModelAssignmentId ?? "No provider model — local planner" },
      { label: "Context Pack", value: receipt.brainContextPackId },
      { label: "Runtime generation", value: receipt.runtimeGenerationHash.slice(0, 16) },
      { label: "Issued", value: formatTime(receipt.issuedAt) },
      { label: "Expires", value: formatTime(receipt.expiresAt) },
      { label: "Binding chain", value: `${receipt.bindings.length} sealed transitions` },
    ]} />
    <section aria-label="Activated action-class routes">
      <h4>Activated action-class routes</h4>
      <ol className="os-activation-route-list">
        {receipt.items.map((route) => <li key={route.actionClassId}>
          <strong>{route.actionClassId}</strong>
          <span>
            {route.agentId} · {route.toolId} · {route.toolBindingKind === "mcp"
              ? `MCP ${route.mcpServerId}`
              : "local binding"}
          </span>
          <span>Model pin {route.executionModelAssignmentId}</span>
          <span>{route.evidenceTypeIds.length} evidence types · expires {formatTime(route.routeExpiresAt)}</span>
        </li>)}
      </ol>
    </section>
    <section aria-label="Activation binding chain">
      <h4>Binding chain</h4>
      <ol className="os-activation-binding-list">
        {receipt.bindings.map((binding) => <li key={binding.id}>
          <strong>{binding.sequence}. {binding.bindingType.replaceAll("_", " ")}</strong>
          <span>{binding.subjectId} · {formatTime(binding.boundAt)}</span>
        </li>)}
      </ol>
    </section>
    <JsonDetails
      id="autonomous-activation-proof-technical-hashes"
      label="Technical activation hashes"
      value={{
        receiptHash: receipt.receiptHash,
        contractHash: receipt.contractHash,
        runtimeGenerationHash: receipt.runtimeGenerationHash,
        planningSelectionHash: receipt.planning.selectionHash,
        planningPrimaryConfigurationHash:
          receipt.planning.primaryConfigurationHash,
        planningFallbackConfigurationHash:
          receipt.planning.fallbackConfigurationHash,
        modelAssignmentSetHash: receipt.modelAssignmentSetHash,
        evidencePolicyHash: receipt.evidencePolicyHash,
        brainContextPackHash: receipt.brainContextPackHash,
        routeSetHash: receipt.routeSetHash,
        routeHashes: receipt.items.map((item) => ({
          actionClassId: item.actionClassId,
          routeHash: item.routeHash,
          toolActivationReceiptHash: item.toolActivationReceiptHash,
          toolManifestHash: item.toolManifestHash,
        })),
        bindingHashes: receipt.bindings.map((binding) => binding.bindingHash),
      }}
    />
  </>;
}
