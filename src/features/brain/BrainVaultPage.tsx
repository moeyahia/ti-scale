import { useEffect, useState } from "react";
import { activateAttackKnowledgeVaultPreset, amendAttackKnowledgeVaultPreset, checkVaultHealth, connectVault, createBrainMutationKey, disconnectVault, exportVault, fetchAttackKnowledgeVaultPreset, fetchVaultSnapshot, importVault, reindexVault, repairVault, resolveVaultConflict, syncVault } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { useModalFocus } from "../../design-system/hooks/useModalFocus";
import type { VaultConnection, VaultHealthCheckResult, VaultOperationResult, VaultRecoveryResult } from "../../domain/types/brain";
import { BrainEmpty, BrainNav, formatBrainDate } from "./BrainNav";
import {
  commitThenReconcile,
  createVaultRecoveryAttempt,
  executeVaultRecoveryAttempt,
  type VaultRecoveryAttempt,
} from "./vaultRecoveryFlow";

function VaultDisconnectDialog({ connection, hasHealthyReplacement, pending, onCancel, onConfirm }: {
  connection: VaultConnection;
  hasHealthyReplacement: boolean;
  pending: boolean;
  onCancel: () => void;
  onConfirm: (input: { reason: string; allowProjectionDegraded: boolean }) => void;
}) {
  const [reason, setReason] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [degradedAcknowledged, setDegradedAcknowledged] = useState(false);
  const modalFocus = useModalFocus(true, onCancel, pending);
  const allowProjectionDegraded = !hasHealthyReplacement && degradedAcknowledged;
  const canDisconnect = reason.trim().length >= 12
    && acknowledged
    && (hasHealthyReplacement || degradedAcknowledged)
    && !pending;
  return <div className="brain-modal-layer" role="presentation" onMouseDown={(event) => {
    if (event.target === event.currentTarget && !pending) onCancel();
  }}>
    <section ref={modalFocus.dialogRef} className="brain-edit-dialog brain-vault-disconnect-dialog" role="dialog" aria-modal="true" aria-labelledby="vault-disconnect-title" aria-describedby="vault-disconnect-description" tabIndex={-1} onKeyDown={modalFocus.onDialogKeyDown}>
      <p className="os-eyebrow">Audited projection lifecycle</p>
      <h2 id="vault-disconnect-title">Disconnect {connection.displayName}</h2>
      <p id="vault-disconnect-description">Ti-Scale will stop future projection and synchronization for this connection. It will not delete the Vault, rewrite a note, remove an attachment, or change canonical Second Brain memory.</p>
      <dl>
        <div><dt>Vault path</dt><dd><code>{connection.vaultPath}</code></dd></div>
        <div><dt>After disconnect</dt><dd>{hasHealthyReplacement ? "A health-verified replacement remains active" : "Obsidian projection enters a controlled degraded state"}</dd></div>
      </dl>
      <label>Reason for disconnecting<textarea data-modal-initial-focus value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Retire the generic projection after the reviewed Attack Knowledge Vault is healthy." /></label>
      <label className="os-check-field"><input type="checkbox" aria-label="Acknowledge Vault disconnect effects" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /><span><strong>I understand this stops future synchronization only</strong><small>Existing files and notes remain exactly where they are.</small></span></label>
      {!hasHealthyReplacement && <label className="os-check-field"><input type="checkbox" aria-label="Allow controlled degraded Obsidian projection" checked={degradedAcknowledged} onChange={(event) => setDegradedAcknowledged(event.target.checked)} /><span><strong>Continue without an active Obsidian projection</strong><small>Canonical SQLite memory remains available, but Vault projection is visibly degraded until another connection passes its round-trip health check.</small></span></label>}
      <div><Button variant="secondary" disabled={pending} onClick={onCancel}>Cancel</Button><Button variant="danger" disabled={!canDisconnect} onClick={() => onConfirm({ reason: reason.trim(), allowProjectionDegraded })}>{pending ? "Disconnecting…" : "Disconnect Vault projection"}</Button></div>
    </section>
  </div>;
}

export default function BrainVaultPage() {
  const vault = useQuery("brain-vault", fetchVaultSnapshot, { staleTime: 0 });
  const [includeConfirmedKnowledge, setIncludeConfirmedKnowledge] = useState(false);
  const [includeOperatorProfile, setIncludeOperatorProfile] = useState(false);
  const attackVaultPreset = useQuery(
    `brain-vault-attack-preset-${includeConfirmedKnowledge ? "confirmed" : "verified"}-${includeOperatorProfile ? "operator-profile" : "attack-only"}`,
    (signal) => fetchAttackKnowledgeVaultPreset(includeConfirmedKnowledge, signal, includeOperatorProfile),
    { staleTime: 0 },
  );
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [permission, setPermission] = useState(false);
  const [health, setHealth] = useState<VaultHealthCheckResult>();
  const [presetPermission, setPresetPermission] = useState(false);
  const [presetAcknowledged, setPresetAcknowledged] = useState(false);
  const [presetHealth, setPresetHealth] = useState<VaultHealthCheckResult>();
  const [presetState, setPresetState] = useState<{
    busy?: "health" | "activate" | "amend";
    message?: string;
    error?: Error;
    errorSource?: "health" | "activate" | "amend";
  }>({});
  const [disconnectTarget, setDisconnectTarget] = useState<VaultConnection>();
  const [disconnectPending, setDisconnectPending] = useState(false);
  const [state, setState] = useState<{
    busy?: string;
    result?: VaultOperationResult | VaultRecoveryResult;
    message?: string;
    error?: Error;
    errorSource?: "health" | "connect" | "operation" | "repair" | "reindex" | "reconcile";
    errorConnectionId?: string;
    recoveryAttempt?: VaultRecoveryAttempt;
  }>({});
  const snapshot = vault.data;
  const preset = attackVaultPreset.data;
  const operationRetryControlId = state.errorSource === "health"
    ? "brain-vault-custom-health-retry"
    : state.errorSource === "connect"
      ? "brain-vault-connect-retry"
      : state.errorSource === "repair"
        ? "brain-vault-repair-retry"
        : state.errorSource === "reindex"
          ? "brain-vault-reindex-retry"
          : state.errorSource === "reconcile"
            ? "brain-vault-reconcile-retry"
            : undefined;
  const operationRetryLabel = state.errorSource === "health"
    ? "Retry custom Vault path health check"
    : state.errorSource === "connect"
      ? "Retry Vault connection"
      : state.errorSource === "repair"
        ? "Retry Vault repair"
        : state.errorSource === "reindex"
          ? "Retry Vault reindex"
          : state.errorSource === "reconcile"
            ? "Retry Vault status refresh"
            : undefined;
  useEffect(() => {
    if (!includeOperatorProfile || preset?.operatorProfileAvailability.available !== false) return;
    // The authenticated operator may remove or expire the last eligible
    // preference while this page is open. Return to the valid attack-only
    // preview instead of leaving an impossible selection or hiding the card.
    setIncludeOperatorProfile(false);
    setPresetHealth(undefined);
    setPresetAcknowledged(false);
  }, [includeOperatorProfile, preset?.operatorProfileAvailability.available]);
  const available = Boolean(snapshot?.enabled && snapshot.syncEnabled !== false);
  const run = async (
    busy: string,
    action: () => Promise<VaultOperationResult | VaultRecoveryResult>,
    message?: string,
    errorSource: "operation" | "repair" | "reindex" = "operation",
    errorConnectionId?: string,
  ) => {
    setState({ busy });
    try {
      const outcome = await commitThenReconcile({
        mutate: action,
        reconcile: vault.reconcile,
        onCommitted: (result) => setState({
          result,
          message: `${message ?? result.message} The server committed this receipt; refreshing Vault status…`,
        }),
      });
      if (outcome.reconcileError) {
        setState({
          result: outcome.result,
          message: `${message ?? outcome.result.message} The operation is committed; only the status refresh failed.`,
          error: outcome.reconcileError,
          errorSource: "reconcile",
        });
      } else setState({ result: outcome.result, message: message ?? outcome.result.message });
    } catch (error) {
      setState({
        error: error instanceof Error ? error : new Error("Vault operation failed"),
        errorSource,
        ...(errorConnectionId ? { errorConnectionId } : {}),
      });
    }
  };
  const runRecovery = async (attempt: VaultRecoveryAttempt) => {
    setState({ busy: `${attempt.operation}:${attempt.connectionId}`, recoveryAttempt: attempt });
    try {
      const outcome = await commitThenReconcile({
        mutate: () => executeVaultRecoveryAttempt(attempt, repairVault, reindexVault),
        reconcile: vault.reconcile,
        onCommitted: (result) => setState({
          result,
          recoveryAttempt: attempt,
          message: `${result.message} The server committed this recovery receipt; refreshing Vault status…`,
        }),
      });
      if (outcome.reconcileError) {
        setState({
          result: outcome.result,
          recoveryAttempt: attempt,
          message: `${outcome.result.message} Recovery is committed; only the status refresh failed.`,
          error: outcome.reconcileError,
          errorSource: "reconcile",
          errorConnectionId: attempt.connectionId,
        });
      } else {
        setState({ result: outcome.result, recoveryAttempt: attempt, message: outcome.result.message });
      }
    } catch (error) {
      setState({
        error: error instanceof Error ? error : new Error("Vault recovery failed"),
        errorSource: attempt.operation,
        errorConnectionId: attempt.connectionId,
        recoveryAttempt: attempt,
      });
    }
  };
  const startRecovery = (operation: "repair" | "reindex", connectionId: string, expectedUpdatedAt: string) => runRecovery(
    createVaultRecoveryAttempt({
      operation,
      connectionId,
      expectedUpdatedAt,
      idempotencyKey: createBrainMutationKey(),
    }),
  );
  const testCandidateHealth = async () => {
    const candidatePath = path.trim();
    setHealth(undefined);
    setState({ busy: "health" });
    try {
      const result = await checkVaultHealth({ vaultPath: candidatePath, permissionGranted: true });
      setPath(result.vaultPath);
      setHealth(result);
      setState({ message: result.message });
    } catch (error) {
      setState({ error: error instanceof Error ? error : new Error("Unable to verify vault health"), errorSource: "health" });
    }
  };
  const testAttackKnowledgeVaultHealth = async () => {
    if (!preset) return;
    setPresetHealth(undefined);
    setPresetState({ busy: "health" });
    try {
      const result = await checkVaultHealth({ vaultPath: preset.vaultPath, permissionGranted: true });
      setPresetHealth(result);
      setPresetState({ message: result.message });
    } catch (error) {
      setPresetState({
        error: error instanceof Error ? error : new Error("Unable to verify Attack Knowledge Vault health"),
        errorSource: "health",
      });
    }
  };
  const activateAttackKnowledgeVault = async () => {
    if (!preset) return;
    const operatorProfileUpgrade = includeOperatorProfile ? preset.operatorProfileScopeUpgrade : undefined;
    const confirmedUpgrade = includeConfirmedKnowledge ? preset.confirmedScopeUpgrade : undefined;
    const upgrade = operatorProfileUpgrade ?? confirmedUpgrade;
    setPresetState({ busy: upgrade ? "amend" : "activate" });
    try {
      if (operatorProfileUpgrade) {
        await amendAttackKnowledgeVaultPreset({
          connectionId: operatorProfileUpgrade.connectionId,
          expectedUpdatedAt: operatorProfileUpgrade.expectedUpdatedAt,
          expectedCurrentPolicyHash: operatorProfileUpgrade.currentPolicyHash,
          expectedTargetPolicyHash: operatorProfileUpgrade.targetPolicyHash,
          includeConfirmed: true,
          includeOperatorProfile: true,
          permissionGranted: true,
          operatorProfileAcknowledged: true,
          reason: "Include the explicit consent-backed Operator Preferences and Profile in the existing Attack Knowledge Vault",
        });
      } else if (confirmedUpgrade) {
        await amendAttackKnowledgeVaultPreset({
          connectionId: confirmedUpgrade.connectionId,
          expectedUpdatedAt: confirmedUpgrade.expectedUpdatedAt,
          expectedCurrentPolicyHash: confirmedUpgrade.currentPolicyHash,
          expectedTargetPolicyHash: confirmedUpgrade.targetPolicyHash,
          includeConfirmed: true,
          permissionGranted: true,
          amendmentAcknowledged: true,
          reason: "Include explicitly operator-confirmed reusable attack knowledge in the existing Attack Knowledge Vault",
        });
      } else {
        await activateAttackKnowledgeVaultPreset({
          expectedPolicyHash: preset.policyHash,
          includeConfirmed: includeConfirmedKnowledge,
          permissionGranted: true,
          activationAcknowledged: true,
        });
      }
      await Promise.all([vault.reconcile(), attackVaultPreset.reconcile()]);
      setPresetPermission(false);
      setPresetAcknowledged(false);
      setPresetHealth(undefined);
      setPresetState({
        message: operatorProfileUpgrade
          ? `Operator Preferences and Profile are now eligible in the 10 Operator folder on the same Vault connection and path. ${operatorProfileUpgrade.operatorProfileNodeCount.toLocaleString()} explicitly consented profile node${operatorProfileUpgrade.operatorProfileNodeCount === 1 ? " is" : "s are"} ready for a separate export; no note was written or deleted by this policy amendment.`
          : confirmedUpgrade
          ? `Confirmed attack knowledge is now eligible on the same Vault connection and path. ${confirmedUpgrade.eligibleNodeDelta.toLocaleString()} additional reviewed node${confirmedUpgrade.eligibleNodeDelta === 1 ? " is" : "s are"} ready for explicit export; no note was written or deleted by this policy amendment.`
          : "Attack Knowledge Vault activated after a fresh filesystem round-trip. No target, mission, run, IP address, raw evidence, or restricted memory was added by activation.",
      });
    } catch (error) {
      setPresetState({
        error: error instanceof Error ? error : new Error(upgrade ? "Unable to amend Attack Knowledge Vault scope" : "Unable to activate Attack Knowledge Vault"),
        errorSource: upgrade ? "amend" : "activate",
      });
    }
  };
  const testConnectionHealth = async (connectionId: string) => {
    setState({ busy: `health:${connectionId}` });
    try {
      const result = await checkVaultHealth({ connectionId });
      await vault.reconcile();
      setState({ message: result.message });
    } catch (error) {
      setState({ error: error instanceof Error ? error : new Error("Unable to verify vault health"), errorSource: "operation" });
    }
  };
  const connect = async () => {
    setState({ busy: "connect" });
    try {
      await connectVault({ vaultPath: path.trim(), displayName: name.trim(), permissionGranted: true, syncScope: { lifecycleStatuses: ["confirmed", "verified", "disputed", "stale"] } });
      await vault.reconcile();
      setState({ message: "Vault connected after a fresh filesystem round-trip. Canonical data remains in SQLite until you explicitly export or synchronize." }); setPath(""); setPermission(false); setHealth(undefined);
      requestAnimationFrame(() => requestAnimationFrame(() => {
        document.querySelector<HTMLElement>(".brain-vault-active")?.scrollIntoView({ block: "start" });
      }));
    } catch (error) { setState({ error: error instanceof Error ? error : new Error("Unable to connect vault"), errorSource: "connect" }); }
  };
  const disconnect = async (input: { reason: string; allowProjectionDegraded: boolean }) => {
    if (!disconnectTarget) return;
    const target = disconnectTarget;
    setDisconnectPending(true);
    setState({ busy: `disconnect:${target.id}` });
    try {
      const outcome = await commitThenReconcile({
        mutate: () => disconnectVault({
          connectionId: target.id,
          expectedUpdatedAt: target.updatedAt,
          reason: input.reason,
          disconnectAcknowledged: true,
          allowProjectionDegraded: input.allowProjectionDegraded,
        }),
        reconcile: vault.reconcile,
        onCommitted: (mutation) => setState({
          message: `${mutation.result.message} The immutable audit receipt is ${mutation.result.auditRecordId}. Refreshing Vault status…`,
        }),
      });
      setDisconnectTarget(undefined);
      if (outcome.reconcileError) {
        setState({
          message: `${outcome.result.result.message} The disconnect is committed; only the status refresh failed.`,
          error: outcome.reconcileError,
          errorSource: "reconcile",
        });
      } else {
        setState({ message: outcome.result.result.message });
      }
    } catch (error) {
      setState({
        error: error instanceof Error ? error : new Error("Unable to disconnect Vault projection"),
        errorSource: "operation",
        errorConnectionId: target.id,
      });
    } finally {
      setDisconnectPending(false);
    }
  };
  const retryRecovery = async () => {
    if (state.errorSource === "reconcile" && state.result) {
      setState({
        busy: "reconcile",
        result: state.result,
        recoveryAttempt: state.recoveryAttempt,
        message: "The operation is already committed; refreshing status without repeating it.",
      });
      try {
        await vault.reconcile();
        setState({ result: state.result, recoveryAttempt: state.recoveryAttempt, message: state.result.message });
      } catch (error) {
        setState({
          result: state.result,
          recoveryAttempt: state.recoveryAttempt,
          message: "The operation remains committed; status refresh still needs attention.",
          error: error instanceof Error ? error : new Error("Vault status refresh failed"),
          errorSource: "reconcile",
          ...(state.errorConnectionId ? { errorConnectionId: state.errorConnectionId } : {}),
        });
      }
      return;
    }
    if (state.recoveryAttempt) {
      await runRecovery(state.recoveryAttempt);
      return;
    }
    if (!state.errorConnectionId || (state.errorSource !== "repair" && state.errorSource !== "reindex")) return;
    const operation = state.errorSource;
    try {
      const latest = await fetchVaultSnapshot(new AbortController().signal);
      const connection = latest.connections.find((item) => item.id === state.errorConnectionId);
      if (!connection) {
        setState({ error: new Error("The Vault connection no longer exists. Return to Vault setup and reconnect it deliberately."), errorSource: operation });
        return;
      }
      await startRecovery(operation, connection.id, connection.updatedAt);
    } catch (error) {
      setState({
        error: error instanceof Error ? error : new Error("Unable to refresh Vault status before retry"),
        errorSource: operation,
        errorConnectionId: state.errorConnectionId,
      });
    }
  };
  const recoveryResult = state.result && "operation" in state.result ? state.result : undefined;
  const activeConnections = snapshot?.connections.filter((connection) => connection.status !== "disconnected") ?? [];
  const retiredConnections = snapshot?.connections.filter((connection) => connection.status === "disconnected") ?? [];
  const scopeUpgradeSelected = Boolean(includeConfirmedKnowledge && preset?.confirmedScopeUpgrade);
  const operatorProfileUpgradeSelected = Boolean(includeOperatorProfile && preset?.operatorProfileScopeUpgrade);
  const presetActionRequired = Boolean(preset && (!preset.activePreset || scopeUpgradeSelected || operatorProfileUpgradeSelected));
  const confirmedChoiceDisabled = Boolean(
    presetState.busy
    || (preset?.activePreset && !preset.confirmedScopeUpgrade),
  );
  const operatorProfileChoiceDisabled = Boolean(
    presetState.busy
    || !preset?.activePreset?.includeConfirmed
    || preset.activePreset.includeOperatorProfile
    || !preset?.operatorProfileAvailability.available
  );
  const disconnectHasHealthyReplacement = disconnectTarget ? activeConnections.some((connection) => (
    connection.id !== disconnectTarget.id
    && connection.status === "connected"
    && connection.pathAvailable !== false
    && Boolean(connection.lastHealthCheckAt && connection.healthChecks)
  )) : false;
  return (
    <div className="os-page brain-page brain-vault-page">
      <PageHeader eyebrow="Human-readable memory projection" title="Obsidian Vault" description="A versioned Markdown, YAML, and [[wikilink]] projection. SQLite remains canonical; filesystem conflicts never overwrite operator edits silently." />
      <BrainNav />
      {vault.isLoading && <LoadingPanel label="Checking Obsidian vault health and conflicts" />}
      {vault.error && !vault.data && <ErrorPanel
        error={vault.error}
        onRetry={vault.refresh}
        retryControlId="brain-vault-snapshot-retry"
        retryLabel="Retry Vault snapshot"
      />}
      {attackVaultPreset.isLoading && <LoadingPanel label="Preparing the Attack Knowledge Vault policy preview" />}
      {attackVaultPreset.error && !preset && <ErrorPanel
        title="Attack Knowledge Vault preview is unavailable"
        error={attackVaultPreset.error}
        onRetry={attackVaultPreset.refresh}
        retryControlId="brain-vault-preset-preview-retry"
        retryLabel="Retry Attack Knowledge Vault preview"
      />}
      {preset && <Card className="brain-vault-connect brain-attack-vault-preset">
        <div className="os-section-heading"><div><p className="os-eyebrow">Recommended reusable knowledge projection</p><h2>{preset.displayName}</h2></div><StatusPill status={preset.activePreset ? "connected" : preset.enabled ? "review" : "disabled"} /></div>
        <p>Build a reusable library around technology versions, topology patterns, vulnerabilities, attack procedures, scripts, outcomes, hazards, and recoveries. Operational records stay in SQLite and are not copied into this Vault.</p>
        <dl>
          <div><dt>Path inside configured root</dt><dd><code>{preset.vaultPath}</code></dd></div>
          <div><dt>Eligible now</dt><dd>{preset.projection.policyEligibleNodeCount.toLocaleString()} reviewed knowledge nodes</dd></div>
          <div><dt>Operational records withheld</dt><dd>{preset.projection.excludedOperationalNodeCount.toLocaleString()}</dd></div>
          <div><dt>Lifecycle</dt><dd>{preset.projection.lifecycleStatuses.join(" + ")}</dd></div>
          <div><dt>Sensitivity</dt><dd>{preset.projection.sensitivities.join(", ")}; restricted withheld</dd></div>
        </dl>
        <details>
          <summary>Review projected categories and folders</summary>
          <p><strong>Reusable categories:</strong> {preset.projection.nodeTypes.map((item) => item.replaceAll("_", " ")).join(", ")}.</p>
          <p><strong>Folders:</strong> {preset.projection.folders.join(", ")}.</p>
          <p><strong>Always withheld:</strong> {preset.privacyBoundary.excludesOperationalLocators.join(", ")}.</p>
        </details>
        <label className="os-check-field"><input type="checkbox" aria-label="Include operator-confirmed attack knowledge" checked={includeConfirmedKnowledge || Boolean(preset.activePreset?.includeConfirmed)} disabled={confirmedChoiceDisabled} onChange={(event) => { setIncludeConfirmedKnowledge(event.target.checked); if (!event.target.checked) setIncludeOperatorProfile(false); setPresetHealth(undefined); setPresetAcknowledged(false); }} /><span><strong>Include operator-confirmed attack knowledge</strong><small>{preset.confirmedScopeUpgrade ? `Adds ${preset.confirmedScopeUpgrade.eligibleNodeDelta.toLocaleString()} explicitly confirmed reusable node${preset.confirmedScopeUpgrade.eligibleNodeDelta === 1 ? "" : "s"} without replacing this Vault.` : "Off by default. Verified knowledge remains included."}</small></span></label>
        <label className="os-check-field"><input type="checkbox" aria-label="Include Operator Preferences and Profile" checked={includeOperatorProfile || Boolean(preset.activePreset?.includeOperatorProfile)} disabled={operatorProfileChoiceDisabled} onChange={(event) => { setIncludeOperatorProfile(event.target.checked); setPresetHealth(undefined); setPresetAcknowledged(false); }} /><span><strong>Include Operator Preferences and Profile</strong><small>{preset.activePreset?.includeOperatorProfile ? `This consent-backed scope is active. ${preset.operatorProfileAvailability.eligibleNodeCount.toLocaleString()} eligible profile node${preset.operatorProfileAvailability.eligibleNodeCount === 1 ? " is" : "s are"} currently available for 10 Operator.` : !preset.operatorProfileAvailability.available ? "No eligible confirmed Operator Preferences or Profile records exist for your account. Confirm a global preference in Operator Preferences, then return here." : preset.operatorProfileScopeUpgrade ? `Adds only ${preset.operatorProfileScopeUpgrade.operatorProfileNodeCount.toLocaleString()} explicitly confirmed preference, operator, and application-domain node${preset.operatorProfileScopeUpgrade.operatorProfileNodeCount === 1 ? "" : "s"}. Targets, engagement names, addresses, and operational records remain excluded.` : preset.activePreset?.includeConfirmed ? `${preset.operatorProfileAvailability.eligibleNodeCount.toLocaleString()} eligible confirmed profile node${preset.operatorProfileAvailability.eligibleNodeCount === 1 ? " is" : "s are"} available. Selection requires a separate consent review and never changes authorization policy.` : "Available only after confirmed attack knowledge is active. It requires a separate consent review and never changes authorization policy."}</small></span></label>
        {presetActionRequired && <>
          <label className="os-check-field"><input type="checkbox" aria-label="Grant Attack Knowledge Vault filesystem permission" checked={presetPermission} disabled={Boolean(presetState.busy)} onChange={(event) => { setPresetPermission(event.target.checked); if (!event.target.checked) setPresetHealth(undefined); }} /><span><strong>Grant filesystem permission for this path</strong><small>{scopeUpgradeSelected ? "Allows a fresh write, read, rename, and delete health proof on the existing path. The policy amendment itself writes or deletes no notes." : "Allows Ti-Scale to create and atomically update only this preset Vault under the configured root."}</small></span></label>
          <label className="os-check-field"><input type="checkbox" aria-label={operatorProfileUpgradeSelected ? "Acknowledge Operator Profile Vault scope amendment" : scopeUpgradeSelected ? "Acknowledge Attack Knowledge Vault confirmed scope amendment" : "Acknowledge Attack Knowledge Vault activation"} checked={presetAcknowledged} disabled={Boolean(presetState.busy)} onChange={(event) => setPresetAcknowledged(event.target.checked)} /><span><strong>{operatorProfileUpgradeSelected ? "Add my explicit Operator Preferences and Profile" : scopeUpgradeSelected ? "Amend this connection to verified and confirmed knowledge" : "Activate this exact reviewed projection policy"}</strong><small>{operatorProfileUpgradeSelected ? "Only the authenticated operator's explicitly confirmed profile graph is admitted to 10 Operator. No target, engagement, mission, run, address, or restricted memory is included. Export remains separate." : scopeUpgradeSelected ? "The same connection ID, path, existing notes, synchronization history, and conflicts are retained. Export remains a separate action." : "Activation creates the connection and empty folder taxonomy. It does not export notes until a separate export or synchronization action."}</small></span></label>
          <div className="brain-vault-actions">
            <Button variant="secondary" onClick={testAttackKnowledgeVaultHealth} disabled={!preset.enabled || !presetPermission || Boolean(presetState.busy)}>Test preset path</Button>
            <Button onClick={activateAttackKnowledgeVault} disabled={!preset.enabled || !presetPermission || !presetAcknowledged || presetHealth?.vaultPath !== preset.vaultPath || Boolean(presetState.busy)}>{operatorProfileUpgradeSelected ? "Add Operator Profile to Vault" : scopeUpgradeSelected ? "Apply confirmed knowledge scope" : "Activate Attack Knowledge Vault"}</Button>
          </div>
        </>}
        {preset.activePreset && !scopeUpgradeSelected && !operatorProfileUpgradeSelected && <div className="os-state-panel" role="status"><div><strong>Attack Knowledge Vault is active</strong><p>{preset.activePreset.includeOperatorProfile ? "This exact connection includes verified and explicitly confirmed reusable attack knowledge plus the separately consented Operator Preferences and Profile in 10 Operator." : preset.activePreset.includeConfirmed ? "This exact connection includes verified and explicitly confirmed reusable attack knowledge. Operator Preferences remain private unless you select and separately acknowledge the profile option above." : "This exact connection currently includes verified reusable attack knowledge. Select the confirmed option above to review a same-connection scope expansion."}</p></div></div>}
        {presetHealth?.vaultPath === preset.vaultPath && <div className="os-state-panel" role="status"><div><strong>Preset path round-trip verified</strong><p>Write, read, rename, and delete passed at {formatBrainDate(presetHealth.checkedAt)}. Activation repeats this proof.</p></div></div>}
        {presetState.message && <div className="os-state-panel" role="status"><div><strong>Attack Knowledge Vault update</strong><p>{presetState.message}</p></div></div>}
        {presetState.error && <ErrorPanel
          title={presetState.errorSource === "health" ? "Preset path health check failed" : presetState.errorSource === "amend" ? "Attack Knowledge Vault scope amendment failed" : "Attack Knowledge Vault activation failed"}
          error={presetState.error}
          onRetry={presetState.errorSource === "health" ? testAttackKnowledgeVaultHealth : undefined}
          retryControlId="brain-vault-preset-health-retry"
          retryLabel="Retry preset path health check"
        />}
      </Card>}
      {snapshot && <>
        {activeConnections.length > 0 ? <div className="brain-vault-active" role="region" aria-labelledby="active-obsidian-vaults-heading">
          <div className="os-section-heading">
            <div><p className="os-eyebrow">Connected Second Brain storage</p><h2 id="active-obsidian-vaults-heading">Active Obsidian Vaults</h2></div>
            <span className="os-count" aria-label={`${activeConnections.length} active Obsidian vault${activeConnections.length === 1 ? "" : "s"}`}>{activeConnections.length}</span>
          </div>
          <p className="os-muted">These are real configured Vault connections. SQLite remains transactional truth; each card shows filesystem health and explicit synchronization controls.</p>
          <div className="brain-vault-connections">{activeConnections.map((connection) => {
            const states = snapshot.syncStates.filter((item) => item.connectionId === connection.id);
            const trackedNoteCount = connection.trackedNoteCount ?? states.length;
            const needsReviewCount = connection.needsReviewCount
              ?? states.filter((item) => ["conflict", "quarantined", "error"].includes(item.status)).length;
            const healthVerified = Boolean(connection.lastHealthCheckAt && connection.healthChecks);
            return <Card key={connection.id}>
              <header><div><p className="os-eyebrow">{connection.displayName}</p><h2>{connection.vaultPath}</h2></div><StatusPill status={connection.status} /></header>
              {connection.pathAvailable === false && <div className="os-state-panel os-state-panel--error" role="status"><div><strong>Configured Vault path is offline</strong><p>Ti-Scale did not recreate the missing directory. Restore this exact path and permission, then run Repair vault or Test connection.</p></div></div>}
              <dl><div><dt>Permission granted</dt><dd>{formatBrainDate(connection.permissionGrantedAt)}</dd></div><div><dt>Last round-trip health check</dt><dd>{formatBrainDate(connection.lastHealthCheckAt)}</dd></div><div><dt>Last synchronized</dt><dd>{formatBrainDate(connection.lastSyncAt)}</dd></div><div><dt>Tracked notes</dt><dd>{trackedNoteCount.toLocaleString()}</dd></div><div><dt>Needs review</dt><dd>{needsReviewCount.toLocaleString()}</dd></div></dl>
              {!healthVerified && <p className="os-muted">This connection predates a recorded round-trip proof. Test it before synchronizing files.</p>}
              <p className="os-muted" id={`vault-recovery-help-${connection.id}`}>Repair validates the existing path, preserves conflicts, and marks missing projections. A malformed or unsafe managed note is moved—not copied—into private quarantine so Ti-Scale never creates a restorable duplicate; recovery metadata remains content-free. Reindex refreshes only represented canonical search rows and stops on index-integrity failure. Neither action imports operator text.</p>
              <div className="brain-vault-actions">
                <Button variant="secondary" onClick={() => testConnectionHealth(connection.id)} disabled={Boolean(state.busy)}>Test connection</Button>
                <Button variant="secondary" aria-describedby={`vault-recovery-help-${connection.id}`} onClick={() => startRecovery("repair", connection.id, connection.updatedAt)} disabled={Boolean(state.busy)}>Repair vault</Button>
                <Button variant="secondary" aria-describedby={`vault-recovery-help-${connection.id}`} onClick={() => startRecovery("reindex", connection.id, connection.updatedAt)} disabled={Boolean(state.busy)}>Reindex vault</Button>
                <Button variant="secondary" onClick={() => run(`sync:${connection.id}`, () => syncVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Synchronize</Button>
                <Button variant="quiet" onClick={() => run(`export:${connection.id}`, () => exportVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Export canonical notes</Button>
                <Button variant="quiet" onClick={() => run(`import:${connection.id}`, () => importVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Import operator edits</Button>
                <Button variant="quiet" disabled aria-describedby={`vault-no-backup-${connection.id}`}>Portable ZIP disabled</Button>
                {connection.obsidianUrl && <a className="os-button os-button--quiet" href={connection.obsidianUrl} rel="noopener noreferrer">Open vault in Obsidian</a>}
                <Button variant="danger" onClick={() => setDisconnectTarget(connection)} disabled={Boolean(state.busy)}>Disconnect projection</Button>
              </div>
              <p className="os-muted" id={`vault-no-backup-${connection.id}`}>The operator no-backup policy prevents Ti-Scale from creating retained Vault ZIP copies. Use this connected Vault or synchronize canonical notes directly.</p>
              {states.length > 0 && <details><summary>Note synchronization state</summary><p className="os-muted">{Math.min(states.length, 100).toLocaleString()} recent records shown of {trackedNoteCount.toLocaleString()} tracked notes.</p><ul className="brain-sync-list">{states.slice(0, 100).map((item) => <li key={item.id}><span><code>{item.relativePath}</code>{item.errorMessage && <small>{item.errorMessage}</small>}</span><span className="brain-sync-status">{item.obsidianUrl && <a href={item.obsidianUrl} rel="noopener noreferrer" aria-label={`Open ${item.relativePath} in Obsidian`}>Open</a>}<StatusPill status={item.status} /></span></li>)}</ul></details>}
            </Card>;
          })}</div>
        </div> : <Card><BrainEmpty kind="vault" title="No active Obsidian projection" description="Canonical Second Brain memory remains available in SQLite. Connect and round-trip verify a Vault to restore the optional human-readable projection." /></Card>}
        {retiredConnections.length > 0 && <div className="brain-vault-retired" role="region" aria-labelledby="retired-obsidian-vaults-heading">
          <div className="os-section-heading"><div><p className="os-eyebrow">Preserved, no longer synchronized</p><h2 id="retired-obsidian-vaults-heading">Retired Vault connections</h2></div><span className="os-count">{retiredConnections.length}</span></div>
          <p className="os-muted">These database connections are disconnected. Their Vault directories, notes, attachments, synchronization history, and conflict records were not deleted or rewritten.</p>
          <div className="brain-vault-connections">{retiredConnections.map((connection) => <Card key={connection.id} className="brain-vault-retired-card">
            <header><div><p className="os-eyebrow">{connection.displayName}</p><h2>{connection.vaultPath}</h2></div><StatusPill status="disconnected" /></header>
            <dl><div><dt>Disconnected</dt><dd>{formatBrainDate(connection.updatedAt)}</dd></div><div><dt>Tracked note history</dt><dd>{(connection.trackedNoteCount ?? 0).toLocaleString()}</dd></div><div><dt>Directory available</dt><dd>{connection.pathAvailable === false ? "No" : "Yes"}</dd></div><div><dt>Future synchronization</dt><dd>Stopped</dd></div></dl>
            <p className="os-muted">This is an audit-preserved connection record. Ti-Scale will not project or synchronize through it.</p>
          </Card>)}</div>
        </div>}
        <Card className="brain-vault-connect">
          <div className="os-section-heading"><div><p className="os-eyebrow">Advanced custom projection</p><h2>{activeConnections.length > 0 ? "Connect another custom vault" : "Connect a custom vault"}</h2></div><StatusPill status={available ? "available" : "disabled"} /></div>
          {!snapshot.enabled ? <div className="os-state-panel os-state-panel--error" role="status"><div className="os-state-symbol" aria-hidden="true">!</div><div><strong>Obsidian integration is not configured</strong><p>Configure the server-owned vault root, restart Ti-Scale, then return here to test a path.</p></div></div> : snapshot.syncEnabled === false ? <div className="os-state-panel" role="status"><div><strong>Obsidian synchronization is disabled by Memory Controls</strong><p>Enable a confirmed-memory projection scope before testing or connecting a vault.</p></div></div> : null}
          <p>The server permits vaults only inside {snapshot.allowedRootLabel ?? "its configured vault root"}. It rejects absolute escape paths, traversal, and symlink boundaries.</p>
          <div className="os-field-grid"><label>Display name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Custom research vault" /></label><label>Path inside the allowed root<input value={path} onChange={(event) => { setPath(event.target.value); setHealth(undefined); }} placeholder="Custom-Research-Vault" /></label></div>
          <label className="os-check-field"><input type="checkbox" aria-label="Grant explicit filesystem permission" aria-describedby="brain-vault-filesystem-permission-help" checked={permission} onChange={(event) => { setPermission(event.target.checked); if (!event.target.checked) setHealth(undefined); }} /><span><strong>Grant explicit filesystem permission</strong><small id="brain-vault-filesystem-permission-help">Allow Ti-Scale to create and atomically synchronize Markdown notes inside this selected vault only.</small></span></label>
          <div className="brain-vault-actions"><Button variant="secondary" onClick={testCandidateHealth} disabled={!available || !permission || !path.trim() || Boolean(state.busy)}>Test write, read, rename, and delete</Button><Button onClick={connect} disabled={!available || !permission || !name.trim() || !path.trim() || health?.vaultPath !== path.trim() || Boolean(state.busy)}>Connect verified vault</Button></div>
          {health?.vaultPath === path.trim() && <div className="os-state-panel" role="status"><div><strong>Round-trip verified</strong><p>Write, read, rename, and delete passed at {formatBrainDate(health.checkedAt)}. Connection performs the proof again before becoming active.</p></div></div>}
        </Card>
        <Card className="brain-conflicts"><div className="os-section-heading"><div><p className="os-eyebrow">Never silently overwritten</p><h2>Vault conflicts</h2></div><span className="os-count">{snapshot.conflicts.filter((item) => item.status === "open").length}</span></div>{snapshot.conflicts.filter((item) => item.status === "open").length === 0 ? <p className="os-muted">No concurrent database and vault edits require resolution.</p> : <div className="brain-conflict-list">{snapshot.conflicts.filter((item) => item.status === "open").map((conflict) => <article key={conflict.id}><header><div><strong>{conflict.relativePath}</strong><small>Detected {formatBrainDate(conflict.detectedAt)}</small></div><StatusPill status="conflict" /></header>{(conflict.databaseTextRedacted || conflict.vaultTextRedacted) && <div className="brain-conflict-diff"><section><h3>Canonical database</h3><pre>{conflict.databaseTextRedacted ?? "Preview not returned by the service."}</pre></section><section><h3>Obsidian vault</h3><pre>{conflict.vaultTextRedacted ?? "Preview not returned by the service."}</pre></section></div>}<p>Choose which version becomes canonical. The losing version remains represented by audit and version history according to policy.</p><div><Button variant="secondary" onClick={() => run(`resolve-db:${conflict.id}`, () => resolveVaultConflict(conflict.id, "database"), "Conflict resolved using the canonical database version.")} disabled={Boolean(state.busy)}>Keep database version</Button><Button variant="secondary" onClick={() => run(`resolve-vault:${conflict.id}`, () => resolveVaultConflict(conflict.id, "vault"), "Conflict resolved using the operator's vault version.")} disabled={Boolean(state.busy)}>Keep vault version</Button></div></article>)}</div>}</Card>
      </>}
      {(state.busy?.startsWith("repair:") || state.busy?.startsWith("reindex:")) && <div className="os-state-panel" role="status"><div><strong>{state.busy.startsWith("repair:") ? "Repairing the existing Vault" : "Reindexing managed Vault notes"}</strong><p>Validating the current path and round-trip health, then processing a bounded note set. SQLite remains canonical and open conflicts stay untouched.</p></div></div>}
      {recoveryResult && <Card className="brain-vault-recovery-result"><div className="os-section-heading"><div><p className="os-eyebrow">Latest recovery receipt</p><h2>{recoveryResult.operation === "repair" ? "Vault repair" : "Vault reindex"}</h2></div><StatusPill status={recoveryResult.status} /></div><p>{recoveryResult.message}</p><dl><div><dt>Processed</dt><dd>{recoveryResult.progress.processed}</dd></div><div><dt>Indexed</dt><dd>{recoveryResult.counts.indexed}</dd></div><div><dt>Conflicts preserved</dt><dd>{recoveryResult.counts.conflictsPreserved}</dd></div><div><dt>Quarantined</dt><dd>{recoveryResult.counts.quarantined}</dd></div><div><dt>Missing</dt><dd>{recoveryResult.counts.missing}</dd></div><div><dt>Errors</dt><dd>{recoveryResult.counts.errors}</dd></div></dl>{recoveryResult.issues.length > 0 && <details><summary id="brain-vault-recovery-details" data-testid="brain-vault-recovery-details" data-control-id="brain-vault-recovery-details">Recovery details</summary><ul>{recoveryResult.issues.map((issue, index) => <li key={`${issue.category}-${issue.relativePath ?? index}`}><strong>{issue.category.replaceAll("_", " ")}</strong> — {issue.message}{issue.relativePath && <code>{issue.relativePath}</code>}</li>)}</ul></details>}</Card>}
      {state.message && <div className="brain-operation-toast" role="status"><p>{state.message}</p></div>}
      {state.error && <>
        <div className="os-state-panel os-state-panel--error" role="status"><div>
          <strong>{state.errorSource === "reconcile" ? "Operation committed; status refresh failed" : state.errorSource === "repair" ? "Vault repair stopped safely" : state.errorSource === "reindex" ? "Vault reindex stopped safely" : "Vault operation needs attention"}</strong>
          <p>{state.errorSource === "reconcile" ? "The receipt above is durable. Retry refresh without repeating the committed filesystem or database mutation." : state.errorSource === "repair" ? "No missing path was recreated and no operator edit was imported. Restore the configured path or resolve its permission issue, then retry the same guarded request." : state.errorSource === "reindex" ? "The existing canonical search projection remains authoritative. Restore path or index health, then retry the same bounded reindex request." : "Review the specific error and retry only after its remediation is complete."}</p>
        </div></div>
        <ErrorPanel
          title={state.errorSource === "reconcile" ? "Vault status refresh could not complete" : state.errorSource === "health" ? "Vault path health check failed" : state.errorSource === "connect" ? "Vault could not be connected" : state.errorSource === "repair" ? "Vault repair could not complete" : state.errorSource === "reindex" ? "Vault reindex could not complete" : "Vault operation failed"}
          error={state.error}
          onRetry={state.errorSource === "health" ? testCandidateHealth : state.errorSource === "connect" ? connect : state.errorSource === "repair" || state.errorSource === "reindex" || state.errorSource === "reconcile" ? retryRecovery : undefined}
          retryControlId={operationRetryControlId}
          retryLabel={operationRetryLabel}
        />
      </>}
      {disconnectTarget && <VaultDisconnectDialog
        connection={disconnectTarget}
        hasHealthyReplacement={disconnectHasHealthyReplacement}
        pending={disconnectPending}
        onCancel={() => setDisconnectTarget(undefined)}
        onConfirm={(input) => void disconnect(input)}
      />}
    </div>
  );
}
