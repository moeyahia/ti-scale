import { useState } from "react";
import { checkVaultHealth, connectVault, createBrainMutationKey, exportVault, fetchVaultSnapshot, importVault, portableExportVault, reindexVault, repairVault, resolveVaultConflict, syncVault } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type { VaultHealthCheckResult, VaultOperationResult, VaultRecoveryResult } from "../../domain/types/brain";
import { BrainEmpty, BrainNav, formatBrainDate } from "./BrainNav";
import {
  commitThenReconcile,
  createVaultRecoveryAttempt,
  executeVaultRecoveryAttempt,
  type VaultRecoveryAttempt,
} from "./vaultRecoveryFlow";

export default function BrainVaultPage() {
  const vault = useQuery("brain-vault", fetchVaultSnapshot, { staleTime: 0 });
  const [path, setPath] = useState("");
  const [name, setName] = useState("Ti-Scale Brain");
  const [permission, setPermission] = useState(false);
  const [health, setHealth] = useState<VaultHealthCheckResult>();
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
  const downloadUrl = state.result && "downloadUrl" in state.result ? state.result.downloadUrl : undefined;
  return (
    <div className="os-page brain-page brain-vault-page">
      <PageHeader eyebrow="Human-readable memory projection" title="Obsidian Vault" description="A versioned Markdown, YAML, and [[wikilink]] projection. SQLite remains canonical; filesystem conflicts never overwrite operator edits silently." />
      <BrainNav />
      {vault.isLoading && <LoadingPanel label="Checking Obsidian vault health and conflicts" />}
      {vault.error && !vault.data && <ErrorPanel error={vault.error} onRetry={vault.refresh} />}
      {snapshot && <>
        {snapshot.connections.length > 0 ? <div className="brain-vault-active" role="region" aria-labelledby="active-obsidian-vaults-heading">
          <div className="os-section-heading">
            <div><p className="os-eyebrow">Connected Second Brain storage</p><h2 id="active-obsidian-vaults-heading">Active Obsidian Vaults</h2></div>
            <span className="os-count" aria-label={`${snapshot.connections.length} active Obsidian vault${snapshot.connections.length === 1 ? "" : "s"}`}>{snapshot.connections.length}</span>
          </div>
          <p className="os-muted">These are real configured Vault connections. SQLite remains transactional truth; each card shows filesystem health and explicit synchronization controls.</p>
          <div className="brain-vault-connections">{snapshot.connections.map((connection) => {
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
              <p className="os-muted" id={`vault-recovery-help-${connection.id}`}>Repair validates the existing path, preserves conflicts, marks missing projections, and retains exact-byte guarded private quarantine copies without deleting operator files; only their recovery metadata is content-free. Reindex refreshes only represented canonical search rows and stops on index-integrity failure. Neither action imports operator text.</p>
              <div className="brain-vault-actions">
                <Button variant="secondary" onClick={() => testConnectionHealth(connection.id)} disabled={Boolean(state.busy)}>Test connection</Button>
                <Button variant="secondary" aria-describedby={`vault-recovery-help-${connection.id}`} onClick={() => startRecovery("repair", connection.id, connection.updatedAt)} disabled={Boolean(state.busy)}>Repair vault</Button>
                <Button variant="secondary" aria-describedby={`vault-recovery-help-${connection.id}`} onClick={() => startRecovery("reindex", connection.id, connection.updatedAt)} disabled={Boolean(state.busy)}>Reindex vault</Button>
                <Button variant="secondary" onClick={() => run(`sync:${connection.id}`, () => syncVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Synchronize</Button>
                <Button variant="quiet" onClick={() => run(`export:${connection.id}`, () => exportVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Export canonical notes</Button>
                <Button variant="quiet" onClick={() => run(`import:${connection.id}`, () => importVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Import operator edits</Button>
                <Button variant="quiet" onClick={() => run(`portable:${connection.id}`, () => portableExportVault(connection.id))} disabled={!healthVerified || connection.pathAvailable === false || Boolean(state.busy)}>Create portable ZIP</Button>
                {connection.obsidianUrl && <a className="os-button os-button--quiet" href={connection.obsidianUrl} rel="noopener noreferrer">Open vault in Obsidian</a>}
              </div>
              {states.length > 0 && <details><summary>Note synchronization state</summary><p className="os-muted">{Math.min(states.length, 100).toLocaleString()} recent records shown of {trackedNoteCount.toLocaleString()} tracked notes.</p><ul className="brain-sync-list">{states.slice(0, 100).map((item) => <li key={item.id}><span><code>{item.relativePath}</code>{item.errorMessage && <small>{item.errorMessage}</small>}</span><span className="brain-sync-status">{item.obsidianUrl && <a href={item.obsidianUrl} rel="noopener noreferrer" aria-label={`Open ${item.relativePath} in Obsidian`}>Open</a>}<StatusPill status={item.status} /></span></li>)}</ul></details>}
            </Card>;
          })}</div>
        </div> : <Card><BrainEmpty kind="vault" title="No Obsidian vault connected" description="Connect a path inside the server-configured root to export confirmed memory as portable Markdown and wikilinks." /></Card>}
        <Card className="brain-vault-connect">
          <div className="os-section-heading"><div><p className="os-eyebrow">Filesystem permission</p><h2>{snapshot.connections.length > 0 ? "Connect another local vault" : "Connect a local vault"}</h2></div><StatusPill status={available ? "available" : "disabled"} /></div>
          {!snapshot.enabled ? <div className="os-state-panel os-state-panel--error" role="status"><div className="os-state-symbol" aria-hidden="true">!</div><div><strong>Obsidian integration is not configured</strong><p>Configure the server-owned vault root, restart Ti-Scale, then return here to test a path.</p></div></div> : snapshot.syncEnabled === false ? <div className="os-state-panel" role="status"><div><strong>Obsidian synchronization is disabled by Memory Controls</strong><p>Enable a confirmed-memory projection scope before testing or connecting a vault.</p></div></div> : null}
          <p>The server permits vaults only inside {snapshot.allowedRootLabel ?? "its configured vault root"}. It rejects absolute escape paths, traversal, and symlink boundaries.</p>
          <div className="os-field-grid"><label>Display name<input value={name} onChange={(event) => setName(event.target.value)} /></label><label>Path inside the allowed root<input value={path} onChange={(event) => { setPath(event.target.value); setHealth(undefined); }} placeholder="Ti-Scale-Brain" /></label></div>
          <label className="os-check-field"><input type="checkbox" aria-label="Grant explicit filesystem permission" aria-describedby="brain-vault-filesystem-permission-help" checked={permission} onChange={(event) => { setPermission(event.target.checked); if (!event.target.checked) setHealth(undefined); }} /><span><strong>Grant explicit filesystem permission</strong><small id="brain-vault-filesystem-permission-help">Allow Ti-Scale to create and atomically synchronize Markdown notes inside this selected vault only.</small></span></label>
          <div className="brain-vault-actions"><Button variant="secondary" onClick={testCandidateHealth} disabled={!available || !permission || !path.trim() || Boolean(state.busy)}>Test write, read, rename, and delete</Button><Button onClick={connect} disabled={!available || !permission || !name.trim() || !path.trim() || health?.vaultPath !== path.trim() || Boolean(state.busy)}>Connect verified vault</Button></div>
          {health?.vaultPath === path.trim() && <div className="os-state-panel" role="status"><div><strong>Round-trip verified</strong><p>Write, read, rename, and delete passed at {formatBrainDate(health.checkedAt)}. Connection performs the proof again before becoming active.</p></div></div>}
        </Card>
        <Card className="brain-conflicts"><div className="os-section-heading"><div><p className="os-eyebrow">Never silently overwritten</p><h2>Vault conflicts</h2></div><span className="os-count">{snapshot.conflicts.filter((item) => item.status === "open").length}</span></div>{snapshot.conflicts.filter((item) => item.status === "open").length === 0 ? <p className="os-muted">No concurrent database and vault edits require resolution.</p> : <div className="brain-conflict-list">{snapshot.conflicts.filter((item) => item.status === "open").map((conflict) => <article key={conflict.id}><header><div><strong>{conflict.relativePath}</strong><small>Detected {formatBrainDate(conflict.detectedAt)}</small></div><StatusPill status="conflict" /></header>{(conflict.databaseTextRedacted || conflict.vaultTextRedacted) && <div className="brain-conflict-diff"><section><h3>Canonical database</h3><pre>{conflict.databaseTextRedacted ?? "Preview not returned by the service."}</pre></section><section><h3>Obsidian vault</h3><pre>{conflict.vaultTextRedacted ?? "Preview not returned by the service."}</pre></section></div>}<p>Choose which version becomes canonical. The losing version remains represented by audit and version history according to policy.</p><div><Button variant="secondary" onClick={() => run(`resolve-db:${conflict.id}`, () => resolveVaultConflict(conflict.id, "database"), "Conflict resolved using the canonical database version.")} disabled={Boolean(state.busy)}>Keep database version</Button><Button variant="secondary" onClick={() => run(`resolve-vault:${conflict.id}`, () => resolveVaultConflict(conflict.id, "vault"), "Conflict resolved using the operator's vault version.")} disabled={Boolean(state.busy)}>Keep vault version</Button></div></article>)}</div>}</Card>
      </>}
      {(state.busy?.startsWith("repair:") || state.busy?.startsWith("reindex:")) && <div className="os-state-panel" role="status"><div><strong>{state.busy.startsWith("repair:") ? "Repairing the existing Vault" : "Reindexing managed Vault notes"}</strong><p>Validating the current path and round-trip health, then processing a bounded note set. SQLite remains canonical and open conflicts stay untouched.</p></div></div>}
      {recoveryResult && <Card className="brain-vault-recovery-result"><div className="os-section-heading"><div><p className="os-eyebrow">Latest recovery receipt</p><h2>{recoveryResult.operation === "repair" ? "Vault repair" : "Vault reindex"}</h2></div><StatusPill status={recoveryResult.status} /></div><p>{recoveryResult.message}</p><dl><div><dt>Processed</dt><dd>{recoveryResult.progress.processed}</dd></div><div><dt>Indexed</dt><dd>{recoveryResult.counts.indexed}</dd></div><div><dt>Conflicts preserved</dt><dd>{recoveryResult.counts.conflictsPreserved}</dd></div><div><dt>Quarantined</dt><dd>{recoveryResult.counts.quarantined}</dd></div><div><dt>Missing</dt><dd>{recoveryResult.counts.missing}</dd></div><div><dt>Errors</dt><dd>{recoveryResult.counts.errors}</dd></div></dl>{recoveryResult.issues.length > 0 && <details><summary>Recovery details</summary><ul>{recoveryResult.issues.map((issue, index) => <li key={`${issue.category}-${issue.relativePath ?? index}`}><strong>{issue.category.replaceAll("_", " ")}</strong> — {issue.message}{issue.relativePath && <code>{issue.relativePath}</code>}</li>)}</ul></details>}</Card>}
      {state.message && <div className="brain-operation-toast" role="status"><p>{state.message}</p>{downloadUrl && <a href={downloadUrl}>Download portable ZIP</a>}</div>}
      {state.error && <>
        <div className="os-state-panel os-state-panel--error" role="status"><div>
          <strong>{state.errorSource === "reconcile" ? "Operation committed; status refresh failed" : state.errorSource === "repair" ? "Vault repair stopped safely" : state.errorSource === "reindex" ? "Vault reindex stopped safely" : "Vault operation needs attention"}</strong>
          <p>{state.errorSource === "reconcile" ? "The receipt above is durable. Retry refresh without repeating the committed filesystem or database mutation." : state.errorSource === "repair" ? "No missing path was recreated and no operator edit was imported. Restore the configured path or resolve its permission issue, then retry the same guarded request." : state.errorSource === "reindex" ? "The existing canonical search projection remains authoritative. Restore path or index health, then retry the same bounded reindex request." : "Review the specific error and retry only after its remediation is complete."}</p>
        </div></div>
        <ErrorPanel
          title={state.errorSource === "reconcile" ? "Vault status refresh could not complete" : state.errorSource === "health" ? "Vault path health check failed" : state.errorSource === "connect" ? "Vault could not be connected" : state.errorSource === "repair" ? "Vault repair could not complete" : state.errorSource === "reindex" ? "Vault reindex could not complete" : "Vault operation failed"}
          error={state.error}
          onRetry={state.errorSource === "health" ? testCandidateHealth : state.errorSource === "connect" ? connect : state.errorSource === "repair" || state.errorSource === "reindex" || state.errorSource === "reconcile" ? retryRecovery : undefined}
        />
      </>}
    </div>
  );
}
