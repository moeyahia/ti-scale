import { useEffect, useState, type FormEvent } from "react";
import { fetchMemoryControl, updateMemoryControl } from "../../data/api/brain";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type { MemoryControlPolicy } from "../../domain/types/brain";
import { BrainNav, formatBrainDate } from "./BrainNav";
import "./brain-control.css";

export type EditableMemoryControlPolicy = Omit<MemoryControlPolicy, "version" | "updatedBy" | "updatedAt">;

export function editableMemoryControlPolicy(policy: MemoryControlPolicy): EditableMemoryControlPolicy {
  return {
    enabled: policy.enabled,
    personalPreferencePolicy: policy.personalPreferencePolicy,
    operationalMemoryEnabled: policy.operationalMemoryEnabled,
    engagementIsolation: true,
    defaultRetentionDays: policy.defaultRetentionDays,
    autonomousUse: policy.autonomousUse,
    guidedUse: policy.guidedUse,
    obsidianSyncScope: policy.obsidianSyncScope,
    secretsNeverRetained: true,
  };
}

export async function retryMemoryControlUpdate(
  draft: EditableMemoryControlPolicy,
  dependencies: {
    readonly read: () => Promise<MemoryControlPolicy>;
    readonly update: (expectedVersion: number, policy: EditableMemoryControlPolicy) => Promise<MemoryControlPolicy>;
  } = {
    read: () => fetchMemoryControl(new AbortController().signal),
    update: updateMemoryControl,
  },
): Promise<MemoryControlPolicy> {
  const current = await dependencies.read();
  return dependencies.update(current.version, draft);
}

export default function BrainControlPage() {
  const cache = useQueryCache();
  const query = useQuery("brain-control", fetchMemoryControl, { staleTime: 5_000 });
  const [draft, setDraft] = useState<EditableMemoryControlPolicy>();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error>();
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (query.data) setDraft(editableMemoryControlPolicy(query.data));
  }, [query.data]);

  const set = <K extends keyof EditableMemoryControlPolicy>(key: K, value: EditableMemoryControlPolicy[K]) => {
    setSaved(false);
    setDraft((current) => current ? { ...current, [key]: value } : current);
  };

  const save = async (expectedVersion: number) => {
    if (!draft || saving) return;
    setSaving(true);
    setError(undefined);
    setSaved(false);
    try {
      const result = await updateMemoryControl(expectedVersion, draft);
      setDraft(editableMemoryControlPolicy(result));
      cache.invalidate("brain-control");
      cache.invalidate("brain-summary");
      setSaved(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error("Memory controls could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!query.data) return;
    await save(query.data.version);
  };

  const retrySave = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setError(undefined);
    setSaved(false);
    try {
      // A save can fail because another tab or operator changed the global
      // policy after this form loaded. Re-read the canonical version while
      // preserving this represented draft, then retry once against that
      // current version. Server-side optimistic concurrency still owns the
      // final decision if another write races this bounded retry.
      const result = await retryMemoryControlUpdate(draft);
      setDraft(editableMemoryControlPolicy(result));
      cache.invalidate("brain-control");
      cache.invalidate("brain-summary");
      setSaved(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error("Memory controls could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="os-page brain-page">
      <PageHeader
        eyebrow="Privacy, consent, and retention"
        title="Memory Control Center"
        description="Decide what Ti-Scale may retain, retrieve, and project to Obsidian. Safety and engagement-isolation rules cannot be weakened here."
        actions={<ButtonLink href="/brain/vault" variant="secondary">Export or sync</ButtonLink>}
      />
      <BrainNav />
      {query.isLoading && <LoadingPanel label="Loading canonical memory controls" />}
      {query.error && !query.data && <ErrorPanel error={query.error} onRetry={query.refresh} />}
      {query.data && draft && (
        <form className="brain-control-form" onSubmit={submit}>
          <Card className="brain-control-summary">
            <div><p className="os-eyebrow">Canonical policy</p><h2>Second Brain is {draft.enabled ? "enabled" : "disabled"}</h2><p>Disabling memory immediately removes all nodes from retrieval. Existing records remain inspectable until you explicitly forget or export them.</p></div>
            <StatusPill status={draft.enabled ? "enabled" : "disabled"} />
            <label className="brain-control-switch"><input type="checkbox" checked={draft.enabled} onChange={(event) => set("enabled", event.target.checked)} /><span>Enable memory retention and retrieval</span></label>
          </Card>

          <div className="brain-control-grid">
            <Card>
              <fieldset disabled={!draft.enabled}>
                <legend>Learning and retention</legend>
                <label>Personal preference learning<select value={draft.personalPreferencePolicy} onChange={(event) => set("personalPreferencePolicy", event.target.value as EditableMemoryControlPolicy["personalPreferencePolicy"])}><option value="candidate_only">Candidate only — always review</option><option value="disabled">Disabled</option></select></label>
                <label className="brain-control-switch"><input type="checkbox" checked={draft.operationalMemoryEnabled} onChange={(event) => set("operationalMemoryEnabled", event.target.checked)} /><span>Retain evidence-backed operational knowledge</span></label>
                <label>Default retention<select value={draft.defaultRetentionDays ?? "never"} onChange={(event) => set("defaultRetentionDays", event.target.value === "never" ? null : Number(event.target.value))}><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option><option value="1095">3 years</option><option value="never">No automatic expiry</option></select></label>
              </fieldset>
            </Card>

            <Card>
              <fieldset disabled={!draft.enabled}>
                <legend>Journey use</legend>
                <label className="brain-control-switch"><input type="checkbox" checked={draft.autonomousUse} onChange={(event) => set("autonomousUse", event.target.checked)} /><span>Allow permitted confirmed memory in Autonomous runs</span></label>
                <label className="brain-control-switch"><input type="checkbox" checked={draft.guidedUse} onChange={(event) => set("guidedUse", event.target.checked)} /><span>Allow confirmed preferences and knowledge in Guided missions</span></label>
                <p className="os-muted">Autonomous retrieval remains limited to contract-approved scopes and verified lessons. Guided retrieval remains limited to the current engagement and mission.</p>
              </fieldset>
            </Card>

            <Card>
              <fieldset disabled={!draft.enabled}>
                <legend>Obsidian projection</legend>
                <label>Synchronization scope<select value={draft.obsidianSyncScope} onChange={(event) => set("obsidianSyncScope", event.target.value as EditableMemoryControlPolicy["obsidianSyncScope"])}><option value="disabled">Disabled</option><option value="confirmed">Confirmed nodes</option><option value="confirmed_and_verified">Confirmed and verified nodes</option></select></label>
                <p className="os-muted">Vault access still requires an explicit sandboxed connection. Ti-Scale never edits the vault’s <span className="os-mono">.obsidian</span> settings.</p>
              </fieldset>
            </Card>

            <Card>
              <fieldset>
                <legend>Locked safety invariants</legend>
                <label className="brain-control-switch"><input type="checkbox" checked readOnly disabled /><span>Strict engagement isolation</span></label>
                <label className="brain-control-switch"><input type="checkbox" checked readOnly disabled /><span>Never retain credentials, tokens, private keys, or authentication material</span></label>
                <p className="os-muted">These protections cannot be disabled by a preference, mission, agent, provider, or vault edit.</p>
              </fieldset>
            </Card>
          </div>

          {error && <ErrorPanel title="Memory controls were not saved" error={error} onRetry={() => void retrySave()} />}
          <div className="brain-control-actions" aria-live="polite">
            <div><span>Policy version {query.data.version}</span><span>Last changed {formatBrainDate(query.data.updatedAt)}</span>{saved && <strong>Controls saved</strong>}</div>
            <Button type="submit" disabled={saving}>{saving ? "Saving controls" : "Save memory controls"}</Button>
          </div>
        </form>
      )}
    </div>
  );
}
