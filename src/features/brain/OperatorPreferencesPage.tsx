import { fetchOperatorPreferences } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { ButtonLink, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type { OperatorPreferenceSummary, ProvenanceSource } from "../../domain/types/brain";
import { BrainEmpty, BrainNav, formatBrainDate, scopeLabel } from "./BrainNav";

function label(value: string): string {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/^./u, (first) => first.toUpperCase());
}

function readableValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null) return "None";
  return JSON.stringify(value);
}

function PreferenceSource({ source }: { source: ProvenanceSource }) {
  return (
    <li>
      <div><StatusPill status={source.sourceType} /><code>{source.sourceId}</code></div>
      <span>{formatBrainDate(source.acquiredAt)}</span>
      {source.excerptRedacted && <p>{source.excerptRedacted}</p>}
    </li>
  );
}

function PreferenceCard({ preference }: { preference: OperatorPreferenceSummary }) {
  const values = Object.entries(preference.value);
  return (
    <Card className="brain-preference-card">
      <div className="os-section-heading">
        <div><p className="os-eyebrow">{label(preference.preferenceKey)}</p><h2>{preference.node.title}</h2></div>
        <StatusPill status="confirmed" />
      </div>
      <p>{preference.node.summary}</p>
      <dl className="brain-preference-metadata">
        <div><dt>Scope</dt><dd>{scopeLabel(preference.node.scope)}</dd></div>
        <div><dt>Last confirmed</dt><dd><time>{formatBrainDate(preference.lastConfirmedAt)}</time></dd></div>
        <div><dt>Confirmation</dt><dd>Explicit operator confirmation</dd></div>
        <div><dt>Profile version</dt><dd>{preference.profileVersion}</dd></div>
      </dl>
      {preference.appliesTo.length > 0 && <section className="brain-preference-applies" aria-label="Preference applies to">
        <strong>Used for</strong>
        <ul>{preference.appliesTo.map((item) => <li key={item}>{label(item)}</li>)}</ul>
      </section>}
      {values.length > 0 && <section className="brain-preference-value" aria-label="Stored preference value">
        <strong>Stored preference value</strong>
        <dl>{values.map(([key, value]) => <div key={key}><dt>{label(key)}</dt><dd>{readableValue(value)}</dd></div>)}</dl>
      </section>}
      <section className="brain-preference-provenance" aria-label="Preference provenance">
        <strong>Why this is remembered</strong>
        <p>{preference.provenance.explanation}</p>
        <ul>{preference.provenance.sources.map((source) => <PreferenceSource key={`${source.sourceType}:${source.sourceId}`} source={source} />)}</ul>
      </section>
      <footer>
        <ButtonLink href={`/brain/nodes/${encodeURIComponent(preference.node.id)}`} variant="secondary">Open memory record</ButtonLink>
        <ButtonLink href={`/brain/graph?view=operator&selected=${encodeURIComponent(preference.node.id)}`} variant="quiet">Show in Operator graph</ButtonLink>
      </footer>
    </Card>
  );
}

export default function OperatorPreferencesPage() {
  const preferences = useQuery("brain:operator-preferences", fetchOperatorPreferences, { staleTime: 10_000 });
  return (
    <div className="os-page brain-page brain-preferences-page">
      <PageHeader
        eyebrow="Operator-owned collaboration profile"
        title="Operator Preferences"
        description="Only explicitly confirmed preferences appear here. Each record shows its scope, source, and last confirmation so personalization remains visible and correctable."
        actions={<ButtonLink href="/brain/graph?view=operator">Open Operator graph</ButtonLink>}
      />
      <BrainNav />
      <Card className="brain-preference-boundary" aria-label="Preference isolation boundary">
        <div><p className="os-eyebrow">Separate memory class</p><h2>Preferences guide presentation, never authorization</h2></div>
        <p>Operator Preferences are kept separate from reusable attack knowledge. They enter the Attack Knowledge Vault only through the separate, explicit Operator Profile consent on the Vault page; targets and operational records remain excluded. Preferences can never weaken scope, evidence, disclosure, or safety policy.</p>
      </Card>
      {preferences.isLoading && <LoadingPanel label="Loading confirmed operator preferences" />}
      {preferences.error && !preferences.data && <ErrorPanel error={preferences.error} onRetry={preferences.refresh} />}
      {preferences.data && preferences.data.items.length === 0 && <BrainEmpty
        title="No confirmed operator preferences yet"
        description="Explicitly confirmed collaboration, presentation, accessibility, and workflow preferences will appear here with their source and confirmation time."
        action={<ButtonLink href="/brain/inbox" variant="secondary">Review Memory Inbox</ButtonLink>}
      />}
      {preferences.data && preferences.data.items.length > 0 && <>
        <p className="brain-guidance" role="status">{preferences.data.totalReturned} confirmed operator preference{preferences.data.totalReturned === 1 ? "" : "s"}. They remain outside the Attack Knowledge Vault unless the separate Operator Profile scope is explicitly acknowledged.</p>
        <section className="brain-preference-list" aria-label="Confirmed operator preferences">
          {preferences.data.items.map((preference) => <PreferenceCard key={preference.node.id} preference={preference} />)}
        </section>
      </>}
    </div>
  );
}
