import { useId } from "react";
import { fetchContextPack } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { ButtonLink, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { formatBrainDate, scopeLabel } from "./BrainNav";

export function ContextPackPanel({ packId }: { packId: string }) {
  const titleId = `context-pack-${useId().replaceAll(":", "")}`;
  const pack = useQuery(`brain-context:${packId}`, (signal) => fetchContextPack(packId, signal), { staleTime: 30_000 });
  if (pack.isLoading) return <LoadingPanel label="Loading inspectable context pack" />;
  if (pack.error && !pack.data) return <ErrorPanel title="Context use is unavailable" error={pack.error} onRetry={pack.refresh} />;
  if (!pack.data) return null;
  const usedNodes = pack.data.items.filter((item) => item.used);
  const pathStart = usedNodes[0]?.node.id ?? pack.data.items[0]?.node.id;
  const pathEnd = usedNodes.at(-1)?.node.id ?? pathStart;
  const pathUrl = pathStart
    ? `/brain/graph?view=local&root=${encodeURIComponent(pathStart)}&selected=${encodeURIComponent(pathEnd ?? pathStart)}`
    : "/brain/graph";
  return (
    <section className="brain-context-pack" aria-labelledby={titleId}>
      <header><div><p className="os-eyebrow">Context used</p><h3 id={titleId}>{pack.data.purpose}</h3></div><StatusPill status={pack.data.journey} /></header>
      <p className="brain-context-meta">Created by {pack.data.createdBy} · {formatBrainDate(pack.data.createdAt)} · Budget {pack.data.contextBudget}</p>
      <ButtonLink href={pathUrl} variant="secondary">Show memory path</ButtonLink>
      {pack.data.queryRedacted && <p className="brain-context-query"><strong>Redacted retrieval query</strong>{pack.data.queryRedacted}</p>}
      <ul>{pack.data.items.map((item) => <li key={item.node.id} className={item.used ? "is-used" : "is-ignored"}><div><ButtonLink href={`/brain/nodes/${encodeURIComponent(item.node.id)}`} variant="quiet">{item.node.title}</ButtonLink><StatusPill status={item.used ? "used" : "ignored"} /></div><p>{item.relevanceReason}</p>{item.used && item.influenceSummary && <small>Influence: {item.influenceSummary}</small>}{!item.used && item.ignoredReason && <small>Ignored: {item.ignoredReason}</small>}<span>{scopeLabel(item.node.scope)} · {Math.round(item.node.confidence * 100)}% confidence</span></li>)}</ul>
    </section>
  );
}
