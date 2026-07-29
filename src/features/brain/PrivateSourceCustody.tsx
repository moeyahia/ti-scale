import { ButtonLink } from "../../design-system/components/Primitives";
import type { ProvenanceOrigin, ProvenanceSource } from "../../domain/types/brain";

export function privateSourceBindingCount(sources: readonly ProvenanceSource[]): number {
  return sources.reduce((count, source) => count + (source.origins?.length ?? 0), 0);
}

function missionHref(origin: ProvenanceOrigin): string | undefined {
  return origin.missionId ? `/missions/${encodeURIComponent(origin.missionId)}` : undefined;
}

function runHref(origin: ProvenanceOrigin): string | undefined {
  return origin.missionId && origin.runId
    ? `/missions/${encodeURIComponent(origin.missionId)}/runs/${encodeURIComponent(origin.runId)}`
    : undefined;
}

export function privateSourceDestinationHref(origin: ProvenanceOrigin): string | undefined {
  if (origin.artifactId) return `/intelligence/artifacts/${encodeURIComponent(origin.artifactId)}`;
  if (origin.evidenceId) return `/intelligence/evidence/${encodeURIComponent(origin.evidenceId)}`;
  return runHref(origin) ?? missionHref(origin);
}

/**
 * One access-controlled custody presentation shared by the full node page and
 * the graph inspector. These are canonical private links, not reusable graph
 * edges, and the opaque source reference never becomes attack-note content.
 */
export function PrivateSourceCustody({ source }: { source: ProvenanceSource }) {
  if (!source.origins?.length) return null;
  const exactOriginCount = source.originCount ?? source.origins.length;
  return <section className="brain-source-origin" aria-label="Private source custody">
    <strong>Private source custody · {source.origins.length === exactOriginCount ? exactOriginCount : `${source.origins.length} of ${exactOriginCount}`} exact binding{exactOriginCount === 1 ? "" : "s"}</strong>
    {source.origins.map((origin, index) => {
      const mission = missionHref(origin);
      const run = runHref(origin);
      const sourceHref = privateSourceDestinationHref(origin);
      const originKey = origin.privateSourceReference
        ?? origin.artifactId
        ?? origin.evidenceId
        ?? `${origin.missionId}:${origin.runId}:${index}`;
      return <article key={originKey} className="brain-source-origin-record">
        {source.origins!.length > 1 && <h4>Exact binding {index + 1}</h4>}
        <dl>
          {(origin.engagementLabel || origin.engagementId) && <div><dt>Source collection</dt><dd>{origin.engagementLabel ?? origin.engagementId}</dd></div>}
          {origin.sourceLocator && <div><dt>Originating source</dt><dd><code>{origin.sourceLocator}</code></dd></div>}
          {origin.missionId && <div><dt>Import custody record</dt><dd>{mission ? <ButtonLink href={mission} variant="quiet">{origin.missionName ?? origin.missionId}</ButtonLink> : origin.missionName ?? origin.missionId}</dd></div>}
          {origin.runId && <div><dt>Custody processing run</dt><dd>{run ? <ButtonLink href={run} variant="quiet">{origin.runId}</ButtonLink> : origin.runId}{origin.runStatus ? ` · ${origin.runStatus}` : ""}</dd></div>}
          {origin.artifactId && <div><dt>Source artifact</dt><dd><ButtonLink href={`/intelligence/artifacts/${encodeURIComponent(origin.artifactId)}`} variant="quiet">{origin.artifactId}</ButtonLink></dd></div>}
          {origin.evidenceId && <div><dt>Evidence receipt</dt><dd><ButtonLink href={`/intelligence/evidence/${encodeURIComponent(origin.evidenceId)}`} variant="quiet">{origin.evidenceId}</ButtonLink></dd></div>}
          {origin.privateSourceReference && <div><dt>Private source reference</dt><dd>{sourceHref ? <ButtonLink href={sourceHref} variant="quiet">{origin.privateSourceReference}</ButtonLink> : <code>{origin.privateSourceReference}</code>}</dd></div>}
        </dl>
      </article>;
    })}
    <small>These exact private bindings preserve custody even when this memory has zero reusable knowledge edges. They are never copied into reusable attack content or the Attack Knowledge Vault.</small>
  </section>;
}
