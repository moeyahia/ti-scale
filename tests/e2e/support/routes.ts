export interface StaticRouteCase {
  readonly id: string;
  readonly path: string;
  readonly expectedPath?: string;
}

export type GeneratedHrefNavigationKind = "document" | "same-document" | "duplicate";

/**
 * Classifies the browser transition required to visit one generated internal
 * href from the currently loaded URL.
 *
 * A fragment is not part of an HTTP document identity. Moving between
 * fragments on the same path/query must therefore be audited as a
 * same-document transition, while a repeated exact URL is already covered by
 * the current document. Path, query, and origin changes still require an
 * independently observed top-level document request.
 */
export function classifyGeneratedHrefNavigation(
  currentHref: string,
  targetHref: string,
): GeneratedHrefNavigationKind {
  const current = new URL(currentHref);
  const target = new URL(targetHref, current);
  if (
    current.origin !== target.origin
    || current.pathname !== target.pathname
    || current.search !== target.search
  ) return "document";
  return current.hash === target.hash ? "duplicate" : "same-document";
}

export const STATIC_ROUTE_CASES: readonly StaticRouteCase[] = [
  { id: "overview", path: "/" },
  { id: "missions", path: "/missions" },
  { id: "mission-journey", path: "/missions/new" },
  { id: "autonomous-intake", path: "/missions/new/autonomous" },
  { id: "guided-intake", path: "/missions/new/guided" },
  { id: "guided", path: "/guided" },
  { id: "live", path: "/live" },
  { id: "decisions", path: "/decisions" },
  { id: "approvals-alias", path: "/approvals", expectedPath: "/decisions" },
  { id: "intelligence-alias", path: "/intelligence", expectedPath: "/intelligence/evidence" },
  { id: "evidence", path: "/intelligence/evidence" },
  { id: "findings", path: "/intelligence/findings" },
  { id: "artifacts", path: "/intelligence/artifacts" },
  { id: "agents", path: "/agents" },
  { id: "brain", path: "/brain" },
  { id: "brain-graph", path: "/brain/graph" },
  { id: "brain-preferences", path: "/brain/preferences" },
  { id: "brain-inbox", path: "/brain/inbox" },
  { id: "brain-control", path: "/brain/control" },
  { id: "brain-vault", path: "/brain/vault" },
  { id: "learning", path: "/learning" },
  { id: "research-alias", path: "/research", expectedPath: "/learning" },
  { id: "observability", path: "/observability" },
  { id: "reports", path: "/reports" },
  { id: "system-alias", path: "/system" },
  { id: "system-connections", path: "/system/connections" },
  { id: "system-policies", path: "/system/policies" },
  { id: "system-settings", path: "/system/settings" },
  { id: "manual", path: "/manual" },
  { id: "motion-lab", path: "/motion-lab" },
  { id: "motion-lab-assembly-retired-alias", path: "/motion-lab/assembly", expectedPath: "/motion-lab/particle-core" },
  { id: "motion-lab-particle-core", path: "/motion-lab/particle-core" },
  { id: "motion-lab-particle-module-transition", path: "/motion-lab/particle-module-transition" },
  { id: "motion-lab-webgl-retired-alias", path: "/motion-lab/webgl", expectedPath: "/motion-lab/particle-core" },
  { id: "motion-lab-candidates", path: "/motion-lab/candidates" },
] as const;

export const DYNAMIC_ROUTE_PATTERNS: readonly RegExp[] = [
  /^\/missions\/[^/]+$/u,
  /^\/missions\/[^/]+\/runs\/[^/]+$/u,
  /^\/guided\/[^/]+$/u,
  /^\/live\/[^/]+$/u,
  /^\/intelligence\/(evidence|findings|artifacts)\/[^/]+$/u,
  /^\/agents\/[^/]+$/u,
  /^\/brain\/nodes\/[^/]+$/u,
  /^\/learning\/lessons\/[^/]+$/u,
  /^\/reports\/[^/]+$/u,
] as const;

export function recognizedInternalPath(pathname: string): boolean {
  return STATIC_ROUTE_CASES.some((route) => route.path === pathname || route.expectedPath === pathname)
    || DYNAMIC_ROUTE_PATTERNS.some((pattern) => pattern.test(pathname));
}
