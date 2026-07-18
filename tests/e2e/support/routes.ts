export interface StaticRouteCase {
  readonly id: string;
  readonly path: string;
  readonly expectedPath?: string;
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
