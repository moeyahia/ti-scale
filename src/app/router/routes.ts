export type NavIconName =
  | "overview" | "missions" | "live" | "guided" | "decisions" | "intelligence"
  | "agents" | "brain" | "learning" | "observability" | "reports" | "system" | "manual";

export interface NavigationItem {
  label: string;
  path: string;
  icon: NavIconName;
  matchPrefix?: string;
}

export const PRIMARY_NAVIGATION: NavigationItem[] = [
  { label: "Overview", path: "/", icon: "overview" },
  { label: "Missions", path: "/missions", icon: "missions", matchPrefix: "/missions" },
  { label: "Live Operations", path: "/live", icon: "live", matchPrefix: "/live" },
  { label: "Guided Workspace", path: "/guided", icon: "guided", matchPrefix: "/guided" },
  { label: "Decisions", path: "/decisions", icon: "decisions", matchPrefix: "/decisions" },
  { label: "Intelligence", path: "/intelligence/evidence", icon: "intelligence", matchPrefix: "/intelligence" },
  { label: "Agents", path: "/agents", icon: "agents", matchPrefix: "/agents" },
  { label: "Second Brain", path: "/brain", icon: "brain", matchPrefix: "/brain" },
  { label: "Learning", path: "/learning", icon: "learning", matchPrefix: "/learning" },
  { label: "Observability", path: "/observability", icon: "observability", matchPrefix: "/observability" },
  { label: "Reports", path: "/reports", icon: "reports", matchPrefix: "/reports" },
  { label: "System", path: "/system/connections", icon: "system", matchPrefix: "/system" },
];

export const USER_MANUAL_NAVIGATION: NavigationItem = {
  label: "User Manual",
  path: "/manual",
  icon: "manual",
  matchPrefix: "/manual",
};

export function isNavigationItemActive(item: NavigationItem, pathname: string): boolean {
  if (item.path === "/") return pathname === "/";
  return pathname === item.path || Boolean(item.matchPrefix && pathname.startsWith(`${item.matchPrefix}/`));
}
