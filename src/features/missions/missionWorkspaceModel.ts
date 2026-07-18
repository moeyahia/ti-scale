import type { Journey } from "../../domain/types/commandOs";

export type MissionWorkspaceTab =
  | "summary"
  | "plan"
  | "live"
  | "guide"
  | "evidence"
  | "findings"
  | "conversation"
  | "brain"
  | "learning"
  | "history"
  | "settings";

export interface MissionWorkspaceTabDefinition {
  readonly id: MissionWorkspaceTab;
  readonly label: string;
}

const BEFORE_JOURNEY: readonly MissionWorkspaceTabDefinition[] = [
  { id: "summary", label: "Summary" },
  { id: "plan", label: "Plan" },
];

const AFTER_JOURNEY: readonly MissionWorkspaceTabDefinition[] = [
  { id: "evidence", label: "Evidence" },
  { id: "findings", label: "Findings" },
  { id: "conversation", label: "Conversation" },
  { id: "brain", label: "Brain" },
  { id: "learning", label: "Learning" },
  { id: "history", label: "History" },
  { id: "settings", label: "Settings" },
];

export function missionWorkspaceTabs(journey: Journey): readonly MissionWorkspaceTabDefinition[] {
  const journeyTab: MissionWorkspaceTabDefinition = journey === "autonomous"
    ? { id: "live", label: "Live" }
    : { id: "guide", label: "Guide" };
  return [...BEFORE_JOURNEY, journeyTab, ...AFTER_JOURNEY];
}

/**
 * Resolve a persisted URL tab against the mission's journey. A URL copied from
 * the other journey maps to the equivalent journey surface instead of exposing
 * a hidden third mode. Unknown values always return the durable Summary view.
 */
export function resolveMissionWorkspaceTab(value: string | null | undefined, journey: Journey): MissionWorkspaceTab {
  if (value === "live" || value === "guide") return journey === "autonomous" ? "live" : "guide";
  const candidate = value as MissionWorkspaceTab | null | undefined;
  return missionWorkspaceTabs(journey).some((item) => item.id === candidate) ? candidate! : "summary";
}

export function missionWorkspaceTabFromSearch(search: string, journey: Journey): MissionWorkspaceTab {
  const normalized = search.startsWith("?") ? search.slice(1) : search;
  return resolveMissionWorkspaceTab(new URLSearchParams(normalized).get("tab"), journey);
}

/** Preserve unrelated query state while making Summary the canonical no-query default. */
export function searchForMissionWorkspaceTab(search: string, tab: MissionWorkspaceTab, journey: Journey): string {
  const normalized = search.startsWith("?") ? search.slice(1) : search;
  const params = new URLSearchParams(normalized);
  const resolved = resolveMissionWorkspaceTab(tab, journey);
  if (resolved === "summary") params.delete("tab");
  else params.set("tab", resolved);
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}
