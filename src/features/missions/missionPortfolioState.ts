import type { MissionPortfolioFilterState } from "../../domain/types/commandOs";

export const MISSION_PORTFOLIO_VIEWS = ["table", "board"] as const;
export type MissionPortfolioView = (typeof MISSION_PORTFOLIO_VIEWS)[number];

export type MissionPortfolioState = MissionPortfolioFilterState;

export interface SavedMissionView {
  readonly id: string;
  readonly name: string;
  readonly state: MissionPortfolioState;
  readonly createdAt: string;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function boundedText(value: unknown, maximum: number): string {
  return typeof value === "string" ? value.trim().slice(0, maximum) : "";
}

export function parseMissionPortfolioState(values: Readonly<Record<string, unknown>>): MissionPortfolioState {
  const journey = values.journey === "autonomous" || values.journey === "guided" ? values.journey : "";
  return {
    query: boundedText(values.query, 300),
    journey,
    status: boundedText(values.status, 80),
    engagement: boundedText(values.engagement, 240),
    target: boundedText(values.target, 300),
    agent: boundedText(values.agent, 200),
    provider: boundedText(values.provider, 200),
    updatedFrom: boundedText(values.updatedFrom, 40),
    updatedTo: boundedText(values.updatedTo, 40),
    risk: boundedText(values.risk, 80),
    evidence: values.evidence === "present" || values.evidence === "none" ? values.evidence : "",
    findingSeverity: boundedText(values.findingSeverity, 80),
    decisionState: boundedText(values.decisionState, 80),
    recoveryState: values.recoveryState === "recovering" || values.recoveryState === "blocked" || values.recoveryState === "none"
      ? values.recoveryState : "",
    view: values.view === "board" ? "board" : "table",
  };
}

export function missionPortfolioStateToUrl(state: MissionPortfolioState): Record<string, string | undefined> {
  return {
    query: state.query || undefined,
    journey: state.journey || undefined,
    status: state.status || undefined,
    engagement: state.engagement || undefined,
    target: state.target || undefined,
    agent: state.agent || undefined,
    provider: state.provider || undefined,
    updatedFrom: state.updatedFrom || undefined,
    updatedTo: state.updatedTo || undefined,
    risk: state.risk || undefined,
    evidence: state.evidence || undefined,
    findingSeverity: state.findingSeverity || undefined,
    decisionState: state.decisionState || undefined,
    recoveryState: state.recoveryState || undefined,
    view: state.view === "board" ? "board" : undefined,
  };
}

export function parseSavedMissionViews(raw: string | null): SavedMissionView[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, 12).flatMap((item) => {
      if (!item || typeof item !== "object") return [];
      const record = item as Record<string, unknown>;
      const id = boundedText(record.id, 128);
      const name = boundedText(record.name, 80);
      const createdAt = boundedText(record.createdAt, 40);
      const state = record.state && typeof record.state === "object"
        ? parseMissionPortfolioState(record.state as Record<string, unknown>)
        : parseMissionPortfolioState({});
      if (!IDENTIFIER.test(id) || !name || !Number.isFinite(Date.parse(createdAt))) return [];
      return [{ id, name, state, createdAt }];
    });
  } catch {
    return [];
  }
}

export function serializeSavedMissionViews(views: readonly SavedMissionView[]): string {
  return JSON.stringify(views.slice(0, 12));
}

export type MissionBoardLane = "attention" | "active" | "finished";

export function missionBoardLane(status: string): MissionBoardLane {
  if (["blocked", "recovering", "failed", "waiting_guided_decision"].includes(status)) return "attention";
  if (["completed", "cancelled"].includes(status)) return "finished";
  return "active";
}
