export const JOURNEYS = ["autonomous", "guided"] as const;
export type Journey = (typeof JOURNEYS)[number];

export const RUN_STATES = [
  "queued",
  "planning",
  "awaiting_contract_confirmation",
  "running",
  "waiting_guided_decision",
  "blocked",
  "recovering",
  "completed",
  "failed",
  "cancelled",
] as const;
export type RunState = (typeof RUN_STATES)[number];

export const TERMINAL_RUN_STATES = ["completed", "failed", "cancelled"] as const;
export type TerminalRunState = (typeof TERMINAL_RUN_STATES)[number];

export function isJourney(value: unknown): value is Journey {
  return typeof value === "string" && (JOURNEYS as readonly string[]).includes(value);
}

export function isRunState(value: unknown): value is RunState {
  return typeof value === "string" && (RUN_STATES as readonly string[]).includes(value);
}

export function isTerminalRunState(state: RunState): state is TerminalRunState {
  return (TERMINAL_RUN_STATES as readonly string[]).includes(state);
}

export interface SupervisedRun {
  id: string;
  missionId: string;
  journey: Journey;
  state: RunState;
  launched: boolean;
  contractVersion?: number;
  contractConfirmedAt?: string;
  pendingGuidedDecisionId?: string;
  stateVersion: number;
  stateReason: string;
  createdAt: string;
  /** The signed launch instant. Wall-clock budgets are measured from here. */
  startedAt?: string;
  updatedAt: string;
  endedAt?: string;
}

export interface RunTransitionContext {
  reason: string;
  now: string;
  contractConfirmed?: boolean;
  guidedDecisionId?: string;
}

export interface SupervisorEvent {
  type: "run.state_changed" | "run.checkpoint_required" | "run.safe_stopped";
  runId: string;
  missionId: string;
  journey: Journey;
  occurredAt: string;
  summary: string;
  payload: Readonly<Record<string, unknown>>;
}

export interface TransitionResult {
  run: SupervisedRun;
  events: readonly SupervisorEvent[];
  checkpointRequired: boolean;
}

export interface ActionIntent {
  missionId: string;
  actionType: string;
  arguments: Readonly<Record<string, unknown>>;
  target: string;
  runId: string;
  stepId: string;
  planVersion: number;
  precedingState?: Readonly<Record<string, unknown>>;
}

export type GuidedDecisionStatus =
  | "pending"
  | "authorized"
  | "rejected"
  | "expired"
  | "consumed";

export interface GuidedDecision {
  id: string;
  missionId: string;
  runId: string;
  stepId: string;
  journey: "guided";
  actionFingerprint: string;
  status: GuidedDecisionStatus;
  authorizedAt?: string;
  expiresAt: string;
  consumedAt?: string;
  version: number;
}

export interface AutonomousContractBoundary {
  runId: string;
  version: number;
  status: "draft" | "signed" | "superseded";
  allowedActionTypes: readonly string[];
  prohibitedActionTypes?: readonly string[];
  allowedTargets: readonly string[];
}
