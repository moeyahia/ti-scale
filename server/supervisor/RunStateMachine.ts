import {
  isTerminalRunState,
  type Journey,
  type RunState,
  type RunTransitionContext,
  type SupervisedRun,
  type TransitionResult,
} from "./types";

const TRANSITIONS: Readonly<Record<RunState, readonly RunState[]>> = {
  queued: ["planning", "failed", "cancelled"],
  planning: ["awaiting_contract_confirmation", "running", "blocked", "failed", "cancelled"],
  awaiting_contract_confirmation: ["planning", "running", "failed", "cancelled"],
  running: [
    "waiting_guided_decision",
    "blocked",
    "recovering",
    "completed",
    "failed",
    "cancelled",
  ],
  waiting_guided_decision: ["running", "blocked", "recovering", "failed", "cancelled"],
  blocked: ["running", "waiting_guided_decision", "recovering", "failed", "cancelled"],
  recovering: ["planning", "running", "waiting_guided_decision", "blocked", "failed", "cancelled"],
  completed: [],
  failed: [],
  cancelled: [],
};

export class InvalidRunTransitionError extends Error {
  constructor(
    readonly from: RunState,
    readonly to: RunState,
    message: string,
  ) {
    super(message);
    this.name = "InvalidRunTransitionError";
  }
}

export function allowedRunTransitions(state: RunState, journey: Journey): readonly RunState[] {
  return TRANSITIONS[state].filter((target) => {
    if (journey === "autonomous" && target === "waiting_guided_decision") return false;
    if (journey === "guided" && target === "awaiting_contract_confirmation") return false;
    return true;
  });
}

export function assertRunTransition(
  run: Readonly<SupervisedRun>,
  to: RunState,
  context: Readonly<RunTransitionContext>,
): void {
  if (!context.reason.trim()) {
    throw new InvalidRunTransitionError(run.state, to, "Every run transition requires a human-readable reason");
  }
  if (isTerminalRunState(run.state)) {
    throw new InvalidRunTransitionError(run.state, to, `Terminal run state ${run.state} cannot transition`);
  }
  if (!allowedRunTransitions(run.state, run.journey).includes(to)) {
    throw new InvalidRunTransitionError(
      run.state,
      to,
      `Illegal ${run.journey} run transition: ${run.state} -> ${to}`,
    );
  }
  if (run.journey === "autonomous") {
    if (to === "waiting_guided_decision") {
      throw new InvalidRunTransitionError(run.state, to, "Autonomous runs may never wait for a Guided decision");
    }
    if (to === "awaiting_contract_confirmation" && run.launched) {
      throw new InvalidRunTransitionError(
        run.state,
        to,
        "Autonomous contract confirmation is a pre-launch state only",
      );
    }
    if (to === "running" && !run.launched && !context.contractConfirmed && !run.contractConfirmedAt) {
      throw new InvalidRunTransitionError(
        run.state,
        to,
        "Autonomous launch requires a confirmed mission contract",
      );
    }
  }
  if (run.journey === "guided") {
    if (to === "waiting_guided_decision" && !context.guidedDecisionId?.trim()) {
      throw new InvalidRunTransitionError(
        run.state,
        to,
        "Guided waiting state requires the exact pending decision id",
      );
    }
    if (to === "running" && run.state === "waiting_guided_decision" && !context.guidedDecisionId?.trim()) {
      throw new InvalidRunTransitionError(
        run.state,
        to,
        "Resuming Guided execution requires the resolved decision id",
      );
    }
    if (
      to === "running" &&
      run.state === "waiting_guided_decision" &&
      context.guidedDecisionId !== run.pendingGuidedDecisionId
    ) {
      throw new InvalidRunTransitionError(
        run.state,
        to,
        "Resolved Guided decision does not match the pending decision",
      );
    }
  }
}

export function transitionRun(
  run: Readonly<SupervisedRun>,
  to: RunState,
  context: Readonly<RunTransitionContext>,
): TransitionResult {
  assertRunTransition(run, to, context);
  const launched = run.launched || to === "running";
  const terminal = isTerminalRunState(to);
  const pendingGuidedDecisionId =
    to === "waiting_guided_decision"
      ? context.guidedDecisionId
      : run.state === "waiting_guided_decision" || terminal
        ? undefined
        : run.pendingGuidedDecisionId;
  const next: SupervisedRun = {
    ...run,
    state: to,
    launched,
    contractConfirmedAt:
      run.contractConfirmedAt ?? (context.contractConfirmed ? context.now : undefined),
    pendingGuidedDecisionId,
    stateVersion: run.stateVersion + 1,
    stateReason: context.reason.trim(),
    updatedAt: context.now,
    endedAt: terminal ? context.now : undefined,
  };
  const checkpointRequired = true;
  const events = [
    {
      type: "run.state_changed" as const,
      runId: run.id,
      missionId: run.missionId,
      journey: run.journey,
      occurredAt: context.now,
      summary: `${run.state} -> ${to}: ${context.reason.trim()}`,
      payload: {
        from: run.state,
        to,
        reason: context.reason.trim(),
        stateVersion: next.stateVersion,
        guidedDecisionId: context.guidedDecisionId,
      },
    },
    {
      type: "run.checkpoint_required" as const,
      runId: run.id,
      missionId: run.missionId,
      journey: run.journey,
      occurredAt: context.now,
      summary: `Checkpoint required after transition to ${to}`,
      payload: { state: to, stateVersion: next.stateVersion },
    },
  ];
  return { run: next, events, checkpointRequired };
}
