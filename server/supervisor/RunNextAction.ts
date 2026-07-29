import type { Journey, RunState } from "./types";

const TERMINAL_RUN_STATES = new Set<RunState>([
  "completed",
  "failed",
  "cancelled",
]);

/**
 * Canonical replacement for a persisted next-action summary after a state
 * transition. `undefined` means the transition may retain its current
 * represented next action; `null` deliberately clears it.
 */
export function runNextActionOverride(
  state: RunState,
  journey: Journey,
): string | null | undefined {
  if (TERMINAL_RUN_STATES.has(state)) return null;
  if (state !== "blocked") return undefined;
  return journey === "autonomous"
    ? "Review the safe-stop diagnosis, then amend the contract or start a new run."
    : "Review the blocker, then choose an available represented recovery action.";
}

/** Defensive projection for historical rows created before transition-time cleanup. */
export function projectRunNextAction(input: Readonly<{
  state: RunState;
  journey: Journey;
  persisted: unknown;
}>): string | null {
  const override = runNextActionOverride(input.state, input.journey);
  if (override !== undefined) return override;
  return typeof input.persisted === "string" && input.persisted.trim()
    ? input.persisted.trim()
    : null;
}
