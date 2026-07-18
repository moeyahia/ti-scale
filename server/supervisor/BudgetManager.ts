export const BUDGET_KEYS = [
  "wallClockMs",
  "providerTokens",
  "estimatedCost",
  "toolCalls",
  "providerTurns",
  "retries",
  "replans",
  "concurrency",
  "evidenceBytes",
  "artifactBytes",
] as const;
export type BudgetKey = (typeof BUDGET_KEYS)[number];
export type BudgetValues = Readonly<Partial<Record<BudgetKey, number>>>;

export interface BudgetState {
  limits: BudgetValues;
  usage: BudgetValues;
}

export interface BudgetCheck {
  allowed: boolean;
  exhausted: readonly BudgetKey[];
  projected: BudgetValues;
}

function validateValue(key: BudgetKey, value: number): void {
  if (!Number.isFinite(value) || value < 0) throw new Error(`Invalid ${key} budget value: ${value}`);
}

export function checkBudget(state: Readonly<BudgetState>, delta: BudgetValues): BudgetCheck {
  const projected: Partial<Record<BudgetKey, number>> = { ...state.usage };
  const exhausted: BudgetKey[] = [];
  for (const key of BUDGET_KEYS) {
    const increment = delta[key] ?? 0;
    validateValue(key, increment);
    const current = state.usage[key] ?? 0;
    const next = current + increment;
    projected[key] = next;
    const limit = state.limits[key];
    if (limit !== undefined) {
      validateValue(key, limit);
      if (next > limit) exhausted.push(key);
    }
  }
  return { allowed: exhausted.length === 0, exhausted, projected };
}

export class BudgetManager {
  private state: BudgetState;

  constructor(limits: BudgetValues, usage: BudgetValues = {}) {
    for (const key of BUDGET_KEYS) {
      if (limits[key] !== undefined) validateValue(key, limits[key]!);
      if (usage[key] !== undefined) validateValue(key, usage[key]!);
    }
    this.state = { limits: { ...limits }, usage: { ...usage } };
  }

  snapshot(): BudgetState {
    return { limits: { ...this.state.limits }, usage: { ...this.state.usage } };
  }

  check(delta: BudgetValues): BudgetCheck {
    return checkBudget(this.state, delta);
  }

  consume(delta: BudgetValues): BudgetState {
    const check = this.check(delta);
    if (!check.allowed) throw new Error(`Budget exceeded: ${check.exhausted.join(", ")}`);
    this.state = { limits: this.state.limits, usage: check.projected };
    return this.snapshot();
  }

  releaseConcurrency(count = 1): BudgetState {
    validateValue("concurrency", count);
    this.state = {
      limits: this.state.limits,
      usage: {
        ...this.state.usage,
        concurrency: Math.max(0, (this.state.usage.concurrency ?? 0) - count),
      },
    };
    return this.snapshot();
  }
}
