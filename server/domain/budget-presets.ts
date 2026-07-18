export const BUDGET_PRESET_IDS = ["quick", "standard", "deep", "custom"] as const;
export type BudgetPresetId = (typeof BUDGET_PRESET_IDS)[number];

export interface MissionBudgetPreset {
  readonly id: Exclude<BudgetPresetId, "custom">;
  readonly label: string;
  readonly description: string;
  readonly timeBudgetMinutes: number;
  readonly tokenBudget: number;
  readonly estimatedCostBudget: number;
  readonly toolCallBudget: number;
  readonly retryBudget: number;
  readonly replanBudget: number;
  readonly concurrencyLimit: number;
  readonly screenshotBudget: number;
  readonly evidenceStorageBudgetBytes: number;
  readonly artifactStorageBudgetBytes: number;
  readonly maximumArtifactBytes: number;
}

const MiB = 1024 ** 2;

export const MISSION_BUDGET_PRESETS = {
  quick: {
    id: "quick",
    label: "Quick",
    description: "A short, tightly bounded pass for a small, well-understood scope.",
    timeBudgetMinutes: 30,
    tokenBudget: 50_000,
    estimatedCostBudget: 5,
    toolCallBudget: 250,
    retryBudget: 1,
    replanBudget: 1,
    concurrencyLimit: 2,
    screenshotBudget: 20,
    evidenceStorageBudgetBytes: 64 * MiB,
    artifactStorageBudgetBytes: 256 * MiB,
    maximumArtifactBytes: 32 * MiB,
  },
  standard: {
    id: "standard",
    label: "Standard",
    description: "Balanced depth, evidence capture, and recovery for a typical authorized assessment.",
    timeBudgetMinutes: 120,
    tokenBudget: 250_000,
    estimatedCostBudget: 25,
    toolCallBudget: 1_000,
    retryBudget: 2,
    replanBudget: 2,
    concurrencyLimit: 3,
    screenshotBudget: 100,
    evidenceStorageBudgetBytes: 512 * MiB,
    artifactStorageBudgetBytes: 2 * 1024 * MiB,
    maximumArtifactBytes: 128 * MiB,
  },
  deep: {
    id: "deep",
    label: "Deep",
    description: "Extended, evidence-heavy work for a larger authorized lab or engagement scope.",
    timeBudgetMinutes: 480,
    tokenBudget: 1_000_000,
    estimatedCostBudget: 100,
    toolCallBudget: 5_000,
    retryBudget: 2,
    replanBudget: 2,
    concurrencyLimit: 5,
    screenshotBudget: 500,
    evidenceStorageBudgetBytes: 2 * 1024 * MiB,
    artifactStorageBudgetBytes: 8 * 1024 * MiB,
    maximumArtifactBytes: 512 * MiB,
  },
} as const satisfies Readonly<Record<Exclude<BudgetPresetId, "custom">, MissionBudgetPreset>>;

export function missionBudgetPreset(id: BudgetPresetId): MissionBudgetPreset {
  return id === "custom" ? MISSION_BUDGET_PRESETS.standard : MISSION_BUDGET_PRESETS[id];
}
