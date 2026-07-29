import type { FailureCategory } from "./ErrorTaxonomy";

export interface ActionObservation {
  actionId: string;
  actionFingerprint: string;
  meaningfulProgress: boolean;
  progressSignatureAfter: string;
  completedAt: string;
  errorCategory?: FailureCategory;
  actionKind?: "tool" | "provider_turn" | "replan" | "delegation" | "manual";
  planFingerprint?: string;
  routingViolation?: boolean;
}

export interface LoopDetectorConfig {
  maxHistory: number;
  identicalFingerprintLimit: number;
  alternatingCycleRepetitions: number;
  noProgressActionLimit: number;
  identicalErrorLimit: number;
  equivalentReplanLimit: number;
}

export const DEFAULT_LOOP_DETECTOR_CONFIG: LoopDetectorConfig = {
  maxHistory: 50,
  identicalFingerprintLimit: 3,
  alternatingCycleRepetitions: 2,
  noProgressActionLimit: 3,
  identicalErrorLimit: 3,
  equivalentReplanLimit: 2,
};

export type LoopKind =
  | "identical_action"
  | "alternating_cycle"
  | "stagnation"
  | "repeated_error"
  | "equivalent_replan"
  | "routing_violation";

export interface LoopFinding {
  kind: LoopKind;
  detected: true;
  actionIds: readonly string[];
  summary: string;
}

function afterLastProgress(history: readonly ActionObservation[]): readonly ActionObservation[] {
  let start = 0;
  for (let index = history.length - 1; index >= 0; index -= 1) {
    if (history[index]?.meaningfulProgress) {
      start = index + 1;
      break;
    }
  }
  return history.slice(start);
}

function tail<T>(values: readonly T[], count: number): readonly T[] {
  return values.slice(Math.max(0, values.length - count));
}

export function detectDelegationCycle(agentPath: readonly string[]): readonly string[] | null {
  const positions = new Map<string, number>();
  for (let index = 0; index < agentPath.length; index += 1) {
    const agentId = agentPath[index]!;
    const existing = positions.get(agentId);
    if (existing !== undefined) return agentPath.slice(existing, index + 1);
    positions.set(agentId, index);
  }
  return null;
}

export class LoopDetector {
  readonly config: LoopDetectorConfig;

  constructor(config: Partial<LoopDetectorConfig> = {}) {
    this.config = { ...DEFAULT_LOOP_DETECTOR_CONFIG, ...config };
  }

  boundHistory(history: readonly ActionObservation[]): readonly ActionObservation[] {
    return tail(history, this.config.maxHistory);
  }

  inspect(historyInput: readonly ActionObservation[]): readonly LoopFinding[] {
    const history = this.boundHistory(historyInput);
    const stagnant = afterLastProgress(history);
    if (stagnant.length === 0) return [];
    const findings: LoopFinding[] = [];
    const latest = stagnant[stagnant.length - 1]!;

    const sameActions = stagnant.filter(
      (entry) => entry.actionFingerprint === latest.actionFingerprint,
    );
    if (sameActions.length >= this.config.identicalFingerprintLimit) {
      findings.push({
        kind: "identical_action",
        detected: true,
        actionIds: tail(sameActions, this.config.identicalFingerprintLimit).map((entry) => entry.actionId),
        summary: `The same action was attempted ${sameActions.length} times without meaningful progress.`,
      });
    }

    const alternatingLength = this.config.alternatingCycleRepetitions * 2;
    const alternating = tail(stagnant, alternatingLength);
    if (
      alternating.length === alternatingLength &&
      alternating[0]!.actionFingerprint !== alternating[1]!.actionFingerprint &&
      alternating.every(
        (entry, index) => entry.actionFingerprint === alternating[index % 2]!.actionFingerprint,
      )
    ) {
      findings.push({
        kind: "alternating_cycle",
        detected: true,
        actionIds: alternating.map((entry) => entry.actionId),
        summary: "Actions are alternating in a cycle without meaningful progress.",
      });
    }

    if (stagnant.length >= this.config.noProgressActionLimit) {
      const window = tail(stagnant, this.config.noProgressActionLimit);
      findings.push({
        kind: "stagnation",
        detected: true,
        actionIds: window.map((entry) => entry.actionId),
        summary: `${window.length} completed actions produced no meaningful progress.`,
      });
    }

    if (latest.errorCategory) {
      const errors = stagnant.filter((entry) => entry.errorCategory === latest.errorCategory);
      if (errors.length >= this.config.identicalErrorLimit) {
        findings.push({
          kind: "repeated_error",
          detected: true,
          actionIds: tail(errors, this.config.identicalErrorLimit).map((entry) => entry.actionId),
          summary: `The ${latest.errorCategory} failure repeated without progress.`,
        });
      }
    }

    if (latest.actionKind === "replan" && latest.planFingerprint) {
      const equivalent = stagnant.filter(
        (entry) => entry.actionKind === "replan" && entry.planFingerprint === latest.planFingerprint,
      );
      if (equivalent.length >= this.config.equivalentReplanLimit) {
        findings.push({
          kind: "equivalent_replan",
          detected: true,
          actionIds: tail(equivalent, this.config.equivalentReplanLimit).map((entry) => entry.actionId),
          summary: "Replanning produced a materially equivalent plan.",
        });
      }
    }

    if (latest.routingViolation) {
      findings.push({
        kind: "routing_violation",
        detected: true,
        actionIds: [latest.actionId],
        summary: "The commander attempted specialist execution outside the routing boundary.",
      });
    }
    return findings;
  }
}
