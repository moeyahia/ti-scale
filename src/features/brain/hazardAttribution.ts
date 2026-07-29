import type { MemoryUsage, OperationalHazardDetail } from "../../domain/types/brain";

export interface OperationalHazardRunContext {
  readonly missionId: string;
  readonly runId: string;
  readonly purpose: string;
  readonly createdAt: string;
}

export interface OperationalHazardResetDraft {
  readonly missionId: string;
  readonly runId: string;
  readonly reportedMinimum: number;
}

/**
 * Keeps one idempotency key across ambiguous transport failures. A changed
 * represented draft gets a new key; a confirmed server result retires it.
 */
export class OperationalHazardResetDraftKey {
  #fingerprint?: string;
  #key?: string;

  keyFor(draft: OperationalHazardResetDraft, createKey: () => string): string {
    const fingerprint = JSON.stringify([draft.missionId, draft.runId, draft.reportedMinimum]);
    if (this.#fingerprint !== fingerprint || !this.#key) {
      this.#fingerprint = fingerprint;
      this.#key = createKey();
    }
    return this.#key;
  }

  confirm(draft: OperationalHazardResetDraft): void {
    const fingerprint = JSON.stringify([draft.missionId, draft.runId, draft.reportedMinimum]);
    if (this.#fingerprint !== fingerprint) return;
    this.#fingerprint = undefined;
    this.#key = undefined;
  }
}

/** The endpoint is run-scoped, so only persisted Context Pack links qualify. */
export function operationalHazardRunContexts(
  usage: readonly MemoryUsage[],
): readonly OperationalHazardRunContext[] {
  const contexts = new Map<string, OperationalHazardRunContext>();
  for (const item of usage) {
    if (!item.missionId || !item.runId) continue;
    const key = `${item.missionId}\0${item.runId}`;
    if (!contexts.has(key)) {
      contexts.set(key, {
        missionId: item.missionId,
        runId: item.runId,
        purpose: item.purpose,
        createdAt: item.createdAt,
      });
    }
  }
  return [...contexts.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

/**
 * Keeps exact procedure evidence separate from the operator's broader reset
 * history. The overall minimum is useful operational context, but it must
 * never be redistributed across procedures without an attributable receipt.
 */
export function operationalHazardResetAttribution(
  hazard: Pick<OperationalHazardDetail, "corroboration" | "recovery">,
): {
  readonly exactProcedureResetCount: number;
  readonly operatorReportedOverallMinimum: number | null;
  readonly minimumNotAttributedToThisProcedure: number | null;
} {
  const exactProcedureResetCount = Math.max(0, hazard.recovery.cost.resetCount ?? 0);
  const operatorReportedOverallMinimum = hazard.corroboration.operatorReportedResetMinimum;
  return {
    exactProcedureResetCount,
    operatorReportedOverallMinimum,
    minimumNotAttributedToThisProcedure: operatorReportedOverallMinimum === null
      ? null
      : Math.max(operatorReportedOverallMinimum - exactProcedureResetCount, 0),
  };
}
