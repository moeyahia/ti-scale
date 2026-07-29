import type { AutonomousActivationReceiptVerifier } from "./AutonomousActivationReceiptVerifier";
import {
  AutonomousActivationReceiptIntegrityError,
  type AutonomousActivationReceipt,
  type AutonomousActivationReceiptIntegrityCode,
} from "./AutonomousActivationReceiptTypes";

export type AutonomousActivationReceiptIntegrityStatus =
  | "verified"
  | "expired"
  | "integrity_failure";

export interface AutonomousActivationReceiptIntegrityProjection {
  readonly status: AutonomousActivationReceiptIntegrityStatus;
  readonly code: AutonomousActivationReceiptIntegrityCode | null;
  readonly verifiedAt: string;
  readonly humanMessage: string;
  readonly remediation: string | null;
}

export interface AutonomousActivationReceiptSummary {
  readonly id: string;
  readonly runId: string;
  readonly generation: number;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly planningRoute: "local_deterministic" | "provider_advisory";
  readonly plannerId: string;
  readonly planningModelAssignmentId: string | null;
  readonly selectedActionClassCount: number;
  readonly activatedActionClassCount: number;
  readonly modelRouteCount: number;
  readonly toolRouteCount: number;
  readonly bindingCount: number;
  readonly runtimeGenerationHash: string;
  readonly brainContextPackId: string;
  readonly receiptHash: string;
  readonly integrity: AutonomousActivationReceiptIntegrityProjection;
}

function integrityFailure(
  error: AutonomousActivationReceiptIntegrityError,
  verifiedAt: string,
): AutonomousActivationReceiptIntegrityProjection {
  const expired = error.code === "activation_receipt_expired";
  return {
    status: expired ? "expired" : "integrity_failure",
    code: error.code,
    verifiedAt,
    humanMessage: expired
      ? "This activation proof has expired. Autonomous work must use a newly issued proof before it continues."
      : `This activation proof cannot be trusted: ${error.message}`,
    remediation: expired
      ? "Re-run Autonomous readiness so the exact contract, Brain context, model pins, and tool routes receive a new bounded proof."
      : "Keep the run stopped, inspect the reported integrity code, then re-run readiness against the current contract and runtime generation.",
  };
}

/**
 * Converts the immutable aggregate into a compact operator projection while
 * recomputing integrity from canonical records. Expiry remains visible as a
 * bounded state instead of making an otherwise inspectable proof disappear.
 */
export function projectAutonomousActivationReceipt(
  receipt: AutonomousActivationReceipt,
  verifier: Pick<AutonomousActivationReceiptVerifier, "verify">,
  clock: () => Date = () => new Date(),
): AutonomousActivationReceiptSummary {
  const verifiedAt = clock().toISOString();
  let integrity: AutonomousActivationReceiptIntegrityProjection;
  try {
    verifier.verify(receipt.id, { runId: receipt.runId, allowExpired: true });
    integrity = new Date(verifiedAt).getTime() >= new Date(receipt.expiresAt).getTime()
      ? integrityFailure(
          new AutonomousActivationReceiptIntegrityError(
            "activation_receipt_expired",
            `Autonomous activation receipt ${receipt.id} expired at ${receipt.expiresAt}`,
          ),
          verifiedAt,
        )
      : {
          status: "verified",
          code: null,
          verifiedAt,
          humanMessage: "The signed contract, planning route, Brain context, model pins, tool routes, and binding chain match canonical records.",
          remediation: null,
        };
  } catch (error) {
    if (!(error instanceof AutonomousActivationReceiptIntegrityError)) throw error;
    integrity = integrityFailure(error, verifiedAt);
  }

  const modelRouteIds = new Set(
    receipt.items.map((item) => item.executionModelAssignmentId),
  );
  if (receipt.planning.modelAssignmentId) {
    modelRouteIds.add(receipt.planning.modelAssignmentId);
  }
  return {
    id: receipt.id,
    runId: receipt.runId,
    generation: receipt.generation,
    issuedAt: receipt.issuedAt,
    expiresAt: receipt.expiresAt,
    planningRoute: receipt.planning.route,
    plannerId: receipt.planning.plannerId,
    planningModelAssignmentId: receipt.planning.modelAssignmentId,
    selectedActionClassCount: receipt.selectedActionClassCount,
    activatedActionClassCount: receipt.activatedActionClassCount,
    modelRouteCount: modelRouteIds.size,
    toolRouteCount: receipt.items.length,
    bindingCount: receipt.bindings.length,
    runtimeGenerationHash: receipt.runtimeGenerationHash,
    brainContextPackId: receipt.brainContextPackId,
    receiptHash: receipt.receiptHash,
    integrity,
  };
}
