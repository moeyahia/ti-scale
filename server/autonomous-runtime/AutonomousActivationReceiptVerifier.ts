import type { SqliteDatabase } from "../db";
import {
  AutonomousActivationReceiptRepository,
  recomputeAutonomousActivationReceiptIntegrity,
} from "./AutonomousActivationReceiptRepository";
import {
  AutonomousActivationReceiptIntegrityError,
  type AutonomousActivationReceipt,
  type AutonomousActivationReceiptExpectations,
  type AutonomousActivationReceiptVerification,
} from "./AutonomousActivationReceiptTypes";

function mismatch(
  code: ConstructorParameters<typeof AutonomousActivationReceiptIntegrityError>[0],
  message: string,
): never {
  throw new AutonomousActivationReceiptIntegrityError(code, message);
}

function sorted(values: readonly string[]): string[] {
  const normalized = values.map((value) => value.trim());
  if (
    normalized.length === 0 ||
    normalized.some((value) => value.length === 0) ||
    new Set(normalized).size !== normalized.length
  ) {
    return mismatch(
      "activation_receipt_invalid_input",
      "Expected activation action classes must be unique non-empty IDs",
    );
  }
  return normalized.sort((left, right) => left.localeCompare(right, "en-US"));
}

function same(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/**
 * Recomputes every persisted aggregate and checks current DB lineage before an
 * Autonomous consumer trusts the receipt. A new verifier instance can safely
 * read a receipt after process restart; no boot-local signing state is needed.
 */
export class AutonomousActivationReceiptVerifier {
  readonly #repository: AutonomousActivationReceiptRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.#repository = new AutonomousActivationReceiptRepository(database, clock);
  }

  verify(
    receiptId: string,
    expected: AutonomousActivationReceiptExpectations = {},
  ): AutonomousActivationReceiptVerification {
    const receipt = this.#repository.getById(receiptId);
    this.#verifyExpectations(receipt, expected);
    recomputeAutonomousActivationReceiptIntegrity(this.database, receipt);
    const verifiedAt = this.clock().toISOString();
    if (
      !expected.allowExpired &&
      new Date(verifiedAt).getTime() >= new Date(receipt.expiresAt).getTime()
    ) {
      mismatch(
        "activation_receipt_expired",
        `Autonomous activation receipt ${receipt.id} expired at ${receipt.expiresAt}`,
      );
    }
    return { valid: true, receipt, verifiedAt };
  }

  verifyCurrentForRun(
    runId: string,
    expected: Omit<AutonomousActivationReceiptExpectations, "runId"> = {},
  ): AutonomousActivationReceiptVerification {
    const receipt = this.#repository.findCurrentForRun(runId);
    if (!receipt) {
      mismatch(
        "activation_receipt_not_found",
        `No Autonomous activation receipt exists for run ${runId}`,
      );
    }
    return this.verify(receipt.id, { ...expected, runId });
  }

  #verifyExpectations(
    receipt: AutonomousActivationReceipt,
    expected: AutonomousActivationReceiptExpectations,
  ): void {
    if (
      (expected.missionId !== undefined && expected.missionId !== receipt.missionId) ||
      (expected.runId !== undefined && expected.runId !== receipt.runId)
    ) {
      mismatch(
        "activation_receipt_lineage_mismatch",
        "Autonomous activation receipt mission or run does not match the requested boundary",
      );
    }
    if (
      (expected.contractId !== undefined && expected.contractId !== receipt.contractId) ||
      (
        expected.contractVersion !== undefined &&
        expected.contractVersion !== receipt.contractVersion
      ) ||
      (
        expected.contractHash !== undefined &&
        expected.contractHash.toLowerCase() !== receipt.contractHash
      )
    ) {
      mismatch(
        "activation_receipt_contract_mismatch",
        "Autonomous activation receipt does not match the expected signed contract",
      );
    }
    if (
      expected.runtimeGenerationHash !== undefined &&
      expected.runtimeGenerationHash.toLowerCase() !== receipt.runtimeGenerationHash
    ) {
      mismatch(
        "activation_receipt_runtime_generation_drift",
        "Autonomous runtime generation changed after the activation receipt was issued",
      );
    }
    if (
      expected.evidencePolicyHash !== undefined &&
      expected.evidencePolicyHash.toLowerCase() !== receipt.evidencePolicyHash
    ) {
      mismatch(
        "activation_receipt_contract_mismatch",
        "Autonomous activation receipt evidence policy does not match the expected policy",
      );
    }
    if (
      expected.brainContextPackId !== undefined &&
      expected.brainContextPackId !== receipt.brainContextPackId
    ) {
      mismatch(
        "activation_receipt_brain_context_mismatch",
        "Autonomous activation receipt does not bind the expected Brain Context Pack",
      );
    }
    if (
      expected.planningSelectionHash !== undefined &&
      expected.planningSelectionHash.toLowerCase() !==
        receipt.planning.selectionHash
    ) {
      mismatch(
        "activation_receipt_model_assignment_mismatch",
        "Autonomous activation receipt does not bind the expected run-level planning selection",
      );
    }
    if (
      expected.selectedActionClassIds !== undefined &&
      !same(sorted(expected.selectedActionClassIds), sorted(receipt.selectedActionClassIds))
    ) {
      mismatch(
        "activation_receipt_class_coverage_mismatch",
        "Autonomous activation receipt does not cover the expected action-class set",
      );
    }
    if (
      expected.receiptHash !== undefined &&
      expected.receiptHash.toLowerCase() !== receipt.receiptHash
    ) {
      mismatch(
        "activation_receipt_tampered",
        "Autonomous activation receipt hash does not match the expected receipt",
      );
    }
  }
}
