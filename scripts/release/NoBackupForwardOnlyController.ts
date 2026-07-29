export type NoBackupForwardOnlyCommand = "deploy" | "recover";

export type NoBackupForwardOnlyRecoveryDirection =
  | "restore_source"
  | "complete_target";

export interface NoBackupForwardOnlyPhaseOperations {
  readonly stop: () => void | Promise<void>;
  readonly withMaintenance: <T>(
    operation: () => Promise<T>,
  ) => Promise<T>;
  readonly migrate: () => void | Promise<void>;
  readonly commitTarget: () => void | Promise<void>;
  readonly startAndFinalize: (
    forceRecovery: boolean,
  ) => void | Promise<void>;
}

export interface NoBackupForwardOnlyControllerOperations
  extends NoBackupForwardOnlyPhaseOperations {
  readonly observedSchema: () => number | Promise<number>;
  /**
   * A same-schema release cannot infer its recovery direction from SQLite.
   * The caller must instead expose the durable target-commit record that binds
   * the application and static pointers to the selected target release.
   */
  readonly durableTargetCommitted?: () => boolean | Promise<boolean>;
  readonly restoreSourceBeforeSchemaCommit: (
    cause: unknown,
  ) => void | Promise<void>;
  readonly ensureTargetCommitted: () => void | Promise<void>;
  readonly recordForwardRecoveryFailure?: (
    primaryFailure: unknown,
    recoveryFailure: unknown,
  ) => void | Promise<void>;
}

export interface NoBackupForwardOnlyControllerOptions {
  readonly command: NoBackupForwardOnlyCommand;
  readonly sourceSchema: number;
  readonly targetSchema: number;
  /**
   * Exact, attested schema versions that may be observed after the first
   * irreversible migration commit. Production callers bind this list to the
   * immutable candidate migration attestation.
   *
   * The field remains optional for small standalone controller consumers that
   * model a contiguous source-to-target range directly. The production release
   * path always supplies it.
   */
  readonly forwardSchemas?: readonly number[];
  readonly operations: NoBackupForwardOnlyControllerOperations;
  /**
   * A normal deploy failure remains a failed command even after the source
   * runtime has been restored. A deliberate `recover` command instead returns
   * the durable restored outcome.
   */
  readonly rethrowRestoredDeployFailure?: boolean;
  readonly interruptedRecoveryCause?: unknown;
  readonly recoveryInterruption?: {
    throwIfAborted(): void;
  };
}

export interface NoBackupForwardOnlyControllerResult {
  readonly status: "deployed" | "predeploy_restored";
  readonly recoveryDirection: NoBackupForwardOnlyRecoveryDirection | null;
  readonly recovered: boolean;
}

export async function commitNoBackupTerminalAfterCompatibilityProof<T>(
  options: {
    readonly verifyCompatibility: () => T | Promise<T>;
    readonly afterCompatibilityProof?: (proof: T) => void | Promise<void>;
    readonly commitTerminal: (proof: T) => void | Promise<void>;
  },
): Promise<T> {
  const proof = await options.verifyCompatibility();
  await options.afterCompatibilityProof?.(proof);
  await options.commitTerminal(proof);
  return proof;
}

export function assertNoBackupForwardOnlySchemaProgression(
  sourceSchema: number,
  targetSchema: number,
  forwardSchemas?: readonly number[],
): void {
  if (
    !Number.isSafeInteger(sourceSchema) ||
    !Number.isSafeInteger(targetSchema) ||
    sourceSchema < 0 ||
    targetSchema < sourceSchema
  ) {
    throw new Error("No-backup recovery schema boundary is invalid");
  }
  if (forwardSchemas === undefined) return;
  if (forwardSchemas.length !== targetSchema - sourceSchema) {
    throw new Error(
      "No-backup forward schema progression must include every schema after " +
      "the source through the target",
    );
  }
  for (let index = 0; index < forwardSchemas.length; index += 1) {
    const expected = sourceSchema + index + 1;
    if (
      !Number.isSafeInteger(forwardSchemas[index]) ||
      forwardSchemas[index] !== expected
    ) {
      throw new Error(
        `No-backup forward schema progression is not contiguous at ${String(expected)}`,
      );
    }
  }
}

export function classifyNoBackupForwardOnlyRecovery(
  sourceSchema: number,
  targetSchema: number,
  observedSchema: number,
  forwardSchemas?: readonly number[],
  sameSchemaTargetCommitted?: boolean,
): NoBackupForwardOnlyRecoveryDirection {
  assertNoBackupForwardOnlySchemaProgression(
    sourceSchema,
    targetSchema,
    forwardSchemas,
  );
  if (!Number.isSafeInteger(observedSchema) || observedSchema < 0) {
    throw new Error("No-backup recovery schema boundary is invalid");
  }
  if (sourceSchema === targetSchema) {
    if (observedSchema !== sourceSchema) {
      throw new Error(
        `No-backup recovery cannot classify observed schema ${String(observedSchema)} ` +
        `for attested progression ${String(sourceSchema)}→${String(targetSchema)}`,
      );
    }
    if (sameSchemaTargetCommitted === undefined) {
      throw new Error(
        "Same-schema no-backup recovery requires durable target commitment state",
      );
    }
    return sameSchemaTargetCommitted
      ? "complete_target"
      : "restore_source";
  }
  if (observedSchema === sourceSchema) return "restore_source";
  if (
    observedSchema > sourceSchema &&
    observedSchema <= targetSchema &&
    (
      forwardSchemas === undefined ||
      forwardSchemas.includes(observedSchema)
    )
  ) {
    return "complete_target";
  }
  throw new Error(
    `No-backup recovery cannot classify observed schema ${String(observedSchema)} ` +
    `for attested progression ${String(sourceSchema)}→${String(targetSchema)}`,
  );
}

export function enforceNoBackupRecoveryInterruptionPolicy(
  direction: NoBackupForwardOnlyRecoveryDirection,
  interruption?: { throwIfAborted(): void },
): void {
  if (direction === "restore_source") interruption?.throwIfAborted();
}

/**
 * The service-start boundary is deliberately outside the maintenance-lease
 * callback. A successful callback return proves that the lease release path
 * has run before the target runtime is allowed to start.
 */
export async function executeNoBackupForwardOnlyPhaseSequence(
  operations: NoBackupForwardOnlyPhaseOperations,
): Promise<void> {
  await operations.stop();
  await operations.withMaintenance(async () => {
    await operations.migrate();
    await operations.commitTarget();
  });
  await operations.startAndFinalize(false);
}

/**
 * Production deploy and recovery share this one forward-only state machine.
 *
 * While a migrating database is still at the exact source schema, an
 * interrupted release restores the immutable source runtime. After any
 * attested forward migration commits, downgrade is forbidden and
 * reconciliation resumes the remaining migrations before completing the
 * immutable target. For a same-schema release, the durable target-commit
 * record—not the ambiguous unchanged schema—is the recovery boundary. The
 * operations own durable journal records and observed-state idempotency; this
 * controller owns the direction decision and phase ordering.
 */
export async function executeNoBackupForwardOnlyController(
  options: NoBackupForwardOnlyControllerOptions,
): Promise<NoBackupForwardOnlyControllerResult> {
  assertNoBackupForwardOnlySchemaProgression(
    options.sourceSchema,
    options.targetSchema,
    options.forwardSchemas,
  );
  const direction = async (): Promise<NoBackupForwardOnlyRecoveryDirection> => {
    const sameSchemaTargetCommitted =
      options.sourceSchema === options.targetSchema
        ? await options.operations.durableTargetCommitted?.()
        : undefined;
    return classifyNoBackupForwardOnlyRecovery(
      options.sourceSchema,
      options.targetSchema,
      await options.operations.observedSchema(),
      options.forwardSchemas,
      sameSchemaTargetCommitted,
    );
  };

  const finishTarget = async (
    primaryFailure?: unknown,
  ): Promise<NoBackupForwardOnlyControllerResult> => {
    try {
      await options.operations.ensureTargetCommitted();
      await options.operations.startAndFinalize(true);
      return {
        status: "deployed",
        recoveryDirection: "complete_target",
        recovered: true,
      };
    } catch (recoveryFailure) {
      if (primaryFailure !== undefined) {
        await options.operations.recordForwardRecoveryFailure?.(
          primaryFailure,
          recoveryFailure,
        );
        throw new AggregateError(
          [primaryFailure, recoveryFailure],
          "No-backup forward deployment failed after schema commit and forward recovery is still required",
        );
      }
      throw recoveryFailure;
    }
  };

  if (options.command === "recover") {
    const recoveryDirection = await direction();
    if (recoveryDirection === "restore_source") {
      enforceNoBackupRecoveryInterruptionPolicy(
        recoveryDirection,
        options.recoveryInterruption,
      );
      await options.operations.restoreSourceBeforeSchemaCommit(
        options.interruptedRecoveryCause ??
          new Error("Recovered an interrupted no-backup forward deployment before schema commit"),
      );
      return {
        status: "predeploy_restored",
        recoveryDirection,
        recovered: true,
      };
    }
    return finishTarget();
  }

  try {
    await executeNoBackupForwardOnlyPhaseSequence(options.operations);
    return {
      status: "deployed",
      recoveryDirection: null,
      recovered: false,
    };
  } catch (primaryFailure) {
    const recoveryDirection = await direction();
    if (recoveryDirection === "restore_source") {
      await options.operations.restoreSourceBeforeSchemaCommit(primaryFailure);
      if (options.rethrowRestoredDeployFailure !== false) throw primaryFailure;
      return {
        status: "predeploy_restored",
        recoveryDirection,
        recovered: true,
      };
    }
    return finishTarget(primaryFailure);
  }
}
