import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  realpathSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import {
  createDirectoryDurably,
  renameDirectoryDurably,
  writeDurableFileAtomically,
} from "./DurableAtomicFile";

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const RECORD_NAME = /^(\d{8})-([a-f0-9]{64})\.json$/u;
const INTERRUPTED_TEMPORARY_NAME =
  /^\d{8}-[a-f0-9]{64}\.json\.\d+\.[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.tmp$/u;
const INTERRUPTED_TRANSACTION_OPENING_DIRECTORY =
  /^\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.\d+\.[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.opening$/u;
const MAX_TRANSACTION_DISCOVERY_DEPTH = 8;
const MAX_TRANSACTION_DISCOVERY_ENTRIES = 20_000;
const POSTCOMMIT_FORWARD_MUTATIONS = new Set([
  "service_start",
  "running_state_verification",
  "deployment_receipt_commit",
]);
const POSTCOMMIT_RECONCILIATION_MUTATIONS = new Set([
  "target_state_verification",
  "service_start",
  "running_state_verification",
  "deployment_receipt_commit",
  "terminal_receipt_commit",
]);
const POST_SOURCE_RUNTIME_COMMIT_MUTATIONS = new Set([
  "deployment_receipt_restore",
  "runtime_activation",
  "running_state_verification",
  "terminal_receipt_commit",
]);
const SOURCE_RUNTIME_COMMIT_PREREQUISITES = [
  "service_stop_for_recovery",
  "source_state_verification",
  "service_start",
] as const;

export const FUNCTIONAL_RELEASE_TRANSACTION_SCHEMA =
  "ti-scale.functional-release-transaction.v2" as const;

export type FunctionalReleaseTransactionOperation = "deploy" | "rollback";
export type FunctionalReleaseTransactionDirection = "forward" | "recovery";
export type FunctionalReleaseTransactionEvent =
  | "opened"
  | "evidence"
  | "mutation_prepared"
  | "mutation_completed"
  | "target_committed"
  | "recovery_started"
  | "terminal";

export type FunctionalReleaseTerminalOutcome =
  | "deployed"
  | "rolled_back"
  | "predeploy_restored"
  | "preserved_current_restored";

export interface FunctionalReleaseTransactionBinding {
  readonly schemaVersion: "ti-scale.functional-release-transaction-binding.v2";
  readonly transactionId: string;
  readonly operation: FunctionalReleaseTransactionOperation;
  readonly releaseId: string;
  readonly receiptPath: string;
  readonly recoveryIntent: "restore_predeploy" | "restore_preserved_current";
  readonly identity: Readonly<Record<string, unknown>>;
}

export interface FunctionalReleaseTransactionRecord {
  readonly schemaVersion: typeof FUNCTIONAL_RELEASE_TRANSACTION_SCHEMA;
  readonly transactionId: string;
  readonly operation: FunctionalReleaseTransactionOperation;
  readonly releaseId: string;
  readonly sequence: number;
  readonly previousRecordSha256: string | null;
  readonly bindingSha256: string;
  readonly recordedAt: string;
  readonly event: FunctionalReleaseTransactionEvent;
  readonly direction?: FunctionalReleaseTransactionDirection;
  readonly mutation?: string;
  readonly detail?: Readonly<Record<string, unknown>>;
  readonly recordSha256: string;
}

export interface FunctionalReleaseTransactionJournal {
  readonly directory: string;
  readonly binding: FunctionalReleaseTransactionBinding;
  readonly bindingSha256: string;
  readonly records: readonly FunctionalReleaseTransactionRecord[];
  readonly latest: FunctionalReleaseTransactionRecord;
  readonly terminal: FunctionalReleaseTransactionRecord | undefined;
}

export interface IncompleteFunctionalReleaseTransaction {
  readonly directory: string;
  readonly transactionId: string;
  readonly operation: FunctionalReleaseTransactionOperation;
  readonly releaseId: string;
  readonly latestSequence: number;
  readonly latestEvent: FunctionalReleaseTransactionEvent;
  readonly latestMutation: string | null;
}

export interface AppendFunctionalReleaseTransactionRecord {
  readonly event: Exclude<FunctionalReleaseTransactionEvent, "opened">;
  readonly direction?: FunctionalReleaseTransactionDirection;
  readonly mutation?: string;
  readonly detail?: Readonly<Record<string, unknown>>;
  readonly recordedAt?: string;
}

export type FunctionalReleaseJournalPublicationPhase =
  | "staging_directory_created"
  | "opening_record_committed"
  | "staging_directory_synced"
  | "final_name_renamed"
  | "final_parent_synced";

export interface DurableRecoveryStep {
  readonly mutation: string;
  /** Immutable intent/state bound before the step is allowed to execute. */
  readonly prepareDetail?: Readonly<Record<string, unknown>>;
  /**
   * Must be observed-state idempotent: return `already_exact` without issuing
   * the mutation when a previous process completed it before being killed.
   */
  readonly apply: () => "mutated" | "already_exact" | Promise<"mutated" | "already_exact">;
}

export interface DurableRecoveryOperations {
  readonly reconciliationIntent?: "restore_source" | "complete_target";
  readonly assertBindingAndObservedState: (
    journal: FunctionalReleaseTransactionJournal,
  ) => void | Promise<void>;
  readonly steps: readonly DurableRecoveryStep[];
  readonly terminalReceipt: () => {
    readonly path: string;
    readonly value: Readonly<Record<string, unknown>>;
    readonly outcome: FunctionalReleaseTerminalOutcome;
  } | Promise<{
    readonly path: string;
    readonly value: Readonly<Record<string, unknown>>;
    readonly outcome: FunctionalReleaseTerminalOutcome;
  }>;
  readonly verifyTerminal: (
    terminal: FunctionalReleaseTransactionRecord,
  ) => void | Promise<void>;
  /** Subprocess fault-injection/audit hook; never changes journal ordering. */
  readonly onPhase?: (
    phase: "after_step_apply" | "after_terminal_receipt_commit" | "after_terminal_record",
    mutation?: string,
  ) => void | Promise<void>;
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!child.startsWith(`..${sep}`) && child !== "..");
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object).sort((left, right) => left.localeCompare(right, "en"))
        .map((key) => [key, canonicalValue(object[key])]),
    );
  }
  if (
    value === null || typeof value === "string" || typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) return value;
  throw new Error("Release transaction journal contains a non-JSON value");
}

export function canonicalReleaseTransactionJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function releaseTransactionSha256(value: unknown): string {
  return createHash("sha256").update(
    typeof value === "string" || value instanceof Uint8Array
      ? value
      : canonicalReleaseTransactionJson(value),
  ).digest("hex");
}

function safeIdentity(value: string, label: string): string {
  if (!SAFE_ID.test(value) || value === "." || value === "..") {
    throw new Error(`${label} is not a safe release transaction identifier`);
  }
  return value;
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function recordWithoutHash(
  record: Omit<FunctionalReleaseTransactionRecord, "recordSha256">,
): Omit<FunctionalReleaseTransactionRecord, "recordSha256"> {
  return record;
}

function recordFilename(sequence: number, sha256: string): string {
  return `${String(sequence).padStart(8, "0")}-${sha256}.json`;
}

function assertJournalDirectory(directoryValue: string): string {
  const directory = resolve(directoryValue);
  const metadata = lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Release transaction journal path must be a real directory");
  }
  const canonical = realpathSync(directory);
  if (canonical !== directory) {
    throw new Error("Release transaction journal must not traverse symbolic-link ancestry");
  }
  if (!containedBy(dirname(canonical), canonical)) {
    throw new Error("Release transaction journal directory is invalid");
  }
  return directory;
}

function parseRecord(
  path: string,
  filenameSequence: number,
  filenameSha256: string,
): FunctionalReleaseTransactionRecord {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Release transaction journal contains a non-regular record");
  }
  const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<FunctionalReleaseTransactionRecord>;
  if (
    raw.schemaVersion !== FUNCTIONAL_RELEASE_TRANSACTION_SCHEMA ||
    typeof raw.transactionId !== "string" || typeof raw.releaseId !== "string" ||
    (raw.operation !== "deploy" && raw.operation !== "rollback") ||
    !Number.isSafeInteger(raw.sequence) || raw.sequence !== filenameSequence ||
    (raw.previousRecordSha256 !== null &&
      (typeof raw.previousRecordSha256 !== "string" || !SHA256.test(raw.previousRecordSha256))) ||
    typeof raw.bindingSha256 !== "string" || !SHA256.test(raw.bindingSha256) ||
    !validTimestamp(raw.recordedAt) ||
    ![
      "opened",
      "evidence",
      "mutation_prepared",
      "mutation_completed",
      "target_committed",
      "recovery_started",
      "terminal",
    ].includes(
      String(raw.event),
    ) ||
    typeof raw.recordSha256 !== "string" || !SHA256.test(raw.recordSha256)
  ) throw new Error("Release transaction journal record metadata is invalid");
  safeIdentity(raw.transactionId, "Transaction ID");
  safeIdentity(raw.releaseId, "Release ID");
  if (raw.direction !== undefined && raw.direction !== "forward" && raw.direction !== "recovery") {
    throw new Error("Release transaction journal direction is invalid");
  }
  if (raw.mutation !== undefined) safeIdentity(raw.mutation, "Mutation name");
  if (raw.detail !== undefined && (!raw.detail || typeof raw.detail !== "object" || Array.isArray(raw.detail))) {
    throw new Error("Release transaction journal detail must be an object");
  }
  const { recordSha256, ...unsigned } = raw as FunctionalReleaseTransactionRecord;
  const actual = releaseTransactionSha256(unsigned);
  if (recordSha256 !== filenameSha256 || actual !== recordSha256) {
    throw new Error("Release transaction journal record checksum is invalid (tampered journal refused)");
  }
  return raw as FunctionalReleaseTransactionRecord;
}

function validateRecordSemantics(
  binding: FunctionalReleaseTransactionBinding,
  records: readonly FunctionalReleaseTransactionRecord[],
): void {
  const bindingSha256 = releaseTransactionSha256(binding);
  const sourceRuntimeProtocolEnabled =
    (binding.identity as Record<string, unknown>).releaseStartupProtocol === "source_runtime_commit_v1";
  const noBackupPreviewEnabled =
    (binding.identity as Record<string, unknown>).deploymentKind ===
      "no_backup_preview_v1";
  const prepared = new Set<string>();
  const completed = new Set<string>();
  const preparedRecords = new Map<string, FunctionalReleaseTransactionRecord>();
  const completedRecords = new Map<string, FunctionalReleaseTransactionRecord>();
  let recoveryStarted = false;
  let targetCommitted = false;
  let sourceRuntimeCommitted = false;
  let terminal = false;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index]!;
    if (
      record.sequence !== index ||
      record.transactionId !== binding.transactionId ||
      record.operation !== binding.operation || record.releaseId !== binding.releaseId ||
      record.bindingSha256 !== bindingSha256 ||
      record.previousRecordSha256 !== (index === 0 ? null : records[index - 1]!.recordSha256)
    ) throw new Error("Release transaction journal is stale, spliced, or identity-ambiguous");
    if (terminal) throw new Error("Release transaction journal contains records after its terminal record");
    if (index === 0) {
      if (record.event !== "opened" || record.detail?.binding === undefined) {
        throw new Error("Release transaction journal does not begin with its immutable binding");
      }
      continue;
    }
    if (record.event === "opened") throw new Error("Release transaction journal contains a duplicate opening record");
    if (record.event === "target_committed") {
      if (targetCommitted || recoveryStarted) {
        throw new Error("Release transaction target commitment is duplicated or occurs after recovery began");
      }
      const incomplete = [...prepared].filter((key) => !completed.has(key));
      if (incomplete.length) {
        throw new Error("Release transaction target commitment has incomplete forward mutations");
      }
      const requiredTargetMutations = [
        "forward:service_stop",
        "forward:application_activation",
        "forward:static_activation",
        "forward:target_data_verification",
      ];
      if (requiredTargetMutations.some((key) => !completed.has(key))) {
        throw new Error("Release transaction target commitment is missing required target activation mutations");
      }
      const targetState = record.detail?.targetState;
      const targetStateSha256 = record.detail?.targetStateSha256;
      if (
        !targetState || typeof targetState !== "object" || Array.isArray(targetState) ||
        typeof targetStateSha256 !== "string" || !SHA256.test(targetStateSha256) ||
        releaseTransactionSha256(targetState) !== targetStateSha256
      ) throw new Error("Release transaction target commitment is invalid");
      targetCommitted = true;
      continue;
    }
    if (record.event === "recovery_started") {
      if (recoveryStarted) throw new Error("Release transaction journal contains duplicate recovery starts");
      const expectedIntent = targetCommitted ? "complete_target" : binding.recoveryIntent;
      if (record.detail?.recoveryIntent !== expectedIntent) {
        throw new Error("Release transaction recovery intent conflicts with its durable commitment boundary");
      }
      recoveryStarted = true;
      continue;
    }
    if (record.event === "mutation_prepared" || record.event === "mutation_completed") {
      if (!record.direction || !record.mutation) {
        throw new Error("Release transaction mutation record is incomplete");
      }
      if (recoveryStarted && record.direction === "forward") {
        throw new Error("Release transaction attempted a forward mutation after recovery began");
      }
      if (!recoveryStarted && record.direction === "recovery") {
        throw new Error("Release transaction attempted recovery mutation before recovery began");
      }
      if (
        sourceRuntimeCommitted &&
        !POST_SOURCE_RUNTIME_COMMIT_MUTATIONS.has(record.mutation)
      ) {
        throw new Error(
          `Release transaction mutation is not allowed after source-runtime commitment: ${record.mutation}`,
        );
      }
      if (targetCommitted) {
        const allowed = record.direction === "forward"
          ? POSTCOMMIT_FORWARD_MUTATIONS
          : POSTCOMMIT_RECONCILIATION_MUTATIONS;
        if (!allowed.has(record.mutation)) {
          throw new Error(
            `Release transaction mutation is not allowed after target commitment: ${record.direction}:${record.mutation}`,
          );
        }
      }
      const key = `${record.direction}:${record.mutation}`;
      if (record.event === "mutation_prepared") {
        if (prepared.has(key) || completed.has(key)) {
          throw new Error(`Release transaction mutation is duplicated: ${key}`);
        }
        if (record.mutation === "source_runtime_commit") {
          if (
            !sourceRuntimeProtocolEnabled || record.direction !== "recovery" ||
            targetCommitted || !recoveryStarted
          ) {
            throw new Error("Source-runtime commitment is outside source-recovery authority");
          }
          if (SOURCE_RUNTIME_COMMIT_PREREQUISITES.some((mutation) =>
            !completed.has(`recovery:${mutation}`)
          )) {
            throw new Error("Source-runtime commitment is missing a completed recovery prerequisite");
          }
          const identity = binding.identity as Record<string, unknown>;
          const expectedSource = binding.operation === "deploy"
            ? identity.predeploy
            : identity.preservedCurrent;
          const sourceState = record.detail?.sourceState;
          const sourceStateSha256 = record.detail?.sourceStateSha256;
          if (
            !expectedSource || typeof expectedSource !== "object" || Array.isArray(expectedSource) ||
            !sourceState || typeof sourceState !== "object" || Array.isArray(sourceState) ||
            typeof sourceStateSha256 !== "string" || !SHA256.test(sourceStateSha256) ||
            releaseTransactionSha256(sourceState) !== sourceStateSha256 ||
            releaseTransactionSha256(sourceState) !== releaseTransactionSha256(expectedSource)
          ) throw new Error("Source-runtime commitment does not match the immutable source identity");
        }
        if (
          noBackupPreviewEnabled &&
          (
            record.mutation === "deployment_receipt_commit" ||
            record.mutation === "terminal_receipt_commit" ||
            record.mutation === "deployment_receipt_restore"
          )
        ) {
          const receiptPath = record.detail?.receiptPath;
          const receiptSha256 = record.detail?.receiptSha256;
          const legacyIdentitySha256 =
            record.detail?.legacyIdentitySha256;
          const receipt = record.detail?.receipt;
          const embeddedLegacy = (
            receipt && typeof receipt === "object" &&
              !Array.isArray(receipt)
              ? (
                (receipt as Record<string, unknown>).chillspwnAfter ??
                (receipt as Record<string, unknown>).legacyAfter
              )
              : undefined
          );
          const canonicalReceiptSha256 =
            receipt && typeof receipt === "object" &&
              !Array.isArray(receipt)
              ? createHash("sha256").update(
                `${JSON.stringify(canonicalValue(receipt), null, 2)}\n`,
              ).digest("hex")
              : undefined;
          if (
            receiptPath !== binding.receiptPath ||
            typeof receiptSha256 !== "string" ||
            !SHA256.test(receiptSha256) ||
            typeof legacyIdentitySha256 !== "string" ||
            !SHA256.test(legacyIdentitySha256) ||
            (
              record.mutation !== "deployment_receipt_restore" &&
              (
                !receipt ||
                typeof receipt !== "object" ||
                Array.isArray(receipt) ||
                canonicalReceiptSha256 !== receiptSha256 ||
                !embeddedLegacy ||
                typeof embeddedLegacy !== "object" ||
                Array.isArray(embeddedLegacy) ||
                releaseTransactionSha256(embeddedLegacy) !==
                  legacyIdentitySha256
              )
            )
          ) {
            throw new Error(
              `No-backup receipt mutation lacks an immutable prepared intent: ${key}`,
            );
          }
        }
        prepared.add(key);
        preparedRecords.set(key, record);
      } else {
        if (!prepared.has(key) || completed.has(key)) {
          throw new Error(`Release transaction mutation completion is ambiguous: ${key}`);
        }
        if (
          noBackupPreviewEnabled &&
          (
            record.mutation === "deployment_receipt_commit" ||
            record.mutation === "terminal_receipt_commit" ||
            record.mutation === "deployment_receipt_restore"
          )
        ) {
          const preparation = preparedRecords.get(key);
          if (
            !preparation ||
            record.detail?.receiptPath !== binding.receiptPath ||
            record.detail?.receiptSha256 !==
              preparation.detail?.receiptSha256 ||
            record.detail?.legacyIdentitySha256 !==
              preparation.detail?.legacyIdentitySha256
          ) {
            throw new Error(
              `No-backup receipt completion differs from its prepared intent: ${key}`,
            );
          }
        }
        completed.add(key);
        completedRecords.set(key, record);
        if (record.mutation === "source_runtime_commit") {
          if (record.direction !== "recovery" || record.detail?.outcome !== "already_exact") {
            throw new Error("Source-runtime commitment lacks an exact verification outcome");
          }
          sourceRuntimeCommitted = true;
        }
      }
    }
    if (record.event === "terminal") {
      const outcome = record.detail?.outcome;
      const expectedOutcome = binding.operation === "deploy"
        ? targetCommitted ? "deployed" : "predeploy_restored"
        : targetCommitted ? "rolled_back" : "preserved_current_restored";
      if (outcome !== expectedOutcome) {
        throw new Error(
          `Release transaction terminal outcome conflicts with its operation/commitment boundary; expected ${expectedOutcome}`,
        );
      }
      if (!targetCommitted && !recoveryStarted) {
        throw new Error("Uncommitted release transaction cannot terminate before source recovery begins");
      }
      if (!targetCommitted && sourceRuntimeProtocolEnabled && !sourceRuntimeCommitted) {
        throw new Error("Source-runtime protocol cannot terminate without its durable source commitment");
      }
      if (sourceRuntimeCommitted) {
        if (
          !completed.has("recovery:deployment_receipt_restore") ||
          !completed.has("recovery:runtime_activation") ||
          !completed.has("recovery:running_state_verification")
        ) {
          throw new Error(
            "Source-runtime recovery cannot terminate before receipt restoration and real application verification",
          );
        }
      }
      if (noBackupPreviewEnabled) {
        const terminalDetail = record.detail;
        const assertTerminalReceiptBinding = (
          receiptCompletion: FunctionalReleaseTransactionRecord | undefined,
          label: string,
        ): void => {
          if (
            !receiptCompletion ||
            terminalDetail?.receiptPath !== binding.receiptPath ||
            terminalDetail?.receiptSha256 !==
              receiptCompletion.detail?.receiptSha256 ||
            terminalDetail?.legacyIdentitySha256 !==
              receiptCompletion.detail?.legacyIdentitySha256 ||
            terminalDetail?.receiptLegacyIdentitySha256 !==
              receiptCompletion.detail?.legacyIdentitySha256 ||
            typeof terminalDetail?.reconciliationLegacyIdentitySha256 !==
              "string" ||
            !SHA256.test(
              terminalDetail.reconciliationLegacyIdentitySha256,
            )
          ) {
            throw new Error(
              `No-backup ${label} terminal lacks its exact committed receipt and legacy proof`,
            );
          }
        };
        if (targetCommitted) {
          const forwardReceipt = completedRecords.get(
            "forward:deployment_receipt_commit",
          );
          const recoveryReceipt = completedRecords.get(
            "recovery:deployment_receipt_commit",
          );
          if (forwardReceipt && recoveryReceipt) {
            throw new Error(
              "No-backup target has conflicting receipt commitments",
            );
          }
          assertTerminalReceiptBinding(
            forwardReceipt ?? recoveryReceipt,
            "target",
          );
        } else {
          const terminalReceipt = completedRecords.get(
            "recovery:terminal_receipt_commit",
          );
          const restoredReceipt = completedRecords.get(
            "recovery:deployment_receipt_restore",
          );
          assertTerminalReceiptBinding(terminalReceipt, "source recovery");
          if (
            !restoredReceipt ||
            terminalDetail?.restoredReceiptSha256 !==
              restoredReceipt.detail?.receiptSha256 ||
            terminalDetail?.restoredLegacyIdentitySha256 !==
              restoredReceipt.detail?.legacyIdentitySha256
          ) {
            throw new Error(
              "No-backup source terminal lacks its restored receipt commitment",
            );
          }
        }
      }
      if (targetCommitted) {
        const completedInEitherDirection = (mutation: string): boolean =>
          completed.has(`forward:${mutation}`) || completed.has(`recovery:${mutation}`);
        if (
          !completedInEitherDirection("service_start") ||
          !completedInEitherDirection("deployment_receipt_commit")
        ) {
          throw new Error("Committed target cannot terminate before service and deployment receipt completion");
        }
        if (
          (binding.identity as Record<string, unknown>).requireRunningStateVerification === true &&
          !completedInEitherDirection("running_state_verification")
        ) {
          throw new Error(
            "Committed target cannot terminate before durable running-state verification",
          );
        }
      }
      terminal = true;
    }
  }
}

export function createFunctionalReleaseTransactionJournal(options: {
  readonly directory: string;
  readonly operation: FunctionalReleaseTransactionOperation;
  readonly releaseId: string;
  readonly receiptPath: string;
  readonly recoveryIntent: FunctionalReleaseTransactionBinding["recoveryIntent"];
  readonly identity: Readonly<Record<string, unknown>>;
  readonly transactionId?: string;
  readonly recordedAt?: string;
  readonly onPublicationPhase?: (phase: FunctionalReleaseJournalPublicationPhase) => void;
}): FunctionalReleaseTransactionJournal {
  const directory = resolve(options.directory);
  if (existsSync(directory)) throw new Error(`Release transaction journal already exists: ${directory}`);
  const recordedAt = options.recordedAt ?? new Date().toISOString();
  if (!validTimestamp(recordedAt)) throw new Error("Release transaction opening timestamp is invalid");
  const binding: FunctionalReleaseTransactionBinding = Object.freeze({
    schemaVersion: "ti-scale.functional-release-transaction-binding.v2",
    transactionId: safeIdentity(options.transactionId ?? randomUUID(), "Transaction ID"),
    operation: options.operation,
    releaseId: safeIdentity(options.releaseId, "Release ID"),
    receiptPath: resolve(options.receiptPath),
    recoveryIntent: options.recoveryIntent,
    identity: canonicalValue(options.identity) as Readonly<Record<string, unknown>>,
  });
  const stagingDirectory = resolve(
    dirname(directory),
    `.${basename(directory)}.${process.pid}.${randomUUID()}.opening`,
  );
  createDirectoryDurably(stagingDirectory, { mode: 0o700 });
  options.onPublicationPhase?.("staging_directory_created");
  const bindingSha256 = releaseTransactionSha256(binding);
  const unsigned = recordWithoutHash({
    schemaVersion: FUNCTIONAL_RELEASE_TRANSACTION_SCHEMA,
    transactionId: binding.transactionId,
    operation: binding.operation,
    releaseId: binding.releaseId,
    sequence: 0,
    previousRecordSha256: null,
    bindingSha256,
    recordedAt,
    event: "opened",
    detail: { binding },
  });
  const recordSha256 = releaseTransactionSha256(unsigned);
  const record: FunctionalReleaseTransactionRecord = { ...unsigned, recordSha256 };
  writeDurableFileAtomically(
    resolve(stagingDirectory, recordFilename(0, recordSha256)),
    `${canonicalReleaseTransactionJson(record)}\n`,
    { mode: 0o600 },
  );
  options.onPublicationPhase?.("opening_record_committed");
  // The discoverable final journal name is published only after its immutable
  // binding/opening record is durable. A crash before this rename leaves an
  // ignored staging directory; a crash after it leaves a readable journal.
  renameDirectoryDurably(stagingDirectory, directory, {
    onPhase: (phase) => {
      options.onPublicationPhase?.(phase === "source_synced"
        ? "staging_directory_synced"
        : phase === "renamed"
          ? "final_name_renamed"
          : "final_parent_synced");
    },
  });
  return readFunctionalReleaseTransactionJournal(directory);
}

export function readFunctionalReleaseTransactionJournal(
  directoryValue: string,
  options: { readonly allowedRoot?: string } = {},
): FunctionalReleaseTransactionJournal {
  const directory = assertJournalDirectory(directoryValue);
  if (options.allowedRoot) {
    const allowedRoot = realpathSync(resolve(options.allowedRoot));
    if (!containedBy(allowedRoot, directory) || directory === allowedRoot) {
      throw new Error("Release transaction journal is outside the managed transaction root");
    }
  }
  const candidates = readdirSync(directory).filter((name) => {
    if (RECORD_NAME.test(name)) return true;
    // A SIGKILL before atomic rename may leave a uniquely named temporary.
    // It was never a committed record and is therefore non-authoritative.
    if (INTERRUPTED_TEMPORARY_NAME.test(name) && lstatSync(resolve(directory, name)).isFile()) return false;
    throw new Error(`Release transaction journal contains an unexpected entry: ${name}`);
  });
  if (!candidates.length) throw new Error("Release transaction journal has no committed records");
  const parsed = candidates.map((name) => {
    const match = RECORD_NAME.exec(name)!;
    return parseRecord(resolve(directory, name), Number(match[1]), match[2]!);
  }).sort((left, right) => left.sequence - right.sequence);
  const sequences = new Set<number>();
  for (const record of parsed) {
    if (sequences.has(record.sequence)) throw new Error("Release transaction journal has an ambiguous sequence");
    sequences.add(record.sequence);
  }
  const rawBinding = parsed[0]?.detail?.binding;
  if (!rawBinding || typeof rawBinding !== "object" || Array.isArray(rawBinding)) {
    throw new Error("Release transaction journal binding is missing");
  }
  const binding = rawBinding as FunctionalReleaseTransactionBinding;
  if (
    binding.schemaVersion !== "ti-scale.functional-release-transaction-binding.v2" ||
    (binding.operation !== "deploy" && binding.operation !== "rollback") ||
    typeof binding.transactionId !== "string" || typeof binding.releaseId !== "string" ||
    typeof binding.receiptPath !== "string" ||
    (binding.recoveryIntent !== "restore_predeploy" && binding.recoveryIntent !== "restore_preserved_current") ||
    !binding.identity || typeof binding.identity !== "object" || Array.isArray(binding.identity)
  ) throw new Error("Release transaction journal binding is invalid");
  validateRecordSemantics(binding, parsed);
  const terminal = parsed.at(-1)?.event === "terminal" ? parsed.at(-1) : undefined;
  return Object.freeze({
    directory,
    binding: Object.freeze(binding),
    bindingSha256: releaseTransactionSha256(binding),
    records: Object.freeze(parsed),
    latest: parsed.at(-1)!,
    terminal,
  });
}

/**
 * Finds every nonterminal transaction below the root-owned release-control
 * tree without following links. A crashed owner releases flock, so a new
 * deploy/rollback must use this durable inventory rather than interpreting an
 * unlocked process boundary as proof that no older transaction owns recovery.
 */
export function discoverIncompleteFunctionalReleaseTransactions(
  rootValue: string,
): readonly IncompleteFunctionalReleaseTransaction[] {
  const root = resolve(rootValue);
  if (!existsSync(root)) return Object.freeze([]);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error("Release transaction discovery root must be a real canonical directory");
  }

  let visitedEntries = 0;
  const incomplete: IncompleteFunctionalReleaseTransaction[] = [];
  const visit = (directory: string, depth: number): void => {
    if (depth > MAX_TRANSACTION_DISCOVERY_DEPTH) {
      throw new Error("Release transaction discovery exceeded its bounded directory depth");
    }
    const entries = readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      visitedEntries += 1;
      if (visitedEntries > MAX_TRANSACTION_DISCOVERY_ENTRIES) {
        throw new Error("Release transaction discovery exceeded its bounded entry count");
      }
      const path = resolve(directory, entry.name);
      if (!containedBy(root, path)) throw new Error("Release transaction discovery escaped its managed root");
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) {
        throw new Error(`Release transaction discovery refuses symbolic links: ${path}`);
      }
      if (entry.name === "transaction-journal") {
        if (!metadata.isDirectory()) {
          throw new Error(`Release transaction journal candidate is not a directory: ${path}`);
        }
        const journal = readFunctionalReleaseTransactionJournal(path, { allowedRoot: root });
        if (!journal.terminal) {
          incomplete.push(Object.freeze({
            directory: journal.directory,
            transactionId: journal.binding.transactionId,
            operation: journal.binding.operation,
            releaseId: journal.binding.releaseId,
            latestSequence: journal.latest.sequence,
            latestEvent: journal.latest.event,
            latestMutation: journal.latest.mutation ?? null,
          }));
        }
        continue;
      }
      if (
        depth === 0 &&
        metadata.isDirectory() &&
        INTERRUPTED_TRANSACTION_OPENING_DIRECTORY.test(entry.name)
      ) {
        continue;
      }
      if (metadata.isDirectory()) visit(path, depth + 1);
    }
  };
  visit(root, 0);
  return Object.freeze(incomplete.sort((left, right) =>
    left.directory.localeCompare(right.directory, "en")));
}

export function appendFunctionalReleaseTransactionRecord(
  directoryValue: string,
  input: AppendFunctionalReleaseTransactionRecord,
): FunctionalReleaseTransactionJournal {
  const journal = readFunctionalReleaseTransactionJournal(directoryValue);
  const record = nextFunctionalReleaseTransactionRecord(journal, input);
  // Validate the complete semantic chain before publishing the next durable
  // record. Invalid API use must not poison an otherwise recoverable journal.
  validateRecordSemantics(journal.binding, [...journal.records, record]);
  const path = resolve(journal.directory, recordFilename(record.sequence, record.recordSha256));
  if (existsSync(path)) throw new Error("Release transaction journal sequence already exists");
  writeDurableFileAtomically(path, `${canonicalReleaseTransactionJson(record)}\n`, { mode: 0o600 });
  return readFunctionalReleaseTransactionJournal(journal.directory);
}

function nextFunctionalReleaseTransactionRecord(
  journal: FunctionalReleaseTransactionJournal,
  input: AppendFunctionalReleaseTransactionRecord,
): FunctionalReleaseTransactionRecord {
  const recordedAt = input.recordedAt ?? new Date().toISOString();
  if (!validTimestamp(recordedAt)) throw new Error("Release transaction record timestamp is invalid");
  if (journal.terminal) throw new Error("Release transaction journal is already terminal");
  if (input.event === "mutation_prepared" || input.event === "mutation_completed") {
    if (!input.direction || !input.mutation) throw new Error("Mutation journal records require direction and mutation");
    safeIdentity(input.mutation, "Mutation name");
  } else if (input.direction !== undefined || input.mutation !== undefined) {
    throw new Error("Only mutation records may declare a direction or mutation");
  }
  const sequence = journal.records.length;
  const unsigned = recordWithoutHash({
    schemaVersion: FUNCTIONAL_RELEASE_TRANSACTION_SCHEMA,
    transactionId: journal.binding.transactionId,
    operation: journal.binding.operation,
    releaseId: journal.binding.releaseId,
    sequence,
    previousRecordSha256: journal.latest.recordSha256,
    bindingSha256: journal.bindingSha256,
    recordedAt,
    event: input.event,
    ...(input.direction ? { direction: input.direction } : {}),
    ...(input.mutation ? { mutation: input.mutation } : {}),
    ...(input.detail ? { detail: canonicalValue(input.detail) as Readonly<Record<string, unknown>> } : {}),
  });
  const recordSha256 = releaseTransactionSha256(unsigned);
  const record: FunctionalReleaseTransactionRecord = { ...unsigned, recordSha256 };
  return record;
}

export function prepareFunctionalReleaseMutation(
  directory: string,
  direction: FunctionalReleaseTransactionDirection,
  mutation: string,
  detail?: Readonly<Record<string, unknown>>,
): FunctionalReleaseTransactionJournal {
  return appendFunctionalReleaseTransactionRecord(directory, {
    event: "mutation_prepared",
    direction,
    mutation,
    ...(detail ? { detail } : {}),
  });
}

export function completeFunctionalReleaseMutation(
  directory: string,
  direction: FunctionalReleaseTransactionDirection,
  mutation: string,
  detail?: Readonly<Record<string, unknown>>,
): FunctionalReleaseTransactionJournal {
  return appendFunctionalReleaseTransactionRecord(directory, {
    event: "mutation_completed",
    direction,
    mutation,
    ...(detail ? { detail } : {}),
  });
}

export function commitFunctionalReleaseTransactionTarget(
  directory: string,
  targetState: Readonly<Record<string, unknown>>,
  recordedAt?: string,
): FunctionalReleaseTransactionJournal {
  const canonicalTargetState = canonicalValue(targetState) as Readonly<Record<string, unknown>>;
  if (!Object.keys(canonicalTargetState).length) {
    throw new Error("Release transaction target commitment requires a non-empty target state");
  }
  return appendFunctionalReleaseTransactionRecord(directory, {
    event: "target_committed",
    ...(recordedAt ? { recordedAt } : {}),
    detail: {
      targetState: canonicalTargetState,
      targetStateSha256: releaseTransactionSha256(canonicalTargetState),
    },
  });
}

export function functionalReleaseTargetCommitRecord(
  journal: FunctionalReleaseTransactionJournal,
): FunctionalReleaseTransactionRecord | undefined {
  const commitments = journal.records.filter((record) => record.event === "target_committed");
  if (commitments.length > 1) throw new Error("Release transaction has ambiguous target commitments");
  return commitments[0];
}

function recoveryMutationState(
  journal: FunctionalReleaseTransactionJournal,
  mutation: string,
): "unseen" | "prepared" | "completed" {
  const records = journal.records.filter((record) =>
    record.direction === "recovery" && record.mutation === mutation
  );
  if (records.some((record) => record.event === "mutation_completed")) return "completed";
  if (records.some((record) => record.event === "mutation_prepared")) return "prepared";
  return "unseen";
}

/**
 * Reconciles toward the caller-selected durable identity. Before a target
 * commitment this is the source identity; after commitment it is the target
 * identity and must preserve candidate writes. Each reconciliation step is
 * journaled once before execution and is safe to re-enter after an
 * uncatchable process/host crash.
 */
export async function reconcileFunctionalReleaseTransaction(
  directoryValue: string,
  operations: DurableRecoveryOperations,
): Promise<"already_terminal" | "recovered"> {
  let journal = readFunctionalReleaseTransactionJournal(directoryValue);
  const targetCommitted = functionalReleaseTargetCommitRecord(journal) !== undefined;
  const requestedIntent = operations.reconciliationIntent ?? "restore_source";
  if (targetCommitted && requestedIntent !== "complete_target") {
    throw new Error("Committed release target may not enter source-restoration recovery");
  }
  if (!targetCommitted && requestedIntent === "complete_target") {
    throw new Error("Release target may not reconcile forward before durable commitment");
  }
  await operations.assertBindingAndObservedState(journal);
  if (journal.terminal) {
    await operations.verifyTerminal(journal.terminal);
    return "already_terminal";
  }
  if (!journal.records.some((record) => record.event === "recovery_started")) {
    journal = appendFunctionalReleaseTransactionRecord(journal.directory, {
      event: "recovery_started",
      detail: {
        recoveryIntent: operations.reconciliationIntent === "complete_target"
          ? "complete_target"
          : journal.binding.recoveryIntent,
      },
    });
  } else {
    const recordedIntent = journal.records.find((record) => record.event === "recovery_started")
      ?.detail?.recoveryIntent;
    const expectedIntent = requestedIntent === "complete_target"
      ? "complete_target"
      : journal.binding.recoveryIntent;
    if (recordedIntent !== expectedIntent) {
      throw new Error("Release reconciliation intent conflicts with its durable journal");
    }
  }
  // Once the immutable source identity has been durably committed, recovery
  // must never replay an unseen pointer/data/start mutation. Those mutations
  // either completed earlier or were proven unnecessary by the exact source
  // verification bound into source_runtime_commit. Resume only the narrow
  // post-commit set (receipt truth, runtime activation, running verification,
  // and the terminal receipt handled below).
  const sourceRuntimeCommitStateAtEntry =
    recoveryMutationState(journal, "source_runtime_commit");
  const sourceRuntimeBoundaryAtEntry = sourceRuntimeCommitStateAtEntry !== "unseen";
  const sourceRuntimeCommitStep = operations.steps.find((step) =>
    step.mutation === "source_runtime_commit"
  );
  if (sourceRuntimeCommitStateAtEntry === "prepared" && !sourceRuntimeCommitStep) {
    throw new Error("Prepared source-runtime commitment has no reconciliation operation");
  }
  const orderedSteps = sourceRuntimeCommitStateAtEntry === "prepared"
    ? [
        sourceRuntimeCommitStep!,
        ...operations.steps.filter((step) => step.mutation !== "source_runtime_commit"),
      ]
    : operations.steps;
  for (const step of orderedSteps) {
    if (
      sourceRuntimeBoundaryAtEntry &&
      step.mutation !== "source_runtime_commit" &&
      !POST_SOURCE_RUNTIME_COMMIT_MUTATIONS.has(step.mutation)
    ) continue;
    let state = recoveryMutationState(journal, step.mutation);
    if (state === "completed") continue;
    if (state === "unseen") {
      journal = prepareFunctionalReleaseMutation(
        journal.directory,
        "recovery",
        step.mutation,
        step.prepareDetail,
      );
      state = "prepared";
    }
    if (state !== "prepared") throw new Error("Release recovery mutation journal state is ambiguous");
    const outcome = await step.apply();
    await operations.onPhase?.("after_step_apply", step.mutation);
    journal = completeFunctionalReleaseMutation(journal.directory, "recovery", step.mutation, { outcome });
  }
  const terminalReceipt = await operations.terminalReceipt();
  const terminalReceiptPath = resolve(terminalReceipt.path);
  if (dirname(terminalReceiptPath) !== dirname(journal.directory)) {
    throw new Error("Recovery terminal receipt must be adjacent to its transaction journal");
  }
  const terminalReceiptBytes = `${canonicalReleaseTransactionJson(terminalReceipt.value)}\n`;
  let terminalReceiptSha256: string;
  let receiptState = recoveryMutationState(journal, "terminal_receipt_commit");
  if (receiptState === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      journal.directory,
      "recovery",
      "terminal_receipt_commit",
      { receiptPath: terminalReceiptPath },
    );
    receiptState = "prepared";
  }
  if (receiptState === "prepared") {
    if (existsSync(terminalReceiptPath)) {
      const metadata = lstatSync(terminalReceiptPath);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error("Recovery terminal receipt path is not a regular file");
      }
      if (readFileSync(terminalReceiptPath, "utf8") !== terminalReceiptBytes) {
        throw new Error("Existing recovery terminal receipt is ambiguous or tampered");
      }
    } else {
      writeDurableFileAtomically(terminalReceiptPath, terminalReceiptBytes, { mode: 0o600 });
    }
    terminalReceiptSha256 = releaseTransactionSha256(terminalReceiptBytes);
    await operations.onPhase?.("after_terminal_receipt_commit", "terminal_receipt_commit");
    journal = completeFunctionalReleaseMutation(
      journal.directory,
      "recovery",
      "terminal_receipt_commit",
      { receiptPath: terminalReceiptPath, receiptSha256: terminalReceiptSha256 },
    );
  } else {
    if (!existsSync(terminalReceiptPath) || readFileSync(terminalReceiptPath, "utf8") !== terminalReceiptBytes) {
      throw new Error("Committed recovery terminal receipt is missing or changed");
    }
    terminalReceiptSha256 = releaseTransactionSha256(terminalReceiptBytes);
  }
  const terminalRecordInput = {
    event: "terminal",
    recordedAt: new Date().toISOString(),
    detail: {
      outcome: terminalReceipt.outcome,
      receiptPath: terminalReceiptPath,
      receiptSha256: terminalReceiptSha256,
    },
  } as const satisfies AppendFunctionalReleaseTransactionRecord;
  const proposedTerminal = nextFunctionalReleaseTransactionRecord(journal, terminalRecordInput);
  // A terminal record is the success commit, not a promise that verification
  // will happen later. If target/receipt verification fails, leave the journal
  // nonterminal so admission retains ownership and reconciliation can retry.
  validateRecordSemantics(journal.binding, [...journal.records, proposedTerminal]);
  await operations.verifyTerminal(proposedTerminal);
  journal = appendFunctionalReleaseTransactionRecord(journal.directory, terminalRecordInput);
  await operations.onPhase?.("after_terminal_record");
  return "recovered";
}

export function functionalReleaseJournalBasename(directory: string): string {
  return basename(resolve(directory));
}
