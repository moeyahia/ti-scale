import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readlinkSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { createDatabaseConnection } from "../../server/db/connection";
import { inImmediateTransaction } from "../../server/db";
import {
  canonicalJson,
  sha256,
} from "../../server/intelligence-v24/validation";
import {
  appendFunctionalReleaseTransactionRecord,
  isSupportedNoBackupDeploymentIdentity,
  readFunctionalReleaseTransactionJournal,
} from "./DurableReleaseTransaction";
import { currentActiveReleaseLockDescriptor } from "./ReleaseLockContext";

const RESOURCE_ID = "canonical_database";
const RELEASE_REASON = "orphaned_no_backup_release_controller_absent";
const AUDIT_ACTION =
  "canonical_database_lease.orphaned_no_backup_maintenance_reconciled";
const EVIDENCE_KIND = "no_backup_maintenance_lease_reconciled.v1";

interface MaintenanceLeaseRow {
  readonly id: string;
  readonly mode: string;
  readonly owner_id: string;
  readonly operation: string;
  readonly fencing_token: number;
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly expires_at: string;
  readonly released_at: string | null;
  readonly release_reason: string | null;
}

interface MaintenanceMarker {
  readonly schemaVersion: "ti-scale.canonical-maintenance-marker.v1";
  readonly id: string;
  readonly ownerId: string;
  readonly operation: string;
  readonly fencingToken: number;
  readonly acquiredAt: string;
  readonly expiresAt: string;
}

interface ExistingAudit {
  readonly id: string;
  readonly record_hash: string;
}

type PartialLeaseState =
  | "marker_and_row"
  | "marker_and_row_renewal_skew"
  | "marker_only"
  | "row_only"
  | "released_row_and_marker"
  | "released_row_only";

export interface OrphanedNoBackupServiceBoundary {
  readonly activeState: string;
  readonly mainPid: number;
  readonly controlGroup: string;
  readonly controlGroupProcessIds: readonly number[];
  readonly portListening: boolean;
}

export interface ReconcileOrphanedNoBackupMaintenanceLeaseInput {
  readonly transactionRoot: string;
  readonly journalDirectory: string;
  readonly releaseId: string;
  readonly databasePath: string;
  readonly releaseLockPath: string;
  readonly stopped: OrphanedNoBackupServiceBoundary;
  /**
   * Must inspect the canonical database and both SQLite sidecars before this
   * reconciler opens its own bounded connection.
   */
  readonly assertNoDatabaseHandles: () => void;
  readonly maintenanceMarkerPath?: string;
  readonly actorId?: string;
}

export interface OrphanedNoBackupMaintenanceLeaseNotRequired {
  readonly status: "not_required";
  readonly inspectedAt: string;
}

export interface OrphanedNoBackupMaintenanceLeaseReleased {
  readonly status: "released" | "already_reconciled";
  readonly leaseId: string;
  readonly ownerId: string;
  readonly ownerPid: number;
  readonly fencingToken: number;
  readonly releaseReason: typeof RELEASE_REASON;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
  readonly inspectedAt: string;
}

export type OrphanedNoBackupMaintenanceLeaseReconciliationResult =
  | OrphanedNoBackupMaintenanceLeaseNotRequired
  | OrphanedNoBackupMaintenanceLeaseReleased;

export interface OrphanedNoBackupMaintenanceLeaseReconcilerOptions {
  readonly clock?: () => Date;
  readonly processExists?: (pid: number) => boolean;
  readonly createAuditId?: () => string;
  readonly onPhase?: (
    phase:
      | "after_database_commit"
      | "after_marker_cleanup"
      | "after_journal_evidence",
  ) => void;
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" ||
    (!child.startsWith(`..${sep}`) && child !== ".." &&
      !child.startsWith("/"));
}

function identifier(value: string, label: string, maximum = 256): string {
  const normalized = value.trim();
  if (
    !normalized ||
    normalized.length > maximum ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(normalized)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function operatingSystemProcessExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error &&
      error.code === "ESRCH");
  }
}

function assertStoppedBoundary(boundary: OrphanedNoBackupServiceBoundary): void {
  const processIds = [...new Set(boundary.controlGroupProcessIds)];
  if (
    processIds.some((pid) => !Number.isSafeInteger(pid) || pid <= 0) ||
    boundary.activeState !== "inactive" ||
    boundary.mainPid !== 0 ||
    processIds.length !== 0 ||
    boundary.portListening ||
    !boundary.controlGroup.startsWith("/") ||
    basename(boundary.controlGroup) !== "ti-scale.service"
  ) {
    throw new Error(
      "Orphaned no-backup maintenance reconciliation requires an inactive, " +
        "empty, non-listening Ti-Scale service boundary",
    );
  }
}

function assertCurrentReleaseLock(path: string): void {
  const descriptor = currentActiveReleaseLockDescriptor();
  if (descriptor === undefined) {
    throw new Error(
      "Orphaned no-backup maintenance reconciliation requires current release-flock ownership",
    );
  }
  let descriptorPath: string;
  try {
    descriptorPath = resolve(readlinkSync(`/proc/self/fd/${descriptor}`));
  } catch {
    throw new Error(
      "Orphaned no-backup maintenance reconciliation cannot prove its release-flock descriptor",
    );
  }
  if (descriptorPath !== resolve(path)) {
    throw new Error(
      "Orphaned no-backup maintenance reconciliation owns a different release flock",
    );
  }
}

function readOptionalMarker(path: string): MaintenanceMarker | undefined {
  if (!existsSync(path)) return undefined;
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== 0 ||
    metadata.gid !== 0 ||
    (metadata.mode & 0o777) !== 0o600
  ) {
    throw new Error(
      "The canonical maintenance marker is not a safe root-owned file",
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("The canonical maintenance marker is malformed");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The canonical maintenance marker is malformed");
  }
  const marker = value as Partial<MaintenanceMarker>;
  if (
    marker.schemaVersion !== "ti-scale.canonical-maintenance-marker.v1" ||
    typeof marker.id !== "string" ||
    typeof marker.ownerId !== "string" ||
    typeof marker.operation !== "string" ||
    !Number.isSafeInteger(marker.fencingToken) ||
    typeof marker.acquiredAt !== "string" ||
    !Number.isFinite(Date.parse(marker.acquiredAt)) ||
    typeof marker.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(marker.expiresAt))
  ) {
    throw new Error("The canonical maintenance marker is malformed");
  }
  return marker as MaintenanceMarker;
}

function assertMarkerMatchesRow(
  marker: MaintenanceMarker,
  row: MaintenanceLeaseRow,
  options: { readonly allowRenewalSkew?: boolean } = {},
): "exact" | "renewal_skew" {
  const immutableIdentityMatches =
    marker.id === row.id &&
    marker.ownerId === row.owner_id &&
    marker.operation === row.operation &&
    marker.fencingToken === Number(row.fencing_token) &&
    marker.acquiredAt === row.acquired_at;
  const expiryMatches = marker.expiresAt === row.expires_at;
  const boundedRenewalSkew = options.allowRenewalSkew === true &&
    Date.parse(marker.expiresAt) >= Date.parse(row.expires_at);
  if (
    !immutableIdentityMatches ||
    (!expiryMatches && !boundedRenewalSkew)
  ) {
    throw new Error(
      "Canonical maintenance marker does not exactly match its SQLite lease row",
    );
  }
  return expiryMatches ? "exact" : "renewal_skew";
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function removeExactMarker(
  path: string,
  expected: MaintenanceMarker,
): void {
  const current = readOptionalMarker(path);
  if (!current) return;
  if (
    current.schemaVersion !== expected.schemaVersion ||
    current.id !== expected.id ||
    current.ownerId !== expected.ownerId ||
    current.operation !== expected.operation ||
    current.fencingToken !== expected.fencingToken ||
    current.acquiredAt !== expected.acquiredAt ||
    current.expiresAt !== expected.expiresAt
  ) {
    throw new Error(
      "Canonical maintenance marker changed before durable reconciliation cleanup",
    );
  }
  unlinkSync(path);
  syncDirectory(dirname(path));
}

function ownerPid(
  ownerId: string,
  expectedOwnerPrefix: string,
): number {
  const ownerPidText = ownerId.slice(expectedOwnerPrefix.length);
  const parsed = Number(ownerPidText);
  if (
    ownerId !== `${expectedOwnerPrefix}${ownerPidText}` ||
    !Number.isSafeInteger(parsed) ||
    parsed <= 0 ||
    parsed === process.pid
  ) {
    throw new Error(
      "No-backup maintenance owner ID does not contain one original PID",
    );
  }
  return parsed;
}

function appendReconciliationEvidence(
  journalDirectory: string,
  result: OrphanedNoBackupMaintenanceLeaseReleased,
): void {
  const journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  if (
    journal.records.some((record) =>
      record.event === "evidence" &&
      record.detail?.kind === EVIDENCE_KIND &&
      record.detail?.leaseId === result.leaseId &&
      record.detail?.auditRecordHash === result.auditRecordHash
    )
  ) return;
  appendFunctionalReleaseTransactionRecord(journalDirectory, {
    event: "evidence",
    detail: {
      kind: EVIDENCE_KIND,
      leaseId: result.leaseId,
      ownerId: result.ownerId,
      ownerPid: result.ownerPid,
      fencingToken: result.fencingToken,
      releaseReason: result.releaseReason,
      auditRecordId: result.auditRecordId,
      auditRecordHash: result.auditRecordHash,
      inspectedAt: result.inspectedAt,
      backupPolicy: "none",
    },
  });
}

export class OrphanedNoBackupMaintenanceLeaseReconciler {
  readonly #clock: () => Date;
  readonly #processExists: (pid: number) => boolean;
  readonly #createAuditId: () => string;
  readonly #onPhase:
    | OrphanedNoBackupMaintenanceLeaseReconcilerOptions["onPhase"]
    | undefined;

  constructor(
    options: OrphanedNoBackupMaintenanceLeaseReconcilerOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#processExists = options.processExists ?? operatingSystemProcessExists;
    this.#createAuditId = options.createAuditId ??
      (() => `audit_no_backup_maintenance_${randomUUID()}`);
    this.#onPhase = options.onPhase;
  }

  reconcile(
    input: ReconcileOrphanedNoBackupMaintenanceLeaseInput,
  ): OrphanedNoBackupMaintenanceLeaseReconciliationResult {
    const releaseId = identifier(input.releaseId, "Release ID", 128);
    const actorId = identifier(
      input.actorId ?? `no-backup-recovery:${process.pid}`,
      "Reconciliation actor ID",
    );
    const transactionRoot = resolve(input.transactionRoot);
    const journalDirectory = resolve(input.journalDirectory);
    if (!containedBy(transactionRoot, journalDirectory)) {
      throw new Error(
        "No-backup maintenance journal escapes its transaction root",
      );
    }
    const journal = readFunctionalReleaseTransactionJournal(journalDirectory, {
      allowedRoot: transactionRoot,
    });
    const identity = journal.binding.identity as Record<string, unknown>;
    if (
      journal.terminal ||
      journal.binding.operation !== "deploy" ||
      journal.binding.releaseId !== releaseId ||
      !isSupportedNoBackupDeploymentIdentity(identity) ||
      identity.backupPolicy !== "none"
    ) {
      throw new Error(
        "Orphaned no-backup maintenance reconciliation lacks one exact nonterminal journal",
      );
    }
    assertCurrentReleaseLock(input.releaseLockPath);
    assertStoppedBoundary(input.stopped);
    input.assertNoDatabaseHandles();

    const databasePath = resolve(input.databasePath);
    const markerPath = resolve(
      input.maintenanceMarkerPath ??
        `${databasePath}.maintenance-lock.json`,
    );
    const marker = readOptionalMarker(markerPath);
    const expectedOperation = `no-backup-preview:${releaseId}`;
    const expectedOwnerPrefix = `${expectedOperation}:`;
    const inspectedAt = this.#clock().toISOString();
    const database = createDatabaseConnection({
      filename: databasePath,
      fileMustExist: true,
      verifyIntegrity: false,
    });

    let result:
      | OrphanedNoBackupMaintenanceLeaseReleased
      | OrphanedNoBackupMaintenanceLeaseNotRequired;
    let markerToRemove: MaintenanceMarker | undefined;
    let databaseCommitCreated = false;
    try {
      const allActive = database.prepare(`
        SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
          heartbeat_at, expires_at, released_at, release_reason
        FROM canonical_database_leases
        WHERE resource_id = ? AND released_at IS NULL
        ORDER BY fencing_token DESC, id DESC
      `).all(RESOURCE_ID) as MaintenanceLeaseRow[];
      const rows = database.prepare(`
        SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
          heartbeat_at, expires_at, released_at, release_reason
        FROM canonical_database_leases
        WHERE resource_id = ?
          AND owner_id LIKE ?
          AND operation = ?
        ORDER BY fencing_token DESC, id DESC
      `).all(
        RESOURCE_ID,
        `${expectedOwnerPrefix}%`,
        expectedOperation,
      ) as MaintenanceLeaseRow[];
      const unreleased = rows.filter((row) => row.released_at === null);
      if (unreleased.length > 1) {
        throw new Error(
          "Multiple orphaned no-backup maintenance leases make recovery ambiguous",
        );
      }

      let markerRowMatch: "exact" | "renewal_skew" | undefined;
      let markerRow: MaintenanceLeaseRow | undefined;
      if (marker) {
        if (
          marker.operation !== expectedOperation ||
          !marker.ownerId.startsWith(expectedOwnerPrefix)
        ) {
          throw new Error(
            "Canonical maintenance marker belongs to a different operation",
          );
        }
        markerRow = database.prepare(`
          SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
            heartbeat_at, expires_at, released_at, release_reason
          FROM canonical_database_leases
          WHERE id = ?
        `).get(marker.id) as MaintenanceLeaseRow | undefined;
        if (markerRow) {
          const markerRowId = markerRow.id;
          markerRowMatch = assertMarkerMatchesRow(marker, markerRow, {
            allowRenewalSkew:
              markerRow.released_at === null ||
              markerRow.release_reason === RELEASE_REASON,
          });
          if (!rows.some((row) => row.id === markerRowId)) {
            throw new Error(
              "Canonical maintenance marker row is outside the exact journal-bound operation",
            );
          }
        }
      }

      const activeRow = unreleased[0];
      if (
        allActive.some((row) =>
          !activeRow || row.id !== activeRow.id
        )
      ) {
        throw new Error(
          "Unrelated active canonical database leases make orphan recovery ambiguous",
        );
      }
      if (
        marker && activeRow && marker.id !== activeRow.id
      ) {
        throw new Error(
          "Canonical maintenance marker and active lease identify different owners",
        );
      }

      const previouslyReconciled = rows.find((row) =>
        row.released_at !== null && row.release_reason === RELEASE_REASON &&
        (!marker || row.id === marker.id)
      );
      if (
        markerRow &&
        markerRow.released_at !== null &&
        markerRow.release_reason !== RELEASE_REASON
      ) {
        throw new Error(
          "Canonical maintenance marker refers to a lease released by another path",
        );
      }
      const candidate = activeRow ?? previouslyReconciled;
      if (!candidate && !marker) {
        return Object.freeze({ status: "not_required", inspectedAt });
      }

      const candidateId = candidate?.id ?? marker!.id;
      const candidateOwnerId = candidate?.owner_id ?? marker!.ownerId;
      const candidateOperation = candidate?.operation ?? marker!.operation;
      const candidateFencingToken = Number(
        candidate?.fencing_token ?? marker!.fencingToken,
      );
      if (
        candidateOperation !== expectedOperation ||
        !candidateOwnerId.startsWith(expectedOwnerPrefix) ||
        candidate?.mode === "writer"
      ) {
        throw new Error(
          "Journal-bound no-backup lease is not the expected maintenance operation",
        );
      }
      const originalOwnerPid = ownerPid(
        candidateOwnerId,
        expectedOwnerPrefix,
      );
      if (this.#processExists(originalOwnerPid)) {
        throw new Error(
          "The original no-backup maintenance owner process still exists",
        );
      }

      const partialState: PartialLeaseState =
        candidate !== undefined && candidate.released_at !== null
        ? marker
          ? "released_row_and_marker"
          : "released_row_only"
        : candidate
          ? marker
            ? markerRowMatch === "renewal_skew"
              ? "marker_and_row_renewal_skew"
              : "marker_and_row"
            : "row_only"
          : "marker_only";
      const existingAudit = database.prepare(`
        SELECT id, record_hash
        FROM audit_records
        WHERE action = ? AND resource_type = 'canonical_database_lease'
          AND resource_id = ?
        ORDER BY rowid DESC
        LIMIT 1
      `).get(AUDIT_ACTION, candidateId) as ExistingAudit | undefined;

      if (candidate !== undefined && candidate.released_at !== null) {
        if (
          candidate.release_reason !== RELEASE_REASON ||
          !existingAudit
        ) {
          throw new Error(
            "Previously released maintenance lease lacks its exact reconciliation audit",
          );
        }
        markerToRemove = marker;
        result = Object.freeze({
          status: "already_reconciled" as const,
          leaseId: candidateId,
          ownerId: candidateOwnerId,
          ownerPid: originalOwnerPid,
          fencingToken: candidateFencingToken,
          releaseReason: RELEASE_REASON,
          auditRecordId: existingAudit.id,
          auditRecordHash: existingAudit.record_hash,
          inspectedAt,
        });
      } else if (!candidate && existingAudit) {
        markerToRemove = marker;
        result = Object.freeze({
          status: "already_reconciled" as const,
          leaseId: candidateId,
          ownerId: candidateOwnerId,
          ownerPid: originalOwnerPid,
          fencingToken: candidateFencingToken,
          releaseReason: RELEASE_REASON,
          auditRecordId: existingAudit.id,
          auditRecordHash: existingAudit.record_hash,
          inspectedAt,
        });
      } else {
        result = inImmediateTransaction(database, () => {
          if (candidate) {
            const exact = database.prepare(`
              SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
                heartbeat_at, expires_at, released_at, release_reason
              FROM canonical_database_leases
              WHERE id = ?
            `).get(candidate.id) as MaintenanceLeaseRow | undefined;
            if (
              !exact ||
              exact.released_at !== null ||
              exact.mode !== "maintenance" ||
              exact.owner_id !== candidateOwnerId ||
              exact.operation !== expectedOperation ||
              Number(exact.fencing_token) !== candidateFencingToken ||
              exact.acquired_at !== candidate.acquired_at ||
              exact.expires_at !== candidate.expires_at
            ) {
              throw new Error(
                "No-backup maintenance lease identity changed before reconciliation",
              );
            }
            if (marker) {
              assertMarkerMatchesRow(marker, exact, {
                allowRenewalSkew: true,
              });
            }
          } else if (!marker) {
            throw new Error(
              "No-backup marker-only state disappeared before reconciliation",
            );
          }

          const previous = database.prepare(
            "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
          ).get() as { readonly record_hash: string } | undefined;
          const auditRecordId = identifier(
            this.#createAuditId(),
            "Reconciliation audit record ID",
          );
          const details = {
            schemaVersion:
              "ti-scale.orphaned-no-backup-maintenance-reconciliation.v1",
            releaseId,
            transactionId: journal.binding.transactionId,
            journalBindingSha256: journal.bindingSha256,
            partialState,
            lease: {
              id: candidateId,
              mode: "maintenance",
              ownerId: candidateOwnerId,
              ownerPid: originalOwnerPid,
              operation: candidateOperation,
              fencingToken: candidateFencingToken,
              acquiredAt: candidate?.acquired_at ?? marker!.acquiredAt,
              heartbeatAt: candidate?.heartbeat_at ?? marker!.acquiredAt,
              expiresAt: candidate?.expires_at ?? marker!.expiresAt,
              sqliteRowPresent: candidate !== undefined,
            },
            marker: {
              path: markerPath,
              present: marker !== undefined,
              identityMatchesLease: candidate && marker
                ? true
                : candidate
                  ? null
                  : true,
            },
            stopped: {
              activeState: input.stopped.activeState,
              mainPid: input.stopped.mainPid,
              controlGroup: input.stopped.controlGroup,
              controlGroupProcessIds: [] as readonly number[],
              portListening: input.stopped.portListening,
            },
            originalOwnerProcessProvenAbsent: true,
            currentReleaseFlockProvenOwned: true,
            canonicalDatabaseHandlesProvenAbsentBeforeInspection: true,
            backupPolicy: "none",
            releaseReason: RELEASE_REASON,
          } as const;
          const reason =
            "The exact no-backup release controller died while holding canonical maintenance";
          const hashBody = {
            id: auditRecordId,
            actorType: "system",
            actorId,
            action: AUDIT_ACTION,
            resourceType: "canonical_database_lease",
            resourceId: candidateId,
            reason,
            details,
            missionId: null,
            runId: null,
            journey: null,
            previousHash: previous?.record_hash ?? null,
            occurredAt: inspectedAt,
          } as const;
          const auditRecordHash = sha256(
            `${previous?.record_hash ?? ""}\n${canonicalJson(hashBody)}`,
          );
          if (candidate) {
            const update = database.prepare(`
              UPDATE canonical_database_leases
              SET released_at = ?, release_reason = ?
              WHERE id = ? AND resource_id = ? AND mode = 'maintenance'
                AND owner_id = ? AND operation = ? AND fencing_token = ?
                AND acquired_at = ? AND expires_at = ?
                AND released_at IS NULL
            `).run(
              inspectedAt,
              RELEASE_REASON,
              candidate.id,
              RESOURCE_ID,
              candidateOwnerId,
              expectedOperation,
              candidateFencingToken,
              candidate.acquired_at,
              candidate.expires_at,
            );
            if (update.changes !== 1) {
              throw new Error(
                "No-backup maintenance lease changed before durable release",
              );
            }
          }
          database.prepare(`
            INSERT INTO audit_records (
              id, mission_id, run_id, journey, actor_type, actor_id, action,
              resource_type, resource_id, reason, details_json, previous_hash,
              record_hash, occurred_at
            ) VALUES (?, NULL, NULL, NULL, 'system', ?, ?,
              'canonical_database_lease', ?, ?, ?, ?, ?, ?)
          `).run(
            auditRecordId,
            actorId,
            AUDIT_ACTION,
            candidateId,
            reason,
            canonicalJson(details),
            previous?.record_hash ?? null,
            auditRecordHash,
            inspectedAt,
          );
          markerToRemove = marker;
          return Object.freeze({
            status: "released" as const,
            leaseId: candidateId,
            ownerId: candidateOwnerId,
            ownerPid: originalOwnerPid,
            fencingToken: candidateFencingToken,
            releaseReason: RELEASE_REASON,
            auditRecordId,
            auditRecordHash,
            inspectedAt,
          });
        });
        databaseCommitCreated = true;
      }
    } finally {
      database.close();
    }

    if (databaseCommitCreated) {
      this.#onPhase?.("after_database_commit");
    }
    if (
      result.status === "released" ||
      result.status === "already_reconciled"
    ) {
      if (markerToRemove) removeExactMarker(markerPath, markerToRemove);
      this.#onPhase?.("after_marker_cleanup");
      appendReconciliationEvidence(journalDirectory, result);
      this.#onPhase?.("after_journal_evidence");
    }
    return result;
  }
}
