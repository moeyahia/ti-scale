import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import type { Dirent } from "node:fs";
import type { MemoryRepository } from "../memory/MemoryRepository";
import { OBSIDIAN_V2_4_VAULT_FOLDERS } from "./ObsidianMarkdown";
import {
  OPERATOR_PROFILE_VAULT_FOLDER,
  vaultScopeIncludesOperatorProfile,
} from "./OperatorProfileVaultProjection";
import {
  VaultManagedNoteInspectionError,
  type ObsidianVaultBridge,
} from "./ObsidianVaultBridge";
import { VaultDestinationChangedError } from "./VaultPathPolicy";
import type { VaultPathPolicy } from "./VaultPathPolicy";
import {
  VaultRecoveryRepository,
  type RecoveryProjectionStatus,
  type RecoveryProjectionUpdate,
  type RecoverySyncState,
} from "./VaultRecoveryRepository";
import type {
  VaultRecoveryCounts,
  VaultRecoveryIssue,
  VaultRecoveryOperation,
  VaultRecoveryResult,
} from "./types";

const MAX_MANAGED_NOTES = 5_000;
const MAX_ISSUES = 100;

interface RecoveryServiceOptions {
  readonly clock?: () => Date;
  readonly maximumManagedNotes?: number;
}

interface DiscoveredFiles {
  readonly files: readonly string[];
  readonly unsafePaths: ReadonlySet<string>;
  readonly truncated: boolean;
  readonly errorCount: number;
  readonly issues: readonly VaultRecoveryIssue[];
}

function hashText(value: string): string {
  return createHash("sha256").update(value.replaceAll("\r\n", "\n"), "utf8").digest("hex");
}

type MutableRecoveryCounts = { -readonly [Key in keyof VaultRecoveryCounts]: VaultRecoveryCounts[Key] };

function emptyCounts(): MutableRecoveryCounts {
  return {
    synced: 0,
    databaseAhead: 0,
    vaultAhead: 0,
    conflictsPreserved: 0,
    quarantined: 0,
    missing: 0,
    pending: 0,
    indexed: 0,
    skipped: 0,
    errors: 0,
  };
}

function classifyProjection(
  state: RecoverySyncState | undefined,
  databaseHash: string,
  vaultHash: string,
): RecoveryProjectionStatus {
  if (databaseHash === vaultHash) return "synced";
  if (!state) return "vault_ahead";
  const databaseChanged = state.databaseContentHash !== databaseHash;
  const vaultChanged = state.vaultContentHash !== vaultHash;
  if (databaseChanged && vaultChanged) return "conflict";
  return databaseChanged ? "database_ahead" : "vault_ahead";
}

function issueMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : "Managed note could not be processed";
  if (/symbolic link|symlink/iu.test(message)) return "Managed path is a symbolic link and was not followed or modified.";
  if (/reusable-memory|credential|secret|private key|token/iu.test(message)) {
    return "Managed note failed reusable-memory safety validation and was moved into private quarantine; no duplicate or restorable backup was created, and recovery metadata is content-free.";
  }
  if (error instanceof VaultDestinationChangedError) {
    return "Managed note changed during recovery. It was left untouched and must be inspected again before quarantine can be retried.";
  }
  return "Managed note was malformed or inconsistent and was moved into private quarantine; no duplicate or restorable backup was created, and recovery metadata is content-free.";
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function isPermissionError(error: unknown): boolean {
  return ["EACCES", "EPERM"].includes(errorCode(error) ?? "");
}

function discoverManagedMarkdown(
  policy: VaultPathPolicy,
  vaultRoot: string,
  maximum: number,
  managedFolders: readonly string[] = OBSIDIAN_V2_4_VAULT_FOLDERS,
): DiscoveredFiles {
  const files: string[] = [];
  const unsafePaths = new Set<string>();
  const issues: VaultRecoveryIssue[] = [];
  let truncated = false;
  let errorCount = 0;
  const visit = (relativeDirectory: string): void => {
    if (files.length >= maximum) { truncated = true; return; }
    let absolute: string;
    let entries: Dirent[];
    try {
      absolute = policy.resolveRelative(vaultRoot, relativeDirectory);
      if (!existsSync(absolute)) return;
      entries = readdirSync(absolute, { withFileTypes: true }) as Dirent[];
    } catch (error) {
      errorCount += 1;
      if (issues.length < MAX_ISSUES) issues.push({
        category: isPermissionError(error) ? "permission_denied" : "processing_error",
        relativePath: relativeDirectory,
        message: isPermissionError(error)
          ? "Ti-Scale cannot read this managed Vault directory. Restore read and traverse permission, then retry recovery."
          : "Managed Vault directory could not be enumerated safely; no contained path was modified.",
      });
      return;
    }
    for (const entry of entries) {
      if (files.length >= maximum) { truncated = true; return; }
      const relativePath = `${relativeDirectory}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        unsafePaths.add(relativePath);
        if (issues.length < MAX_ISSUES) issues.push({
          category: "unsafe_path",
          relativePath,
          message: "Managed path is a symbolic link and was not followed or modified.",
        });
        continue;
      }
      if (entry.isDirectory()) visit(relativePath);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) files.push(relativePath);
    }
  };
  for (const folder of managedFolders) {
    if (folder === "Attachments") continue;
    visit(folder);
    if (truncated) break;
  }
  if (truncated && issues.length < MAX_ISSUES) issues.push({
    category: "scan_limit",
    message: `Managed-note scan stopped at the bounded ${maximum}-note limit. Run recovery again after reducing or partitioning the vault.`,
  });
  return { files, unsafePaths, truncated, errorCount, issues };
}

/**
 * Bounded Vault recovery. Repair reconciles projection metadata and
 * quarantines malformed files. Reindex performs the same validation and
 * incrementally refreshes only canonical SQLite FTS rows represented by valid
 * managed notes. Neither operation imports Vault text into canonical memory.
 */
export class VaultRecoveryService {
  readonly #repository: VaultRecoveryRepository;
  readonly #memory: MemoryRepository;
  readonly #bridge: ObsidianVaultBridge;
  readonly #paths: VaultPathPolicy;
  readonly #clock: () => Date;
  readonly #maximumManagedNotes: number;

  constructor(
    repository: VaultRecoveryRepository,
    memory: MemoryRepository,
    bridge: ObsidianVaultBridge,
    pathPolicy: VaultPathPolicy,
    options: RecoveryServiceOptions = {},
  ) {
    this.#repository = repository;
    this.#memory = memory;
    this.#bridge = bridge;
    this.#paths = pathPolicy;
    this.#clock = options.clock ?? (() => new Date());
    this.#maximumManagedNotes = options.maximumManagedNotes ?? MAX_MANAGED_NOTES;
  }

  run(input: {
    readonly operation: VaultRecoveryOperation;
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly allowedNodeIds: ReadonlySet<string>;
  }): VaultRecoveryResult {
    const startedAt = this.#clock().toISOString();
    const startMs = Date.parse(startedAt);
    this.#bridge.assertVaultSyncAllowed();
    this.#repository.requireConnectionVersion(
      input.connectionId,
      input.expectedUpdatedAt,
    );
    // Enforce lifecycle state before the filesystem round trip below. That
    // round trip writes, reads, renames, and deletes one temporary health file,
    // so even that bounded proof is forbidden after metadata-only disconnect.
    const connection = this.#bridge.requireConnection(input.connectionId);
    // Fail closed when a configured Vault is offline. Recovery must never
    // recreate a disappeared path and report it as healthy.
    const vaultRoot = this.#paths.resolveExistingVault(connection.vaultPath);
    const health = this.#bridge.verifyExistingVaultPath(vaultRoot);
    const intentRecovery = this.#bridge.recoverQuarantineIntents(input.connectionId);
    const states = this.#repository.listSyncStates(input.connectionId, this.#maximumManagedNotes + 1);
    const boundedStates = states.slice(0, this.#maximumManagedNotes);
    const stateScanTruncated = states.length > this.#maximumManagedNotes;
    const stateByPath = new Map(boundedStates.map((state) => [state.relativePath, state]));
    const openConflictStateIds = this.#repository.openConflictStateIds(input.connectionId);
    const discovered = discoverManagedMarkdown(
      this.#paths,
      vaultRoot,
      this.#maximumManagedNotes,
      vaultScopeIncludesOperatorProfile(connection.syncScope)
        ? [...OBSIDIAN_V2_4_VAULT_FOLDERS, OPERATOR_PROFILE_VAULT_FOLDER]
        : OBSIDIAN_V2_4_VAULT_FOLDERS,
    );
    const issues: VaultRecoveryIssue[] = [...discovered.issues];
    const counts = emptyCounts();
    counts.quarantined += intentRecovery.recovered;
    counts.errors += discovered.unsafePaths.size + discovered.errorCount + intentRecovery.unresolved;
    if (intentRecovery.unresolved > 0) issues.push({
      category: "quarantine_recovery",
      message: `${intentRecovery.unresolved} durable quarantine move(s) could not be reconciled. Verify the quarantined note and retry.`,
    });
    for (const relativePath of discovered.unsafePaths) {
      this.#repository.recordPathError(
        input.connectionId,
        relativePath,
        "Managed path is a symbolic link and was not followed or modified.",
      );
    }
    const updates = new Map<string, RecoveryProjectionUpdate>();
    const indexed = new Set<string>();
    const foundPaths = new Set(discovered.files);
    const duplicatePaths = new Set<string>();

    const addIssue = (issue: VaultRecoveryIssue): void => {
      if (issues.length < MAX_ISSUES) issues.push(issue);
    };
    const setUpdate = (update: RecoveryProjectionUpdate): void => {
      updates.set(update.relativePath, update);
    };

    // Inspect before selecting any canonical association. This two-pass shape
    // detects duplicates across both pretracked rows and newly discovered
    // notes, so filesystem order can never pick an arbitrary winner.
    const inspectedByPath = new Map<
      string,
      ReturnType<ObsidianVaultBridge["inspectManagedNote"]>
    >();
    const inspectionErrorByPath = new Map<string, unknown>();
    for (const relativePath of discovered.files) {
      try {
        inspectedByPath.set(
          relativePath,
          this.#bridge.inspectManagedNote(input.connectionId, relativePath),
        );
      } catch (error) {
        inspectionErrorByPath.set(relativePath, error);
      }
    }

    const pathsByNode = new Map<string, Set<string>>();
    const registerNodePath = (nodeId: string, relativePath: string): void => {
      const paths = pathsByNode.get(nodeId) ?? new Set<string>();
      paths.add(relativePath);
      pathsByNode.set(nodeId, paths);
    };
    for (const state of boundedStates) {
      if (state.nodeId) registerNodePath(state.nodeId, state.relativePath);
    }
    for (const [relativePath, inspected] of inspectedByPath) {
      registerNodePath(inspected.note.id, relativePath);
    }
    for (const [nodeId, representedPaths] of [...pathsByNode].sort(([left], [right]) => left.localeCompare(right))) {
      const paths = [...representedPaths].sort();
      if (paths.length < 2) continue;
      for (const relativePath of paths) {
        duplicatePaths.add(relativePath);
        const inspected = inspectedByPath.get(relativePath);
        const state = stateByPath.get(relativePath);
        setUpdate({
          relativePath,
          vaultContentHash: inspected?.contentHash ?? state?.vaultContentHash,
          databaseContentHash: state?.databaseContentHash,
          status: "pending",
          errorMessage: "Duplicate stable memory ID detected. Every projection was detached; choose one path deliberately before synchronizing.",
        });
        counts.pending += 1;
        addIssue({
          category: "duplicate_projection",
          relativePath,
          nodeId,
          message: "Duplicate managed projections share one stable memory ID. No path was selected or overwritten; every represented projection is pending operator review.",
        });
        if (state && openConflictStateIds.has(state.id)) counts.conflictsPreserved += 1;
      }
    }

    const quarantineOrDiagnose = (
      relativePath: string,
      error: unknown,
      observedContentHash?: string,
    ): void => {
      if (isPermissionError(error)) {
        counts.errors += 1;
        const message = "Ti-Scale could not read this managed Vault note. Restore file read permission, confirm the path has not been replaced, and retry.";
        this.#repository.recordPathError(input.connectionId, relativePath, message);
        addIssue({ category: "permission_denied", relativePath, message });
        return;
      }
      if (!observedContentHash) {
        counts.errors += 1;
        const message = issueMessage(error);
        this.#repository.recordPathError(input.connectionId, relativePath, message);
        addIssue({
          category: error instanceof VaultDestinationChangedError
            ? "concurrent_change"
            : /symbolic link|symlink/iu.test(String(error)) ? "unsafe_path" : "processing_error",
          relativePath,
          message,
        });
        return;
      }
      try {
        this.#bridge.quarantineManagedNote(
          input.connectionId,
          relativePath,
          issueMessage(error),
          observedContentHash,
        );
        counts.quarantined += 1;
        addIssue({ category: "malformed_note", relativePath, message: issueMessage(error) });
      } catch (quarantineError) {
        counts.errors += 1;
        const message = issueMessage(quarantineError);
        this.#repository.recordPathError(input.connectionId, relativePath, message);
        addIssue({
          category: quarantineError instanceof VaultDestinationChangedError
            ? "concurrent_change"
            : isPermissionError(quarantineError)
              ? "permission_denied"
              : /symbolic link|symlink/iu.test(String(quarantineError)) ? "unsafe_path" : "quarantine_recovery",
          relativePath,
          message,
        });
      }
    };

    for (const relativePath of discovered.files) {
      const state = stateByPath.get(relativePath);
      if (duplicatePaths.has(relativePath)) continue;
      if (state && openConflictStateIds.has(state.id)) {
        counts.conflictsPreserved += 1;
        if (state.nodeId && input.allowedNodeIds.has(state.nodeId) && input.operation === "reindex") indexed.add(state.nodeId);
        addIssue({
          category: "conflict_preserved",
          relativePath,
          ...(state.nodeId ? { nodeId: state.nodeId } : {}),
          message: "Open operator/database conflict was preserved for deliberate resolution.",
        });
        continue;
      }
      const inspectionError = inspectionErrorByPath.get(relativePath);
      if (inspectionError) {
        quarantineOrDiagnose(
          relativePath,
          inspectionError,
          inspectionError instanceof VaultManagedNoteInspectionError
            ? inspectionError.contentHash
            : undefined,
        );
        continue;
      }
      const inspected = inspectedByPath.get(relativePath)!;
      if (state?.nodeId && state.nodeId !== inspected.note.id) {
        quarantineOrDiagnose(
          relativePath,
          new Error("Managed vault stable ID does not match its tracked canonical node"),
          inspected.sourceHash,
        );
        continue;
      }
      const canonical = this.#memory.getNode(inspected.note.id, true);
      if (!canonical || canonical.lifecycleStatus === "forgotten") {
        setUpdate({
          relativePath,
          vaultContentHash: inspected.contentHash,
          status: "pending",
          errorMessage: "No canonical memory node matches this stable ID; review through Memory Inbox before import.",
        });
        counts.pending += 1;
        addIssue({
          category: "pending_candidate",
          relativePath,
          message: "Valid Vault note has no canonical memory node and remains a reviewable pending projection.",
        });
        continue;
      }
      if (!input.allowedNodeIds.has(canonical.id)) {
        counts.skipped += 1;
        addIssue({
          category: "scope_denied",
          relativePath,
          message: "A managed note outside the operator's current disclosure scope was left unchanged.",
        });
        continue;
      }
      this.#bridge.assertConnectionNodeAllowed(input.connectionId, canonical.id);
      if (discovered.truncated && !state) {
        setUpdate({
          relativePath,
          vaultContentHash: inspected.contentHash,
          status: "pending",
          errorMessage: "The bounded scan was incomplete, so this new projection was not attached to a canonical node.",
        });
        counts.pending += 1;
        continue;
      }
      const rendered = this.#bridge.renderNode(canonical.id, connection, input.allowedNodeIds);
      const databaseHash = hashText(rendered.text);
      const status = classifyProjection(state, databaseHash, inspected.contentHash);
      setUpdate({
        relativePath,
        nodeId: canonical.id,
        databaseVersion: canonical.version,
        vaultContentHash: inspected.contentHash,
        databaseContentHash: databaseHash,
        status,
        ...(status === "conflict" ? { errorMessage: "Concurrent database and Vault edits require deliberate synchronization and conflict resolution." } : {}),
      });
      if (status === "synced") counts.synced += 1;
      else if (status === "database_ahead") counts.databaseAhead += 1;
      else if (status === "vault_ahead") counts.vaultAhead += 1;
      else if (status === "conflict") {
        counts.conflictsPreserved += 1;
        addIssue({
          category: "conflict_preserved",
          relativePath,
          nodeId: canonical.id,
          message: "Concurrent canonical and operator edits were detected; neither version was overwritten.",
        });
      }
      if (input.operation === "reindex") indexed.add(canonical.id);
    }

    for (const state of boundedStates) {
      if (foundPaths.has(state.relativePath) || discovered.unsafePaths.has(state.relativePath) || duplicatePaths.has(state.relativePath)) continue;
      if (state.status === "quarantined") continue;
      if (openConflictStateIds.has(state.id)) {
        counts.conflictsPreserved += 1;
        if (state.nodeId && input.operation === "reindex" && input.allowedNodeIds.has(state.nodeId)) indexed.add(state.nodeId);
        continue;
      }
      if (state.nodeId && input.allowedNodeIds.has(state.nodeId) && this.#memory.getNode(state.nodeId, true)) {
        setUpdate({
          relativePath: state.relativePath,
          nodeId: state.nodeId,
          databaseVersion: this.#memory.requireNode(state.nodeId).version,
          databaseContentHash: state.databaseContentHash,
          status: "database_ahead",
          errorMessage: "Managed projection is missing. Synchronize or export to restore it from canonical SQLite.",
        });
        counts.missing += 1;
        counts.databaseAhead += 1;
        addIssue({
          category: "missing_projection",
          relativePath: state.relativePath,
          nodeId: state.nodeId,
          message: "Managed projection is missing; canonical SQLite content was preserved and not recreated automatically.",
        });
        if (input.operation === "reindex") indexed.add(state.nodeId);
      } else if (!state.nodeId) {
        setUpdate({ relativePath: state.relativePath, status: "deleted", errorMessage: "Unlinked managed note is no longer present." });
        counts.missing += 1;
      } else {
        counts.skipped += 1;
      }
    }

    if (stateScanTruncated) {
      counts.errors += 1;
      addIssue({
        category: "scan_limit",
        message: `Tracked-state reconciliation stopped at the bounded ${this.#maximumManagedNotes}-record limit.`,
      });
    }
    counts.indexed = indexed.size;
    const processed = discovered.files.length + boundedStates.filter((state) => !foundPaths.has(state.relativePath)).length;
    const needsReview = counts.conflictsPreserved + counts.quarantined + counts.missing + counts.pending + counts.errors;
    const status = needsReview > 0 || discovered.truncated || stateScanTruncated ? "partial" : "completed";
    const connectionVersion = this.#repository.complete({
      connectionId: input.connectionId,
      expectedUpdatedAt: input.expectedUpdatedAt,
      connectionStatus: counts.errors > 0 || counts.quarantined > 0 || counts.missing > 0 ? "degraded" : "connected",
      updates: [...updates.values()],
      indexNodeIds: input.operation === "reindex" ? [...indexed] : [],
    });
    const completedAt = this.#clock().toISOString();
    const elapsedMs = Math.max(0, Date.parse(completedAt) - startMs);
    const message = input.operation === "repair"
      ? status === "completed"
        ? `Vault repair validated ${processed} managed records; no operator edits were overwritten.`
        : `Vault repair processed ${processed} managed records; ${needsReview} need review and no operator edits were overwritten.`
      : `Reindexed ${counts.indexed} canonical notes from ${discovered.files.length} managed projections; SQLite remained authoritative${needsReview > 0 ? ` and ${needsReview} records need review` : ""}.`;
    return {
      operation: input.operation,
      connectionId: input.connectionId,
      status,
      startedAt,
      completedAt,
      elapsedMs,
      expectedConnectionVersion: input.expectedUpdatedAt,
      connectionVersion,
      health: { checkedAt: health.checkedAt, checks: health.checks },
      progress: { discovered: discovered.files.length, processed, remaining: discovered.truncated || stateScanTruncated ? 1 : 0 },
      counts,
      issues,
      issueSampleTruncated: issues.length >= MAX_ISSUES || discovered.truncated || stateScanTruncated,
      message,
    };
  }
}
