import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";
import type { SqliteDatabase } from "../db";
import {
  assertReusableMemoryText,
  REUSABLE_MEMORY_LIMITS,
} from "../memory/ReusableMemorySafety";
import {
  normalizeObsidianWikilinkTarget,
  OBSIDIAN_V2_4_VAULT_FOLDERS,
  parseObsidianNote,
} from "./ObsidianMarkdown";
import type { ObsidianVaultBridge } from "./ObsidianVaultBridge";
import {
  OPERATOR_PROFILE_VAULT_FOLDER,
  vaultScopeIncludesOperatorProfile,
} from "./OperatorProfileVaultProjection";
import type {
  VaultBulkExportOptions,
  VaultBulkExportResult,
  VaultConnection,
} from "./types";
import type { VaultPathPolicy } from "./VaultPathPolicy";

const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,239}$/u;
const MAX_ISSUES = 100;
const MAX_MANAGED_NOTES = 100_000;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const CLOSE_ON_EXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function stableFileBytes(path: string): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | CLOSE_ON_EXEC | NO_FOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile()) throw new Error("Managed Vault projection is not a regular file");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      !after.isFile()
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || bytes.byteLength !== after.size
    ) throw new Error("Managed Vault projection changed while it was verified");
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

interface SyncStateRow {
  readonly node_id: string | null;
  readonly relative_path: string;
  readonly database_content_hash: string | null;
  readonly vault_content_hash: string | null;
  readonly status: string;
}

interface ProjectionPlanEntry {
  readonly nodeId: string;
  readonly version: number;
  readonly relativePath: string;
  readonly projectionHash: string;
}

export interface VaultProjectionIssue {
  readonly category:
    | "connection"
    | "duplicate_path"
    | "missing_state"
    | "unexpected_state"
    | "state_not_synced"
    | "missing_file"
    | "unsafe_file"
    | "content_mismatch"
    | "invalid_note"
    | "unsafe_content"
    | "identity_mismatch"
    | "untracked_note"
    | "unresolved_wikilink"
    | "out_of_scope_wikilink"
    | "open_conflict";
  readonly message: string;
  readonly nodeId?: string;
  readonly relativePath?: string;
}

export interface VaultProjectionPreview {
  readonly schemaVersion: "ti-scale.vault-projection-preview.v1";
  readonly connectionId: string;
  readonly connectionDisplayName: string;
  readonly connectionStatus: VaultConnection["status"];
  readonly generatedAt: string;
  readonly eligibleNodeCount: number;
  readonly trackedNodeCount: number;
  readonly currentNodeCount: number;
  readonly writeRequiredNodeCount: number;
  readonly attentionRequiredNodeCount: number;
  readonly connectionScopeHash: string;
  readonly selectionHash: string;
  readonly canonicalProjectionHash: string;
  readonly planHash: string;
  readonly readyForExecution: boolean;
  readonly issueCount: number;
  readonly issues: readonly VaultProjectionIssue[];
  readonly issueSampleTruncated: boolean;
}

export interface VaultProjectionReconciliation {
  readonly schemaVersion: "ti-scale.vault-projection-reconciliation.v1";
  readonly connectionId: string;
  readonly checkedAt: string;
  readonly status: "complete" | "attention_required";
  readonly planHash: string;
  readonly eligibleNodeCount: number;
  readonly syncedNodeCount: number;
  readonly missingStateCount: number;
  readonly unexpectedStateCount: number;
  readonly nonSyncedStateCount: number;
  readonly managedMarkdownCount: number;
  readonly untrackedManagedMarkdownCount: number;
  readonly openConflictCount: number;
  readonly verifiedFileCount: number;
  readonly parsedNoteCount: number;
  readonly wikilinkCount: number;
  readonly unresolvedWikilinkCount: number;
  readonly unsafeContentCount: number;
  readonly managedProjectionHash: string;
  readonly wikilinkGraphHash: string;
  readonly issueCount: number;
  readonly issues: readonly VaultProjectionIssue[];
  readonly issueSampleTruncated: boolean;
}

export interface VaultProjectionReceipt {
  readonly schemaVersion: "ti-scale.vault-projection-receipt.v1";
  readonly connectionId: string;
  readonly connectionDisplayName: string;
  readonly approvedBy: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly expectedPlanHash: string;
  readonly export: VaultBulkExportResult;
  readonly reconciliation: VaultProjectionReconciliation;
  readonly status: "completed" | "attention_required" | "failed";
  readonly receiptHash: string;
  readonly receiptRelativePath: string;
}

export interface ExecuteVaultProjectionInput {
  readonly connectionId: string;
  readonly expectedPlanHash: string;
  readonly approvedBy: string;
  readonly exportOptions?: VaultBulkExportOptions;
}

/**
 * Receipt-bound, full eligible-population projection for the active reusable
 * knowledge Vault. Preview and reconciliation are read-only. Execute retains
 * Obsidian's operator-edited conflict semantics and writes every note through
 * the bridge's fsync + guarded-rename path.
 */
export class VaultProjectionReconciliationService {
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    readonly bridge: ObsidianVaultBridge,
    readonly paths: VaultPathPolicy,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
  }

  preview(connectionId: string): VaultProjectionPreview {
    const connection = this.#connection(connectionId);
    const plan = this.#plan(connection);
    const states = this.#states(connection.id);
    const stateByNode = new Map(states.flatMap((state) => state.node_id ? [[state.node_id, state] as const] : []));
    const issues: VaultProjectionIssue[] = [...plan.issues];
    let issueCount = plan.issueCount;
    let currentNodeCount = 0;
    let writeRequiredNodeCount = 0;
    let attentionRequiredNodeCount = 0;
    const addIssue = (issue: VaultProjectionIssue): void => {
      issueCount += 1;
      if (issues.length < MAX_ISSUES) issues.push(issue);
    };
    const plannedNodeIds = new Set(plan.entries.map((entry) => entry.nodeId));
    const seenStateNodeIds = new Set<string>();
    for (const state of states) {
      if (
        !state.node_id
        || !plannedNodeIds.has(state.node_id)
        || seenStateNodeIds.has(state.node_id)
      ) {
        attentionRequiredNodeCount += 1;
        addIssue({
          category: "unexpected_state",
          ...(state.node_id ? { nodeId: state.node_id } : {}),
          relativePath: state.relative_path,
          message: !state.node_id
            ? "An unbound Vault synchronization row requires import or reconciliation."
            : "A tracked Vault projection is outside the reviewed eligible population or duplicated.",
        });
      }
      if (state.node_id) seenStateNodeIds.add(state.node_id);
    }
    const expectedPaths = new Set(plan.entries.map((entry) => entry.relativePath));
    const trackedPaths = new Set(states.map((state) => state.relative_path));
    for (const relativePath of this.#managedMarkdown(connection)) {
      if (trackedPaths.has(relativePath) || expectedPaths.has(relativePath)) continue;
      attentionRequiredNodeCount += 1;
      addIssue({
        category: "untracked_note",
        relativePath,
        message: "An untracked note exists inside a managed Vault folder.",
      });
    }
    const openConflictCount = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM vault_conflicts
      WHERE connection_id = ? AND status = 'open'
    `).get(connection.id) as { count: number }).count);
    if (openConflictCount > 0) {
      attentionRequiredNodeCount += openConflictCount;
      issueCount += openConflictCount;
      if (issues.length < MAX_ISSUES) issues.push({
        category: "open_conflict",
        message: `${openConflictCount} open Vault conflict(s) require operator resolution.`,
      });
    }

    for (const entry of plan.entries) {
      const state = stateByNode.get(entry.nodeId);
      const path = this.paths.resolveRelative(connection.vaultPath, state?.relative_path ?? entry.relativePath);
      if (!state) {
        if (!existsSync(path)) writeRequiredNodeCount += 1;
        else {
          try {
            if (sha256(stableFileBytes(path)) === entry.projectionHash) writeRequiredNodeCount += 1;
            else {
              attentionRequiredNodeCount += 1;
              addIssue({
                category: "content_mismatch",
                nodeId: entry.nodeId,
                relativePath: entry.relativePath,
                message: "An unmanaged note occupies the canonical projection path with different content.",
              });
            }
          } catch {
            attentionRequiredNodeCount += 1;
            addIssue({
              category: "unsafe_file",
              nodeId: entry.nodeId,
              relativePath: entry.relativePath,
              message: "The unmanaged projection path is not a stable regular file.",
            });
          }
        }
        continue;
      }
      if (["vault_ahead", "conflict", "quarantined", "deleted"].includes(state.status)) {
        attentionRequiredNodeCount += 1;
        addIssue({
          category: "state_not_synced",
          nodeId: entry.nodeId,
          relativePath: state.relative_path,
          message: `The tracked projection requires operator attention (${state.status}).`,
        });
        continue;
      }
      if (!existsSync(path)) {
        writeRequiredNodeCount += 1;
        continue;
      }
      try {
        const actualHash = sha256(stableFileBytes(path));
        const databaseChanged = state.database_content_hash !== entry.projectionHash;
        const vaultChanged = state.vault_content_hash !== actualHash;
        if (
          state.status === "synced"
          && !databaseChanged
          && !vaultChanged
          && actualHash === entry.projectionHash
        ) {
          currentNodeCount += 1;
        } else if (actualHash === entry.projectionHash || (databaseChanged && !vaultChanged)) {
          // The canonical database changed while the tracked Vault file stayed
          // at its last synchronized hash, or synchronization metadata needs a
          // safe repair. The bridge can project this without losing user edits.
          writeRequiredNodeCount += 1;
        } else {
          attentionRequiredNodeCount += 1;
          addIssue({
            category: "content_mismatch",
            nodeId: entry.nodeId,
            relativePath: state.relative_path,
            message: "The tracked Obsidian note changed outside the approved canonical projection.",
          });
        }
      } catch {
        attentionRequiredNodeCount += 1;
        addIssue({
          category: "unsafe_file",
          nodeId: entry.nodeId,
          relativePath: state.relative_path,
          message: "The tracked projection is not a stable regular file.",
        });
      }
    }

    return {
      schemaVersion: "ti-scale.vault-projection-preview.v1",
      connectionId: connection.id,
      connectionDisplayName: connection.displayName,
      connectionStatus: connection.status,
      generatedAt: this.#clock().toISOString(),
      eligibleNodeCount: plan.entries.length,
      trackedNodeCount: stateByNode.size,
      currentNodeCount,
      writeRequiredNodeCount,
      attentionRequiredNodeCount,
      connectionScopeHash: plan.connectionScopeHash,
      selectionHash: plan.selectionHash,
      canonicalProjectionHash: plan.canonicalProjectionHash,
      planHash: plan.planHash,
      readyForExecution: connection.status === "connected"
        && attentionRequiredNodeCount === 0
        && issueCount === 0,
      issueCount,
      issues,
      issueSampleTruncated: issueCount > issues.length,
    };
  }

  async execute(input: ExecuteVaultProjectionInput): Promise<VaultProjectionReceipt> {
    if (!SHA256.test(input.expectedPlanHash)) {
      throw new TypeError("Expected Vault projection plan hash must be a lowercase SHA-256 digest");
    }
    if (!ACTOR_ID.test(input.approvedBy)) {
      throw new TypeError("Vault projection approver must be a stable operator identifier");
    }
    const preview = this.preview(input.connectionId);
    if (preview.planHash !== input.expectedPlanHash) {
      throw new Error("Vault projection plan changed after review; run a new read-only preview");
    }
    if (!preview.readyForExecution) {
      throw new Error("Vault projection preview requires conflict or connection recovery before execution");
    }
    const connection = this.#connection(input.connectionId);
    this.bridge.verifyExistingVaultPath(connection.vaultPath);

    // Approved execution may remove previously projected notes that have since
    // become ineligible. Preview never calls this mutating cleanup path.
    const selected = this.bridge.exportableNodeIds(connection.id);
    const selectedHash = sha256(canonical([...selected].sort()));
    if (selectedHash !== preview.selectionHash) {
      throw new Error("Vault projection selection changed during execution admission");
    }
    const admitted = this.preview(connection.id);
    if (admitted.planHash !== input.expectedPlanHash || !admitted.readyForExecution) {
      throw new Error("Vault projection content changed during execution admission; run a new read-only preview");
    }
    const startedAt = this.#clock().toISOString();
    const exported = await this.bridge.exportNodes(connection.id, selected, input.exportOptions);
    const reconciliation = this.reconcile(connection.id, input.expectedPlanHash);
    const completedAt = this.#clock().toISOString();
    const status: VaultProjectionReceipt["status"] = exported.counts.failed > 0
      ? "failed"
      : reconciliation.status === "complete"
        ? "completed"
        : "attention_required";
    const receiptBody = {
      schemaVersion: "ti-scale.vault-projection-receipt.v1" as const,
      connectionId: connection.id,
      connectionDisplayName: connection.displayName,
      approvedBy: input.approvedBy,
      startedAt,
      completedAt,
      expectedPlanHash: input.expectedPlanHash,
      export: exported,
      reconciliation,
      status,
    };
    const receiptHash = sha256(canonical(receiptBody));
    const stamp = completedAt.replace(/[:.]/gu, "-");
    const receiptRelativePath = `.ti-scale/projection-receipts/${stamp}-${receiptHash.slice(0, 20)}-${randomUUID()}.json`;
    const receipt: VaultProjectionReceipt = {
      ...receiptBody,
      receiptHash,
      receiptRelativePath,
    };
    this.paths.atomicWrite(
      connection.vaultPath,
      receiptRelativePath,
      `${JSON.stringify(receipt, null, 2)}\n`,
      { exists: false },
    );
    const persisted = stableFileBytes(this.paths.resolveRelative(connection.vaultPath, receiptRelativePath));
    if (sha256(canonical(JSON.parse(persisted.toString("utf8")))) !== sha256(canonical(receipt))) {
      throw new Error("Vault projection reconciliation receipt failed its durable read-back check");
    }
    return receipt;
  }

  reconcile(connectionId: string, expectedPlanHash?: string): VaultProjectionReconciliation {
    if (expectedPlanHash !== undefined && !SHA256.test(expectedPlanHash)) {
      throw new TypeError("Expected Vault projection plan hash must be a lowercase SHA-256 digest");
    }
    const connection = this.#connection(connectionId, false);
    const plan = this.#plan(connection);
    const issues: VaultProjectionIssue[] = [...plan.issues];
    let issueCount = plan.issueCount;
    const addIssue = (issue: VaultProjectionIssue): void => {
      issueCount += 1;
      if (issues.length < MAX_ISSUES) issues.push(issue);
    };
    if (expectedPlanHash && expectedPlanHash !== plan.planHash) {
      addIssue({
        category: "connection",
        message: "Canonical projection content changed after the approved preview.",
      });
    }

    const states = this.#states(connection.id);
    const planByNode = new Map(plan.entries.map((entry) => [entry.nodeId, entry]));
    const eligiblePaths = new Map<string, string>();
    const actualProjectionRecords: string[] = [];
    const wikilinkRecords: string[] = [];
    let syncedNodeCount = 0;
    let missingStateCount = 0;
    let unexpectedStateCount = 0;
    let nonSyncedStateCount = 0;
    let verifiedFileCount = 0;
    let parsedNoteCount = 0;
    let wikilinkCount = 0;
    let unresolvedWikilinkCount = 0;
    let unsafeContentCount = 0;
    const stateByNode = new Map<string, SyncStateRow>();

    for (const state of states) {
      if (!state.node_id) {
        unexpectedStateCount += 1;
        addIssue({
          category: "unexpected_state",
          relativePath: state.relative_path,
          message: `An unbound Vault synchronization row remains ${state.status}.`,
        });
        continue;
      }
      stateByNode.set(state.node_id, state);
      if (!planByNode.has(state.node_id)) {
        unexpectedStateCount += 1;
        addIssue({
          category: "unexpected_state",
          nodeId: state.node_id,
          relativePath: state.relative_path,
          message: "A tracked projection is outside the current eligible connection policy.",
        });
      }
    }

    for (const entry of plan.entries) {
      const state = stateByNode.get(entry.nodeId);
      if (!state) {
        missingStateCount += 1;
        addIssue({
          category: "missing_state",
          nodeId: entry.nodeId,
          relativePath: entry.relativePath,
          message: "Eligible canonical knowledge has no Vault synchronization record.",
        });
        continue;
      }
      const effectivePath = state.relative_path;
      eligiblePaths.set(effectivePath.replace(/\.md$/iu, ""), entry.nodeId);
      if (state.status !== "synced") {
        nonSyncedStateCount += 1;
        addIssue({
          category: "state_not_synced",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: `Eligible canonical knowledge is tracked as ${state.status}.`,
        });
      } else syncedNodeCount += 1;
      const path = this.paths.resolveRelative(connection.vaultPath, effectivePath);
      if (!existsSync(path)) {
        addIssue({
          category: "missing_file",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: "The tracked Obsidian note is missing.",
        });
        continue;
      }
      let bytes: Buffer;
      try {
        const metadata = lstatSync(path);
        if (metadata.isSymbolicLink() || !metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
          throw new Error("Managed note must be a non-symbolic-link 0600 regular file");
        }
        bytes = stableFileBytes(path);
      } catch {
        addIssue({
          category: "unsafe_file",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: "The tracked Obsidian note failed regular-file, permission, or stable-read validation.",
        });
        continue;
      }
      const actualHash = sha256(bytes);
      actualProjectionRecords.push(`${entry.nodeId}\0${effectivePath}\0${actualHash}`);
      verifiedFileCount += 1;
      if (actualHash !== entry.projectionHash) {
        addIssue({
          category: "content_mismatch",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: "The Vault note does not match the current canonical projection.",
        });
      }
      const text = bytes.toString("utf8");
      try {
        assertReusableMemoryText([{
          field: "vaultProjection.note",
          value: text,
          maximumBytes: REUSABLE_MEMORY_LIMITS.vaultNote,
        }]);
      } catch {
        unsafeContentCount += 1;
        addIssue({
          category: "unsafe_content",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: "The managed note failed the reusable-memory secret or size boundary.",
        });
      }
      try {
        const parsed = parseObsidianNote(text);
        parsedNoteCount += 1;
        if (parsed.id !== entry.nodeId) {
          addIssue({
            category: "identity_mismatch",
            nodeId: entry.nodeId,
            relativePath: effectivePath,
            message: "The note frontmatter stable ID does not match its synchronization record.",
          });
        }
      } catch {
        addIssue({
          category: "invalid_note",
          nodeId: entry.nodeId,
          relativePath: effectivePath,
          message: "The managed note is not valid Ti-Scale Obsidian Markdown.",
        });
      }

    }

    // Validate native links only after the first pass has built the complete
    // eligible node-path map. Link counts therefore cannot depend on note order.
    for (const entry of plan.entries) {
      const state = stateByNode.get(entry.nodeId);
      if (!state) continue;
      const path = this.paths.resolveRelative(connection.vaultPath, state.relative_path);
      if (!existsSync(path)) continue;
      let text: string;
      try { text = stableFileBytes(path).toString("utf8"); }
      catch { continue; }
      const matcher = /!?\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]*)?\]\]/gu;
      for (const match of text.matchAll(matcher)) {
        const target = match[1]!.trim();
        wikilinkCount += 1;
        wikilinkRecords.push(`${state.relative_path}\0${target}`);
        if (target.startsWith("Attachments/")) {
          let resolves = false;
          try {
            const attachment = this.paths.resolveRelative(connection.vaultPath, target);
            const metadata = lstatSync(attachment);
            resolves = !metadata.isSymbolicLink() && metadata.isFile();
          } catch { resolves = false; }
          if (!resolves) {
            unresolvedWikilinkCount += 1;
            addIssue({
              category: "unresolved_wikilink",
              nodeId: entry.nodeId,
              relativePath: state.relative_path,
              message: "A projected attachment wikilink does not resolve to a regular file.",
            });
          }
          continue;
        }
        const normalized = normalizeObsidianWikilinkTarget(`${target}.md`);
        const targetPath = normalized ? `${normalized}.md` : undefined;
        let resolves = false;
        if (normalized && eligiblePaths.has(normalized) && targetPath) {
          try {
            const targetAbsolute = this.paths.resolveRelative(connection.vaultPath, targetPath);
            const metadata = lstatSync(targetAbsolute);
            resolves = !metadata.isSymbolicLink() && metadata.isFile();
          } catch { resolves = false; }
        }
        if (!resolves) {
          unresolvedWikilinkCount += 1;
          addIssue({
            category: normalized && targetPath && existsSync(this.paths.resolveRelative(connection.vaultPath, targetPath))
              ? "out_of_scope_wikilink"
              : "unresolved_wikilink",
            nodeId: entry.nodeId,
            relativePath: state.relative_path,
            message: "A native Obsidian relationship does not resolve inside the eligible projected knowledge set.",
          });
        }
      }
    }

    const managed = this.#managedMarkdown(connection);
    const trackedPaths = new Set(states.map((state) => state.relative_path));
    const untracked = managed.filter((path) => !trackedPaths.has(path));
    for (const relativePath of untracked) {
      addIssue({
        category: "untracked_note",
        relativePath,
        message: "A managed Markdown note is not represented by Vault synchronization state.",
      });
    }
    const openConflictCount = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM vault_conflicts
      WHERE connection_id = ? AND status = 'open'
    `).get(connection.id) as { count: number }).count);
    if (openConflictCount > 0) {
      issueCount += openConflictCount;
      if (issues.length < MAX_ISSUES) issues.push({
        category: "open_conflict",
        message: `${openConflictCount} open Vault conflict(s) require operator resolution.`,
      });
    }
    const managedProjectionHash = sha256(actualProjectionRecords.sort().join("\n"));
    const wikilinkGraphHash = sha256(wikilinkRecords.sort().join("\n"));
    const status = issueCount === 0
      && syncedNodeCount === plan.entries.length
      && verifiedFileCount === plan.entries.length
      && parsedNoteCount === plan.entries.length
      && managed.length === plan.entries.length
      ? "complete"
      : "attention_required";
    return {
      schemaVersion: "ti-scale.vault-projection-reconciliation.v1",
      connectionId: connection.id,
      checkedAt: this.#clock().toISOString(),
      status,
      planHash: plan.planHash,
      eligibleNodeCount: plan.entries.length,
      syncedNodeCount,
      missingStateCount,
      unexpectedStateCount,
      nonSyncedStateCount,
      managedMarkdownCount: managed.length,
      untrackedManagedMarkdownCount: untracked.length,
      openConflictCount,
      verifiedFileCount,
      parsedNoteCount,
      wikilinkCount,
      unresolvedWikilinkCount,
      unsafeContentCount,
      managedProjectionHash,
      wikilinkGraphHash,
      issueCount,
      issues,
      issueSampleTruncated: issueCount > issues.length,
    };
  }

  #connection(connectionId: string, requireConnected = true): VaultConnection {
    const connection = this.bridge.requireConnection(connectionId);
    if (requireConnected && connection.status !== "connected") {
      throw new Error("Full Vault projection requires an active connected Obsidian vault");
    }
    if (connection.status === "disconnected") {
      throw new Error("Disconnected Vaults cannot be reconciled");
    }
    this.paths.resolveExistingVault(connection.vaultPath);
    return connection;
  }

  #states(connectionId: string): readonly SyncStateRow[] {
    return this.database.prepare(`
      SELECT node_id, relative_path, database_content_hash, vault_content_hash, status
      FROM vault_sync_state WHERE connection_id = ?
      ORDER BY relative_path
    `).all(connectionId) as SyncStateRow[];
  }

  #plan(connection: VaultConnection): {
    readonly entries: readonly ProjectionPlanEntry[];
    readonly connectionScopeHash: string;
    readonly selectionHash: string;
    readonly canonicalProjectionHash: string;
    readonly planHash: string;
    readonly issueCount: number;
    readonly issues: readonly VaultProjectionIssue[];
  } {
    const nodeIds = [...this.bridge.previewExportableNodeIds(connection.id)].sort();
    const states = this.#states(connection.id);
    const stateByNode = new Map(states.flatMap((state) => state.node_id ? [[state.node_id, state] as const] : []));
    const entries: ProjectionPlanEntry[] = [];
    const issues: VaultProjectionIssue[] = [];
    let issueCount = 0;
    const paths = new Map<string, string>();
    for (const nodeId of nodeIds) {
      const rendered = this.bridge.renderNode(nodeId, connection);
      const relativePath = stateByNode.get(nodeId)?.relative_path ?? rendered.relativePath;
      const previousNodeId = paths.get(relativePath);
      if (previousNodeId && previousNodeId !== nodeId) {
        issueCount += 1;
        if (issues.length < MAX_ISSUES) issues.push({
          category: "duplicate_path",
          nodeId,
          relativePath,
          message: "Two eligible canonical nodes resolve to one Obsidian note path.",
        });
      } else paths.set(relativePath, nodeId);
      entries.push({
        nodeId,
        version: rendered.node.version,
        relativePath,
        projectionHash: sha256(rendered.text),
      });
    }
    const connectionScopeHash = sha256(canonical(connection.syncScope));
    const selectionHash = sha256(canonical(nodeIds));
    const canonicalProjectionHash = sha256(canonical(entries));
    const planHash = sha256(canonical({
      schemaVersion: "ti-scale.vault-projection-plan.v1",
      connectionId: connection.id,
      connectionScopeHash,
      selectionHash,
      canonicalProjectionHash,
    }));
    return {
      entries,
      connectionScopeHash,
      selectionHash,
      canonicalProjectionHash,
      planHash,
      issueCount,
      issues,
    };
  }

  #managedMarkdown(connection: VaultConnection): readonly string[] {
    const folders = [
      ...OBSIDIAN_V2_4_VAULT_FOLDERS,
      ...(vaultScopeIncludesOperatorProfile(connection.syncScope) ? [OPERATOR_PROFILE_VAULT_FOLDER] : []),
    ];
    const results: string[] = [];
    const seen = new Set<string>();
    const visit = (relativeDirectory: string): void => {
      const directory = this.paths.resolveRelative(connection.vaultPath, relativeDirectory);
      if (!existsSync(directory)) return;
      const metadata = lstatSync(directory);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error("Managed Vault folder is not a real directory");
      }
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const relativePath = `${relativeDirectory}/${entry.name}`;
        if (entry.isSymbolicLink()) throw new Error("Symbolic links are not permitted in managed Vault folders");
        if (entry.isDirectory()) visit(relativePath);
        else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
          results.push(relativePath);
          if (results.length > MAX_MANAGED_NOTES) {
            throw new Error(`Vault reconciliation is limited to ${MAX_MANAGED_NOTES} managed Markdown notes`);
          }
        }
      }
    };
    for (const folder of folders) {
      if (seen.has(folder)) continue;
      seen.add(folder);
      visit(folder);
    }
    return results.sort((left, right) => left.localeCompare(right, "en"));
  }
}
