import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db/types";
import { inImmediateTransaction } from "../db/transaction";
import type { VaultConnection } from "./types";
import type { ObsidianVaultBridge } from "./ObsidianVaultBridge";
import {
  activeAttackKnowledgeVaultPresetConnection,
  attackKnowledgeVaultPolicyHash,
  attackKnowledgeVaultPresetPreview,
  attackKnowledgeVaultSyncScope,
} from "./AttackKnowledgeVaultPreset";

export class AttackKnowledgeVaultScopeAmendmentConflictError extends Error {
  constructor(message = "The Attack Knowledge Vault policy changed before its scope could be amended") {
    super(message);
    this.name = "AttackKnowledgeVaultScopeAmendmentConflictError";
  }
}

export interface AttackKnowledgeVaultScopeAmendmentResult {
  readonly connection: VaultConnection;
  readonly previousPolicyHash: string;
  readonly targetPolicyHash: string;
  readonly eligibleNodeCountBefore: number;
  readonly eligibleNodeCountAfter: number;
  readonly eligibleNodeDelta: number;
  readonly amendedAt: string;
  readonly auditRecordId: string;
  readonly filesystemHealth: {
    readonly checkedAt: string;
    readonly checks: { readonly write: true; readonly read: true; readonly rename: true; readonly delete: true };
  };
  readonly connectionIdChanged: false;
  readonly vaultPathChanged: false;
  readonly filesDeleted: 0;
  readonly notesWritten: 0;
}

export interface AttackKnowledgeVaultOperatorProfileAmendmentResult
  extends AttackKnowledgeVaultScopeAmendmentResult {
  readonly operatorProfileFolder: "10 Operator";
  readonly operatorProfileFolderCreated: boolean;
  readonly operatorProfileNodeCount: number;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function nextVersion(now: string, prior: string): string {
  if (now > prior) return now;
  return new Date(Date.parse(prior) + 1).toISOString();
}

/**
 * Owns the only supported preset scope amendment: verified-only to verified
 * plus operator-confirmed reusable attack knowledge. It deliberately does not
 * expose a general Vault-scope editor or a downgrade that could delete a
 * projection on the next export.
 */
export class AttackKnowledgeVaultPolicyService {
  readonly #database: SqliteDatabase;
  readonly #bridge: ObsidianVaultBridge;
  readonly #clock: () => Date;

  constructor(
    database: SqliteDatabase,
    bridge: ObsidianVaultBridge,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#database = database;
    this.#bridge = bridge;
    this.#clock = options.clock ?? (() => new Date());
  }

  includeConfirmed(input: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly expectedCurrentPolicyHash: string;
    readonly expectedTargetPolicyHash: string;
    readonly actor: string;
    readonly reason: string;
    readonly amendmentAcknowledged: true;
  }): AttackKnowledgeVaultScopeAmendmentResult {
    if (input.amendmentAcknowledged !== true) {
      throw new TypeError("Explicit confirmed-knowledge scope amendment acknowledgement is required");
    }
    if (!input.actor.trim()) throw new TypeError("Scope amendment actor is required");
    if (input.reason.trim().length < 12 || input.reason.length > 1_000) {
      throw new TypeError("Scope amendment reason must contain 12-1000 characters");
    }

    const currentPolicyHash = attackKnowledgeVaultPolicyHash();
    const targetPolicyHash = attackKnowledgeVaultPolicyHash({ includeConfirmed: true });
    if (
      input.expectedCurrentPolicyHash !== currentPolicyHash
      || input.expectedTargetPolicyHash !== targetPolicyHash
    ) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "The reviewed Attack Knowledge Vault policy hashes are stale",
      );
    }
    const preset = activeAttackKnowledgeVaultPresetConnection(this.#database);
    if (
      !preset
      || preset.id !== input.connectionId
      || preset.updatedAt !== input.expectedUpdatedAt
      || preset.includeConfirmed
    ) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError();
    }
    const current = this.#bridge.requireConnection(input.connectionId);
    if (current.status !== "connected") {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "The Attack Knowledge Vault must be connected before its scope is amended",
      );
    }
    const projectionLifecycles = new Set(this.#bridge.projectionLifecycleStatuses());
    if (!projectionLifecycles.has("verified") || !projectionLifecycles.has("confirmed")) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "Memory Control must permit confirmed and verified Obsidian projection before this scope is amended",
      );
    }
    const health = this.#bridge.verifyExistingVaultPath(current.vaultPath);
    const targetScope = attackKnowledgeVaultSyncScope({ includeConfirmed: true });
    const currentScope = attackKnowledgeVaultSyncScope();
    const amendedAt = nextVersion(this.#clock().toISOString(), current.updatedAt);

    const amendment = inImmediateTransaction(this.#database, () => {
      const fresh = activeAttackKnowledgeVaultPresetConnection(this.#database);
      if (
        !fresh
        || fresh.id !== current.id
        || fresh.updatedAt !== current.updatedAt
        || fresh.includeConfirmed
      ) {
        throw new AttackKnowledgeVaultScopeAmendmentConflictError();
      }
      // Bind the receipt to the exact eligible population while the immediate
      // transaction prevents a concurrent memory promotion from changing it.
      const before = attackKnowledgeVaultPresetPreview(this.#database);
      const after = attackKnowledgeVaultPresetPreview(this.#database, { includeConfirmed: true });
      const eligibleNodeCountBefore = before.projection.policyEligibleNodeCount;
      const eligibleNodeCountAfter = after.projection.policyEligibleNodeCount;
      const eligibleNodeDelta = Math.max(0, eligibleNodeCountAfter - eligibleNodeCountBefore);
      const updated = this.#database.prepare(`
        UPDATE vault_connections
        SET sync_scope_json = ?, updated_at = ?
        WHERE id = ? AND updated_at = ? AND sync_scope_json = ?
          AND status != 'disconnected'
      `).run(
        JSON.stringify(targetScope),
        amendedAt,
        current.id,
        current.updatedAt,
        JSON.stringify(current.syncScope),
      );
      if (updated.changes !== 1) throw new AttackKnowledgeVaultScopeAmendmentConflictError();

      const previous = this.#database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { record_hash: string } | undefined;
      const id = `audit-vault-${randomUUID()}`;
      const details = {
        presetId: "ti_scale_attack_knowledge_v1",
        connectionId: current.id,
        previousPolicyHash: currentPolicyHash,
        targetPolicyHash,
        previousSyncScope: currentScope,
        targetSyncScope: targetScope,
        eligibleNodeCountBefore,
        eligibleNodeCountAfter,
        eligibleNodeDelta,
        filesystemHealthCheckedAt: health.checkedAt,
        filesystemHealthChecks: health.checks,
        connectionIdChanged: false,
        vaultPathChanged: false,
        filesDeleted: 0,
        notesWritten: 0,
      };
      const hashMaterial = {
        id,
        actor: input.actor.trim(),
        action: "vault.attack_knowledge_preset.scope_amended",
        resourceType: "vault_connection",
        resourceId: current.id,
        reason: input.reason.trim(),
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: amendedAt,
      };
      this.#database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id, reason,
          details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'operator', ?, ?, 'vault_connection', ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.actor.trim(),
        hashMaterial.action,
        current.id,
        input.reason.trim(),
        JSON.stringify(details),
        previous?.record_hash ?? null,
        sha256(canonical(hashMaterial)),
        amendedAt,
      );
      return { auditRecordId: id, eligibleNodeCountBefore, eligibleNodeCountAfter, eligibleNodeDelta };
    });

    return {
      connection: this.#bridge.requireConnection(current.id),
      previousPolicyHash: currentPolicyHash,
      targetPolicyHash,
      eligibleNodeCountBefore: amendment.eligibleNodeCountBefore,
      eligibleNodeCountAfter: amendment.eligibleNodeCountAfter,
      eligibleNodeDelta: amendment.eligibleNodeDelta,
      amendedAt,
      auditRecordId: amendment.auditRecordId,
      filesystemHealth: { checkedAt: health.checkedAt, checks: health.checks },
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    };
  }

  /**
   * Expands the already confirmed Attack Knowledge Vault to the explicit,
   * consent-backed Operator Profile graph. This is intentionally a second
   * review: confirming attack knowledge never silently exports preferences.
   */
  includeOperatorProfile(input: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly expectedCurrentPolicyHash: string;
    readonly expectedTargetPolicyHash: string;
    readonly actor: string;
    readonly reason: string;
    readonly operatorProfileAcknowledged: true;
  }): AttackKnowledgeVaultOperatorProfileAmendmentResult {
    if (input.operatorProfileAcknowledged !== true) {
      throw new TypeError("Explicit Operator Profile Vault scope acknowledgement is required");
    }
    if (!input.actor.trim()) throw new TypeError("Scope amendment actor is required");
    if (input.reason.trim().length < 12 || input.reason.length > 1_000) {
      throw new TypeError("Scope amendment reason must contain 12-1000 characters");
    }

    const currentOptions = { includeConfirmed: true } as const;
    const targetOptions = {
      includeConfirmed: true,
      includeOperatorProfile: true,
      operatorProfileId: input.actor.trim(),
    } as const;
    const currentPolicyHash = attackKnowledgeVaultPolicyHash(currentOptions);
    const targetPolicyHash = attackKnowledgeVaultPolicyHash(targetOptions);
    if (
      input.expectedCurrentPolicyHash !== currentPolicyHash
      || input.expectedTargetPolicyHash !== targetPolicyHash
    ) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "The reviewed Operator Profile Vault policy hashes are stale",
      );
    }
    const preset = activeAttackKnowledgeVaultPresetConnection(this.#database);
    if (
      !preset
      || preset.id !== input.connectionId
      || preset.updatedAt !== input.expectedUpdatedAt
      || !preset.includeConfirmed
      || preset.includeOperatorProfile
    ) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError();
    }
    const current = this.#bridge.requireConnection(input.connectionId);
    if (current.status !== "connected") {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "The Attack Knowledge Vault must be connected before its Operator Profile scope is amended",
      );
    }
    const projectionLifecycles = new Set(this.#bridge.projectionLifecycleStatuses());
    if (!projectionLifecycles.has("confirmed")) {
      throw new AttackKnowledgeVaultScopeAmendmentConflictError(
        "Memory Control must permit confirmed Obsidian projection before Operator Profile scope is amended",
      );
    }
    const health = this.#bridge.verifyExistingVaultPath(current.vaultPath);
    const targetScope = attackKnowledgeVaultSyncScope(targetOptions);
    const currentScope = attackKnowledgeVaultSyncScope(currentOptions);
    const amendedAt = nextVersion(this.#clock().toISOString(), current.updatedAt);

    const amendment = inImmediateTransaction(this.#database, () => {
      const fresh = activeAttackKnowledgeVaultPresetConnection(this.#database);
      if (
        !fresh
        || fresh.id !== current.id
        || fresh.updatedAt !== current.updatedAt
        || !fresh.includeConfirmed
        || fresh.includeOperatorProfile
      ) {
        throw new AttackKnowledgeVaultScopeAmendmentConflictError();
      }
      const before = attackKnowledgeVaultPresetPreview(this.#database, currentOptions);
      const after = attackKnowledgeVaultPresetPreview(this.#database, targetOptions);
      const upgrade = after.operatorProfileScopeUpgrade;
      if (!upgrade || upgrade.connectionId !== current.id) {
        throw new AttackKnowledgeVaultScopeAmendmentConflictError(
          "The Operator Profile projection population changed before amendment",
        );
      }
      const folder = this.#bridge.ensureOperatorProfileFolder(current.id);
      const updated = this.#database.prepare(`
        UPDATE vault_connections
        SET sync_scope_json = ?, updated_at = ?
        WHERE id = ? AND updated_at = ? AND sync_scope_json = ?
          AND status != 'disconnected'
      `).run(
        JSON.stringify(targetScope),
        amendedAt,
        current.id,
        current.updatedAt,
        JSON.stringify(current.syncScope),
      );
      if (updated.changes !== 1) throw new AttackKnowledgeVaultScopeAmendmentConflictError();

      const previous = this.#database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { record_hash: string } | undefined;
      const id = `audit-vault-${randomUUID()}`;
      const details = {
        presetId: "ti_scale_attack_knowledge_v1",
        connectionId: current.id,
        previousPolicyHash: currentPolicyHash,
        targetPolicyHash,
        previousSyncScope: currentScope,
        targetSyncScope: targetScope,
        eligibleNodeCountBefore: before.projection.policyEligibleNodeCount,
        eligibleNodeCountAfter: after.projection.policyEligibleNodeCount,
        eligibleNodeDelta: upgrade.eligibleNodeDelta,
        operatorProfileNodeCount: upgrade.operatorProfileNodeCount,
        operatorProfileFolder: folder.folder,
        operatorProfileFolderCreated: folder.created,
        filesystemHealthCheckedAt: health.checkedAt,
        filesystemHealthChecks: health.checks,
        connectionIdChanged: false,
        vaultPathChanged: false,
        filesDeleted: 0,
        notesWritten: 0,
      };
      const hashMaterial = {
        id,
        actor: input.actor.trim(),
        action: "vault.attack_knowledge_preset.operator_profile_scope_amended",
        resourceType: "vault_connection",
        resourceId: current.id,
        reason: input.reason.trim(),
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: amendedAt,
      };
      this.#database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id, reason,
          details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'operator', ?, ?, 'vault_connection', ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.actor.trim(),
        hashMaterial.action,
        current.id,
        input.reason.trim(),
        JSON.stringify(details),
        previous?.record_hash ?? null,
        sha256(canonical(hashMaterial)),
        amendedAt,
      );
      return {
        auditRecordId: id,
        eligibleNodeCountBefore: before.projection.policyEligibleNodeCount,
        eligibleNodeCountAfter: after.projection.policyEligibleNodeCount,
        eligibleNodeDelta: upgrade.eligibleNodeDelta,
        operatorProfileNodeCount: upgrade.operatorProfileNodeCount,
        operatorProfileFolder: folder.folder,
        operatorProfileFolderCreated: folder.created,
      };
    });

    return {
      connection: this.#bridge.requireConnection(current.id),
      previousPolicyHash: currentPolicyHash,
      targetPolicyHash,
      ...amendment,
      amendedAt,
      filesystemHealth: { checkedAt: health.checkedAt, checks: health.checks },
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    };
  }
}
