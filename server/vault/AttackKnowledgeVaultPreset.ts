import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { SqliteDatabase } from "../db/types";
import {
  ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
  isAttackCentricReusableNodeType,
  type MemoryNode,
  type MemorySensitivity,
} from "../memory/types";
import {
  TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES,
} from "../memory/TerminalAttackKnowledgeReview";
import { OBSIDIAN_V2_4_VAULT_FOLDERS } from "./ObsidianMarkdown";
import {
  OPERATOR_PROFILE_VAULT_FOLDER,
  OPERATOR_PROFILE_VAULT_NODE_TYPES,
  OPERATOR_PROFILE_VAULT_PROJECTION_POLICY,
  operatorProfileVaultEligibleNodeIds,
} from "./OperatorProfileVaultProjection";

export const ATTACK_KNOWLEDGE_VAULT_PRESET_ID = "ti_scale_attack_knowledge_v1" as const;
export const ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME = "Ti-Scale Attack Knowledge Vault" as const;
export const ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH = "Attack-Knowledge-Vault" as const;
export const ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES = [
  "public",
  "internal",
  "private",
] as const satisfies readonly MemorySensitivity[];

export interface AttackKnowledgeVaultPresetOptions {
  /** Confirmed knowledge is deliberately opt-in. Verified remains the default. */
  readonly includeConfirmed?: boolean;
  /**
   * Explicitly confirmed operator preferences are a second, independent
   * privacy review. They cannot be enabled without confirmed lifecycle scope.
   */
  readonly includeOperatorProfile?: boolean;
  /** Operator identity is part of the profile projection policy hash. */
  readonly operatorProfileId?: string;
}

export interface AttackKnowledgeVaultPresetPreview {
  readonly id: typeof ATTACK_KNOWLEDGE_VAULT_PRESET_ID;
  readonly displayName: typeof ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME;
  readonly vaultPath: typeof ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH;
  readonly policyHash: string;
  readonly activationRequired: true;
  readonly alreadyActiveConnectionId?: string;
  /** The one reserved preset connection, regardless of which exact lifecycle
   * variant it currently uses. This prevents a policy review for the other
   * variant from being mistaken for a second Vault activation. */
  readonly activePreset?: {
    readonly connectionId: string;
    readonly updatedAt: string;
    readonly includeConfirmed: boolean;
    readonly includeOperatorProfile: boolean;
    readonly operatorProfileId?: string;
    readonly policyHash: string;
  };
  /** A deliberately one-way expansion of the existing verified-only preset.
   * The same connection ID and filesystem path are retained. */
  readonly confirmedScopeUpgrade?: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly currentPolicyHash: string;
    readonly targetPolicyHash: string;
    readonly eligibleNodeCountBefore: number;
    readonly eligibleNodeCountAfter: number;
    readonly eligibleNodeDelta: number;
  };
  readonly operatorProfileScopeUpgrade?: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly currentPolicyHash: string;
    readonly targetPolicyHash: string;
    readonly eligibleNodeCountBefore: number;
    readonly eligibleNodeCountAfter: number;
    readonly eligibleNodeDelta: number;
    readonly operatorProfileNodeCount: number;
  };
  /**
   * Actor-bound eligibility is returned for every preview, including the
   * default attack-only preview. The browser can therefore explain and
   * disable an empty Operator Profile choice before requesting a policy that
   * cannot be applied.
   */
  readonly operatorProfileAvailability: {
    readonly requested: boolean;
    readonly available: boolean;
    readonly status: "available" | "no_eligible_confirmed_profile";
    readonly eligibleNodeCount: number;
  };
  readonly projection: {
    readonly nodeTypes: readonly string[];
    readonly scopeKinds: readonly ["global"];
    readonly lifecycleStatuses: readonly ("verified" | "confirmed")[];
    readonly sensitivities: readonly MemorySensitivity[];
    readonly folders: readonly string[];
    readonly policyEligibleNodeCount: number;
    readonly excludedOperationalNodeCount: number;
    readonly confirmedKnowledgeIsOptIn: boolean;
    readonly operatorProfileIncluded: boolean;
    readonly operatorProfileNodeCount: number;
  };
  readonly privacyBoundary: {
    readonly excludesNodeTypes: readonly string[];
    readonly excludesOperationalLocators: readonly string[];
    readonly restrictedSensitivityWithheld: true;
  };
}

const EXCLUDED_OPERATIONAL_NODE_TYPES = [
  "mission",
  "run",
  "plan",
  "phase",
  "step",
  "target",
  "asset",
  "entity",
  "decision",
  "evidence",
  "finding",
  "artifact",
  "report",
  "source",
] as const;

const EXCLUDED_OPERATIONAL_LOCATORS = [
  "IP addresses and CIDRs",
  "target URLs and hostnames",
  "engagement and mission names",
  "filesystem paths",
  "credentials and raw evidence payloads",
] as const;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function legacyAttackKnowledgeVaultSyncScope(
  options: AttackKnowledgeVaultPresetOptions = {},
): Readonly<Record<string, unknown>> {
  const { candidateReviewNodeTypes: _candidateReviewNodeTypes, ...legacy } =
    attackKnowledgeVaultSyncScope(options);
  return legacy;
}

export function attackKnowledgeVaultPresetVariant(
  syncScope: Record<string, unknown>,
): AttackKnowledgeVaultPresetOptions | undefined {
  const actual = canonical(syncScope);
  if (
    actual === canonical(attackKnowledgeVaultSyncScope())
    || actual === canonical(legacyAttackKnowledgeVaultSyncScope())
  ) return { includeConfirmed: false };
  if (
    actual === canonical(attackKnowledgeVaultSyncScope({ includeConfirmed: true }))
    || actual === canonical(legacyAttackKnowledgeVaultSyncScope({ includeConfirmed: true }))
  ) {
    return { includeConfirmed: true };
  }
  const operatorIds = syncScope.operatorIds;
  const operatorProfileId = Array.isArray(operatorIds)
    && operatorIds.length === 1
    && typeof operatorIds[0] === "string"
    ? operatorIds[0]
    : undefined;
  const operatorOptions = operatorProfileId
    ? {
        includeConfirmed: true,
        includeOperatorProfile: true,
        operatorProfileId,
      } as const
    : undefined;
  if (
    operatorOptions
    && (
      actual === canonical(attackKnowledgeVaultSyncScope(operatorOptions))
      || actual === canonical(legacyAttackKnowledgeVaultSyncScope(operatorOptions))
    )
  ) {
    return { includeConfirmed: true, includeOperatorProfile: true, operatorProfileId };
  }
  return undefined;
}

export interface ActiveAttackKnowledgeVaultPresetConnection {
  readonly id: string;
  readonly vaultPath: string;
  readonly updatedAt: string;
  readonly includeConfirmed: boolean;
  readonly includeOperatorProfile: boolean;
  readonly operatorProfileId?: string;
}

/** Finds only one of the exact, reserved preset variants. A broad custom
 * connection sharing a display label is never accepted as the product Vault. */
export function activeAttackKnowledgeVaultPresetConnection(
  database: SqliteDatabase,
): ActiveAttackKnowledgeVaultPresetConnection | undefined {
  const rows = database.prepare(`
    SELECT id, vault_path, sync_scope_json, updated_at
    FROM vault_connections
    WHERE display_name = ? AND status != 'disconnected'
    ORDER BY updated_at DESC
  `).all(ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME) as Array<{
    id: string;
    vault_path: string;
    sync_scope_json: string;
    updated_at: string;
  }>;
  for (const row of rows) {
    if (basename(row.vault_path) !== ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH) continue;
    try {
      const scope = JSON.parse(row.sync_scope_json) as unknown;
      if (!scope || typeof scope !== "object" || Array.isArray(scope)) continue;
      const variant = attackKnowledgeVaultPresetVariant(scope as Record<string, unknown>);
      if (!variant) continue;
      return {
        id: row.id,
        vaultPath: row.vault_path,
        updatedAt: row.updated_at,
        includeConfirmed: variant.includeConfirmed === true,
        includeOperatorProfile: variant.includeOperatorProfile === true,
        ...(variant.operatorProfileId ? { operatorProfileId: variant.operatorProfileId } : {}),
      };
    } catch {
      // A malformed or non-preset scope is not silently treated as the
      // reserved product connection.
    }
  }
  return undefined;
}

export function attackKnowledgeVaultSyncScope(
  options: AttackKnowledgeVaultPresetOptions = {},
): Readonly<Record<string, readonly string[]>> {
  if (options.includeOperatorProfile && !options.includeConfirmed) {
    throw new TypeError("Operator Profile Vault projection requires confirmed lifecycle scope");
  }
  if (options.includeOperatorProfile && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u.test(options.operatorProfileId ?? "")) {
    throw new TypeError("Operator Profile Vault projection requires one valid operator identity");
  }
  return Object.freeze({
    nodeTypes: Object.freeze([
      ...ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
      ...(options.includeOperatorProfile ? OPERATOR_PROFILE_VAULT_NODE_TYPES : []),
    ]),
    scopeKinds: Object.freeze(["global"]),
    lifecycleStatuses: Object.freeze(options.includeConfirmed
      ? ["verified", "confirmed"]
      : ["verified"]),
    candidateReviewNodeTypes: Object.freeze([
      ...TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES,
    ]),
    sensitivities: Object.freeze([...ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES]),
    ...(options.includeOperatorProfile ? {
      operatorProfileProjection: Object.freeze([OPERATOR_PROFILE_VAULT_PROJECTION_POLICY]),
      operatorIds: Object.freeze([options.operatorProfileId!]),
    } : {}),
  });
}

export function attackKnowledgeVaultPolicyHash(
  options: AttackKnowledgeVaultPresetOptions = {},
): string {
  return createHash("sha256").update(canonical({
    presetId: ATTACK_KNOWLEDGE_VAULT_PRESET_ID,
    vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
    syncScope: attackKnowledgeVaultSyncScope(options),
    folders: options.includeOperatorProfile
      ? [...OBSIDIAN_V2_4_VAULT_FOLDERS, OPERATOR_PROFILE_VAULT_FOLDER]
      : OBSIDIAN_V2_4_VAULT_FOLDERS,
  }), "utf8").digest("hex");
}

/**
 * The product preset has a stricter boundary than a generic Vault connection.
 * It is intentionally independent from target, mission, and engagement state.
 */
export function assertAttackKnowledgeVaultNodeAllowed(
  node: Pick<MemoryNode, "nodeType" | "scope" | "lifecycleStatus" | "sensitivity">,
  options: AttackKnowledgeVaultPresetOptions = {},
): void {
  if (!isAttackCentricReusableNodeType(node.nodeType)) {
    throw new Error(`Memory node type ${node.nodeType} is private operational provenance and cannot be projected as reusable Vault knowledge`);
  }
  if (node.scope.kind !== "global" || node.scope.engagementId || node.scope.missionId) {
    throw new Error("Attack Knowledge Vault projection requires a global scope without engagement or mission identifiers");
  }
  const allowedLifecycle = options.includeConfirmed
    ? node.lifecycleStatus === "verified" || node.lifecycleStatus === "confirmed"
    : node.lifecycleStatus === "verified";
  if (!allowedLifecycle) {
    throw new Error(`Memory lifecycle ${node.lifecycleStatus} is outside the Attack Knowledge Vault verified projection`);
  }
  if (!ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES.includes(
    node.sensitivity as (typeof ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES)[number],
  )) {
    throw new Error(`Memory sensitivity ${node.sensitivity} is outside the Attack Knowledge Vault projection`);
  }
}

export function attackKnowledgeVaultPresetPreview(
  database: SqliteDatabase,
  options: AttackKnowledgeVaultPresetOptions = {},
): AttackKnowledgeVaultPresetPreview {
  if (options.includeOperatorProfile && !options.includeConfirmed) {
    throw new TypeError("Operator Profile Vault projection requires confirmed lifecycle scope");
  }
  if (options.includeOperatorProfile && !options.operatorProfileId) {
    throw new TypeError("Operator Profile Vault projection requires one operator identity");
  }
  const operatorProfileNodeIds = options.operatorProfileId
    ? operatorProfileVaultEligibleNodeIds(database, options.operatorProfileId)
    : [];
  const operatorProfileAvailable = operatorProfileNodeIds.length > 0;
  // A zero-node profile request is represented explicitly as unavailable; it
  // is never emitted as an internally inconsistent, allegedly included
  // projection. This keeps direct API callers and a concurrent preference
  // removal fail-clear while the mutation service still refuses amendment.
  const operatorProfileIncluded = options.includeOperatorProfile === true && operatorProfileAvailable;
  const effectiveOptions: AttackKnowledgeVaultPresetOptions = {
    includeConfirmed: options.includeConfirmed === true,
    ...(operatorProfileIncluded ? {
      includeOperatorProfile: true,
      operatorProfileId: options.operatorProfileId,
    } : {}),
  };
  const syncScope = attackKnowledgeVaultSyncScope(effectiveOptions);
  const placeholders = (values: readonly string[]): string => values.map(() => "?").join(", ");
  const nodeTypes = syncScope.nodeTypes!;
  const attackNodeTypes = [...ATTACK_CENTRIC_REUSABLE_NODE_TYPES];
  const lifecycleStatuses = syncScope.lifecycleStatuses!;
  const sensitivities = syncScope.sensitivities!;
  const eligible = database.prepare(`
    SELECT COUNT(*) AS count
    FROM memory_nodes
    WHERE node_type IN (${placeholders(attackNodeTypes)})
      AND scope = 'global'
      AND engagement_id IS NULL
      AND mission_id IS NULL
      AND lifecycle_status IN (${placeholders(lifecycleStatuses)})
      AND sensitivity IN (${placeholders(sensitivities)})
  `).get(...attackNodeTypes, ...lifecycleStatuses, ...sensitivities) as { count: number };
  const includedOperatorProfileNodeIds = operatorProfileIncluded ? operatorProfileNodeIds : [];
  const eligibleCount = Number(eligible.count) + includedOperatorProfileNodeIds.length;
  const operational = database.prepare(`
    SELECT COUNT(*) AS count
    FROM memory_nodes
    WHERE node_type IN (${placeholders(EXCLUDED_OPERATIONAL_NODE_TYPES)})
  `).get(...EXCLUDED_OPERATIONAL_NODE_TYPES) as { count: number };
  const presetConnection = activeAttackKnowledgeVaultPresetConnection(database);
  const active = presetConnection
    && presetConnection.includeConfirmed === (options.includeConfirmed === true)
    && presetConnection.includeOperatorProfile === operatorProfileIncluded
    && (!operatorProfileIncluded || presetConnection.operatorProfileId === options.operatorProfileId)
    ? presetConnection
    : undefined;
  const verifiedOnlyEligible = options.includeConfirmed === true
    ? database.prepare(`
        SELECT COUNT(*) AS count
        FROM memory_nodes
        WHERE node_type IN (${placeholders(attackNodeTypes)})
          AND scope = 'global'
          AND engagement_id IS NULL
          AND mission_id IS NULL
          AND lifecycle_status = 'verified'
          AND sensitivity IN (${placeholders(sensitivities)})
      `).get(...attackNodeTypes, ...sensitivities) as { count: number }
    : eligible;
  const confirmedEligible = options.includeConfirmed === true
    ? eligible
    : database.prepare(`
        SELECT COUNT(*) AS count
        FROM memory_nodes
        WHERE node_type IN (${placeholders(attackNodeTypes)})
          AND scope = 'global'
          AND engagement_id IS NULL
          AND mission_id IS NULL
          AND lifecycle_status IN ('verified', 'confirmed')
          AND sensitivity IN (${placeholders(sensitivities)})
      `).get(...attackNodeTypes, ...sensitivities) as { count: number };
  const confirmedScopeUpgrade = presetConnection && !presetConnection.includeConfirmed
    ? {
        connectionId: presetConnection.id,
        expectedUpdatedAt: presetConnection.updatedAt,
        currentPolicyHash: attackKnowledgeVaultPolicyHash(),
        targetPolicyHash: attackKnowledgeVaultPolicyHash({ includeConfirmed: true }),
        eligibleNodeCountBefore: Number(verifiedOnlyEligible.count),
        eligibleNodeCountAfter: Number(confirmedEligible.count),
        eligibleNodeDelta: Math.max(0, Number(confirmedEligible.count) - Number(verifiedOnlyEligible.count)),
      }
    : undefined;
  const operatorProfileTarget = {
    includeConfirmed: true,
    includeOperatorProfile: true,
    operatorProfileId: options.operatorProfileId,
  } as const;
  const operatorProfileScopeUpgrade = presetConnection
    && presetConnection.includeConfirmed
    && !presetConnection.includeOperatorProfile
    && operatorProfileIncluded
    ? {
        connectionId: presetConnection.id,
        expectedUpdatedAt: presetConnection.updatedAt,
        currentPolicyHash: attackKnowledgeVaultPolicyHash({ includeConfirmed: true }),
        targetPolicyHash: attackKnowledgeVaultPolicyHash(operatorProfileTarget),
        eligibleNodeCountBefore: Number(confirmedEligible.count),
        eligibleNodeCountAfter: eligibleCount,
        eligibleNodeDelta: Math.max(0, eligibleCount - Number(confirmedEligible.count)),
        operatorProfileNodeCount: includedOperatorProfileNodeIds.length,
      }
    : undefined;
  return {
    id: ATTACK_KNOWLEDGE_VAULT_PRESET_ID,
    displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
    vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
    policyHash: attackKnowledgeVaultPolicyHash(effectiveOptions),
    activationRequired: true,
    ...(active ? { alreadyActiveConnectionId: active.id } : {}),
    ...(presetConnection ? {
      activePreset: {
        connectionId: presetConnection.id,
        updatedAt: presetConnection.updatedAt,
        includeConfirmed: presetConnection.includeConfirmed,
        includeOperatorProfile: presetConnection.includeOperatorProfile,
        ...(presetConnection.operatorProfileId ? { operatorProfileId: presetConnection.operatorProfileId } : {}),
        policyHash: attackKnowledgeVaultPolicyHash({
          includeConfirmed: presetConnection.includeConfirmed,
          includeOperatorProfile: presetConnection.includeOperatorProfile,
          operatorProfileId: presetConnection.operatorProfileId,
        }),
      },
    } : {}),
    ...(confirmedScopeUpgrade ? { confirmedScopeUpgrade } : {}),
    ...(operatorProfileScopeUpgrade ? { operatorProfileScopeUpgrade } : {}),
    operatorProfileAvailability: {
      requested: options.includeOperatorProfile === true,
      available: operatorProfileAvailable,
      status: operatorProfileAvailable ? "available" : "no_eligible_confirmed_profile",
      eligibleNodeCount: operatorProfileNodeIds.length,
    },
    projection: {
      nodeTypes: [...nodeTypes],
      scopeKinds: ["global"],
      lifecycleStatuses: [...lifecycleStatuses] as ("verified" | "confirmed")[],
      sensitivities: [...sensitivities] as MemorySensitivity[],
      folders: [
        ...OBSIDIAN_V2_4_VAULT_FOLDERS,
        ...(operatorProfileIncluded ? [OPERATOR_PROFILE_VAULT_FOLDER] : []),
      ],
      policyEligibleNodeCount: eligibleCount,
      excludedOperationalNodeCount: Number(operational.count),
      confirmedKnowledgeIsOptIn: options.includeConfirmed === true,
      operatorProfileIncluded,
      operatorProfileNodeCount: includedOperatorProfileNodeIds.length,
    },
    privacyBoundary: {
      excludesNodeTypes: [...EXCLUDED_OPERATIONAL_NODE_TYPES],
      excludesOperationalLocators: [...EXCLUDED_OPERATIONAL_LOCATORS],
      restrictedSensitivityWithheld: true,
    },
  };
}
