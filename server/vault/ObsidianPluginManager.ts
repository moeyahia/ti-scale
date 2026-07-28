import { createHash, randomUUID } from "node:crypto";
import {
  chownSync,
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db/types";
import {
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY,
  BRAIN_ATLAS_REGIONS,
  operatorProfileBrainAtlasMapping,
  type BrainAtlasRegion,
} from "./AttackBrainAtlasMappingRegistry";
import {
  brainAtlasConfigurationHash,
  generateBrainAtlasConfiguration,
  serializeBrainAtlasConfiguration,
  validateBrainAtlasConfiguration,
} from "./BrainAtlasProfile";
import {
  ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
  activeAttackKnowledgeVaultPresetConnection,
} from "./AttackKnowledgeVaultPreset";
import {
  operatorProfileVaultEligibleNodeIds,
  operatorProfileVaultOperatorId,
  vaultScopeIncludesOperatorProfile,
} from "./OperatorProfileVaultProjection";
import { VaultPathPolicy } from "./VaultPathPolicy";

export const BRAIN_ATLAS_PLUGIN_ID = "brain-atlas" as const;

export interface BrainAtlasPinnedRelease {
  readonly pluginId: typeof BRAIN_ATLAS_PLUGIN_ID;
  readonly version: string;
  readonly repository: string;
  readonly commit: string;
  readonly license: "MIT";
  readonly minimumObsidianVersion: string;
  readonly assets: Readonly<Record<"main.js" | "manifest.json" | "styles.css", string>>;
  readonly licenseFile: { readonly name: "LICENSE"; readonly sha256: string };
}

export const BRAIN_ATLAS_PINNED_RELEASE = Object.freeze({
  pluginId: BRAIN_ATLAS_PLUGIN_ID,
  version: "0.2.1",
  repository: "https://github.com/colorpulse6/brain-atlas",
  commit: "477302c6a220d3e8ae00e3192b00cfd7508f25fd",
  license: "MIT",
  minimumObsidianVersion: "1.5.0",
  assets: Object.freeze({
    "main.js": "bab94f5d9367724a8ae43ac120c03b25917267e2b2193d17765347a87ae37164",
    "manifest.json": "ae1f454cd8ca6cb757114e8bfd8ba4bdd21be385f7b1adcb586f9b1cb043cdea",
    "styles.css": "ab63af3bacb08a58159c9b0a91a7db3e16facad205eb94ff6b1b712b71908543",
  }),
  licenseFile: Object.freeze({
    name: "LICENSE",
    sha256: "cf42c8a7e34b667b96c7749591a5eeeb18a199aca0820b2fbca0b1de193aa017",
  }),
}) satisfies BrainAtlasPinnedRelease;

type BrainAtlasAssetName = keyof BrainAtlasPinnedRelease["assets"];

export interface BrainAtlasHealthIssue {
  readonly code:
    | "attack_vault_not_connected"
    | "attack_vault_not_healthy"
    | "plugin_not_installed"
    | "plugin_not_enabled"
    | "asset_missing"
    | "asset_hash_mismatch"
    | "license_missing"
    | "license_hash_mismatch"
    | "manifest_invalid"
    | "release_metadata_invalid"
    | "configuration_invalid";
  readonly message: string;
  readonly remediation: string;
}

export interface BrainAtlasPluginHealth {
  readonly pluginId: typeof BRAIN_ATLAS_PLUGIN_ID;
  readonly expectedVersion: string;
  readonly status: "healthy" | "not_connected" | "not_installed" | "degraded";
  readonly healthy: boolean;
  readonly installed: boolean;
  readonly enabled: boolean;
  readonly connection?: {
    readonly id: string;
    readonly displayName: string;
    readonly status: string;
  };
  readonly assets: Readonly<Record<BrainAtlasAssetName, {
    readonly expectedSha256: string;
    readonly actualSha256?: string;
    readonly matches: boolean;
  }>>;
  readonly license: {
    readonly expectedSha256: string;
    readonly actualSha256?: string;
    readonly matches: boolean;
  };
  readonly configuration: {
    readonly valid: boolean;
    readonly sha256?: string;
    readonly registryNodeTypeCount: number;
    readonly operatorProfileMappingCount: number;
    readonly kindMappingCount: number;
    readonly regionMappingCount: number;
  };
  readonly knowledge: {
    readonly nodeCount: number;
    readonly mappedNodeCount: number;
    readonly unmappedNodeCount: number;
    readonly typedEdgeCount: number;
    readonly uniqueUndirectedPairCount: number;
    readonly regionNodeCounts: Readonly<Record<BrainAtlasRegion, number>>;
  };
  readonly issues: readonly BrainAtlasHealthIssue[];
  readonly checkedAt: string;
}

export interface BrainAtlasInstallResult {
  readonly pluginId: typeof BRAIN_ATLAS_PLUGIN_ID;
  readonly version: string;
  readonly connectionId: string;
  readonly status: "installed" | "updated";
  readonly enabled: true;
  readonly preservedCommunityPluginCount: number;
  readonly configurationSha256: string;
  readonly installedAt: string;
  readonly health: BrainAtlasPluginHealth;
}

interface ConnectionRow {
  readonly id: string;
  readonly vault_path: string;
  readonly display_name: string;
  readonly status: string;
  readonly sync_scope_json: string;
}

interface FileSnapshot {
  readonly relativePath: string;
  readonly bytes: Buffer;
  readonly sha256: string;
}

const MANAGED_ASSET_NAMES = ["main.js", "manifest.json", "styles.css"] as const;
const MAX_PLUGIN_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PLUGIN_TREE_BYTES = 24 * 1024 * 1024;
const MAX_PLUGIN_TREE_FILES = 128;

function sha256(value: Uint8Array | string): string {
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

function parseJsonObject(bytes: Buffer, label: string): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is not valid JSON`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

function parseCommunityPlugins(bytes: Buffer | undefined): string[] {
  if (!bytes) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("Obsidian community-plugins.json is not valid JSON"); }
  if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== "string" || !value.trim())) {
    throw new Error("Obsidian community-plugins.json must be a string list");
  }
  return [...new Set(parsed as string[])];
}

function readRegularFile(path: string, label: string, maximum = MAX_PLUGIN_FILE_BYTES): Buffer {
  if (!existsSync(path)) throw new Error(`${label} is missing`);
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > maximum) {
    throw new Error(`${label} must be a bounded regular non-symbolic-link file`);
  }
  return readFileSync(path);
}

function directorySnapshot(path: string): FileSnapshot[] {
  if (!existsSync(path)) return [];
  const root = lstatSync(path);
  if (root.isSymbolicLink() || !root.isDirectory()) {
    throw new Error("Existing Brain Atlas plugin path must be a regular directory");
  }
  const result: FileSnapshot[] = [];
  let totalBytes = 0;
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      if (entry.isSymbolicLink()) throw new Error("Symbolic links are not permitted in the Brain Atlas plugin directory");
      const absolute = resolve(directory, entry.name);
      const child = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(absolute, child);
      else if (entry.isFile()) {
        const bytes = readRegularFile(absolute, `Brain Atlas plugin file ${child}`);
        totalBytes += bytes.length;
        if (result.length >= MAX_PLUGIN_TREE_FILES || totalBytes > MAX_PLUGIN_TREE_BYTES) {
          throw new Error("Brain Atlas plugin directory exceeds its bounded reconciliation limit");
        }
        result.push({ relativePath: child, bytes, sha256: sha256(bytes) });
      } else throw new Error("Brain Atlas plugin directory contains an unsupported filesystem entry");
    }
  };
  visit(path, "");
  return result;
}

function snapshotHash(snapshot: readonly FileSnapshot[]): string {
  return sha256(snapshot.map((item) => `${item.relativePath}\0${item.sha256}`).join("\n"));
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, "r");
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function durableWrite(path: string, bytes: Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  chmodSync(path, 0o600);
}

/**
 * A Brain Atlas install may be performed by an administrative CLI while the
 * Vault is owned by the restricted Ti-Scale service account. Keep the
 * published plugin readable by that canonical owner instead of accidentally
 * leaving a root-only tree that passes the CLI check but fails at runtime.
 */
function applyVaultOwnership(path: string, uid: number, gid: number): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink()) throw new Error("Symbolic links are not permitted in managed Brain Atlas paths");
  if (metadata.uid !== uid || metadata.gid !== gid) chownSync(path, uid, gid);
  if (!metadata.isDirectory()) return;
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw new Error("Symbolic links are not permitted in managed Brain Atlas paths");
    applyVaultOwnership(resolve(path, entry.name), uid, gid);
  }
}

function releaseMetadata(release: BrainAtlasPinnedRelease): string {
  return `${JSON.stringify(release, null, 2)}\n`;
}

function releaseMatches(value: unknown, release: BrainAtlasPinnedRelease): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return canonical(value) === canonical(release);
}

function emptyRegionCounts(): Record<BrainAtlasRegion, number> {
  return Object.fromEntries(BRAIN_ATLAS_REGIONS.map((region) => [region, 0])) as Record<BrainAtlasRegion, number>;
}

export class ObsidianPluginManager {
  readonly #database: SqliteDatabase;
  readonly #paths: VaultPathPolicy;
  readonly #release: BrainAtlasPinnedRelease;
  readonly #clock: () => Date;

  constructor(options: {
    readonly database: SqliteDatabase;
    readonly pathPolicy: VaultPathPolicy;
    readonly release?: BrainAtlasPinnedRelease;
    readonly clock?: () => Date;
  }) {
    this.#database = options.database;
    this.#paths = options.pathPolicy;
    this.#release = options.release ?? BRAIN_ATLAS_PINNED_RELEASE;
    this.#clock = options.clock ?? (() => new Date());
  }

  /** Exact immutable release identity used by health, install, and handoff. */
  pinnedRelease(): BrainAtlasPinnedRelease {
    return this.#release;
  }

  #activeConnection(requestedId?: string): ConnectionRow | undefined {
    const activeId = activeAttackKnowledgeVaultPresetConnection(this.#database)?.id;
    if (!activeId || (requestedId && requestedId !== activeId)) return undefined;
    return this.#database.prepare(`
      SELECT id, vault_path, display_name, status, sync_scope_json
      FROM vault_connections WHERE id = ?
    `).get(activeId) as ConnectionRow | undefined;
  }

  #knowledge(connection: ConnectionRow | undefined): BrainAtlasPluginHealth["knowledge"] {
    const regionNodeCounts = emptyRegionCounts();
    if (!connection) return {
      nodeCount: 0,
      mappedNodeCount: 0,
      unmappedNodeCount: 0,
      typedEdgeCount: 0,
      uniqueUndirectedPairCount: 0,
      regionNodeCounts,
    };
    const scope = parseJsonObject(Buffer.from(connection.sync_scope_json), "Attack Knowledge Vault sync scope");
    const nodeTypes = Array.isArray(scope.nodeTypes) ? scope.nodeTypes.filter((value): value is string => typeof value === "string") : [];
    const lifecycles = Array.isArray(scope.lifecycleStatuses) ? scope.lifecycleStatuses.filter((value): value is string => typeof value === "string") : [];
    const sensitivities = Array.isArray(scope.sensitivities) ? scope.sensitivities.filter((value): value is string => typeof value === "string") : [];
    if (nodeTypes.length === 0 || lifecycles.length === 0 || sensitivities.length === 0) {
      return { nodeCount: 0, mappedNodeCount: 0, unmappedNodeCount: 0, typedEdgeCount: 0, uniqueUndirectedPairCount: 0, regionNodeCounts };
    }
    const placeholders = (values: readonly string[]): string => values.map(() => "?").join(",");
    const mapping = new Map(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((item) => [item.nodeType, item]));
    const attackNodeTypes = nodeTypes.filter((nodeType) => mapping.has(nodeType as never));
    const operatorId = vaultScopeIncludesOperatorProfile(scope)
      ? operatorProfileVaultOperatorId(scope)
      : undefined;
    const operatorProfileNodeIds = operatorId
      ? operatorProfileVaultEligibleNodeIds(this.#database, operatorId)
      : [];
    if (attackNodeTypes.length === 0 && operatorProfileNodeIds.length === 0) {
      return { nodeCount: 0, mappedNodeCount: 0, unmappedNodeCount: 0, typedEdgeCount: 0, uniqueUndirectedPairCount: 0, regionNodeCounts };
    }
    const rows = attackNodeTypes.length === 0
      ? []
      : this.#database.prepare(`
        SELECT node_type AS nodeType, COUNT(*) AS count
        FROM memory_nodes
        WHERE node_type IN (${placeholders(attackNodeTypes)})
          AND lifecycle_status IN (${placeholders(lifecycles)})
          AND sensitivity IN (${placeholders(sensitivities)})
          AND scope = 'global' AND engagement_id IS NULL AND mission_id IS NULL
        GROUP BY node_type
      `).all(...attackNodeTypes, ...lifecycles, ...sensitivities) as Array<{ nodeType: string; count: number }>;
    let nodeCount = 0;
    let mappedNodeCount = 0;
    for (const row of rows) {
      const count = Number(row.count);
      nodeCount += count;
      const item = mapping.get(row.nodeType as never);
      if (item) {
        mappedNodeCount += count;
        regionNodeCounts[item.region] += count;
      }
    }
    const operatorProfileRows = operatorProfileNodeIds.length === 0
      ? []
      : this.#database.prepare(`
        SELECT id, node_type AS nodeType
        FROM memory_nodes
        WHERE id IN (${placeholders(operatorProfileNodeIds)})
          AND lifecycle_status IN (${placeholders(lifecycles)})
          AND sensitivity IN (${placeholders(sensitivities)})
          AND scope = 'global' AND engagement_id IS NULL AND mission_id IS NULL
        ORDER BY id
      `).all(...operatorProfileNodeIds, ...lifecycles, ...sensitivities) as Array<{
        id: string;
        nodeType: string;
      }>;
    for (const row of operatorProfileRows) {
      nodeCount += 1;
      const item = operatorProfileBrainAtlasMapping(row);
      if (item) {
        mappedNodeCount += 1;
        regionNodeCounts[item.region] += 1;
      }
    }
    const eligibleClauses: string[] = [];
    const eligibleArguments: string[] = [];
    if (attackNodeTypes.length > 0) {
      eligibleClauses.push(`candidate.node_type IN (${placeholders(attackNodeTypes)})`);
      eligibleArguments.push(...attackNodeTypes);
    }
    if (operatorProfileNodeIds.length > 0) {
      eligibleClauses.push(`candidate.id IN (${placeholders(operatorProfileNodeIds)})`);
      eligibleArguments.push(...operatorProfileNodeIds);
    }
    const edge = this.#database.prepare(`
      WITH eligible AS (
        SELECT id FROM memory_nodes candidate
        WHERE (${eligibleClauses.join(" OR ")})
          AND lifecycle_status IN (${placeholders(lifecycles)})
          AND sensitivity IN (${placeholders(sensitivities)})
          AND scope = 'global' AND engagement_id IS NULL AND mission_id IS NULL
      )
      SELECT COUNT(*) AS typedEdgeCount,
        COUNT(DISTINCT CASE
          WHEN edge.source_node_id < edge.target_node_id
            THEN edge.source_node_id || char(0) || edge.target_node_id
          ELSE edge.target_node_id || char(0) || edge.source_node_id
        END) AS uniquePairCount
      FROM memory_edges_safe edge
      JOIN eligible source ON source.id = edge.source_node_id
      JOIN eligible target ON target.id = edge.target_node_id
      WHERE edge.lifecycle_status IN (${placeholders(lifecycles)})
        AND edge.sensitivity IN (${placeholders(sensitivities)})
        AND edge.scope = 'global'
    `).get(...eligibleArguments, ...lifecycles, ...sensitivities, ...lifecycles, ...sensitivities) as {
      typedEdgeCount: number;
      uniquePairCount: number;
    };
    return {
      nodeCount,
      mappedNodeCount,
      unmappedNodeCount: nodeCount - mappedNodeCount,
      typedEdgeCount: Number(edge.typedEdgeCount),
      uniqueUndirectedPairCount: Number(edge.uniquePairCount),
      regionNodeCounts,
    };
  }

  health(connectionId?: string): BrainAtlasPluginHealth {
    const checkedAt = this.#clock().toISOString();
    const issues: BrainAtlasHealthIssue[] = [];
    const connection = this.#activeConnection(connectionId);
    const assetHealth = Object.fromEntries(MANAGED_ASSET_NAMES.map((name) => [name, {
      expectedSha256: this.#release.assets[name], matches: false,
    }])) as Record<BrainAtlasAssetName, { expectedSha256: string; actualSha256?: string; matches: boolean }>;
    const licenseHealth: { expectedSha256: string; actualSha256?: string; matches: boolean } = {
      expectedSha256: this.#release.licenseFile.sha256,
      matches: false,
    };
    let installed = false;
    let enabled = false;
    let configurationValid = false;
    let configurationSha256: string | undefined;
    let operatorProfileMappingCount = 0;
    let kindMappingCount = 0;
    let regionMappingCount = 0;
    if (!connection) {
      issues.push({
        code: "attack_vault_not_connected",
        message: "No exact active Ti-Scale Attack Knowledge Vault connection exists.",
        remediation: "Activate the reviewed Attack Knowledge Vault preset before installing Brain Atlas.",
      });
    } else {
      if (connection.status !== "connected") issues.push({
        code: "attack_vault_not_healthy",
        message: `The Attack Knowledge Vault connection is ${connection.status}.`,
        remediation: "Restore the configured Vault and pass its filesystem round-trip before using the plugin.",
      });
      try {
        const root = this.#paths.resolveExistingVault(connection.vault_path);
        const pluginRoot = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}`);
        installed = existsSync(pluginRoot) && lstatSync(pluginRoot).isDirectory() && !lstatSync(pluginRoot).isSymbolicLink();
        if (!installed) issues.push({ code: "plugin_not_installed", message: "Brain Atlas is not installed in the active Vault.", remediation: "Install the exact pinned release from a locally verified asset bundle." });
        for (const name of MANAGED_ASSET_NAMES) {
          const path = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}/${name}`);
          if (!existsSync(path)) {
            issues.push({ code: "asset_missing", message: `Brain Atlas ${name} is missing.`, remediation: "Reinstall the exact pinned Brain Atlas release." });
            continue;
          }
          const actual = sha256(readRegularFile(path, `Brain Atlas ${name}`));
          assetHealth[name] = { expectedSha256: this.#release.assets[name], actualSha256: actual, matches: actual === this.#release.assets[name] };
          if (!assetHealth[name].matches) issues.push({ code: "asset_hash_mismatch", message: `Brain Atlas ${name} does not match the pinned release.`, remediation: "Stop using the changed plugin and reinstall the attested pinned release." });
        }
        const licensePath = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}/${this.#release.licenseFile.name}`);
        if (!existsSync(licensePath)) issues.push({ code: "license_missing", message: "Brain Atlas LICENSE is missing.", remediation: "Restore the pinned MIT license file before distributing the plugin." });
        else {
          const actual = sha256(readRegularFile(licensePath, "Brain Atlas LICENSE"));
          licenseHealth.actualSha256 = actual;
          licenseHealth.matches = actual === this.#release.licenseFile.sha256;
          if (!licenseHealth.matches) issues.push({ code: "license_hash_mismatch", message: "Brain Atlas LICENSE does not match the pinned source.", remediation: "Restore the reviewed MIT license file." });
        }
        const communityPath = this.#paths.resolveRelative(root, ".obsidian/community-plugins.json");
        enabled = parseCommunityPlugins(existsSync(communityPath) ? readRegularFile(communityPath, "Obsidian community plugin list", 256 * 1024) : undefined).includes(BRAIN_ATLAS_PLUGIN_ID);
        if (!enabled) issues.push({ code: "plugin_not_enabled", message: "Brain Atlas is installed but not enabled for this Vault.", remediation: "Enable Brain Atlas in Obsidian Community plugins or run the bounded installer." });

        const manifestPath = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}/manifest.json`);
        if (existsSync(manifestPath)) {
          const manifest = parseJsonObject(readRegularFile(manifestPath, "Brain Atlas manifest"), "Brain Atlas manifest");
          if (manifest.id !== BRAIN_ATLAS_PLUGIN_ID || manifest.version !== this.#release.version || manifest.minAppVersion !== this.#release.minimumObsidianVersion) {
            issues.push({ code: "manifest_invalid", message: "Brain Atlas manifest identity or version differs from the pin.", remediation: "Reinstall the pinned release and reload Obsidian." });
          }
        }
        const releasePath = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}/release.json`);
        if (!existsSync(releasePath) || !releaseMatches(parseJsonObject(readRegularFile(releasePath, "Brain Atlas release metadata"), "Brain Atlas release metadata"), this.#release)) {
          issues.push({ code: "release_metadata_invalid", message: "Installed Brain Atlas release provenance is missing or differs from the pin.", remediation: "Reconcile the plugin with the reviewed release metadata." });
        }
        const dataPath = this.#paths.resolveRelative(root, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}/data.json`);
        if (existsSync(dataPath)) {
          try {
            const data = parseJsonObject(readRegularFile(dataPath, "Brain Atlas configuration", 2 * 1024 * 1024), "Brain Atlas configuration");
            const validation = validateBrainAtlasConfiguration(data);
            configurationValid = true;
            configurationSha256 = brainAtlasConfigurationHash(data);
            operatorProfileMappingCount = validation.operatorProfileMappingCount;
            kindMappingCount = validation.kindMappingCount;
            regionMappingCount = validation.regionMappingCount;
          } catch {
            issues.push({ code: "configuration_invalid", message: "Brain Atlas configuration does not fully match Ti-Scale's reusable attack and consented Operator Profile taxonomy.", remediation: "Reconcile data.json through the bounded plugin manager; operator visual settings will be preserved." });
          }
        } else issues.push({ code: "configuration_invalid", message: "Brain Atlas data.json is missing.", remediation: "Generate the reviewed attack-taxonomy profile." });
      } catch {
        issues.push({ code: "plugin_not_installed", message: "Brain Atlas files could not be read safely from the configured Vault.", remediation: "Restore the Vault path and inspect regular-file permissions before retrying." });
      }
    }
    const healthy = Boolean(connection)
      && connection!.status === "connected"
      && installed
      && enabled
      && configurationValid
      && Object.values(assetHealth).every((item) => item.matches)
      && licenseHealth.matches
      && issues.length === 0;
    return {
      pluginId: BRAIN_ATLAS_PLUGIN_ID,
      expectedVersion: this.#release.version,
      status: healthy ? "healthy" : !connection ? "not_connected" : !installed ? "not_installed" : "degraded",
      healthy,
      installed,
      enabled,
      ...(connection ? { connection: { id: connection.id, displayName: connection.display_name, status: connection.status } } : {}),
      assets: assetHealth,
      license: licenseHealth,
      configuration: {
        valid: configurationValid,
        ...(configurationSha256 ? { sha256: configurationSha256 } : {}),
        registryNodeTypeCount: ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.length,
        operatorProfileMappingCount,
        kindMappingCount,
        regionMappingCount,
      },
      knowledge: this.#knowledge(connection),
      issues,
      checkedAt,
    };
  }

  installBrainAtlas(input: {
    readonly sourceDirectory: string;
    readonly actor: string;
    readonly connectionId?: string;
  }): BrainAtlasInstallResult {
    if (!isAbsolute(input.sourceDirectory)) throw new TypeError("Brain Atlas source directory must be absolute");
    if (!input.actor.trim()) throw new TypeError("Brain Atlas installer actor is required");
    const sourceRoot = resolve(input.sourceDirectory);
    const sourceMetadata = lstatSync(sourceRoot);
    if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isDirectory()) {
      throw new Error("Brain Atlas source must be a regular non-symbolic-link directory");
    }
    const sourceAssets = new Map<string, Buffer>();
    for (const name of MANAGED_ASSET_NAMES) {
      const path = resolve(sourceRoot, name);
      if (relative(sourceRoot, path).startsWith(`..${sep}`)) throw new Error("Brain Atlas source escapes its directory");
      const bytes = readRegularFile(path, `Brain Atlas source ${name}`);
      if (sha256(bytes) !== this.#release.assets[name]) throw new Error(`Brain Atlas source ${name} does not match the pinned release`);
      sourceAssets.set(name, bytes);
    }
    const sourceLicense = readRegularFile(resolve(sourceRoot, this.#release.licenseFile.name), "Brain Atlas source LICENSE");
    if (sha256(sourceLicense) !== this.#release.licenseFile.sha256) throw new Error("Brain Atlas source LICENSE does not match the reviewed license");
    const manifest = parseJsonObject(sourceAssets.get("manifest.json")!, "Brain Atlas source manifest");
    if (manifest.id !== BRAIN_ATLAS_PLUGIN_ID || manifest.version !== this.#release.version || manifest.minAppVersion !== this.#release.minimumObsidianVersion) {
      throw new Error("Brain Atlas source manifest does not match the pinned plugin identity");
    }

    const connection = this.#activeConnection(input.connectionId);
    if (!connection || connection.status !== "connected") throw new Error("An exact healthy Attack Knowledge Vault connection is required");
    const vaultRoot = this.#paths.resolveExistingVault(connection.vault_path);
    const vaultOwner = statSync(vaultRoot);
    const obsidianRoot = this.#paths.resolveRelative(vaultRoot, ".obsidian", true);
    mkdirSync(obsidianRoot, { recursive: true, mode: 0o700 });
    applyVaultOwnership(obsidianRoot, vaultOwner.uid, vaultOwner.gid);
    const pluginsRoot = this.#paths.resolveRelative(vaultRoot, ".obsidian/plugins", true);
    mkdirSync(pluginsRoot, { recursive: true, mode: 0o700 });
    applyVaultOwnership(pluginsRoot, vaultOwner.uid, vaultOwner.gid);
    const pluginRoot = this.#paths.resolveRelative(vaultRoot, `.obsidian/plugins/${BRAIN_ATLAS_PLUGIN_ID}`);
    const existingSnapshot = directorySnapshot(pluginRoot);
    const existingSnapshotHash = snapshotHash(existingSnapshot);
    const existingData = existingSnapshot.find((item) => item.relativePath === "data.json");
    const generatedData = serializeBrainAtlasConfiguration(existingData
      ? parseJsonObject(existingData.bytes, "Existing Brain Atlas configuration")
      : generateBrainAtlasConfiguration());
    const communityPath = this.#paths.resolveRelative(vaultRoot, ".obsidian/community-plugins.json", true);
    const communityBytes = existsSync(communityPath)
      ? readRegularFile(communityPath, "Obsidian community plugin list", 256 * 1024)
      : undefined;
    const communityPlugins = parseCommunityPlugins(communityBytes);
    const mergedCommunity = [...communityPlugins];
    if (!mergedCommunity.includes(BRAIN_ATLAS_PLUGIN_ID)) mergedCommunity.push(BRAIN_ATLAS_PLUGIN_ID);
    const mergedCommunityBytes = Buffer.from(`${JSON.stringify(mergedCommunity, null, 2)}\n`, "utf8");

    const nonce = randomUUID();
    const stage = this.#paths.resolveRelative(vaultRoot, `.obsidian/plugins/.brain-atlas.install-${nonce}`);
    mkdirSync(stage, { mode: 0o700 });
    try {
      for (const item of existingSnapshot) durableWrite(resolve(stage, item.relativePath), item.bytes);
      for (const name of MANAGED_ASSET_NAMES) {
        const destination = resolve(stage, name);
        if (existsSync(destination)) rmSync(destination, { force: true });
        durableWrite(destination, sourceAssets.get(name)!);
      }
      for (const [name, bytes] of [
        ["data.json", Buffer.from(generatedData, "utf8")],
        ["release.json", Buffer.from(releaseMetadata(this.#release), "utf8")],
        [this.#release.licenseFile.name, sourceLicense],
      ] as const) {
        const destination = resolve(stage, name);
        if (existsSync(destination)) rmSync(destination, { force: true });
        durableWrite(destination, bytes);
      }
      applyVaultOwnership(stage, vaultOwner.uid, vaultOwner.gid);
      fsyncDirectory(stage);
      const currentSnapshot = directorySnapshot(pluginRoot);
      if (snapshotHash(currentSnapshot) !== existingSnapshotHash) {
        throw new Error("Brain Atlas plugin changed while reconciliation was being prepared");
      }
      const existed = existsSync(pluginRoot);
      if (existed) {
        // Forward-only publication: remove the superseded plugin only after
        // the complete candidate is durable. Never retain a restorable
        // `.previous-*` directory, including on a later publication failure.
        rmSync(pluginRoot, { recursive: true, force: false });
        fsyncDirectory(pluginsRoot);
      }
      try {
        renameSync(stage, pluginRoot);
        fsyncDirectory(pluginsRoot);
        this.#paths.atomicWriteBytes(vaultRoot, ".obsidian/community-plugins.json", mergedCommunityBytes, communityBytes
          ? { exists: true, sha256: sha256(communityBytes) }
          : { exists: false });
        applyVaultOwnership(communityPath, vaultOwner.uid, vaultOwner.gid);
      } catch (error) {
        throw error;
      }
      if (existsSync(stage)) rmSync(stage, { recursive: true, force: true });
      fsyncDirectory(pluginsRoot);
      const installedAt = this.#clock().toISOString();
      const health = this.health(connection.id);
      if (!health.healthy) throw new Error("Brain Atlas installation completed but failed its read-only health verification");
      return {
        pluginId: BRAIN_ATLAS_PLUGIN_ID,
        version: this.#release.version,
        connectionId: connection.id,
        status: existed ? "updated" : "installed",
        enabled: true,
        preservedCommunityPluginCount: communityPlugins.filter((item) => item !== BRAIN_ATLAS_PLUGIN_ID).length,
        configurationSha256: brainAtlasConfigurationHash(JSON.parse(generatedData)),
        installedAt,
        health,
      };
    } finally {
      if (existsSync(stage)) rmSync(stage, { recursive: true, force: true });
    }
  }
}
