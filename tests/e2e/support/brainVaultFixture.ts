import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { parseObsidianNote } from "../../../server/vault";
import { E2E_DATABASE_PATH, E2E_VAULT_ROOT } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T22:00:00.000Z";

export interface BrainVaultFixture {
  readonly namespace: string;
  readonly displayName: string;
  readonly relativePath: string;
  readonly baselineAuditRowId: number;
}

export interface BrainVaultOperationsFixture extends BrainVaultFixture {
  readonly engagementId: string;
  readonly importNodeId: string;
  readonly databaseResolutionNodeId: string;
  readonly vaultResolutionNodeId: string;
  readonly importInitialBody: string;
  readonly importVaultBody: string;
  readonly importCanonicalBody: string;
  readonly databaseInitialBody: string;
  readonly databaseVaultBody: string;
  readonly databaseCanonicalBody: string;
  readonly vaultInitialBody: string;
  readonly vaultVaultBody: string;
  readonly vaultCanonicalBody: string;
}

export interface BrainVaultNodeState {
  readonly id: string;
  readonly body: string;
  readonly version: number;
  readonly relativePath?: string;
  readonly syncStatus?: string;
  readonly projectedBody?: string;
}

export interface BrainVaultQuarantineState {
  readonly syncStateId: string;
  readonly nodeId: string | null;
  readonly sourceRelativePath: string;
  readonly status: "quarantined";
  readonly errorMessage?: string;
  readonly intentId?: string;
  readonly intentStatus?: "planned" | "recovery_required" | "committed";
  readonly sourceContentHash?: string;
  readonly quarantineRelative?: string;
  readonly markerRelative?: string;
  readonly sourceExists: boolean;
  readonly copyExists: boolean;
  readonly receiptExists: boolean;
  readonly sourceHash?: string;
  readonly copyHash?: string;
  readonly receipt?: {
    readonly intentId: string;
    readonly sourceContentHash: string;
    readonly quarantineRelative: string;
  };
}

export interface BrainVaultOperationsState {
  readonly connection: { id: string; vaultPath: string; status: string; lastSyncAt: string | null };
  readonly nodes: readonly BrainVaultNodeState[];
  readonly quarantines: readonly BrainVaultQuarantineState[];
  readonly conflicts: readonly {
    id: string;
    nodeId: string | null;
    status: string;
    resolution: string | null;
  }[];
  readonly portableExports: readonly {
    archiveName: string;
    sha256: string;
    byteSize: number;
  }[];
}

export function createBrainVaultFixture(instanceId: string): BrainVaultFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const audit = database.prepare("SELECT COALESCE(MAX(rowid), 0) AS rowId FROM audit_records").get() as { rowId: number };
    return {
      namespace,
      displayName: `Disposable Vault ${namespace}`,
      relativePath: `Disposable-Vault-${namespace}`,
      baselineAuditRowId: audit.rowId,
    };
  } finally {
    database.close();
  }
}

/**
 * Seeds only canonical memory. The browser still has to grant filesystem
 * permission, prove the round trip, connect the Vault, and invoke every
 * projection/import/conflict mutation through the real V2 API.
 */
export function createBrainVaultOperationsFixture(instanceId: string): BrainVaultOperationsFixture {
  const base = createBrainVaultFixture(instanceId);
  const engagementId = `eng-vault-${base.namespace}`;
  const importNodeId = `mem-vault-import-${base.namespace}`;
  const databaseResolutionNodeId = `mem-vault-keep-db-${base.namespace}`;
  const vaultResolutionNodeId = `mem-vault-keep-vault-${base.namespace}`;
  const bodies = {
    importInitialBody: `Initial operator-import projection ${base.namespace}.`,
    importVaultBody: `Operator edited this note in Obsidian ${base.namespace}.`,
    importCanonicalBody: `Canonical follow-up after the imported edit ${base.namespace}.`,
    databaseInitialBody: `Initial database-resolution projection ${base.namespace}.`,
    databaseVaultBody: `Concurrent Obsidian edit that will lose deliberately ${base.namespace}.`,
    databaseCanonicalBody: `Concurrent canonical edit selected deliberately ${base.namespace}.`,
    vaultInitialBody: `Initial vault-resolution projection ${base.namespace}.`,
    vaultVaultBody: `Concurrent Obsidian edit selected deliberately ${base.namespace}.`,
    vaultCanonicalBody: `Concurrent canonical edit that will lose deliberately ${base.namespace}.`,
  } as const;
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    let sequence = 0;
    const repository = new MemoryRepository(database, {
      clock: () => new Date(FIXTURE_TIME),
      createId: (prefix) => `${prefix}_vault_e2e_${base.namespace}_${++sequence}`,
    });
    const definitions = [
      { id: importNodeId, title: `Operator import ${base.namespace}`, body: bodies.importInitialBody },
      { id: databaseResolutionNodeId, title: `Keep database ${base.namespace}`, body: bodies.databaseInitialBody },
      { id: vaultResolutionNodeId, title: `Keep Obsidian ${base.namespace}`, body: bodies.vaultInitialBody },
    ] as const;
    for (const definition of definitions) {
      repository.createNode({
        id: definition.id,
        nodeType: "procedure",
        title: definition.title,
        summary: "Isolated canonical Vault browser fixture with explicit operator provenance.",
        body: definition.body,
        scope: { kind: "engagement", engagementId },
        sensitivity: "internal",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "A deterministic isolated browser fixture supplied this non-sensitive Vault note.",
          sources: [{
            sourceType: "e2e_fixture",
            sourceId: `vault-source-${definition.id}`,
            acquiredAt: FIXTURE_TIME,
            excerptRedacted: "Sanitized Vault projection fixture.",
          }],
        },
        authorType: "operator",
        authorId: "e2e-local-operator",
        retentionPolicy: { allowGuided: true, allowAutonomous: true },
      });
    }
  } finally {
    database.close();
  }
  return {
    ...base,
    engagementId,
    importNodeId,
    databaseResolutionNodeId,
    vaultResolutionNodeId,
    ...bodies,
  };
}

function requireConnection(
  database: ReturnType<typeof createDatabaseConnection>,
  fixture: BrainVaultFixture,
): { id: string; vault_path: string; status: string; last_sync_at: string | null } {
  const connection = database.prepare(`
    SELECT id, vault_path, status, last_sync_at
    FROM vault_connections WHERE display_name = ?
  `).get(fixture.displayName) as {
    id: string;
    vault_path: string;
    status: string;
    last_sync_at: string | null;
  } | undefined;
  if (!connection) throw new Error(`Vault connection is missing for fixture ${fixture.namespace}`);
  return connection;
}

/** Restricts bulk UI actions to this fixture's engagement before any export. */
export function scopeBrainVaultConnection(fixture: BrainVaultOperationsFixture): string {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const connection = requireConnection(database, fixture);
    const result = database.prepare(`
      UPDATE vault_connections SET sync_scope_json = ?, updated_at = ? WHERE id = ?
    `).run(JSON.stringify({
      lifecycleStatuses: ["confirmed"],
      engagementIds: [fixture.engagementId],
    }), new Date().toISOString(), connection.id);
    if (result.changes !== 1) throw new Error("Vault connection scope was not updated exactly once");
    return connection.id;
  } finally {
    database.close();
  }
}

function noteState(
  database: ReturnType<typeof createDatabaseConnection>,
  connection: { id: string; vault_path: string },
  nodeId: string,
): BrainVaultNodeState {
  const node = database.prepare(`SELECT id, body, version FROM memory_nodes WHERE id = ?`).get(nodeId) as {
    id: string;
    body: string;
    version: number;
  } | undefined;
  if (!node) throw new Error(`Vault fixture node is missing: ${nodeId}`);
  const sync = database.prepare(`
    SELECT relative_path, status FROM vault_sync_state
    WHERE connection_id = ? AND node_id = ?
  `).get(connection.id, nodeId) as { relative_path: string; status: string } | undefined;
  const projectionPath = sync ? join(connection.vault_path, sync.relative_path) : undefined;
  const projectedBody = projectionPath && existsSync(projectionPath)
    ? parseObsidianNote(readFileSync(projectionPath, "utf8")).body
    : undefined;
  return {
    id: node.id,
    body: node.body,
    version: Number(node.version),
    ...(sync ? { relativePath: sync.relative_path, syncStatus: sync.status } : {}),
    ...(projectedBody !== undefined ? { projectedBody } : {}),
  };
}

function hashFile(path: string): string | undefined {
  return existsSync(path)
    ? createHash("sha256").update(readFileSync(path)).digest("hex")
    : undefined;
}

export function readBrainVaultOperationsState(
  fixture: BrainVaultOperationsFixture,
): BrainVaultOperationsState {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const connection = requireConnection(database, fixture);
    const conflicts = database.prepare(`
      SELECT id, node_id, status, resolution_reason FROM vault_conflicts
      WHERE connection_id = ? ORDER BY created_at, id
    `).all(connection.id) as Array<{
      id: string;
      node_id: string | null;
      status: string;
      resolution_reason: string | null;
    }>;
    const quarantineRows = database.prepare(`
      SELECT id, node_id, relative_path, status, vault_content_hash, error_message
      FROM vault_sync_state
      WHERE connection_id = ? AND status = 'quarantined'
      ORDER BY last_scanned_at, id
    `).all(connection.id) as Array<{
      id: string;
      node_id: string | null;
      relative_path: string;
      status: "quarantined";
      vault_content_hash: string | null;
      error_message: string | null;
    }>;
    const quarantineIntents = (database.prepare(`
      SELECT value_json FROM settings
      WHERE key LIKE 'brain.vault.quarantine_intent.%'
      ORDER BY updated_at, key
    `).all() as Array<{ value_json: string }>).flatMap((item) => {
      const value = JSON.parse(item.value_json) as {
        id?: unknown;
        connectionId?: unknown;
        syncStateId?: unknown;
        status?: unknown;
        sourceContentHash?: unknown;
        quarantineRelative?: unknown;
        markerRelative?: unknown;
      };
      return value.connectionId === connection.id
        && typeof value.id === "string"
        && typeof value.syncStateId === "string"
        && ["planned", "recovery_required", "committed"].includes(String(value.status))
        && typeof value.sourceContentHash === "string"
        && typeof value.quarantineRelative === "string"
        && typeof value.markerRelative === "string"
        ? [{
          id: value.id,
          syncStateId: value.syncStateId,
          status: value.status as "planned" | "recovery_required" | "committed",
          sourceContentHash: value.sourceContentHash,
          quarantineRelative: value.quarantineRelative,
          markerRelative: value.markerRelative,
        }]
        : [];
    });
    const portableExports = (database.prepare(`
      SELECT value_json FROM settings
      WHERE key LIKE 'brain.portable_export.authorization.%'
      ORDER BY updated_at, key
    `).all() as Array<{ value_json: string }>).flatMap((item) => {
      const value = JSON.parse(item.value_json) as {
        connectionId?: unknown;
        archiveName?: unknown;
        sha256?: unknown;
        byteSize?: unknown;
      };
      return value.connectionId === connection.id
        && typeof value.archiveName === "string"
        && typeof value.sha256 === "string"
        && typeof value.byteSize === "number"
        ? [{ archive_name: value.archiveName, sha256: value.sha256, byte_size: value.byteSize }]
        : [];
    });
    return {
      connection: {
        id: connection.id,
        vaultPath: connection.vault_path,
        status: connection.status,
        lastSyncAt: connection.last_sync_at,
      },
      nodes: [fixture.importNodeId, fixture.databaseResolutionNodeId, fixture.vaultResolutionNodeId]
        .map((nodeId) => noteState(database, connection, nodeId)),
      quarantines: quarantineRows.map((item): BrainVaultQuarantineState => {
        const intent = quarantineIntents.find((candidate) => candidate.syncStateId === item.id);
        const sourcePath = join(connection.vault_path, item.relative_path);
        const copyPath = intent ? join(connection.vault_path, intent.quarantineRelative) : undefined;
        const markerPath = intent ? join(connection.vault_path, intent.markerRelative) : undefined;
        const receipt = markerPath && existsSync(markerPath)
          ? JSON.parse(readFileSync(markerPath, "utf8")) as {
            intentId?: unknown;
            sourceContentHash?: unknown;
            quarantineRelative?: unknown;
          }
          : undefined;
        const parsedReceipt = receipt
          && typeof receipt.intentId === "string"
          && typeof receipt.sourceContentHash === "string"
          && typeof receipt.quarantineRelative === "string"
          ? {
            intentId: receipt.intentId,
            sourceContentHash: receipt.sourceContentHash,
            quarantineRelative: receipt.quarantineRelative,
          }
          : undefined;
        return {
          syncStateId: item.id,
          nodeId: item.node_id,
          sourceRelativePath: item.relative_path,
          status: item.status,
          ...(item.error_message ? { errorMessage: item.error_message } : {}),
          ...(intent ? {
            intentId: intent.id,
            intentStatus: intent.status,
            sourceContentHash: intent.sourceContentHash,
            quarantineRelative: intent.quarantineRelative,
            markerRelative: intent.markerRelative,
          } : item.vault_content_hash ? { sourceContentHash: item.vault_content_hash } : {}),
          sourceExists: existsSync(sourcePath),
          copyExists: Boolean(copyPath && existsSync(copyPath)),
          receiptExists: Boolean(markerPath && existsSync(markerPath)),
          ...(hashFile(sourcePath) ? { sourceHash: hashFile(sourcePath) } : {}),
          ...(copyPath && hashFile(copyPath) ? { copyHash: hashFile(copyPath) } : {}),
          ...(parsedReceipt ? { receipt: parsedReceipt } : {}),
        };
      }),
      conflicts: conflicts.map((item) => ({
        id: item.id,
        nodeId: item.node_id,
        status: item.status,
        resolution: item.resolution_reason,
      })),
      portableExports: portableExports.map((item) => ({
        archiveName: item.archive_name,
        sha256: item.sha256,
        byteSize: Number(item.byte_size),
      })),
    };
  } finally {
    database.close();
  }
}

export function editBrainVaultProjection(
  fixture: BrainVaultOperationsFixture,
  nodeId: string,
  expectedBody: string,
  nextBody: string,
): string {
  const state = readBrainVaultOperationsState(fixture);
  const node = state.nodes.find((item) => item.id === nodeId);
  if (!node?.relativePath) throw new Error(`Vault fixture projection is missing: ${nodeId}`);
  const path = join(state.connection.vaultPath, node.relativePath);
  const text = readFileSync(path, "utf8");
  const parsed = parseObsidianNote(text);
  if (parsed.body !== expectedBody) {
    throw new Error(`Vault fixture body did not match before edit: ${nodeId}`);
  }
  writeFileSync(path, text.replace(expectedBody, nextBody), { encoding: "utf8", mode: 0o600 });
  return node.relativePath;
}

export function correctBrainVaultCanonicalNode(
  fixture: BrainVaultOperationsFixture,
  nodeId: string,
  nextBody: string,
): number {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const corrected = new MemoryRepository(database).correctNode(nodeId, {
      body: nextBody,
      authorType: "operator",
      authorId: "e2e-local-operator",
      changeReason: `Isolated Vault browser fixture ${fixture.namespace}`,
    });
    return corrected.version;
  } finally {
    database.close();
  }
}

export function markBrainVaultConnectionDegraded(fixture: BrainVaultOperationsFixture): void {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const connection = requireConnection(database, fixture);
    const result = database.prepare(`
      UPDATE vault_connections SET status = 'degraded', updated_at = ? WHERE id = ?
    `).run(new Date().toISOString(), connection.id);
    if (result.changes !== 1) throw new Error("Vault connection was not marked degraded exactly once");
  } finally {
    database.close();
  }
}

export function damageBrainVaultForRecovery(fixture: BrainVaultOperationsFixture): {
  readonly outsideTargetPath: string;
  readonly symlinkPath: string;
  readonly malformedSourcePath: string;
  readonly malformedRelativePath: string;
  readonly malformedSourceText: string;
} {
  const state = readBrainVaultOperationsState(fixture);
  const malformed = state.nodes.find((item) => item.id === fixture.importNodeId);
  const missing = state.nodes.find((item) => item.id === fixture.databaseResolutionNodeId);
  if (!malformed?.relativePath || !missing?.relativePath) {
    throw new Error("Vault recovery fixture projections must be exported before damage");
  }
  const malformedSourcePath = join(state.connection.vaultPath, malformed.relativePath);
  const malformedSourceText = "malformed managed note without YAML frontmatter\noperator bytes remain quarantinable\n";
  writeFileSync(
    malformedSourcePath,
    malformedSourceText,
    { encoding: "utf8", mode: 0o600 },
  );
  rmSync(join(state.connection.vaultPath, missing.relativePath));
  const outsideTargetPath = join(state.connection.vaultPath, ".ti-scale", "recovery-symlink-target.txt");
  const symlinkPath = join(state.connection.vaultPath, "10 Operator", `recovery-link-${fixture.namespace}.md`);
  writeFileSync(outsideTargetPath, "outside symlink target must remain unchanged", { encoding: "utf8", mode: 0o600 });
  symlinkSync(outsideTargetPath, symlinkPath);
  return {
    outsideTargetPath,
    symlinkPath,
    malformedSourcePath,
    malformedRelativePath: malformed.relativePath,
    malformedSourceText,
  };
}

export function takeBrainVaultOffline(fixture: BrainVaultFixture): {
  readonly vaultPath: string;
  readonly backupPath: string;
} {
  const vaultPath = join(E2E_VAULT_ROOT, fixture.relativePath);
  const backupPath = join(E2E_VAULT_ROOT, `${fixture.relativePath}.offline-${fixture.namespace}`);
  if (existsSync(backupPath)) rmSync(backupPath, { recursive: true, force: true });
  renameSync(vaultPath, backupPath);
  return { vaultPath, backupPath };
}

export function restoreBrainVaultOnline(paths: { readonly vaultPath: string; readonly backupPath: string }): void {
  if (existsSync(paths.vaultPath)) rmSync(paths.vaultPath, { recursive: true, force: true });
  renameSync(paths.backupPath, paths.vaultPath);
}

export function removeBrainVaultFixtureFiles(fixture: BrainVaultFixture): void {
  rmSync(join(E2E_VAULT_ROOT, fixture.relativePath), { recursive: true, force: true });
  const backup = join(E2E_VAULT_ROOT, `${fixture.relativePath}.offline-${fixture.namespace}`);
  if (existsSync(backup)) rmSync(backup, { recursive: true, force: true });
}

export function readBrainVaultFixture(fixture: BrainVaultFixture) {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Vault E2E requires the isolated V2 database path");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const connection = database.prepare(`
      SELECT id, vault_path, status FROM vault_connections WHERE display_name = ?
    `).get(fixture.displayName) as { id: string; vault_path: string; status: string } | undefined;
    const candidateFingerprint = createHash("sha256")
      .update(`vault-path:${fixture.relativePath}`, "utf8")
      .digest("hex");
    const audits = database.prepare(`
      SELECT action, resource_type, resource_id, details_json, previous_hash, record_hash
      FROM audit_records WHERE rowid > ?
        AND action IN ('vault.health.verified', 'vault.connection.connected')
        AND resource_id IN (?, ?)
      ORDER BY rowid
    `).all(fixture.baselineAuditRowId, candidateFingerprint, connection?.id ?? "") as Array<Record<string, unknown>>;
    const vaultDirectory = join(E2E_VAULT_ROOT, fixture.relativePath);
    const temporaryHealthEntries = existsSync(vaultDirectory)
      ? readdirSync(vaultDirectory).filter((entry) => entry.startsWith(".ti-scale-health-"))
      : [];
    return { connection, audits, vaultDirectory, temporaryHealthEntries };
  } finally {
    database.close();
  }
}
