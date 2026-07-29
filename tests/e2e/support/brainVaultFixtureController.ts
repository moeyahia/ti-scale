import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI_RESULT_PREFIX = "TI_SCALE_BRAIN_VAULT_FIXTURE=";
const PROCESS_ENTRY = fileURLToPath(new URL("./brainVaultFixture.ts", import.meta.url));
const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

export interface BrainVaultFixture {
  readonly namespace: string;
  readonly displayName: string;
  readonly relativePath: string;
  readonly baselineAuditRowId: number;
}

export interface BrainVaultOperationsFixture extends BrainVaultFixture {
  readonly engagementId: string;
  readonly nodeType: "attack_procedure" | "strategy" | "recovery_pattern" | "research";
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
  readonly originalProjectionExists: boolean;
  readonly quarantinedArtifactExists: boolean;
  readonly receiptExists: boolean;
  readonly originalProjectionHash?: string;
  readonly quarantinedArtifactHash?: string;
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
  readonly portableExports: readonly { archiveName: string; sha256: string; byteSize: number }[];
}

export interface BrainVaultProjectionState {
  readonly relativePath: string;
  readonly markdown: string;
  readonly note: {
    readonly id: string;
    readonly lifecycleStatus: string;
    readonly body: string;
    readonly aliases: readonly string[];
  };
}

export interface BrainVaultFixtureState {
  readonly connection?: { id: string; vault_path: string; status: string };
  readonly audits: readonly Record<string, unknown>[];
  readonly vaultDirectory: string;
  readonly temporaryHealthEntries: readonly string[];
}

function invokeFixture<T>(operation: string, input: unknown): T {
  const result = spawnSync("bun", ["run", PROCESS_ENTRY, operation, JSON.stringify(input)], {
    cwd: PROJECT_ROOT,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`Brain Vault fixture ${operation} failed with status ${String(result.status)}. ${result.stderr.trim()}`);
  }
  const line = result.stdout.split(/\r?\n/u).find((candidate) => candidate.startsWith(CLI_RESULT_PREFIX));
  if (!line) throw new Error(`Brain Vault fixture ${operation} returned no structured result. ${result.stdout.trim()}`);
  return JSON.parse(line.slice(CLI_RESULT_PREFIX.length)) as T;
}

export function createBrainVaultFixture(instanceId: string): BrainVaultFixture {
  return invokeFixture("create", instanceId);
}

export function createBrainVaultOperationsFixture(instanceId: string): BrainVaultOperationsFixture {
  return invokeFixture("create-operations", instanceId);
}

export function scopeBrainVaultConnection(fixture: BrainVaultOperationsFixture): string {
  return invokeFixture("scope", fixture);
}

export function readBrainVaultOperationsState(fixture: BrainVaultOperationsFixture): BrainVaultOperationsState {
  return invokeFixture("read-operations", fixture);
}

export function readBrainVaultProjection(
  fixture: BrainVaultOperationsFixture,
  nodeId: string,
): BrainVaultProjectionState {
  return invokeFixture("read-projection", { fixture, nodeId });
}

export function editBrainVaultProjection(
  fixture: BrainVaultOperationsFixture,
  nodeId: string,
  expectedBody: string,
  nextBody: string,
): string {
  return invokeFixture("edit-projection", { fixture, nodeId, expectedBody, nextBody });
}

export function correctBrainVaultCanonicalNode(
  fixture: BrainVaultOperationsFixture,
  nodeId: string,
  nextBody: string,
): number {
  return invokeFixture("correct-canonical", { fixture, nodeId, nextBody });
}

export function markBrainVaultConnectionDegraded(fixture: BrainVaultOperationsFixture): void {
  invokeFixture("mark-degraded", fixture);
}

export function markBrainVaultRecoveryRequired(
  fixture: BrainVaultOperationsFixture,
): { readonly status: "error"; readonly updatedAt: string } {
  return invokeFixture("mark-recovery-required", fixture);
}

export function damageBrainVaultForRecovery(fixture: BrainVaultOperationsFixture): {
  readonly outsideTargetPath: string;
  readonly symlinkPath: string;
  readonly malformedSourcePath: string;
  readonly malformedRelativePath: string;
  readonly malformedSourceText: string;
} {
  return invokeFixture("damage", fixture);
}

export function takeBrainVaultOffline(fixture: BrainVaultFixture): {
  readonly vaultPath: string;
  readonly detachedPath: string;
} {
  return invokeFixture("take-offline", fixture);
}

export function restoreBrainVaultOnline(paths: {
  readonly vaultPath: string;
  readonly detachedPath: string;
}): void {
  invokeFixture("restore-online", paths);
}

export function removeBrainVaultFixtureFiles(fixture: BrainVaultFixture): void {
  invokeFixture("remove-files", fixture);
}

export function readBrainVaultFixture(fixture: BrainVaultFixture): BrainVaultFixtureState {
  return invokeFixture("read", fixture);
}
