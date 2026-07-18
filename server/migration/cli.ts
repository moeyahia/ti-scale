#!/usr/bin/env bun
import { existsSync, lstatSync } from "node:fs";
import { resolve } from "node:path";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import {
  checkDatabaseIntegrity,
  createDatabaseConnection,
  createTimestampedBackup,
} from "../db";
import { MemoryRepository } from "../memory";
import { ObsidianVaultBridge, VaultPathPolicy } from "../vault";
import { ApprovedLegacyVaultProjectionService } from "./ApprovedLegacyVaultProjectionService";
import { LegacyMigrationService, restoreMigrationBackup } from "./LegacyMigrationService";
import { redactLegacyText } from "./SecretSafety";

interface ParsedArguments {
  readonly command: string;
  readonly values: Map<string, string[]>;
  readonly flags: Set<string>;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  const [command = "help", ...rest] = argv;
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) {
      flags.add(key);
      continue;
    }
    values.set(key, [...(values.get(key) ?? []), next]);
    index += 1;
  }
  return { command, values, flags };
}

function required(args: ParsedArguments, key: string): string {
  const value = args.values.get(key)?.at(-1);
  if (!value) throw new Error(`--${key} is required`);
  return resolve(value);
}

function databasePath(args: ParsedArguments, environment: TiScaleCliEnvironment): string {
  return resolveCliDatabasePath(args.values.get("db")?.at(-1), environment);
}

function vaultRoot(args: ParsedArguments, environment: TiScaleCliEnvironment): string {
  return resolveCliVaultRoot(args.values.get("vault-root")?.at(-1), environment);
}

function requiredValue(args: ParsedArguments, key: string): string {
  const value = args.values.get(key)?.at(-1)?.trim();
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function help(): string {
  return `Ti-Scale data import and maintenance CLI

Usage:
  bun run server/migration/cli.ts migrate [--db PATH] [--source PARENT] [--engagement-root PATH] --output DIR [--dry-run] [--resume ID]
  bun run server/migration/cli.ts verify [--db PATH]
  bun run server/migration/cli.ts backup [--db PATH] --output DIR
  bun run server/migration/cli.ts reconcile [--db PATH] --migration-id ID
  bun run server/migration/cli.ts project-vault [--db PATH] [--vault-root ROOT] --migration-id ID --reconciliation-hash HASH --connection ID --dry-run
  bun run server/migration/cli.ts project-vault [--db PATH] [--vault-root ROOT] --migration-id ID --reconciliation-hash HASH --projection-hash HASH --connection ID --approved-by ACTOR --approve-projection
  bun run server/migration/cli.ts restore [--db PATH] --backup PATH --sha256 HASH --service-stopped

Environment fallbacks:
  TI_SCALE_DATABASE_PATH
  TI_SCALE_VAULT_ROOT (project-vault only)

Safety:
  migrate creates a verified database backup and protected source backup before import.
  --source imports safe child directories as engagements; --engagement-root imports that directory as one engagement.
  --dry-run performs discovery/hashing only and never changes the database.
  project-vault --dry-run is read-only and returns the exact projection hash.
  Vault writes require that hash plus --approve-projection and a fresh filesystem round-trip.
  restore refuses to run without --service-stopped.
`;
}

async function main(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
): Promise<number> {
  const args = parseArguments(argv);
  if (args.command === "help" || args.flags.has("help")) {
    process.stdout.write(help());
    return 0;
  }
  if (args.command === "project-vault") {
    const dryRun = args.flags.has("dry-run");
    if (!dryRun && !args.flags.has("approve-projection")) {
      throw new Error("Vault projection requires --approve-projection after reviewing a dry-run preview");
    }
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const configuredVaultRoot = vaultRoot(args, environment);
    if (!existsSync(configuredVaultRoot) || !lstatSync(configuredVaultRoot).isDirectory()) {
      throw new Error("--vault-root must be an existing directory; projection never creates an operator sandbox root");
    }
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      readonly: dryRun,
      fileMustExist: true,
    });
    try {
      const bridge = new ObsidianVaultBridge(
        database,
        new MemoryRepository(database),
        new VaultPathPolicy(configuredVaultRoot),
      );
      const service = new ApprovedLegacyVaultProjectionService(database, bridge);
      const previewInput = {
        migrationId: requiredValue(args, "migration-id"),
        expectedReconciliationHash: requiredValue(args, "reconciliation-hash"),
        connectionId: requiredValue(args, "connection"),
      };
      const preview = service.preview(previewInput);
      if (dryRun) {
        process.stdout.write(`${JSON.stringify({
          status: preview.eligibleNodeCount > 0 ? "ready_for_approval" : "no_eligible_nodes",
          dryRun: true,
          migrationId: preview.migrationId,
          reconciliationHash: preview.reconciliationHash,
          projectionHash: preview.projectionHash,
          connection: {
            id: preview.connectionId,
            displayName: preview.connectionDisplayName,
          },
          counts: {
            mapped: preview.mappedNodeCount,
            eligible: preview.eligibleNodeCount,
            excludedByPolicyOrConnectionScope: preview.excludedNodeCount,
          },
        }, null, 2)}\n`);
        return preview.eligibleNodeCount > 0 ? 0 : 2;
      }
      const result = await service.project({
        ...previewInput,
        expectedProjectionHash: requiredValue(args, "projection-hash"),
        approvedBy: requiredValue(args, "approved-by"),
      });
      const attentionRequired = result.export.counts.conflicts > 0
        || result.export.counts.vaultAhead > 0
        || result.export.counts.quarantined > 0;
      const failed = result.export.counts.failed > 0;
      process.stdout.write(`${JSON.stringify({
        status: failed ? "failed" : attentionRequired ? "attention_required" : "completed",
        dryRun: false,
        approvalId: result.approvalId,
        migrationId: preview.migrationId,
        reconciliationHash: preview.reconciliationHash,
        projectionHash: result.projectionHash,
        projectedNodes: result.projectedNodeIds.length,
        export: result.export,
      }, null, 2)}\n`);
      return failed ? 1 : attentionRequired ? 2 : 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "migrate") {
    const roots = args.values.get("source") ?? [];
    const engagementRoots = args.values.get("engagement-root") ?? [];
    if (!roots.length && !engagementRoots.length) {
      throw new Error("At least one --source or --engagement-root path is required");
    }
    const result = await new LegacyMigrationService({
      databasePath: databasePath(args, environment),
      sourceRoots: roots.map((root) => resolve(root)),
      engagementRoots: engagementRoots.map((root) => resolve(root)),
      outputDirectory: required(args, "output"),
      dryRun: args.flags.has("dry-run"),
      ...(args.values.get("resume")?.at(-1) ? { resumeMigrationId: args.values.get("resume")!.at(-1)! } : {}),
    }).run();
    process.stdout.write(`${JSON.stringify({ migrationId: result.migrationId, reportPath: result.reportPath, counts: result.report.counts }, null, 2)}\n`);
    return 0;
  }
  if (args.command === "verify") {
    const database = createDatabaseConnection({ filename: databasePath(args, environment), readonly: true, fileMustExist: true });
    try {
      const integrity = checkDatabaseIntegrity(database);
      const foreignKeys = database.pragma("foreign_key_check") as unknown[];
      process.stdout.write(`${JSON.stringify({ integrity, foreignKeyViolations: foreignKeys.length }, null, 2)}\n`);
      return integrity.ok && foreignKeys.length === 0 ? 0 : 2;
    } finally { database.close(); }
  }
  if (args.command === "backup") {
    const database = createDatabaseConnection({ filename: databasePath(args, environment), readonly: true, fileMustExist: true });
    try {
      const result = await createTimestampedBackup(database, required(args, "output"), "ti-scale-manual");
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally { database.close(); }
  }
  if (args.command === "reconcile") {
    const database = createDatabaseConnection({ filename: databasePath(args, environment), readonly: true, fileMustExist: true });
    try {
      const migrationId = args.values.get("migration-id")?.at(-1);
      if (!migrationId) throw new Error("--migration-id is required");
      const row = database.prepare(`
        SELECT report_json, report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(migrationId) as { report_json: string; report_hash: string } | undefined;
      if (!row) throw new Error(`No reconciliation report exists for ${migrationId}`);
      process.stdout.write(`${JSON.stringify({ reportHash: row.report_hash, report: JSON.parse(row.report_json) }, null, 2)}\n`);
      return 0;
    } finally { database.close(); }
  }
  if (args.command === "restore") {
    const sha256 = args.values.get("sha256")?.at(-1);
    if (!sha256 || !/^[a-f0-9]{64}$/iu.test(sha256)) throw new Error("--sha256 must be a 64-character SHA-256");
    await restoreMigrationBackup({
      databasePath: databasePath(args, environment),
      backupPath: required(args, "backup"),
      expectedSha256: sha256.toLowerCase(),
      serviceStopped: args.flags.has("service-stopped"),
    });
    process.stdout.write("Database restored and checksum verified.\n");
    return 0;
  }
  throw new Error(`Unknown command: ${args.command}`);
}

if (import.meta.main) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`Migration failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`);
    process.exitCode = 1;
  });
}

export { main as runMigrationCli };
