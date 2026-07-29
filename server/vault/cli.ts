#!/usr/bin/env bun
import { existsSync, lstatSync, readdirSync } from "node:fs";
import { relative, resolve } from "node:path";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { MemoryRepository } from "../memory";
import { withCanonicalWriterLease } from "../maintenance";
import { redactLegacyText } from "../migration/SecretSafety";
import {
  ObsidianVaultBridge,
  VaultBulkExportAbortError,
  VaultBulkExportPolicyError,
} from "./ObsidianVaultBridge";
import { VaultPathPolicy } from "./VaultPathPolicy";
import { ObsidianPluginManager } from "./ObsidianPluginManager";

interface Args {
  readonly command: string;
  readonly values: Map<string, string>;
  readonly flags: Set<string>;
}

function argumentsFor(argv: readonly string[]): Args {
  const [command = "help", ...rest] = argv;
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) flags.add(key);
    else { values.set(key, next); index += 1; }
  }
  return { command, values, flags };
}

function required(args: Args, key: string): string {
  const value = args.values.get(key);
  if (!value?.trim()) throw new Error(`--${key} is required`);
  return value;
}

function positiveInteger(args: Args, key: string, fallback: number): number {
  const source = args.values.get(key);
  if (source === undefined) return fallback;
  if (!/^\d+$/u.test(source)) throw new TypeError(`--${key} must be a positive integer`);
  const value = Number(source);
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`--${key} must be a positive integer`);
  return value;
}

function connectionId(database: ReturnType<typeof createDatabaseConnection>, requested?: string): string {
  if (requested) return requested;
  const rows = database.prepare("SELECT id FROM vault_connections ORDER BY updated_at DESC LIMIT 2").all() as Array<{ id: string }>;
  if (rows.length !== 1) throw new Error("--connection is required unless exactly one vault is connected");
  return rows[0]!.id;
}

function markdownFiles(policy: VaultPathPolicy, root: string): string[] {
  const results: string[] = [];
  const visit = (folder: string): void => {
    const absolute = folder ? policy.resolveRelative(root, folder) : root;
    for (const entry of readdirSync(absolute, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error("Symbolic links are not permitted in managed vaults");
      const relativePath = folder ? `${folder}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if ([".obsidian", ".ti-scale", "Attachments"].includes(entry.name)) continue;
        visit(relativePath);
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) results.push(relativePath);
    }
  };
  visit("");
  return results.sort();
}

function usage(): string {
  return `Ti-Scale Obsidian bridge CLI

Usage:
  bun run server/vault/cli.ts import [--db PATH] [--vault-root ROOT] [--connection ID] [--path NOTE] [--actor ID]
  bun run server/vault/cli.ts export [--db PATH] [--vault-root ROOT] [--connection ID] [--concurrency N] [--progress-interval N] [--quiet] [--actor ID]
  bun run server/vault/cli.ts sync-verify [--db PATH] [--vault-root ROOT] [--connection ID]
  bun run server/vault/cli.ts brain-atlas-health [--db PATH] [--vault-root ROOT] [--connection ID]
  bun run server/vault/cli.ts brain-atlas-install [--db PATH] [--vault-root ROOT] [--connection ID] --source DIR [--actor ID]

Environment fallbacks:
  TI_SCALE_DATABASE_PATH
  TI_SCALE_VAULT_ROOT

SQLite remains canonical. Backups and retained portable ZIPs are disabled by
operator policy; import runs
forward-only, inbox notes remain candidates, and conflicts are never overwritten. Import ignores
.obsidian. Export synchronizes canonical notes only and never creates an archive.
`;
}

export async function runVaultCli(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
): Promise<number> {
  const args = argumentsFor(argv);
  if (args.command === "help" || args.flags.has("help")) { process.stdout.write(usage()); return 0; }
  if (args.values.has("backup-dir")) {
    throw new Error("--backup-dir is unavailable because backups are disabled by operator policy");
  }
  if (args.flags.has("zip") || args.flags.has("brain-atlas")) {
    throw new Error("Portable Vault ZIP creation is disabled by operator no-backup policy");
  }
  const databasePath = resolveCliDatabasePath(args.values.get("db"), environment);
  if (!existsSync(databasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
  const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
  try {
    const policy = new VaultPathPolicy(resolveCliVaultRoot(args.values.get("vault-root"), environment));
    const bridge = new ObsidianVaultBridge(database, new MemoryRepository(database), policy);
    const plugins = new ObsidianPluginManager({ database, pathPolicy: policy });
    if (args.command === "brain-atlas-health") {
      const result = plugins.health(args.values.get("connection"));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return result.healthy ? 0 : 2;
    }
    const supportedWriterCommands = new Set([
      "brain-atlas-install",
      "import",
      "export",
      "sync-verify",
    ]);
    if (!supportedWriterCommands.has(args.command)) {
      throw new Error(`Unknown vault command: ${args.command}`);
    }
    const leaseActor = args.values.get("actor")?.trim() || "operator:cli";
    return await withCanonicalWriterLease(database, {
      ownerId: leaseActor,
      operation: `obsidian-${args.command}`,
    }, async (lease, leases) => {
      leases.assertActive(lease);
    if (args.command === "brain-atlas-install") {
      const result = plugins.installBrainAtlas({
        sourceDirectory: resolve(required(args, "source")),
        actor: args.values.get("actor")?.trim() || "operator:cli",
        ...(args.values.get("connection") ? { connectionId: args.values.get("connection") } : {}),
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return result.health.healthy ? 0 : 2;
    }
    const id = connectionId(database, args.values.get("connection"));
    const actor = args.values.get("actor")?.trim() || "operator:cli";
    const connection = bridge.requireConnection(id);
    if (relative(policy.allowedRoot, connection.vaultPath).startsWith("..")) throw new Error("Connected vault is outside --vault-root");

    if (args.command === "import") {
      bridge.assertVaultSyncAllowed();
      const paths = args.values.get("path") ? [required(args, "path")] : markdownFiles(policy, connection.vaultPath);
      const results = paths.map((path) => bridge.syncChangedPath(id, path, actor));
      process.stdout.write(`${JSON.stringify({
        backup: null,
        backupPolicy: "disabled_by_operator",
        processed: paths.length,
        results,
      }, null, 2)}\n`);
      return 0;
    }
    if (args.command === "export") {
      bridge.assertVaultSyncAllowed();
      const nodeIds = bridge.exportableNodeIds(id);
      const controller = new AbortController();
      const requestStop = (): void => controller.abort();
      process.once("SIGINT", requestStop);
      process.once("SIGTERM", requestStop);
      try {
        const result = await bridge.exportNodes(id, nodeIds, {
          concurrency: positiveInteger(args, "concurrency", 8),
          progressInterval: positiveInteger(args, "progress-interval", 500),
          signal: controller.signal,
          ...(!args.flags.has("quiet") ? {
            onProgress: (progress) => {
              process.stderr.write(`${JSON.stringify({ event: "obsidian_export_progress", ...progress })}\n`);
            },
          } : {}),
        });
        process.stdout.write(`${JSON.stringify({
          status: result.counts.failed > 0
            ? "failed"
            : result.counts.conflicts > 0 || result.counts.vaultAhead > 0 || result.counts.quarantined > 0
              ? "attention_required"
              : "completed",
          result,
        }, null, 2)}\n`);
        if (result.counts.failed > 0) return 1;
        return result.counts.conflicts > 0 || result.counts.vaultAhead > 0 || result.counts.quarantined > 0
          ? 2
          : 0;
      } catch (error) {
        if (error instanceof VaultBulkExportAbortError) {
          process.stdout.write(`${JSON.stringify({ status: "aborted", result: error.result }, null, 2)}\n`);
          return 130;
        }
        if (error instanceof VaultBulkExportPolicyError) {
          process.stdout.write(`${JSON.stringify({ status: "stopped_by_policy", result: error.result }, null, 2)}\n`);
          return 2;
        }
        throw error;
      } finally {
        process.off("SIGINT", requestStop);
        process.off("SIGTERM", requestStop);
      }
    }
    if (args.command === "sync-verify") {
      const result = bridge.verifyConnection(id);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return result.healthy ? 0 : 2;
    }
    throw new Error(`Unknown vault command: ${args.command}`);
    });
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runVaultCli().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`Obsidian bridge failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`);
    process.exitCode = 1;
  });
}
