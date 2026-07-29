#!/usr/bin/env bun
import { existsSync, lstatSync } from "node:fs";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { MemoryRepository } from "../memory";
import { redactLegacyText } from "../migration/SecretSafety";
import { ObsidianVaultBridge } from "./ObsidianVaultBridge";
import { VaultPathPolicy } from "./VaultPathPolicy";
import { VaultProjectionReconciliationService } from "./VaultProjectionReconciliationService";

interface Arguments {
  readonly command: string;
  readonly values: ReadonlyMap<string, string>;
  readonly flags: ReadonlySet<string>;
}

function parseArguments(argv: readonly string[]): Arguments {
  const [command = "help", ...rest] = argv;
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) flags.add(key);
    else {
      if (values.has(key)) throw new Error(`--${key} may be supplied only once`);
      values.set(key, next);
      index += 1;
    }
  }
  return { command, values, flags };
}

function required(args: Arguments, key: string): string {
  const value = args.values.get(key)?.trim();
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function positiveInteger(args: Arguments, key: string, fallback: number): number {
  const raw = args.values.get(key);
  if (raw === undefined) return fallback;
  if (!/^\d+$/u.test(raw)) throw new TypeError(`--${key} must be a positive integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`--${key} must be a positive integer`);
  return value;
}

function usage(): string {
  return `Ti-Scale full eligible Obsidian Vault projection and reconciliation

Usage:
  bun run server/vault/vault-projection-reconciliation-cli.ts preview [--db PATH] [--vault-root ROOT] --connection ID
  bun run server/vault/vault-projection-reconciliation-cli.ts execute [--db PATH] [--vault-root ROOT] --connection ID
    --expected-plan-hash HASH --approved-by ACTOR --approve-projection [--concurrency N] [--progress-interval N] [--quiet]
  bun run server/vault/vault-projection-reconciliation-cli.ts reconcile [--db PATH] [--vault-root ROOT] --connection ID [--expected-plan-hash HASH]

Environment fallbacks:
  TI_SCALE_DATABASE_PATH
  TI_SCALE_VAULT_ROOT

Safety:
  preview and reconcile open SQLite read-only and never write Vault state.
  execute requires the exact reviewed plan hash, a connected Vault round-trip,
  and a canonical writer lease. Notes are individually atomic and resumable;
  operator edits become conflicts. A content-free, hash-bound 0600 receipt is
  written under .ti-scale/projection-receipts only after reconciliation.
`;
}

function configuredPaths(args: Arguments, environment: TiScaleCliEnvironment) {
  const databasePath = resolveCliDatabasePath(args.values.get("db"), environment);
  const vaultRoot = resolveCliVaultRoot(args.values.get("vault-root"), environment);
  if (!existsSync(databasePath) || !lstatSync(databasePath).isFile()) {
    throw new Error("Canonical database does not exist");
  }
  if (!existsSync(vaultRoot) || !lstatSync(vaultRoot).isDirectory()) {
    throw new Error("Vault sandbox root must be an existing directory");
  }
  return { databasePath, vaultRoot };
}

function serviceFor(
  database: ReturnType<typeof createDatabaseConnection>,
  vaultRoot: string,
): VaultProjectionReconciliationService {
  const paths = new VaultPathPolicy(vaultRoot);
  const bridge = new ObsidianVaultBridge(database, new MemoryRepository(database), paths);
  return new VaultProjectionReconciliationService(database, bridge, paths);
}

export async function runVaultProjectionReconciliationCli(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
): Promise<number> {
  const args = parseArguments(argv);
  if (args.command === "help" || args.flags.has("help")) {
    process.stdout.write(usage());
    return 0;
  }
  if (!["preview", "execute", "reconcile"].includes(args.command)) {
    throw new Error(`Unknown Vault projection command: ${args.command}`);
  }
  const paths = configuredPaths(args, environment);
  const connectionId = required(args, "connection");
  if (args.command === "preview" || args.command === "reconcile") {
    const database = createDatabaseConnection({
      filename: paths.databasePath,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      const service = serviceFor(database, paths.vaultRoot);
      if (args.command === "preview") {
        const preview = service.preview(connectionId);
        process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
        return preview.readyForExecution ? 0 : 2;
      }
      const reconciliation = service.reconcile(
        connectionId,
        args.values.get("expected-plan-hash")?.trim(),
      );
      process.stdout.write(`${JSON.stringify(reconciliation, null, 2)}\n`);
      return reconciliation.status === "complete" ? 0 : 2;
    } finally {
      database.close();
    }
  }

  if (!args.flags.has("approve-projection")) {
    throw new Error("Vault projection requires --approve-projection after reviewing preview");
  }
  const actorId = required(args, "approved-by");
  const database = createDatabaseConnection({
    filename: paths.databasePath,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = serviceFor(database, paths.vaultRoot);
    const receipt = await withCanonicalWriterLease(database, {
      ownerId: actorId,
      operation: "full-eligible-obsidian-projection",
    }, async (_handle, _leases, heartbeat) => service.execute({
      connectionId,
      expectedPlanHash: required(args, "expected-plan-hash"),
      approvedBy: actorId,
      exportOptions: {
        concurrency: positiveInteger(args, "concurrency", 8),
        progressInterval: positiveInteger(args, "progress-interval", 500),
        ...(!args.flags.has("quiet") ? {
          onProgress: (progress) => {
            heartbeat.assertActive();
            process.stderr.write(`${JSON.stringify({ event: "obsidian_projection_progress", ...progress })}\n`);
          },
        } : {}),
      },
    }));
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    return receipt.status === "completed" ? 0 : receipt.status === "attention_required" ? 2 : 1;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runVaultProjectionReconciliationCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`Vault projection failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`);
    process.exitCode = 1;
  });
}
