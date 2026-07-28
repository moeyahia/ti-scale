#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import {
  assertDatabaseIntegrity,
  createDatabaseConnection,
} from "../db";
import { MemoryRepository } from "../memory";
import { withCanonicalWriterLease } from "../maintenance";
import { redactLegacyText } from "../migration/SecretSafety";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../vault";
import { CanonicalMemoryReconciliationService } from "./CanonicalMemoryReconciliationService";

interface ParsedArguments {
  readonly command: string;
  readonly values: Map<string, string>;
  readonly flags: Set<string>;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
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
      values.set(key, next);
      index += 1;
    }
  }
  return { command, values, flags };
}

function usage(): string {
  return `Ti-Scale canonical Second Brain reconciliation

Usage:
  bun run server/brain-runtime/cli.ts reconcile [--db PATH] [--vault-root ROOT]
  bun run server/brain-runtime/cli.ts reconcile --execute [--db PATH] [--vault-root ROOT]

The default is a read-only dry run. Backups are disabled by operator policy.
--execute performs a forward-only reconciliation of Ti-Scale-owned
mission/run/evaluation anchors and a one-way Vault export. Vault-ahead edits
are never imported by this command. --backup-dir is rejected.
`;
}

export async function runCanonicalMemoryReconciliationCli(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
  write: (value: string) => void = (value) => process.stdout.write(value),
): Promise<number> {
  const args = parseArguments(argv);
  if (args.command === "help" || args.flags.has("help")) {
    write(usage());
    return 0;
  }
  if (args.command !== "reconcile") throw new Error(`Unknown reconciliation command: ${args.command}`);
  if (args.values.has("backup-dir") || args.flags.has("backup-dir")) {
    throw new Error("--backup-dir is unavailable because backups are disabled by operator policy");
  }
  const databasePath = resolveCliDatabasePath(args.values.get("db"), environment);
  const vaultRoot = resolveCliVaultRoot(args.values.get("vault-root"), environment);
  if (!existsSync(databasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
  const execute = args.flags.has("execute");
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: !execute,
    fileMustExist: true,
  });
  try {
    assertDatabaseIntegrity(database);
    const bridge = new ObsidianVaultBridge(
      database,
      new MemoryRepository(database),
      new VaultPathPolicy(vaultRoot),
    );
    const service = new CanonicalMemoryReconciliationService(
      database,
      new ConnectedVaultMemoryProjector(database, bridge),
    );
    if (!execute) {
      const analysis = service.analyze();
      write(`${JSON.stringify({ mode: "dry_run", analysis }, null, 2)}\n`);
      return analysis.conflicts.length > 0 ? 2 : 0;
    }
    const result = await withCanonicalWriterLease(database, {
      ownerId: "operator:canonical-memory-reconciliation",
      operation: "canonical-brain-reconciliation",
    }, async (handle, leases) => {
      leases.assertActive(handle);
      return service.reconcile();
    });
    const report = result;
    write(`${JSON.stringify({
      mode: "execute",
      backup: null,
      backupPolicy: "disabled_by_operator",
      report,
    }, null, 2)}\n`);
    return report.projection.failures > 0 || report.projection.attentionRequired > 0 ? 2 : 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runCanonicalMemoryReconciliationCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`Canonical memory reconciliation failed: ${redactLegacyText(
      error instanceof Error ? error.message : String(error),
      1_000,
    )}\n`);
    process.exitCode = 1;
  });
}
