import { resolve } from "node:path";
import { createDatabaseConnection } from "../db";
import { HistoricalReportedOutcomeClassificationService } from
  "./HistoricalReportedOutcomeClassificationService";

type Command = "preview" | "apply";

interface CliArguments {
  readonly command: Command;
  readonly databasePath: string;
  readonly cursor?: string;
  readonly maxRecords?: number;
  readonly expectedPreviewHash?: string;
  readonly actorId?: string;
  readonly reason?: string;
  readonly acknowledgeReportedOnly: boolean;
  readonly dryRun: boolean;
}

function parseInteger(value: string | undefined, label: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new TypeError(`${label} must be an integer`);
  return parsed;
}

function parseArguments(argv: readonly string[]): CliArguments {
  const command = argv[0];
  if (command !== "preview" && command !== "apply") {
    throw new TypeError("Usage: historical-reported-outcome-cli.ts <preview|apply> --db PATH");
  }
  const values = new Map<string, string>();
  const flags = new Set<string>();
  const valueOptions = new Set([
    "--db", "--cursor", "--max-records", "--expected-preview-hash", "--actor", "--reason",
  ]);
  const flagOptions = new Set(["--dry-run", "--acknowledge-reported-only"]);
  for (let index = 1; index < argv.length; index += 1) {
    const option = argv[index]!;
    if (flagOptions.has(option)) {
      if (flags.has(option)) throw new TypeError(`Duplicate option: ${option}`);
      flags.add(option);
      continue;
    }
    if (!valueOptions.has(option)) throw new TypeError(`Unknown option: ${option}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new TypeError(`${option} requires a value`);
    if (values.has(option)) throw new TypeError(`Duplicate option: ${option}`);
    values.set(option, value);
    index += 1;
  }
  const databasePath = values.get("--db");
  if (!databasePath) throw new TypeError("--db is required");
  if (command === "preview" && !flags.has("--dry-run")) {
    throw new TypeError("preview requires --dry-run");
  }
  if (command === "apply" && flags.has("--dry-run")) {
    throw new TypeError("apply does not accept --dry-run");
  }
  const maxRecords = parseInteger(values.get("--max-records"), "--max-records");
  return {
    command,
    databasePath: resolve(databasePath),
    ...(values.get("--cursor") ? { cursor: values.get("--cursor") } : {}),
    ...(maxRecords === undefined ? {} : { maxRecords }),
    ...(values.get("--expected-preview-hash")
      ? { expectedPreviewHash: values.get("--expected-preview-hash") }
      : {}),
    ...(values.get("--actor") ? { actorId: values.get("--actor") } : {}),
    ...(values.get("--reason") ? { reason: values.get("--reason") } : {}),
    acknowledgeReportedOnly: flags.has("--acknowledge-reported-only"),
    dryRun: flags.has("--dry-run"),
  };
}

export function runHistoricalReportedOutcomeCli(argv: readonly string[]): unknown {
  const input = parseArguments(argv);
  const database = createDatabaseConnection({
    filename: input.databasePath,
    readonly: input.command === "preview",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = new HistoricalReportedOutcomeClassificationService(database);
    if (input.command === "preview") {
      database.pragma("query_only = ON");
      return service.preview({
        ...(input.cursor ? { afterCursor: input.cursor } : {}),
        ...(input.maxRecords === undefined ? {} : { maxRecords: input.maxRecords }),
      });
    }
    if (!input.expectedPreviewHash || !input.actorId || !input.reason) {
      throw new TypeError("apply requires --expected-preview-hash, --actor, and --reason");
    }
    if (!input.acknowledgeReportedOnly) {
      throw new TypeError("apply requires --acknowledge-reported-only");
    }
    return service.apply({
      ...(input.cursor ? { afterCursor: input.cursor } : {}),
      ...(input.maxRecords === undefined ? {} : { maxRecords: input.maxRecords }),
      expectedPreviewHash: input.expectedPreviewHash,
      acknowledgeReportedOnly: true,
      actorId: input.actorId,
      reason: input.reason,
    });
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  try {
    console.log(JSON.stringify(runHistoricalReportedOutcomeCli(process.argv.slice(2)), null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
