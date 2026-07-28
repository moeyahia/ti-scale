#!/usr/bin/env bun
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { resolveOperationalHazardObservationKey } from "../memory";
import { withCanonicalWriterLease } from "../maintenance";
import { HistoricalAttackKnowledgeBatchPromotionService } from "./HistoricalAttackKnowledgeBatchPromotionService";

interface CliIo {
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale historical attack-knowledge batch promotion

Usage:
  bun run brain:promote-historical -- preview --db PATH --actor ACTOR --reason TEXT --dry-run
    [--after SHA256] [--max-records N] [--max-bytes N] [--max-ms N]

  bun run brain:promote-historical -- run --db PATH --actor ACTOR --reason TEXT
    --expected-preview-hash SHA256 --acknowledge-objective-fact-review
    [--after SHA256] [--max-records N] [--max-bytes N] [--max-ms N]

The preview is read-only and prints a hash-bound manifest of generalized facts,
source hashes, proposed relationships, and deterministic rejection categories.
Run must repeat the identical selection inputs and exact preview hash. It uses
the existing server-only operational-hazard HMAC credential to independently
re-open and re-hash every verified-reference source. No public model is called.
`;
}

function value(tokens: readonly string[], name: string): string | undefined {
  const indexes = tokens.flatMap((token, index) => token === `--${name}` ? [index] : []);
  if (indexes.length > 1) throw new UsageError(`--${name} may be supplied only once`);
  const index = indexes[0];
  if (index === undefined) return undefined;
  const result = tokens[index + 1];
  if (!result || result.startsWith("--")) throw new UsageError(`--${name} requires one value`);
  return result;
}

function required(tokens: readonly string[], name: string): string {
  const result = value(tokens, name)?.trim();
  if (!result) throw new UsageError(`--${name} is required`);
  return result;
}

function numberValue(tokens: readonly string[], name: string): number | undefined {
  const raw = value(tokens, name);
  if (raw === undefined) return undefined;
  if (!/^\d+$/u.test(raw)) throw new UsageError(`--${name} must be a positive integer`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) throw new UsageError(`--${name} is outside its safe range`);
  return parsed;
}

function assertKnown(tokens: readonly string[], command: string): void {
  const valueNames = new Set([
    "--db", "--actor", "--reason", "--after", "--max-records", "--max-bytes",
    "--max-ms", "--expected-preview-hash",
  ]);
  const flags = new Set(["--dry-run", "--acknowledge-objective-fact-review"]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valueNames.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported ${command} option: ${token}`);
  }
}

export async function runHistoricalAttackPromotionCli(
  argv: readonly string[] = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
  io: CliIo = {},
): Promise<number> {
  const write = io.write ?? ((output: string) => process.stdout.write(output));
  const [command = "help", ...tokens] = argv;
  if (command === "help" || command === "--help" || tokens.includes("--help")) {
    write(help());
    return 0;
  }
  if (command !== "preview" && command !== "run") throw new UsageError("Command must be preview or run");
  assertKnown(tokens, command);
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run to make the read-only intent explicit");
  }
  if (command === "preview" && tokens.includes("--acknowledge-objective-fact-review")) {
    throw new UsageError("preview must not include the execution acknowledgement");
  }
  if (command === "run" && tokens.includes("--dry-run")) {
    throw new UsageError("run cannot include --dry-run");
  }

  const databasePath = resolveCliDatabasePath(value(tokens, "db"), environment);
  const common = {
    actorId: required(tokens, "actor"),
    reason: required(tokens, "reason"),
    ...(value(tokens, "after") ? { afterSemanticFingerprint: value(tokens, "after")! } : {}),
    ...(numberValue(tokens, "max-records") === undefined ? {} : { maxRecords: numberValue(tokens, "max-records")! }),
    ...(numberValue(tokens, "max-bytes") === undefined ? {} : { maxSourceBytes: numberValue(tokens, "max-bytes")! }),
    ...(numberValue(tokens, "max-ms") === undefined ? {} : { maxDurationMs: numberValue(tokens, "max-ms")! }),
  };
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: command === "preview",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    if (command === "preview") {
      const service = new HistoricalAttackKnowledgeBatchPromotionService(database);
      const preview = service.preview(common);
      write(`${JSON.stringify({ mode: "dry_run", ...preview }, null, 2)}\n`);
      return 0;
    }
    if (!tokens.includes("--acknowledge-objective-fact-review")) {
      throw new UsageError("run requires --acknowledge-objective-fact-review");
    }
    if (!environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY &&
        !environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE) {
      throw new UsageError(
        "run requires the existing TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY or TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE",
      );
    }
    const receiptHmacKey = resolveOperationalHazardObservationKey({ databasePath, environment });
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, { receiptHmacKey });
    const result = await withCanonicalWriterLease(database, {
      ownerId: common.actorId,
      operation: "historical-attack-promotion",
    }, (handle, leases) => {
      leases.assertActive(handle);
      return service.execute({
        ...common,
        expectedPreviewHash: required(tokens, "expected-preview-hash"),
        acknowledgeObjectiveFactReview: true,
      });
    });
    write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runHistoricalAttackPromotionCli().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`Historical attack promotion failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  });
}
