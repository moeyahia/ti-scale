#!/usr/bin/env bun
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { HistoricalAttackKnowledgeConfirmationService } from "./HistoricalAttackKnowledgeConfirmationService";

interface CliIo {
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale historical attack-knowledge confirmation

Usage:
  bun run brain:confirm-historical -- preview --db PATH --migration ID --actor ACTOR --reason TEXT --dry-run
    [--after SHA256] [--max-candidates 1..1000]

  bun run brain:confirm-historical -- run --db PATH --migration ID --actor ACTOR --reason TEXT
    --expected-preview-hash SHA256 --acknowledge-confirm-all-safe
    [--after SHA256] [--max-candidates 1..1000]

Preview is read-only and hash-binds one deterministic page of sanitized
attack-knowledge candidates plus its typed source-bundle relationships. Run
confirms safe candidates, suppresses candidates that fail the reusable-memory
boundary, creates only staged typed relationships, and writes private source
custody bindings with import mission/run context. Unambiguous relationships are
reported as typed; source-only or ambiguous candidates are reported as
unlinked. It does not verify knowledge, invent relationships, or assign
success/failed outcome tags. Repeat with nextSelectionCursor until hasMore is
false.
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
  const result = Number(raw);
  if (!Number.isSafeInteger(result)) throw new UsageError(`--${name} is outside its safe range`);
  return result;
}

function assertKnown(tokens: readonly string[], command: string): void {
  const valued = new Set([
    "--db", "--migration", "--actor", "--reason", "--after",
    "--max-candidates", "--expected-preview-hash",
  ]);
  const flags = new Set(["--dry-run", "--acknowledge-confirm-all-safe"]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported ${command} option: ${token}`);
  }
}

export async function runHistoricalAttackConfirmationCli(
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
  if (command !== "preview" && command !== "run") {
    throw new UsageError("Command must be preview or run");
  }
  assertKnown(tokens, command);
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run");
  }
  if (command === "run" && tokens.includes("--dry-run")) {
    throw new UsageError("run cannot include --dry-run");
  }
  if (command === "preview" && tokens.includes("--acknowledge-confirm-all-safe")) {
    throw new UsageError("preview must not include the execution acknowledgement");
  }
  const common = {
    migrationId: required(tokens, "migration"),
    actorId: required(tokens, "actor"),
    reason: required(tokens, "reason"),
    ...(value(tokens, "after") ? { afterContentFingerprint: value(tokens, "after")! } : {}),
    ...(numberValue(tokens, "max-candidates") === undefined
      ? {}
      : { maxCandidates: numberValue(tokens, "max-candidates")! }),
  };
  const database = createDatabaseConnection({
    filename: resolveCliDatabasePath(value(tokens, "db"), environment),
    readonly: command === "preview",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = new HistoricalAttackKnowledgeConfirmationService(database);
    if (command === "preview") {
      write(`${JSON.stringify({ mode: "dry_run", ...service.preview(common) }, null, 2)}\n`);
      return 0;
    }
    if (!tokens.includes("--acknowledge-confirm-all-safe")) {
      throw new UsageError("run requires --acknowledge-confirm-all-safe");
    }
    const result = await withCanonicalWriterLease(database, {
      ownerId: common.actorId,
      operation: `historical-attack-confirmation:${common.migrationId}`,
    }, (handle, leases) => {
      leases.assertActive(handle);
      return service.execute({
        ...common,
        expectedPreviewHash: required(tokens, "expected-preview-hash"),
        acknowledgeConfirmAllSafe: true,
      });
    });
    write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runHistoricalAttackConfirmationCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical attack confirmation failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}
