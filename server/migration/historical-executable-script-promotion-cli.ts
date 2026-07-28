#!/usr/bin/env bun
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import { resolveV2ScriptSourceRoot } from "../app/V2ArtifactPaths";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { MemoryRepository } from "../memory";
import {
  FileScriptSourceStore,
  MemoryScriptSourceStore,
  ScriptArtifactService,
} from "../script-artifacts";
import { ConnectedVaultMemoryProjector } from "../vault/ConnectedVaultMemoryProjector";
import { ObsidianVaultBridge } from "../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../vault/VaultPathPolicy";
import {
  HistoricalExecutableScriptPromotionService,
  type HistoricalExecutableScriptPromotionFence,
  type HistoricalExecutableScriptPromotionInput,
} from "./HistoricalExecutableScriptPromotionService";
import { LocalHistoricalExecutableScriptValidator } from "./LocalHistoricalExecutableScriptValidator";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale historical executable-script promotion

Usage:
  bun run brain:promote-historical-script:list -- --db PATH [--limit 1..1000]

  bun run brain:promote-historical-script:preview -- --db PATH
    --request REVIEW.json --dry-run

  bun run brain:promote-historical-script:execute -- --db PATH
    --vault-root PATH
    --request REVIEW.json --expected-preview-hash SHA256
    --expected-source-hash SHA256
    --reviewed-exact-source-and-bindings
    --acknowledge-no-automatic-execution

The request file contains HistoricalExecutableScriptPromotionInput, including
the operator actor, review reason, exact bundle/source/node selection, and
complete reviewed ScriptArtifact documentation. Preview returns the exact
secret-free source for local operator review. Execute does not run the source,
contact a target, or call a public provider. Only Python source compatible with
the production reviewed-interpreter gate can become a canonical artifact.
`;
}

function value(tokens: readonly string[], name: string): string | undefined {
  const indexes = tokens.flatMap((token, index) =>
    token === `--${name}` ? [index] : []);
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

function limit(tokens: readonly string[]): number {
  const raw = value(tokens, "limit");
  if (raw === undefined) return 1_000;
  if (!/^\d+$/u.test(raw)) throw new UsageError("--limit must be an integer");
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 1_000) {
    throw new UsageError("--limit must be between 1 and 1000");
  }
  return parsed;
}

function requestPath(requested: string, cwd: string): string {
  const absolute = resolve(cwd, requested);
  if (!isAbsolute(absolute) || !existsSync(absolute)) {
    throw new UsageError("--request must identify an existing local JSON file");
  }
  const state = lstatSync(absolute);
  if (!state.isFile() || state.isSymbolicLink() || state.size > 256 * 1_024) {
    throw new UsageError("--request must be a regular non-link JSON file no larger than 256 KiB");
  }
  const canonicalParent = realpathSync(dirname(absolute));
  const canonical = join(canonicalParent, absolute.split("/").at(-1)!);
  if (canonical !== absolute) throw new UsageError("--request path must be canonical");
  return canonical;
}

function request(tokens: readonly string[], cwd: string): HistoricalExecutableScriptPromotionInput {
  const path = requestPath(required(tokens, "request"), cwd);
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as HistoricalExecutableScriptPromotionInput;
  } catch {
    throw new UsageError("--request must contain one valid JSON promotion object");
  }
}

function assertKnown(tokens: readonly string[], command: string): void {
  const valued = new Set([
    "--db", "--vault-root", "--limit", "--request", "--expected-preview-hash",
    "--expected-source-hash",
  ]);
  const flags = new Set([
    "--dry-run",
    "--reviewed-exact-source-and-bindings",
    "--acknowledge-no-automatic-execution",
  ]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      index += 1;
      continue;
    }
    if (!flags.has(token)) throw new UsageError(`Unsupported ${command} option: ${token}`);
  }
}

export async function runHistoricalExecutableScriptPromotionCli(
  argv: readonly string[] = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
  io: CliIo = {},
): Promise<number> {
  const write = io.write ?? ((output: string) => process.stdout.write(output));
  const cwd = io.cwd ?? process.cwd();
  const [command = "help", ...tokens] = argv;
  if (command === "help" || command === "--help" || tokens.includes("--help")) {
    write(help());
    return 0;
  }
  if (!["list", "preview", "execute"].includes(command)) {
    throw new UsageError("Command must be list, preview, or execute");
  }
  assertKnown(tokens, command);
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run");
  }
  if (command !== "execute" && (
    tokens.includes("--reviewed-exact-source-and-bindings")
    || tokens.includes("--acknowledge-no-automatic-execution")
  )) {
    throw new UsageError("Promotion acknowledgements are valid only for execute");
  }
  const databasePath = resolveCliDatabasePath(value(tokens, "db"), environment);
  const mutable = command === "execute";
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: !mutable,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const sourceStore = mutable
      ? new FileScriptSourceStore(resolveV2ScriptSourceRoot(
          databasePath,
          environment.TI_SCALE_SCRIPT_SOURCE_ROOT,
        ))
      : new MemoryScriptSourceStore();
    const scripts = new ScriptArtifactService(database, sourceStore);
    const vaultProjector = mutable
      ? new ConnectedVaultMemoryProjector(
          database,
          new ObsidianVaultBridge(
            database,
            new MemoryRepository(database),
            new VaultPathPolicy(resolveCliVaultRoot(
              value(tokens, "vault-root"),
              environment,
            )),
          ),
        )
      : undefined;
    const service = new HistoricalExecutableScriptPromotionService({
      database,
      scripts,
      validator: new LocalHistoricalExecutableScriptValidator(),
      ...(vaultProjector ? { vaultProjector } : {}),
    });
    if (command === "list") {
      write(`${JSON.stringify(service.listEligibility(limit(tokens)), null, 2)}\n`);
      return 0;
    }
    const input = request(tokens, cwd);
    if (command === "preview") {
      write(`${JSON.stringify(service.preview(input), null, 2)}\n`);
      return 0;
    }
    if (!tokens.includes("--reviewed-exact-source-and-bindings")
      || !tokens.includes("--acknowledge-no-automatic-execution")) {
      throw new UsageError("execute requires both explicit operator acknowledgements");
    }
    const fence: HistoricalExecutableScriptPromotionFence = {
      expectedPreviewHash: required(tokens, "expected-preview-hash"),
      expectedSourceHash: required(tokens, "expected-source-hash"),
      reviewedExactSourceAndBindings: true,
      acknowledgedNoAutomaticExecution: true,
    };
    const result = await withCanonicalWriterLease(database, {
      ownerId: input.actorId,
      operation: "historical-executable-script-promotion",
    }, () => service.promote(input, fence));
    const output = {
      ...result,
      scriptArtifact: {
        ...result.scriptArtifact,
        source: undefined,
      },
    };
    write(`${JSON.stringify(output, null, 2)}\n`);
    return result.vaultProjection.complete ? 0 : 2;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runHistoricalExecutableScriptPromotionCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
