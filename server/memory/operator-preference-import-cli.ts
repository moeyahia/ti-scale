#!/usr/bin/env bun
import { dirname, resolve } from "node:path";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { loadTrustedOperatorPreferenceManifest } from "./OperatorPreferenceManifest";
import { OperatorPreferenceImportService } from "./OperatorPreferenceImportService";

class UsageError extends Error {}

interface CliIo {
  readonly write?: (value: string) => void;
}

function help(): string {
  return `Ti-Scale explicit operator-preference import

Usage:
  bun run brain:import-preferences -- preview --manifest PATH --manifest-sha256 SHA256 \
    --db PATH --actor ACTOR --dry-run

  bun run brain:import-preferences -- execute --manifest PATH --manifest-sha256 SHA256 \
    --db PATH --actor ACTOR --reason TEXT --expected-preview-hash SHA256 \
    --acknowledge-explicit-operator-preferences

The v2 manifest is strict, data-only, local, owner-controlled, and hash-pinned.
It accepts only categorized durable preferences and fixes the exclusion of
one-time commands, target-specific data, credentials, and secrets. Preference
content can never override authorization, scope, privacy, evidence integrity,
or runtime safety.
Preview is read-only and prints the exact confirmed preference nodes, profile
values, provenance, stable candidate/profile/observation IDs, and review hash.
Execute uses the canonical candidate -> operator confirmation path, writes a
confirmed preference profile and granted observation, and appends a
tamper-evident audit. Replaying the same reviewed manifest is idempotent.
Secrets, credentials, policy overrides, and inferred sensitive traits are not
valid preference content.
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

function assertKnown(tokens: readonly string[], command: string): void {
  const valued = new Set([
    "--actor",
    "--db",
    "--expected-preview-hash",
    "--manifest",
    "--manifest-sha256",
    "--reason",
  ]);
  const flags = new Set(["--acknowledge-explicit-operator-preferences", "--dry-run"]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      if (tokens[index + 1] === undefined) throw new UsageError(`${token} requires one value`);
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported ${command} option: ${token}`);
  }
}

export async function runOperatorPreferenceImportCli(
  argv: readonly string[] = process.argv.slice(2),
  io: CliIo = {},
): Promise<number> {
  const write = io.write ?? ((output: string) => process.stdout.write(output));
  const [command = "help", ...tokens] = argv;
  if (command === "help" || command === "--help" || tokens.includes("--help")) {
    write(help());
    return 0;
  }
  if (command !== "preview" && command !== "execute") {
    throw new UsageError("Command must be preview or execute");
  }
  assertKnown(tokens, command);
  const dryRun = tokens.includes("--dry-run");
  const acknowledged = tokens.includes("--acknowledge-explicit-operator-preferences");
  if (command === "preview" && !dryRun) throw new UsageError("preview requires --dry-run");
  if (command === "preview" && acknowledged) {
    throw new UsageError("preview must not include the execution acknowledgement");
  }
  if (command === "execute" && dryRun) throw new UsageError("execute cannot include --dry-run");
  if (command === "execute" && !acknowledged) {
    throw new UsageError("execute requires --acknowledge-explicit-operator-preferences");
  }

  const manifestPath = resolve(required(tokens, "manifest"));
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const loaded = loadTrustedOperatorPreferenceManifest({
    path: manifestPath,
    trustRoot: dirname(manifestPath),
    expectedSha256: required(tokens, "manifest-sha256").toLowerCase(),
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  });
  const actorId = required(tokens, "actor");
  const database = createDatabaseConnection({
    filename: resolve(required(tokens, "db")),
    readonly: command === "preview",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = new OperatorPreferenceImportService(database);
    if (command === "preview") {
      write(`${JSON.stringify({ mode: "dry_run", ...service.preview({
        manifest: loaded.value,
        receipt: loaded.receipt,
        actorId,
      }) }, null, 2)}\n`);
      return 0;
    }
    const result = await withCanonicalWriterLease(database, {
      ownerId: actorId,
      operation: "operator-preference-import",
    }, (handle, leases) => {
      leases.assertActive(handle);
      return service.execute({
        manifest: loaded.value,
        receipt: loaded.receipt,
        actorId,
        expectedPreviewHash: required(tokens, "expected-preview-hash").toLowerCase(),
        reason: required(tokens, "reason"),
      });
    });
    write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runOperatorPreferenceImportCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Operator preference import failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}
