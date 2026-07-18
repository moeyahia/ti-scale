import { resolve } from "node:path";
import { StaticArtifactReleaseStore, StaticReleaseError } from "./StaticArtifactReleaseStore";

const STATIC_ONLY_WARNING =
  "This operation changes only the isolated V2 static-artifact pointer; it does not cut over or roll back API, database, workers, runtime state, or the legacy application.";

interface CliOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

function parseOptions(args: readonly string[]): Map<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith("--") || !value || value.startsWith("--")) {
      throw new TypeError(`Invalid static release CLI option near ${name ?? "end of command"}`);
    }
    if (values.has(name)) throw new TypeError(`Duplicate static release CLI option: ${name}`);
    values.set(name, value);
  }
  return values;
}

function required(values: Map<string, string>, name: string, fallback?: string): string {
  const value = values.get(name) ?? fallback;
  if (!value?.trim()) throw new TypeError(`${name} is required`);
  return value;
}

export function runStaticReleaseCli(args: readonly string[], options: CliOptions = {}): number {
  const [command, ...rest] = args;
  if (!command || !["stage", "verify", "activate", "pin", "rollback"].includes(command)) {
    throw new TypeError("Static release command must be stage, verify, activate, pin, or rollback");
  }
  const values = parseOptions(rest);
  const allowed = new Set(command === "stage"
    ? ["--root", "--release-id", "--dist"]
    : command === "verify" || command === "activate"
      ? ["--root", "--release-id"]
      : ["--root"]);
  for (const name of values.keys()) {
    if (!allowed.has(name)) throw new TypeError(`Unsupported ${command} option: ${name}`);
  }
  const environment = options.environment ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const root = required(values, "--root", environment.TI_SCALE_STATIC_RELEASE_ROOT);
  const store = new StaticArtifactReleaseStore({ releaseRoot: resolve(root) });
  let result: unknown;
  if (command === "stage") {
    result = store.stageRelease({
      releaseId: required(values, "--release-id", environment.TI_SCALE_STATIC_RELEASE_ID),
      sourceDirectory: resolve(values.get("--dist") ?? environment.TI_SCALE_DIST_ROOT ?? resolve(cwd, "dist")),
    });
  } else if (command === "verify") {
    result = store.verifyRelease(required(values, "--release-id", environment.TI_SCALE_STATIC_RELEASE_ID));
  } else if (command === "activate") {
    result = store.activateRelease(required(values, "--release-id", environment.TI_SCALE_STATIC_RELEASE_ID));
  } else if (command === "pin") {
    result = store.pinActiveRelease();
  } else {
    result = store.rollbackPointer();
  }
  (options.write ?? ((value) => process.stdout.write(value)))(`${JSON.stringify({
    operation: command,
    scope: "v2_static_artifact_pointer_only",
    warning: STATIC_ONLY_WARNING,
    result,
  }, null, 2)}\n`);
  return 0;
}

if (import.meta.main) {
  try {
    process.exitCode = runStaticReleaseCli(process.argv.slice(2));
  } catch (error) {
    const code = error instanceof StaticReleaseError ? error.code : "static_release_cli_error";
    const message = error instanceof Error ? error.message : "V2 static release command failed";
    process.stderr.write(`${JSON.stringify({ code, message, scope: "v2_static_artifact_pointer_only" })}\n`);
    process.exitCode = 1;
  }
}
