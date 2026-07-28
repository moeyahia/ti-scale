import { resolve } from "node:path";
import { StaticArtifactReleaseStore, StaticReleaseError } from "./StaticArtifactReleaseStore";

const READ_ONLY_NOTICE =
  "Direct static-release mutation commands are disabled by the operator no-backup policy. Deployment is owned by the bounded forward-only controller.";

interface CliOptions {
  readonly environment?: NodeJS.ProcessEnv;
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
  if (!command || !["verify", "pin"].includes(command)) {
    throw new TypeError(
      "Direct static release mutation is disabled; command must be verify or pin",
    );
  }
  const values = parseOptions(rest);
  const allowed = new Set(command === "verify"
    ? ["--root", "--release-id"]
    : ["--root"]);
  for (const name of values.keys()) {
    if (!allowed.has(name)) throw new TypeError(`Unsupported ${command} option: ${name}`);
  }
  const environment = options.environment ?? process.env;
  const root = required(values, "--root", environment.TI_SCALE_STATIC_RELEASE_ROOT);
  const store = new StaticArtifactReleaseStore({ releaseRoot: resolve(root) });
  let result: unknown;
  if (command === "verify") {
    result = store.verifyRelease(required(values, "--release-id", environment.TI_SCALE_STATIC_RELEASE_ID));
  } else {
    result = store.pinActiveRelease();
  }
  (options.write ?? ((value) => process.stdout.write(value)))(`${JSON.stringify({
    operation: command,
    scope: "v2_static_artifact_pointer_only",
    notice: READ_ONLY_NOTICE,
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
