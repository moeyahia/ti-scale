#!/usr/bin/env bun
import {
  LocalToolInstallationPreflight,
  loadTrustedLocalToolCapabilityManifest,
} from "../server/local-tools";

interface Arguments {
  readonly manifest: string;
  readonly trustRoot: string;
  readonly sha256: string;
}

function usage(): never {
  throw new Error(
    "Usage: bun run scripts/local-tool-capability-preflight.ts --manifest <absolute-json> --trust-root <absolute-directory> --sha256 <reviewed-sha256>",
  );
}

function argumentsFrom(values: readonly string[]): Arguments {
  const accepted = new Set(["--manifest", "--trust-root", "--sha256"]);
  const parsed = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key || !accepted.has(key) || !value || parsed.has(key)) usage();
    parsed.set(key, value);
  }
  if (parsed.size !== 3) usage();
  return {
    manifest: parsed.get("--manifest")!,
    trustRoot: parsed.get("--trust-root")!,
    sha256: parsed.get("--sha256")!,
  };
}

function main(): void {
  const options = argumentsFrom(process.argv.slice(2));
  const loaded = loadTrustedLocalToolCapabilityManifest({
    path: options.manifest,
    trustRoot: options.trustRoot,
    expectedSha256: options.sha256,
    allowedOwnerUids: [0],
  });
  const receipts = new LocalToolInstallationPreflight().inspectAll(loaded.value);
  // This command intentionally prints no executable paths, output, arguments,
  // target data, credentials, or environment. It never executes a tool.
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "ti-scale.local-tool-capability-preflight-report.v1",
    manifest: {
      version: loaded.value.descriptor.manifestVersion,
      sourceSha256: loaded.receipt.sourceSha256,
      canonicalSha256: loaded.receipt.canonicalSha256,
      manifestSha256: loaded.value.descriptor.manifestSha256,
      toolCount: loaded.value.descriptor.toolCount,
      enabledToolCount: loaded.value.descriptor.enabledToolCount,
    },
    accounting: {
      checked: receipts.length,
      ready: receipts.filter(({ status }) => status === "ready").length,
      unavailable: receipts.filter(({ status }) => status === "unavailable").length,
      complete: receipts.length === loaded.value.descriptor.toolCount,
    },
    tools: receipts.map((receipt) => ({
      toolId: receipt.toolId,
      status: receipt.status,
      code: receipt.code,
      bindingSha256: receipt.bindingSha256,
      expectedExecutableSha256: receipt.expectedExecutableSha256,
      observedExecutableSha256: receipt.observedExecutableSha256,
      fileCapabilitiesOutputSha256: receipt.fileCapabilitiesOutputSha256,
      noNewPrivilegesCompatible: receipt.noNewPrivilegesCompatible,
      toolExecuted: receipt.probeBoundary.toolExecuted,
      targetArgumentsSupplied: receipt.probeBoundary.targetArgumentsSupplied,
      grantsMissionExecution: receipt.grantsMissionExecution,
    })),
  }, null, 2)}\n`);
}

if (import.meta.main) main();
