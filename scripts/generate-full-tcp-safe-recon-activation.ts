#!/usr/bin/env bun

import { dirname, resolve } from "node:path";
import {
  generateFullTcpSafeReconActivationDocuments,
} from "./release/FullTcpSafeReconActivationDocuments";

const EXPECTED_ARGUMENTS = Object.freeze([
  "--manifest",
  "--manifest-sha256",
  "--runtime",
  "--runtime-sha256",
  "--output",
] as const);

const CVE_CATALOG_ARGUMENTS = Object.freeze([
  "--cve-candidate-catalog",
  "--cve-candidate-catalog-sha256",
] as const);

export function argumentsByName(argv: readonly string[]): Readonly<Record<string, string>> {
  if (argv.length % 2 !== 0) throw new Error("Every Full-TCP generator option requires one value");
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]!;
    const value = argv[index + 1]!;
    if (!name.startsWith("--") || !value || Object.hasOwn(values, name)) {
      throw new Error("Full-TCP generator arguments must be unique --name value pairs");
    }
    values[name] = value;
  }
  const supported = new Set([
    ...EXPECTED_ARGUMENTS,
    "--manifest-trust-root",
    "--runtime-trust-root",
    "--manifest-version",
    "--configuration-version",
    ...CVE_CATALOG_ARGUMENTS,
    "--cve-candidate-catalog-trust-root",
    "--maximum-cve-candidates-per-product",
  ]);
  const unexpected = Object.keys(values).filter((name) => !supported.has(name));
  const missing = EXPECTED_ARGUMENTS.filter((name) => !values[name]);
  if (unexpected.length || missing.length) {
    throw new Error(`Invalid Full-TCP generator arguments (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`);
  }
  const configuredCatalogArguments = CVE_CATALOG_ARGUMENTS
    .filter((name) => values[name]).length;
  if (configuredCatalogArguments === 1) {
    throw new Error(
      "CVE activation requires both --cve-candidate-catalog and --cve-candidate-catalog-sha256",
    );
  }
  if (configuredCatalogArguments === 0
    && (values["--cve-candidate-catalog-trust-root"]
      || values["--maximum-cve-candidates-per-product"])) {
    throw new Error(
      "CVE catalogue trust-root and candidate cap require the complete pinned catalogue path/SHA pair",
    );
  }
  const maximumCandidates = values["--maximum-cve-candidates-per-product"];
  if (maximumCandidates !== undefined
    && (!/^(?:[1-9]|[1-9]\d|100)$/u.test(maximumCandidates)
      || !Number.isSafeInteger(Number(maximumCandidates)))) {
    throw new Error("--maximum-cve-candidates-per-product must be an integer from 1 through 100");
  }
  return Object.freeze(values);
}

async function main(): Promise<void> {
  const values = argumentsByName(process.argv.slice(2));
  const manifestPath = resolve(values["--manifest"]!);
  const runtimePath = resolve(values["--runtime"]!);
  const cveCandidateCatalogPath = values["--cve-candidate-catalog"]
    ? resolve(values["--cve-candidate-catalog"])
    : undefined;
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const allowedOwnerUids = currentUid === 0 ? [0] : [0, currentUid];
  const result = await generateFullTcpSafeReconActivationDocuments({
    sourceManifest: {
      path: manifestPath,
      trustRoot: resolve(values["--manifest-trust-root"] ?? dirname(manifestPath)),
      expectedSha256: values["--manifest-sha256"]!,
      allowedOwnerUids,
      maximumBytes: 2 * 1_024 * 1_024,
    },
    sourceRuntime: {
      path: runtimePath,
      trustRoot: resolve(values["--runtime-trust-root"] ?? dirname(runtimePath)),
      expectedSha256: values["--runtime-sha256"]!,
      allowedOwnerUids,
      maximumBytes: 256 * 1_024,
    },
    ...(cveCandidateCatalogPath ? {
      sourceCveCandidateCatalog: {
        path: cveCandidateCatalogPath,
        trustRoot: resolve(
          values["--cve-candidate-catalog-trust-root"]
            ?? dirname(cveCandidateCatalogPath),
        ),
        expectedSha256: values["--cve-candidate-catalog-sha256"]!,
        allowedOwnerUids,
        maximumBytes: 8 * 1_024 * 1_024,
      },
      ...(values["--maximum-cve-candidates-per-product"] ? {
        maximumCveCandidatesPerProduct:
          Number(values["--maximum-cve-candidates-per-product"]),
      } : {}),
    } : {}),
    outputDirectory: resolve(values["--output"]!),
    ...(values["--manifest-version"] ? { manifestVersion: values["--manifest-version"] } : {}),
    ...(values["--configuration-version"] ? { configurationVersion: values["--configuration-version"] } : {}),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
