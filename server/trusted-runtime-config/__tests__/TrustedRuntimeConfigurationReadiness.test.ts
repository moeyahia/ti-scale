import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TRUSTED_RUNTIME_CONFIGURATION_READINESS_SCHEMA_VERSION,
  projectTrustedRuntimeConfigurationReadiness,
  type TrustedJsonFileReference,
} from "../index";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "ti-scale-readiness-secret-path-"));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}

function owners(): readonly number[] {
  const uid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return uid === 0 ? [0] : [0, uid];
}

function reference(trustRoot: string, name: string, source: string): TrustedJsonFileReference {
  const path = join(trustRoot, name);
  writeFileSync(path, source, { flag: "wx", mode: 0o600 });
  return {
    path,
    trustRoot,
    expectedSha256: createHash("sha256").update(source).digest("hex"),
    allowedOwnerUids: owners(),
  };
}

describe("trusted runtime configuration readiness projection", () => {
  test("preserves the default unconfigured, non-authorizing state without reading a file", () => {
    const readiness = projectTrustedRuntimeConfigurationReadiness(
      undefined,
      () => new Date("2026-07-19T12:00:00.000Z"),
    );

    expect(readiness).toEqual({
      schemaVersion: TRUSTED_RUNTIME_CONFIGURATION_READINESS_SCHEMA_VERSION,
      status: "unconfigured",
      configured: false,
      complete: false,
      reason: "No trusted runtime configuration documents are configured. Runtime activation remains unavailable.",
      checkedAt: "2026-07-19T12:00:00.000Z",
      documents: {
        planningPolicy: {
          configured: false,
          status: "unconfigured",
          reason: "No reviewed reference is configured for this document.",
        },
        runtimeSourceManifests: {
          configured: false,
          status: "unconfigured",
          reason: "No reviewed reference is configured for this document.",
        },
        workspaceMappings: {
          configured: false,
          status: "unconfigured",
          reason: "No reviewed reference is configured for this document.",
        },
      },
      executionAuthorized: false,
      plannerMounted: false,
      providerExecutionMounted: false,
      specialistExecutionMounted: false,
      toolExecutionMounted: false,
    });
    expect(Object.isFrozen(readiness)).toBe(true);
    expect(Object.isFrozen(readiness.documents)).toBe(true);
  });

  test("reports an explicitly configured missing file as unavailable without leaking its path", () => {
    const trustRoot = root();
    const missingPath = join(trustRoot, "operator-token-never-expose.json");
    const readiness = projectTrustedRuntimeConfigurationReadiness({
      planningPolicy: {
        path: missingPath,
        trustRoot,
        expectedSha256: "a".repeat(64),
        allowedOwnerUids: owners(),
      },
    });

    expect(readiness).toMatchObject({
      status: "unavailable",
      configured: true,
      complete: false,
      executionAuthorized: false,
      documents: {
        planningPolicy: { configured: true, status: "unavailable" },
        runtimeSourceManifests: { configured: false, status: "unconfigured" },
      },
    });
    const serialized = JSON.stringify(readiness);
    expect(serialized).not.toContain(missingPath);
    expect(serialized).not.toContain(trustRoot);
    expect(serialized).not.toContain("ENOENT");
    expect(serialized).not.toContain("operator-token");
  });

  test("reports a configured malformed or digest-drifted document as invalid", () => {
    const trustRoot = root();
    const malformed = reference(trustRoot, "workspace.json", '{"unexpected":true}\n');
    const readiness = projectTrustedRuntimeConfigurationReadiness({
      workspaceMappings: malformed,
    });

    expect(readiness).toMatchObject({
      status: "invalid",
      configured: true,
      complete: false,
      toolExecutionMounted: false,
      documents: {
        workspaceMappings: {
          configured: true,
          status: "invalid",
          reason: "The configured reviewed document failed trust, integrity, or schema validation.",
        },
      },
    });
    expect(readiness.documents.workspaceMappings).not.toHaveProperty("sourceSha256");

    const digestDrift = projectTrustedRuntimeConfigurationReadiness({
      workspaceMappings: { ...malformed, expectedSha256: "f".repeat(64) },
    });
    expect(digestDrift.documents.workspaceMappings.status).toBe("invalid");
  });
});
