import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DirectProcessLocalToolInvocationAdapter,
  LocalToolCapabilityManifest,
  parseBubblewrapProbeSandboxDescriptor,
} from "../../local-tools";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import { LocalGuidedToolActivationCoordinator } from "../LocalGuidedToolActivationCoordinator";
import type { LoadedLocalGuidedToolConfiguration } from "../LocalGuidedToolConfiguration";

const TOOL_TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const SANDBOX_TEMPLATE = new URL(
  "../../../deployment/runtime-config/bubblewrap-probe-sandbox.v1.json",
  import.meta.url,
);
const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

function fileReceipt(sourceSha256: string): TrustedLocalFileReceipt {
  return {
    schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
    sourcePath: "/reviewed/config.json",
    trustRoot: "/reviewed",
    sourceSha256,
    canonicalSha256: sourceSha256,
    byteSize: 1,
    ownerUid: 0,
    ownerGid: 0,
    mode: 0o600,
    device: "1",
    inode: "1",
  };
}

function fixture(runtimeResultSinkBound = true) {
  const runtimeRoot = mkdtempSync(join(tmpdir(), "ti-scale-guided-activation-"));
  roots.push(runtimeRoot);
  mkdirSync(join(runtimeRoot, "mission"), { mode: 0o700 });
  const manifest = new LocalToolCapabilityManifest(
    JSON.parse(readFileSync(TOOL_TEMPLATE, "utf8")),
  );
  const probeSandbox = parseBubblewrapProbeSandboxDescriptor(
    JSON.parse(readFileSync(SANDBOX_TEMPLATE, "utf8")),
  );
  const configuration: LoadedLocalGuidedToolConfiguration = {
    status: "loaded",
    manifest,
    probeSandbox,
    workspaceMappings: {
      schemaVersion: "ti-scale.engagement-workspace-mappings.v1",
      mappingVersion: "activation-test-v1",
      mappings: [{ logicalRoot: "/engagements", runtimeRoot }],
    },
    receipts: {
      capabilityManifest: fileReceipt(manifest.descriptor.manifestSha256),
      probeSandbox: fileReceipt(probeSandbox.expectedSha256),
      workspaceMappings: fileReceipt("a".repeat(64)),
    },
  };
  const resolver = new EngagementWorkspaceResolver(configuration.workspaceMappings.mappings);
  const adapter = new DirectProcessLocalToolInvocationAdapter({
    manifest,
    workspaceResolver: resolver,
    sandboxExecutable: {
      path: probeSandbox.executablePath,
      expectedSha256: probeSandbox.expectedSha256,
    },
  });
  const unbind = adapter.bindResultSink({ async acceptLocalProcessToolResult() {} });
  const coordinator = new LocalGuidedToolActivationCoordinator({
    configuration,
    adapter,
    executionPort: { runtimeResultSinkBound },
  });
  return { coordinator, unbind };
}

describe("LocalGuidedToolActivationCoordinator", () => {
  test("combines real install, sealed probe, adapter, workspace, result, and cancellation receipts", async () => {
    const { coordinator, unbind } = fixture();
    try {
      const snapshot = await coordinator.refresh();
      expect(snapshot).toMatchObject({
        status: "ready",
        workspaceConfinementReady: true,
        runtimeResultSinkReady: true,
        adapterReadiness: {
          grantsMissionExecution: false,
          boundary: {
            targetContact: false,
            resultSinkBound: true,
            cooperativeCancellation: true,
          },
        },
        toolBindingReadiness: {
          accounting: { registered: 4, ready: 4, complete: true, current: true },
        },
      });
      expect(snapshot.activationReceipts).toHaveLength(5);
      expect(snapshot.activationReceipts
        .filter(({ toolId }) => toolId !== "kali:nmap-tcp-connect-service-scan")
        .every((receipt) =>
        receipt.installationReady
        && receipt.isolatedProbeReady
        && receipt.invocationAdapterReady
        && receipt.workspaceConfinementReady
        && receipt.resultSinkReady
        && receipt.cancellationReady)).toBeTrue();
      expect(snapshot.activationReceipts.find(({ toolId }) =>
        toolId === "kali:nmap-tcp-connect-service-scan")).toMatchObject({
        installationReady: false,
        isolatedProbeReady: false,
        invocationAdapterReady: false,
        resultSinkReady: false,
        cancellationReady: false,
      });
      expect([...coordinator.readyToolIds()].sort()).toEqual([
        "kali:curl-http-metadata",
        "kali:host-dns-query",
        "kali:ncat-tcp-connect",
        "kali:ping-host-liveness",
      ]);
      for (const receipt of snapshot.activationReceipts.filter(
        ({ isolatedProbeReady }) => isolatedProbeReady,
      )) {
        const preflight = coordinator.readToolExecutionPreflight(receipt.toolId);
        expect(preflight).toMatchObject({
          toolId: receipt.toolId,
          status: "ready",
          code: "ready",
          bindingSha256: receipt.preflightBindingSha256,
          executableIdentity: { sha256: receipt.executableSha256 },
        });
        expect(Date.parse(preflight!.checkedAt)).toBeLessThanOrEqual(
          Date.parse(receipt.observedAt),
        );
        expect(Date.parse(receipt.expiresAt)).toBeLessThanOrEqual(
          Date.parse(preflight!.expiresAt),
        );
      }
    } finally {
      await coordinator.stop();
      unbind();
    }
  }, 30_000);

  test("fails every tool closed when the mission-runtime result sink is not actually bound", async () => {
    const { coordinator, unbind } = fixture(false);
    try {
      const snapshot = await coordinator.refresh();
      expect(snapshot.status).toBe("unavailable");
      expect(snapshot.runtimeResultSinkReady).toBeFalse();
      expect(snapshot.activationReceipts.every(({ resultSinkReady }) => !resultSinkReady)).toBeTrue();
      expect(coordinator.readyToolIds().size).toBe(0);
    } finally {
      await coordinator.stop();
      unbind();
    }
  }, 30_000);
});
