import { describe, expect, test } from "bun:test";
import type { ToolExecutableIdentity } from "../../system-capabilities";
import {
  ToolBindingReadinessRunner,
  ToolExecutionPreflightService,
} from "../../system-capabilities";
import {
  REVIEWED_WEB_ASSESSMENT_TOOL_PACK,
  WebAssessmentBoundaryError,
  compileGuidedWebAssessmentInvocation,
  normalizeCanonicalWebTarget,
  webAssessmentActionFingerprint,
  webAssessmentPackSha256,
} from "../WebAssessmentToolPack";
import {
  buildWebAssessmentActivationSnapshot,
  createWebAssessmentToolBindingRegistry,
  projectReadyWebAssessmentRuntime,
  webAssessmentRuntimeSourceManifests,
} from "../WebAssessmentCapabilityIntegration";
import type {
  CompileGuidedWebAssessmentInvocationInput,
  ReviewedWebAssessmentToolId,
  WebAssessmentAdapterReadinessReceipt,
  WebAssessmentProbeReceipt,
} from "../types";

const NOW = new Date("2026-07-20T09:00:00.000Z");

function compilationInput(
  overrides: Partial<CompileGuidedWebAssessmentInvocationInput> = {},
): CompileGuidedWebAssessmentInvocationInput {
  const identity = {
    missionId: "mission_web_test",
    runId: "run_web_test",
    actionId: "action_web_test",
    toolId: "kali:whatweb-bounded-fingerprint" as const,
    canonicalMissionTarget: "https://example.test/",
    requestedUrl: "https://example.test/",
    logicalWorkspace: "/engagements/web-test",
    profile: "bounded_standard" as const,
    ...overrides,
  };
  const representedActionFingerprint = overrides.representedActionFingerprint
    ?? webAssessmentActionFingerprint(identity);
  return {
    ...identity,
    invocationId: "web_invocation_test",
    journey: "guided",
    authorizationVerified: true,
    actionClassAllowed: true,
    guidedDecisionStatus: "approved",
    representedActionFingerprint,
    ...overrides,
  };
}

function readyIdentity(sha256: string, inode: string): ToolExecutableIdentity {
  return {
    sha256,
    device: "1",
    inode,
    sizeBytes: 4096,
    mode: 0o755,
    uid: 0,
    gid: 0,
  };
}

async function readyBindingSnapshot() {
  const registry = createWebAssessmentToolBindingRegistry();
  const identities = new Map(registry.list().map((binding, index) => [
    binding.executablePath,
    readyIdentity(
      REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.find(({ toolId }) => toolId === binding.toolId)!
        .executable.expectedSha256,
      String(index + 10),
    ),
  ]));
  const preflight = new ToolExecutionPreflightService({
    environment: {
      isolation: {
        networkEnforced: true,
        filesystemWritesEnforced: true,
        immutableSnapshotEnforced: true,
      },
      async inspectExecutable(path) {
        const identity = identities.get(path);
        return identity ? { state: "ready" as const, identity } : { state: "missing" as const };
      },
      async inspectWorkingDirectory() { return true; },
      async readNoNewPrivileges() { return true; },
      async execute(input) {
        return {
          exitCode: 0,
          signal: null,
          stdout: "reviewed version output\n",
          stderr: "",
          timedOut: false,
          outputLimitExceeded: false,
          executableIdentity: input.expectedExecutableIdentity,
        };
      },
    },
    clock: () => NOW,
  });
  return new ToolBindingReadinessRunner(registry, preflight, () => NOW).runAll();
}

function installationReceipts(): readonly WebAssessmentProbeReceipt[] {
  return REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools
    .filter(({ activation }) => activation === "reviewed_guided")
    .map((tool) => ({
      schemaVersion: "ti-scale.web-assessment-probe-receipt.v1",
      toolId: tool.toolId,
      installationReady: true,
      probeReady: true,
      observedExecutableSha256: tool.executable.expectedSha256,
      expectedExecutableSha256: tool.executable.expectedSha256,
      targetContact: false,
      observedAt: NOW.toISOString(),
      failureCode: null,
    }));
}

function adapterReceipt(
  overrides: Partial<WebAssessmentAdapterReadinessReceipt> = {},
): WebAssessmentAdapterReadinessReceipt {
  const registry = createWebAssessmentToolBindingRegistry();
  return {
    schemaVersion: "ti-scale.web-assessment-adapter-readiness.v1",
    adapterId: "ti-scale:reviewed-web-assessment-process",
    packSha256: webAssessmentPackSha256(),
    registrySha256: registry.descriptor.registrySha256,
    runtimeManifestSha256: registry.descriptor.runtimeManifestSha256,
    readyToolIds: [
      "kali:ffuf-bounded-content-discovery",
      "kali:whatweb-bounded-fingerprint",
    ],
    blockers: [],
    boundary: {
      directArgv: true,
      shell: false,
      exactTargetBinding: true,
      workspaceConfinement: true,
      immutableExecutableSnapshot: true,
      fixedDictionaryStaging: true,
      boundedOutput: true,
      boundedRuntime: true,
      cooperativeCancellation: true,
      resultNormalization: true,
      targetContactDuringReadiness: false,
    },
    observedAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
    grantsMissionExecution: false,
    ...overrides,
  };
}

describe("reviewed web-assessment compiler", () => {
  test("compiles one exact WhatWeb argv without granting execution", () => {
    const compiled = compileGuidedWebAssessmentInvocation(compilationInput());
    expect(compiled.toolId).toBe("kali:whatweb-bounded-fingerprint");
    expect(compiled.shell).toBeFalse();
    expect(compiled.authorizationGrantedByCompiler).toBeFalse();
    expect(compiled.arguments.at(-1)).toBe("https://example.test/");
    expect(compiled.arguments).toContain("--follow-redirect=never");
    expect(compiled.arguments).toContain("--max-threads=1");
    expect(compiled.stagedInput.kind).toBe("none");
  });

  test("compiles FFUF with a fixed bounded dictionary and separate argv values", () => {
    const base = compilationInput({
      toolId: "kali:ffuf-bounded-content-discovery",
    });
    const compiled = compileGuidedWebAssessmentInvocation({
      ...base,
      representedActionFingerprint: webAssessmentActionFingerprint(base),
    });
    expect(compiled.shell).toBeFalse();
    expect(compiled.arguments).toContain("/run/ti-scale-input/paths.txt");
    expect(compiled.arguments).toContain("https://example.test/FUZZ");
    expect(compiled.arguments).toContain("10");
    expect(compiled.stagedInput.lines).toHaveLength(14);
    expect(new Set(compiled.stagedInput.lines).size).toBe(14);
  });

  test("fails closed for missing authorization, denied class, changed action, and Autonomous use", () => {
    const cases: Array<[Partial<CompileGuidedWebAssessmentInvocationInput>, string]> = [
      [{ authorizationVerified: false }, "authorization_unverified"],
      [{ actionClassAllowed: false }, "action_class_denied"],
      [{ representedActionFingerprint: "0".repeat(64) }, "represented_action_changed"],
      [{ journey: "autonomous" }, "autonomous_not_authorized"],
      [{ guidedDecisionStatus: "pending" }, "guided_decision_required"],
    ];
    for (const [override, code] of cases) {
      try {
        compileGuidedWebAssessmentInvocation(compilationInput(override));
        throw new Error("expected compiler rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(WebAssessmentBoundaryError);
        expect((error as WebAssessmentBoundaryError).code).toBe(code);
      }
    }
  });

  test("rejects ambiguous URLs and target drift before argv compilation", () => {
    expect(() => normalizeCanonicalWebTarget("https://user:pass@example.test/"))
      .toThrow("without credentials");
    expect(() => normalizeCanonicalWebTarget("https://example.test/?next=x"))
      .toThrow("without credentials");
    expect(() => normalizeCanonicalWebTarget("https://example.test/base", true))
      .toThrow("ending in '/'");
    expect(() => webAssessmentActionFingerprint({
      ...compilationInput(),
      requestedUrl: "https://other.example.test/",
    })).toThrow("differs from the canonical mission target");
  });

  test("held inventory tools cannot be smuggled through the reviewed compiler", () => {
    const input = compilationInput({
      toolId: "kali:gobuster-held" as unknown as ReviewedWebAssessmentToolId,
    });
    expect(() => compileGuidedWebAssessmentInvocation({
      ...input,
      representedActionFingerprint: webAssessmentActionFingerprint(input),
    })).toThrow("not activated");
  });
});

describe("web-assessment registry and readiness integration", () => {
  test("registers only the two reviewed bindings while retaining explicit held inventory", () => {
    const registry = createWebAssessmentToolBindingRegistry();
    expect(registry.list().map(({ toolId }) => toolId)).toEqual([
      "kali:ffuf-bounded-content-discovery",
      "kali:whatweb-bounded-fingerprint",
    ]);
    expect(registry.descriptor.registeredBindingCount).toBe(2);
    expect(registry.descriptor.runtimeToolCount).toBe(6);
    expect(registry.descriptor.runtimeToolsWithoutLocalBinding).toBe(4);
    expect(webAssessmentRuntimeSourceManifests().tools.filter(({ available }) => available))
      .toHaveLength(0);
  });

  test("projects readiness only when registry, installation, and full adapter boundaries join", async () => {
    const bindingReadiness = await readyBindingSnapshot();
    const activation = buildWebAssessmentActivationSnapshot({
      toolBindingReadiness: bindingReadiness,
      installationReceipts: installationReceipts(),
      adapterReadiness: adapterReceipt(),
      now: NOW,
    });
    expect(activation.status).toBe("ready");
    expect(activation.readyToolIds).toEqual([
      "kali:ffuf-bounded-content-discovery",
      "kali:whatweb-bounded-fingerprint",
    ]);
    expect(activation.tools.filter(({ state }) => state === "held")).toHaveLength(4);
    const projection = projectReadyWebAssessmentRuntime(activation);
    expect(projection.tools.filter(({ available }) => available).map(({ id }) => id)).toEqual([
      "kali:whatweb-bounded-fingerprint",
      "kali:ffuf-bounded-content-discovery",
    ]);
    expect(projection.agents[0]?.available).toBeTrue();
  });

  test("reports an expired adapter as a specific unavailable boundary", async () => {
    const bindingReadiness = await readyBindingSnapshot();
    const activation = buildWebAssessmentActivationSnapshot({
      toolBindingReadiness: bindingReadiness,
      installationReceipts: installationReceipts(),
      adapterReadiness: adapterReceipt({ expiresAt: NOW.toISOString() }),
      now: NOW,
    });
    expect(activation.status).toBe("unavailable");
    expect(activation.readyToolIds).toEqual([]);
    expect(activation.tools
      .filter(({ state }) => state === "unavailable")
      .every(({ reason }) => reason.includes("adapter"))).toBeTrue();
  });
});
