import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  IntegrityAuthority,
  LocalResearchReadinessProbe,
  loadProductionResearchReadinessProbeConfiguration,
  parseResearchReadinessProbeDescriptor,
  ResearchReadinessAttestor,
  ResearchReadinessProbeMonitor,
  ResearchReadinessReceiptAuthority,
  resolveResearchIntegrityKey,
  type ResearchDependencyKind,
  type ResearchReadinessProbeDescriptor,
  type ResearchReadinessProbeExecutor,
} from "../../../server/research";

const DESCRIPTOR_PATH = new URL(
  "../../../deployment/runtime-config/research-readiness-probe.v1.json",
  import.meta.url,
);
const KEY = "local-research-readiness-test-key-material-32-bytes";

function descriptor(): ResearchReadinessProbeDescriptor {
  return parseResearchReadinessProbeDescriptor(
    JSON.parse(readFileSync(DESCRIPTOR_PATH, "utf8")),
  );
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-research-probe-test-"));
  const authority = new ResearchReadinessReceiptAuthority(KEY);
  return {
    root,
    authority,
    dispose: () => rmSync(root, { recursive: true, force: true }),
  };
}

function output(
  input: {
    readonly descriptor: ResearchReadinessProbeDescriptor;
    readonly dependency: ResearchDependencyKind;
    readonly nonce: string;
  },
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    schemaVersion: "ti-scale.research-readiness-result.v1",
    dependency: input.dependency,
    nonceHash: createHash("sha256").update(input.nonce).digest("hex"),
    writeReadVerified: true,
    resetVerified: true,
    networkDenied: true,
    outsideWriteDenied: true,
    credentialEnvironmentEmpty: true,
    limits: {
      addressSpace: input.descriptor.limits.addressSpaceBytes,
      cpuSeconds: input.descriptor.limits.cpuSeconds,
      fileBytes: input.descriptor.limits.maxFileBytes,
      openFiles: input.descriptor.limits.maxOpenFiles,
      processes: input.descriptor.limits.maxProcesses,
    },
    ...overrides,
  });
}

function executor(
  alter: (
    input: Parameters<ResearchReadinessProbeExecutor["execute"]>[0],
  ) => Record<string, unknown> = () => ({}),
): ResearchReadinessProbeExecutor {
  return {
    async execute(input) {
      return {
        exitCode: 0,
        signal: null,
        stdout: output(input, alter(input)),
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
      };
    },
  };
}

describe("LocalResearchReadinessProbe", () => {
  test("runs real target-free bubblewrap probes with no network and cleans both disposable workspaces", async () => {
    const value = fixture();
    try {
      const result = await new LocalResearchReadinessProbe(
        descriptor(),
        value.authority,
        { temporaryRoot: value.root },
      ).run();
      expect(result.failures).toEqual([]);
      expect(result.workspaceCleanupVerified).toBe(true);
      expect(readdirSync(value.root)).toEqual([]);
      expect(result.disposableLab).toMatchObject({
        status: "pass",
        dependency: "disposable_lab",
        controls: {
          resetVerified: true,
          liveClientTargetsAllowed: false,
          productionSecretsMounted: false,
          productionMutationAllowed: false,
          quotaBound: true,
        },
      });
      expect(result.isolatedWorker).toMatchObject({
        status: "pass",
        dependency: "isolated_worker",
      });
      expect(value.authority.verifyReceipt(result.disposableLab)).toBe(true);
      expect(value.authority.verifyReceipt(result.isolatedWorker)).toBe(true);
    } finally {
      value.dispose();
    }
  });

  test("rejects receipt tampering and stale signed results", async () => {
    const value = fixture();
    try {
      const clock = () => new Date("2026-07-24T12:00:00.000Z");
      const result = await new LocalResearchReadinessProbe(
        descriptor(),
        value.authority,
        { temporaryRoot: value.root, executor: executor(), clock },
      ).run();
      expect(value.authority.verifyReceipt({
        ...result.disposableLab,
        evidenceHash: "f".repeat(64),
      })).toBe(false);
      const stale = new ResearchReadinessAttestor({
        integrityAuthority: new IntegrityAuthority(KEY),
        readDisposableLabAttestation: () => result.disposableLab,
        verifyDisposableLabAttestation: (receipt) =>
          value.authority.verifyReceipt(receipt),
        readIsolatedWorkerAttestation: () => result.isolatedWorker,
        verifyIsolatedWorkerAttestation: (receipt) =>
          value.authority.verifyReceipt(receipt),
        clock: () => new Date(
          Date.parse(result.disposableLab.expiresAt) + 1,
        ),
      }).snapshot();
      expect(stale).toEqual({
        disposableLabReady: false,
        isolatedWorkerReady: false,
        integritySigningKeyReady: true,
      });
    } finally {
      value.dispose();
    }
  });

  test("fails closed when the isolation binary is missing or changed", async () => {
    const value = fixture();
    try {
      const missing = await new LocalResearchReadinessProbe(
        {
          ...descriptor(),
          isolationExecutable: {
            path: "/missing/ti-scale-bwrap",
            sha256: "0".repeat(64),
          },
        },
        value.authority,
        { temporaryRoot: value.root, executor: executor() },
      ).run();
      expect(missing.failures.map(({ code }) => code)).toEqual([
        "isolation_unavailable",
        "isolation_unavailable",
      ]);
      expect(missing.disposableLab.status).toBe("fail");
      expect(missing.isolatedWorker.status).toBe("fail");
      expect(readdirSync(value.root)).toEqual([]);

      const changed = await new LocalResearchReadinessProbe(
        {
          ...descriptor(),
          isolationExecutable: {
            ...descriptor().isolationExecutable,
            sha256: "0".repeat(64),
          },
        },
        value.authority,
        { temporaryRoot: value.root, executor: executor() },
      ).run();
      expect(changed.failures.map(({ code }) => code)).toEqual([
        "identity_mismatch",
        "identity_mismatch",
      ]);
    } finally {
      value.dispose();
    }
  });

  test("fails closed when network isolation, credential isolation, or cleanup proof is absent", async () => {
    const value = fixture();
    try {
      const result = await new LocalResearchReadinessProbe(
        descriptor(),
        value.authority,
        {
          temporaryRoot: value.root,
          executor: executor(({ dependency }) =>
            dependency === "disposable_lab"
              ? { networkDenied: false }
              : { credentialEnvironmentEmpty: false }),
        },
      ).run();
      expect(result.failures.map(({ code }) => code)).toEqual([
        "isolation_failed",
        "isolation_failed",
      ]);
      expect(result.workspaceCleanupVerified).toBe(true);
      expect(readdirSync(value.root)).toEqual([]);
    } finally {
      value.dispose();
    }
  });

  test("times out fail-closed and still cleans every workspace", async () => {
    const value = fixture();
    try {
      const timeoutExecutor: ResearchReadinessProbeExecutor = {
        async execute() {
          return {
            exitCode: null,
            signal: "SIGKILL",
            stdout: "",
            stderr: "",
            timedOut: true,
            outputLimitExceeded: false,
          };
        },
      };
      const result = await new LocalResearchReadinessProbe(
        descriptor(),
        value.authority,
        { temporaryRoot: value.root, executor: timeoutExecutor },
      ).run();
      expect(result.failures.map(({ code }) => code)).toEqual([
        "execution_timeout",
        "execution_timeout",
      ]);
      expect(result.workspaceCleanupVerified).toBe(true);
      expect(readdirSync(value.root)).toEqual([]);
    } finally {
      value.dispose();
    }
  });

  test("projects only current signed receipts and re-attests after monitor restart", async () => {
    const value = fixture();
    try {
      const integrity = new IntegrityAuthority(KEY);
      const createMonitor = () => new ResearchReadinessProbeMonitor(
        new LocalResearchReadinessProbe(
          descriptor(),
          value.authority,
          {
            temporaryRoot: value.root,
            executor: executor(),
            clock: () => new Date("2026-07-24T12:00:00.000Z"),
          },
        ),
        value.authority,
        { refreshIntervalMs: 1_000 },
      );
      const first = createMonitor();
      await first.start();
      const firstReadiness = new ResearchReadinessAttestor({
        integrityAuthority: integrity,
        readDisposableLabAttestation: () =>
          first.read("disposable_lab"),
        verifyDisposableLabAttestation: (receipt) =>
          first.verify(receipt),
        readIsolatedWorkerAttestation: () =>
          first.read("isolated_worker"),
        verifyIsolatedWorkerAttestation: (receipt) =>
          first.verify(receipt),
        clock: () => new Date("2026-07-24T12:00:01.000Z"),
      });
      expect(firstReadiness.snapshot().disposableLabReady).toBe(true);
      await first.stop();
      expect(firstReadiness.snapshot().disposableLabReady).toBe(false);

      const restarted = createMonitor();
      await restarted.start();
      const restartedReadiness = new ResearchReadinessAttestor({
        integrityAuthority: integrity,
        readDisposableLabAttestation: () =>
          restarted.read("disposable_lab"),
        verifyDisposableLabAttestation: (receipt) =>
          restarted.verify(receipt),
        readIsolatedWorkerAttestation: () =>
          restarted.read("isolated_worker"),
        verifyIsolatedWorkerAttestation: (receipt) =>
          restarted.verify(receipt),
        clock: () => new Date("2026-07-24T12:00:01.000Z"),
      });
      expect(restartedReadiness.snapshot()).toEqual({
        disposableLabReady: true,
        isolatedWorkerReady: true,
        integritySigningKeyReady: true,
      });
      await restarted.stop();
      expect(readdirSync(value.root)).toEqual([]);
    } finally {
      value.dispose();
    }
  });

  test("loads only a complete hash-pinned production descriptor and a private key file", () => {
    const value = fixture();
    try {
      const descriptorPath = join(value.root, "research-readiness.json");
      const keyPath = join(value.root, "research-readiness-key");
      const source = readFileSync(DESCRIPTOR_PATH);
      writeFileSync(descriptorPath, source, { mode: 0o600 });
      writeFileSync(keyPath, `${KEY}\n`, { mode: 0o600 });
      chmodSync(value.root, 0o700);
      const sourceSha256 = createHash("sha256").update(source).digest("hex");
      const environment = {
        TI_SCALE_RESEARCH_READINESS_TRUST_ROOT: value.root,
        TI_SCALE_RESEARCH_READINESS_DESCRIPTOR_PATH: descriptorPath,
        TI_SCALE_RESEARCH_READINESS_DESCRIPTOR_SHA256: sourceSha256,
        TI_SCALE_RESEARCH_READINESS_TEMP_ROOT: join(value.root, "work"),
        TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE: keyPath,
      };
      expect(loadProductionResearchReadinessProbeConfiguration(
        environment,
      )).toMatchObject({
        status: "loaded",
        descriptor: {
          evaluatorId: "ti-scale.local-research-readiness.v1",
        },
      });
      expect(resolveResearchIntegrityKey(environment)).toBe(KEY);
      expect(() => loadProductionResearchReadinessProbeConfiguration({
        ...environment,
        TI_SCALE_RESEARCH_READINESS_DESCRIPTOR_SHA256: "0".repeat(64),
      })).toThrow("does not match its reviewed SHA-256");
      expect(() => loadProductionResearchReadinessProbeConfiguration({
        TI_SCALE_RESEARCH_READINESS_TRUST_ROOT: value.root,
      })).toThrow("configuration is incomplete");
      chmodSync(keyPath, 0o644);
      expect(() => resolveResearchIntegrityKey(environment)).toThrow(
        "private regular file",
      );
    } finally {
      value.dispose();
    }
  });

  test("keeps the service available when optional Research deployment configuration is absent", () => {
    const dropIn = readFileSync(new URL(
      "../../../deployment/systemd/ti-scale.service.d/55-research-readiness.conf",
      import.meta.url,
    ), "utf8");
    expect(dropIn).toContain("LoadCredential=research-integrity-key\n");
    expect(dropIn).toContain(
      "EnvironmentFile=-/etc/ti-scale/research-readiness.env",
    );
    expect(dropIn).not.toContain("ConditionPathExists=");
    expect(dropIn).not.toContain(
      "LoadCredential=research-integrity-key:/etc/",
    );
    expect(dropIn).not.toContain(
      "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE=%d/",
    );
    expect(loadProductionResearchReadinessProbeConfiguration({})).toEqual({
      status: "unconfigured",
      reason:
        "No complete trusted local Research readiness probe configuration is configured.",
    });
    expect(resolveResearchIntegrityKey({})).toBeUndefined();

    const value = fixture();
    try {
      expect(resolveResearchIntegrityKey({
        CREDENTIALS_DIRECTORY: value.root,
      })).toBeUndefined();
      writeFileSync(
        join(value.root, "research-integrity-key"),
        `${KEY}\n`,
        { mode: 0o600 },
      );
      expect(resolveResearchIntegrityKey({
        CREDENTIALS_DIRECTORY: value.root,
      })).toBe(KEY);
    } finally {
      value.dispose();
    }
  });
});
