import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FailureDiagnosisService } from "../../intelligence-v24/FailureDiagnosisService";
import {
  deterministicOptions,
  testDatabase,
} from "../../intelligence-v24/__tests__/fixtures";
import {
  ToolExecutionPreflightService,
  toolPreflightFailureDiagnosisInput,
  type ToolExecutionPreflightEnvironment,
  type ToolExecutableIdentity,
  type ToolProbeExecutionResult,
} from "../ToolExecutionPreflight";

const NOW = new Date("2026-07-18T21:00:00.000Z");
const EXECUTABLE_IDENTITY: ToolExecutableIdentity = Object.freeze({
  sha256: "a".repeat(64),
  device: "1",
  inode: "2",
  sizeBytes: 1024,
  mode: 0o755,
  uid: 0,
  gid: 0,
});

function execution(overrides: Partial<ToolProbeExecutionResult> = {}): ToolProbeExecutionResult {
  return {
    exitCode: 0,
    signal: null,
    stdout: "Nmap version 7.99\n",
    stderr: "",
    timedOut: false,
    outputLimitExceeded: false,
    executableIdentity: EXECUTABLE_IDENTITY,
    ...overrides,
  };
}

function environment(overrides: Partial<ToolExecutionPreflightEnvironment> = {}): ToolExecutionPreflightEnvironment {
  return {
    isolation: {
      networkEnforced: true,
      filesystemWritesEnforced: true,
      immutableSnapshotEnforced: true,
    },
    inspectExecutable: async () => ({ state: "ready", identity: EXECUTABLE_IDENTITY }),
    inspectWorkingDirectory: async () => true,
    readNoNewPrivileges: async () => true,
    execute: async () => execution(),
    ...overrides,
  };
}

function service(overrides: Partial<ToolExecutionPreflightEnvironment> = {}) {
  return new ToolExecutionPreflightService({
    environment: environment(overrides),
    clock: () => NOW,
  });
}

const NMAP_SPEC = Object.freeze({
  toolId: "kali:nmap",
  displayName: "Nmap",
  executablePath: "/usr/bin/nmap",
  probeArguments: ["--version"] as const,
  workingDirectory: "/var/lib/ti-scale/workspaces/engagements/reapertwo",
  ttlMs: 60_000,
});

describe("argument-bounded local tool execution preflight", () => {
  test("attests one exact executable without PATH lookup, shell use, mission arguments, or execution authority", async () => {
    let received: Parameters<ToolExecutionPreflightEnvironment["execute"]>[0] | undefined;
    const preflight = service({
      execute: async (input) => {
        received = input;
        return execution();
      },
    });
    const result = await preflight.check(NMAP_SPEC);

    expect(result).toMatchObject({
      schemaVersion: "ti-scale.tool-execution-preflight.v2",
      status: "ready",
      code: "ready",
      probeBoundary: {
        shell: false,
        targetArgumentsSupplied: false,
        providerArgumentsSupplied: false,
        mcpArgumentsSupplied: false,
        networkIsolationEnforced: true,
        filesystemWriteIsolationEnforced: true,
        immutableSnapshotExecutionEnforced: true,
        externalContact: "not_measured",
      },
      executableIdentity: EXECUTABLE_IDENTITY,
      noNewPrivileges: true,
      checkedAt: NOW.toISOString(),
      expiresAt: "2026-07-18T21:01:00.000Z",
      execution: {
        exitCode: 0,
        signal: null,
        spawnErrorCode: null,
      },
    });
    expect(result.bindingSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.execution.outputSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(received).toEqual({
      executablePath: "/usr/bin/nmap",
      arguments: ["--version"],
      workingDirectory: "/var/lib/ti-scale/workspaces/engagements/reapertwo",
      timeoutMs: 3_000,
      maximumOutputBytes: 32 * 1_024,
      expectedExecutableIdentity: EXECUTABLE_IDENTITY,
    });
    expect(preflight.read("kali:nmap")).toEqual(result);
  });

  test("classifies the observed nmap NoNewPrivs/file-capability EPERM as a non-retryable dependency conflict", async () => {
    const result = await service({
      execute: async () => execution({
        exitCode: null,
        stdout: "",
        stderr: "/usr/bin/nmap: exec: /usr/lib/nmap/nmap: Operation not permitted\n",
        spawnErrorCode: "EPERM",
      }),
    }).check(NMAP_SPEC);

    expect(result).toMatchObject({
      status: "unavailable",
      code: "no_new_privileges_capability_conflict",
      noNewPrivileges: true,
      probeBoundary: { targetArgumentsSupplied: false, networkIsolationEnforced: true },
      failure: {
        category: "dependency_missing",
        retryable: false,
      },
    });
    expect(result.explanation).toContain("Linux refused to start it");
    expect(result.remediation).toContain("Do not copy or strip capabilities");
    expect(result.failure?.operatorActions.map(({ kind }) => kind)).toEqual([
      "configure_dependency",
      "use_compatible_fallback",
      "amend_plan",
    ]);
  });

  test("stops before execution when the mapped engagement directory is unavailable", async () => {
    let executed = false;
    const result = await service({
      inspectWorkingDirectory: async () => false,
      execute: async () => {
        executed = true;
        return execution();
      },
    }).check(NMAP_SPEC);

    expect(executed).toBe(false);
    expect(result).toMatchObject({
      status: "unavailable",
      code: "working_directory_unavailable",
      probeBoundary: { targetArgumentsSupplied: false, networkIsolationEnforced: true },
      failure: { category: "dependency_missing", retryable: false },
      execution: { outputBytes: 0, outputSha256: null },
    });
    expect(result.remediation).toContain("configured workspace map");
  });

  test("does not manufacture output bytes for an empty successful process", async () => {
    const result = await service({
      readNoNewPrivileges: async () => false,
      execute: async () => execution({ stdout: "", stderr: "" }),
    }).check(NMAP_SPEC);
    expect(result).toMatchObject({
      status: "unavailable",
      code: "startup_probe_empty",
      execution: { outputBytes: 0, outputSha256: null },
    });
  });

  test("independently rejects output beyond the reviewed bound when a worker omits its limit flag", async () => {
    const result = await service({
      execute: async () => execution({
        stdout: "x".repeat(1_025),
        outputLimitExceeded: false,
      }),
    }).check({ ...NMAP_SPEC, maximumOutputBytes: 1_024 });

    expect(result).toMatchObject({
      status: "unavailable",
      code: "startup_probe_output_limit",
      execution: { outputBytes: 1_025 },
    });
  });

  test("the production default refuses before starting a process without an immutable snapshot executor", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-preflight-no-executor-"));
    const executable = join(root, "bounded-probe");
    const marker = join(root, "executed");
    try {
      writeFileSync(executable, [
        "#!/bin/sh",
        `: > ${JSON.stringify(marker)}`,
        "sleep 30",
        "printf 'fixture 1.0\\n'",
        "",
      ].join("\n"), { mode: 0o700 });
      chmodSync(executable, 0o700);
      const result = await new ToolExecutionPreflightService().check({
        toolId: "validation:bounded-process-group",
        displayName: "Bounded process group fixture",
        executablePath: executable,
        probeArguments: ["--version"],
        workingDirectory: root,
        timeoutMs: 1_000,
        maximumOutputBytes: 1_024,
        ttlMs: 1_000,
      });
      expect(result).toMatchObject({
        status: "unavailable",
        code: "startup_probe_isolation_unavailable",
        probeBoundary: {
          targetArgumentsSupplied: false,
          networkIsolationEnforced: false,
          immutableSnapshotExecutionEnforced: false,
          externalContact: "not_measured",
        },
      });
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("does not start the supplied executor when any technical isolation boundary is absent", async () => {
    let executed = false;
    const result = await service({
      isolation: {
        networkEnforced: false,
        filesystemWritesEnforced: false,
        immutableSnapshotEnforced: false,
      },
      execute: async () => {
        executed = true;
        return execution();
      },
    }).check(NMAP_SPEC);

    expect(executed).toBe(false);
    expect(result).toMatchObject({
      status: "unavailable",
      code: "startup_probe_isolation_unavailable",
      probeBoundary: {
        targetArgumentsSupplied: false,
        networkIsolationEnforced: false,
        filesystemWriteIsolationEnforced: false,
        immutableSnapshotExecutionEnforced: false,
        externalContact: "not_measured",
      },
    });
    expect(result.explanation).toContain("was not started");
  });

  test("blocks a deterministic same-inode mutation-and-restore attempt before forged output can run", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-preflight-mutation-restore-"));
    const executable = join(root, "mutable-probe");
    const reviewed = "#!/bin/sh\nprintf 'reviewed 1.0\\n'\n";
    const forged = "#!/bin/sh\nprintf 'forged__ 1.0\\n'\n";
    let executeCalled = false;
    try {
      writeFileSync(executable, reviewed, { mode: 0o700 });
      const result = await service({
        isolation: {
          networkEnforced: true,
          filesystemWritesEnforced: true,
          immutableSnapshotEnforced: false,
        },
        execute: async () => {
          executeCalled = true;
          writeFileSync(executable, forged, { mode: 0o700 });
          writeFileSync(executable, reviewed, { mode: 0o700 });
          return execution({ stdout: "forged output\n" });
        },
      }).check({
        ...NMAP_SPEC,
        executablePath: executable,
        workingDirectory: root,
      });

      expect(executeCalled).toBe(false);
      expect(readFileSync(executable, "utf8")).toBe(reviewed);
      expect(result).toMatchObject({
        status: "unavailable",
        code: "startup_probe_isolation_unavailable",
        probeBoundary: { immutableSnapshotExecutionEnforced: false },
        execution: { outputBytes: 0, outputSha256: null },
      });
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("fails closed when executable identity changes after the bounded probe", async () => {
    let inspections = 0;
    const result = await service({
      inspectExecutable: async () => ({
        state: "ready",
        identity: {
          ...EXECUTABLE_IDENTITY,
          sha256: (++inspections === 1 ? "a" : "b").repeat(64),
        },
      }),
    }).check(NMAP_SPEC);

    expect(result).toMatchObject({
      status: "unavailable",
      code: "executable_identity_changed",
    });
  });

  test("rejects a symlinked executable before it can run", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-preflight-symlink-"));
    try {
      const executable = join(root, "version-fixture");
      const link = join(root, "version-link");
      writeFileSync(executable, "#!/bin/sh\nprintf 'fixture 1.0\\n'\n", { mode: 0o700 });
      symlinkSync(executable, link);
      const result = await new ToolExecutionPreflightService().check({
        toolId: "validation:symlink",
        displayName: "Symlink fixture",
        executablePath: link,
        probeArguments: ["--version"],
        ttlMs: 1_000,
      });
      expect(result).toMatchObject({
        status: "unavailable",
        code: "executable_not_regular_file",
        executableIdentity: null,
        execution: { exitCode: null, outputBytes: 0 },
      });
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each([
    [0o722, "executable_unsafe_permissions"],
    [0o600, "executable_not_executable"],
  ] as const)("rejects an exact executable with unsafe mode %o", async (mode, code) => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-preflight-mode-"));
    try {
      const executable = join(root, "version-fixture");
      writeFileSync(executable, "#!/bin/sh\nprintf 'fixture 1.0\\n'\n", { mode });
      chmodSync(executable, mode);
      const result = await new ToolExecutionPreflightService().check({
        toolId: "validation:mode",
        displayName: "Mode fixture",
        executablePath: executable,
        probeArguments: ["--version"],
        ttlMs: 1_000,
      });
      expect(result).toMatchObject({ status: "unavailable", code });
      expect(result.execution).toMatchObject({ exitCode: null, outputBytes: 0 });
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("rejects shell-shaped probes and relative executable or workspace paths before environment access", async () => {
    const preflight = service();
    await expect(preflight.check({
      ...NMAP_SPEC,
      probeArguments: ["--version; id"],
    })).rejects.toThrow("conventional version/help arguments");
    await expect(preflight.check({
      ...NMAP_SPEC,
      executablePath: "nmap",
    })).rejects.toThrow("absolute");
    await expect(preflight.check({
      ...NMAP_SPEC,
      workingDirectory: "reapertwo/scans",
    })).rejects.toThrow("absolute");
  });

  test("persists an operator-readable canonical FailureDiagnosis for the nmap boundary failure", async () => {
    const preflight = await service({
      execute: async () => execution({
        exitCode: null,
        stdout: "",
        stderr: "Operation not permitted",
        spawnErrorCode: "EPERM",
      }),
    }).check(NMAP_SPEC);
    const database = testDatabase();
    try {
      const failures = new FailureDiagnosisService(database, deterministicOptions());
      const diagnosis = failures.create(toolPreflightFailureDiagnosisInput(preflight, {
        missionId: "mission-one",
        runId: "run-one",
        actor: { id: "tool-preflight", type: "system" },
      }));

      expect(diagnosis).toMatchObject({
        missionId: "mission-one",
        runId: "run-one",
        subjectType: "run",
        subjectId: "run-one",
        category: "dependency_missing",
        code: "no_new_privileges_capability_conflict",
        failedComponentRef: "kali:nmap",
        retryable: false,
        objectiveImpact: "The affected step did not start. Prior mission state and evidence remain unchanged.",
      });
      expect(diagnosis.humanReason).toContain("no-new-privileges boundary");
      expect(diagnosis.policyOrDependency).toContain("file-capability elevation");
      expect(database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });
});
