import { describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDatabaseConnection } from "../../db";
import {
  assertEarlyAuthenticationAdmissionReceipt,
  captureEarlyAuthenticationStartBoundary,
  EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
  waitForEarlyAuthenticationAdmission,
} from "../../../scripts/release/EarlyAuthenticationAdmission";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const DIRECT_SERVICE_WRAPPER_WORKER = join(
  PROJECT_ROOT,
  "tests/unit/release/fixtures/direct-service-wrapper-worker.ts",
);

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve Ti-Scale port");
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}

function isolatedEnvironment(input: Readonly<{
  port: number;
  databasePath: string;
  vaultRoot: string;
  scriptRoot: string;
  operatorToken: string;
}>): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.startsWith("TI_SCALE_LOCAL_TOOL_")
      || name.startsWith("TI_SCALE_AUTONOMOUS_DNS_")
      || name.startsWith("TI_SCALE_WINDOWS_IDENTITY_")
      || name.startsWith("TI_SCALE_RUNTIME_SOURCE_")) {
      delete environment[name];
    }
  }
  return {
    ...environment,
    TI_SCALE_HOST: "127.0.0.1",
    TI_SCALE_PORT: String(input.port),
    TI_SCALE_DATABASE_PATH: input.databasePath,
    TI_SCALE_VAULT_ROOT: input.vaultRoot,
    TI_SCALE_SCRIPT_SOURCE_ROOT: input.scriptRoot,
    TI_SCALE_OPERATOR_TOKEN: input.operatorToken,
    TI_SCALE_OPERATOR_ID: "operator:standalone-graceful-shutdown",
    TI_SCALE_UI_ORIGIN: `http://127.0.0.1:${input.port}`,
    TI_SCALE_PREVIEW: "true",
    TI_SCALE_SERVE_STATIC: "false",
    TI_SCALE_SECURE_COOKIES: "false",
    TI_SCALE_KILL_SWITCH: "false",
    TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
    TI_SCALE_WINDOWS_IDENTITY_ENABLED: "false",
    TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "false",
    TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
  };
}

async function waitForHealth(child: ChildProcess, url: string, readLogs: () => string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Standalone Ti-Scale exited during startup: ${readLogs()}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(500) });
      if (response.status === 200) return;
    } catch {
      // The disposable listener is still starting.
    }
    await delay(25);
  }
  throw new Error(`Standalone Ti-Scale did not become healthy: ${readLogs()}`);
}

async function waitForOutput(
  child: ChildProcess,
  readLogs: () => string,
  expected: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (readLogs().includes(expected)) return;
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Standalone Ti-Scale exited before ${expected}: ${readLogs()}`);
    }
    await delay(20);
  }
  throw new Error(`Standalone Ti-Scale did not emit ${expected}: ${readLogs()}`);
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<number | null> {
  if (child.exitCode !== null || child.signalCode !== null) return child.exitCode;
  return await new Promise<number | null>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Standalone Ti-Scale did not exit")), timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve(code);
    });
  });
}

describe("standalone Ti-Scale graceful shutdown", () => {
  test("two production-entrypoint cold starts expose exact local authentication inside eight seconds", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-cold-restart-auth-"));
    const databasePath = join(root, "data", "ti-scale.sqlite");
    const vaultRoot = join(root, "vaults");
    const scriptRoot = join(root, "artifacts", "scripts");
    mkdirSync(join(root, "data"), { recursive: true });
    mkdirSync(vaultRoot, { recursive: true });
    mkdirSync(scriptRoot, { recursive: true });
    const port = await reservePort();
    const operatorToken = randomBytes(32).toString("hex");
    let previousInvocationId = "no-process-before-first-cold-start";
    const receipts = [];
    const processIds: number[] = [];

    try {
      for (let restart = 0; restart < 2; restart += 1) {
        const start = captureEarlyAuthenticationStartBoundary();
        const child = spawn(process.execPath, ["run", "server/index.ts"], {
          cwd: PROJECT_ROOT,
          env: isolatedEnvironment({ port, databasePath, vaultRoot, scriptRoot, operatorToken }),
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
        child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
        const logs = () => `${stdout}\n${stderr}`.replaceAll(operatorToken, "[REDACTED]");
        const pid = child.pid;
        if (!pid) throw new Error("Cold-start fixture did not receive a child PID");
        const currentInvocationId = `standalone-process:${String(pid)}`;
        processIds.push(pid);
        try {
          const receipt = await waitForEarlyAuthenticationAdmission({
            start,
            previousInvocationId,
            observeProcess: () => {
              if (child.exitCode !== null || child.signalCode !== null) {
                throw new Error(`Cold-start process exited before admission: ${logs()}`);
              }
              return {
                activeState: "active",
                mainPid: pid,
                invocationId: currentInvocationId,
              };
            },
            requestSession: async (context) => {
              const response = await fetch(`http://127.0.0.1:${String(port)}/api/v2/auth/session`, {
                method: "GET",
                cache: "no-store",
                headers: { Accept: "application/json" },
                signal: AbortSignal.any([
                  context.signal,
                  AbortSignal.timeout(Math.min(500, context.remainingMs)),
                ]),
              });
              return { status: response.status, body: await response.json() };
            },
          });
          expect(assertEarlyAuthenticationAdmissionReceipt(receipt, {
            previousInvocationId,
            currentInvocationId,
          })).toEqual(receipt);
          expect(receipt.responseAfterStartMs).toBeLessThan(
            EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
          );
          receipts.push(receipt);
          await waitForOutput(child, logs, "operational admission ready", 10_000);
          expect(`${stdout}\n${stderr}`).not.toContain(operatorToken);
          expect(child.kill("SIGTERM")).toBe(true);
          expect(await waitForExit(child, 6_000)).toBe(0);
          expect(stdout).toContain("shutdown completed");
          previousInvocationId = currentInvocationId;
        } finally {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGKILL");
            await waitForExit(child, 2_000).catch(() => undefined);
          }
        }
      }

      expect(processIds).toHaveLength(2);
      expect(processIds[0]).not.toBe(processIds[1]);
      expect(receipts).toHaveLength(2);
      expect(receipts[1]?.previousInvocationId).toBe(receipts[0]?.observedInvocationId);
      const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
      try {
        const leases = database.prepare(`
          SELECT owner_id, released_at, release_reason
          FROM canonical_database_leases
          WHERE operation = 'standalone-service-runtime'
          ORDER BY acquired_at
        `).all() as Array<{
          owner_id: string;
          released_at: string | null;
          release_reason: string | null;
        }>;
        expect(leases).toHaveLength(2);
        expect(leases).toEqual(processIds.map((pid) => ({
          owner_id: `ti-scale-service:${String(pid)}`,
          released_at: expect.any(String),
          release_reason: "service-shutdown:SIGTERM",
        })));
        expect(database.pragma("integrity_check", { simple: true })).toBe("ok");
      } finally {
        database.close();
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  test("the stable wrapper becomes the server PID and SIGTERM releases its canonical writer lease", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-standalone-shutdown-"));
    const databasePath = join(root, "data", "ti-scale.sqlite");
    const vaultRoot = join(root, "vaults");
    const scriptRoot = join(root, "artifacts", "scripts");
    mkdirSync(join(root, "data"), { recursive: true });
    mkdirSync(vaultRoot, { recursive: true });
    mkdirSync(scriptRoot, { recursive: true });
    const port = await reservePort();
    const operatorToken = randomBytes(32).toString("hex");
    const child = spawn(process.execPath, [DIRECT_SERVICE_WRAPPER_WORKER, PROJECT_ROOT], {
      cwd: PROJECT_ROOT,
      env: isolatedEnvironment({ port, databasePath, vaultRoot, scriptRoot, operatorToken }),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    const logs = () => `${stdout}\n${stderr}`.replaceAll(operatorToken, "[REDACTED]");

    try {
      await waitForHealth(child, `http://127.0.0.1:${port}/api/v2/health`, logs);
      await waitForOutput(child, logs, "operational admission ready", 10_000);
      expect(typeof child.pid).toBe("number");
      const liveDatabase = createDatabaseConnection({
        filename: databasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const activeLease = liveDatabase.prepare(`
          SELECT owner_id, released_at
          FROM canonical_database_leases
          WHERE operation = 'standalone-service-runtime'
          ORDER BY acquired_at DESC LIMIT 1
        `).get() as { owner_id: string; released_at: string | null } | undefined;
        expect(activeLease).toEqual({
          owner_id: `ti-scale-service:${String(child.pid)}`,
          released_at: null,
        });
      } finally {
        liveDatabase.close();
      }
      const started = performance.now();
      expect(child.kill("SIGTERM")).toBe(true);
      await delay(25);
      // A duplicate service-manager signal must remain inside the same
      // graceful drain rather than restoring Node's default termination.
      expect(child.kill("SIGTERM")).toBe(true);
      expect(await waitForExit(child, 6_000)).toBe(0);
      expect(performance.now() - started).toBeLessThan(5_000);
      expect(stdout).toContain("Ti-Scale received SIGTERM; draining isolated resources");
      expect(stdout).toMatch(/Ti-Scale shutdown completed in [0-9]+ms/u);
      expect(stderr).not.toContain("shutdown timed out");
      expect(`${stdout}\n${stderr}`).not.toContain(operatorToken);

      const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
      try {
        const leases = database.prepare(`
          SELECT released_at, release_reason
          FROM canonical_database_leases
          WHERE operation = 'standalone-service-runtime'
          ORDER BY acquired_at DESC
        `).all() as Array<{ released_at: string | null; release_reason: string | null }>;
        expect(leases).toHaveLength(1);
        expect(leases[0]?.released_at).not.toBeNull();
        expect(leases[0]?.release_reason).toBe("service-shutdown:SIGTERM");
        expect(database.pragma("integrity_check", { simple: true })).toBe("ok");
      } finally {
        database.close();
      }
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await waitForExit(child, 2_000).catch(() => undefined);
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 15_000);

  test("SIGTERM during startup drains initialized resources and releases the writer lease before operational admission", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-startup-shutdown-"));
    const databasePath = join(root, "data", "ti-scale.sqlite");
    const vaultRoot = join(root, "vaults");
    const scriptRoot = join(root, "artifacts", "scripts");
    mkdirSync(join(root, "data"), { recursive: true });
    mkdirSync(vaultRoot, { recursive: true });
    mkdirSync(scriptRoot, { recursive: true });
    const port = await reservePort();
    const operatorToken = randomBytes(32).toString("hex");
    const child = spawn(process.execPath, ["run", "server/index.ts"], {
      cwd: PROJECT_ROOT,
      env: {
        ...isolatedEnvironment({ port, databasePath, vaultRoot, scriptRoot, operatorToken }),
        NODE_ENV: "test",
        TI_SCALE_TEST_STARTUP_HOLD_AFTER_LEASE_MS: "5000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    const logs = () => `${stdout}\n${stderr}`.replaceAll(operatorToken, "[REDACTED]");

    try {
      await waitForOutput(
        child,
        logs,
        "Ti-Scale startup shutdown test hold ready after writer lease",
        10_000,
      );
      const sessionResponse = await fetch(`http://127.0.0.1:${port}/api/v2/auth/session`, {
        signal: AbortSignal.timeout(1_000),
      });
      expect(sessionResponse.status).toBe(200);
      expect(await sessionResponse.json()).toEqual({
        schemaVersion: "2.4",
        configured: true,
        authenticated: false,
      });
      const loginResponse = await fetch(`http://127.0.0.1:${port}/api/v2/auth/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorToken }),
        signal: AbortSignal.timeout(1_000),
      });
      expect(loginResponse.status).toBe(200);
      expect(await loginResponse.json()).toMatchObject({
        schemaVersion: "2.4",
        authenticated: true,
        actorId: "operator:standalone-graceful-shutdown",
      });
      expect(loginResponse.headers.get("set-cookie")).toContain("ti_scale_session=");
      const healthResponse = await fetch(`http://127.0.0.1:${port}/api/v2/health`, {
        signal: AbortSignal.timeout(1_000),
      });
      expect(healthResponse.status).toBe(200);
      expect(await healthResponse.json()).toMatchObject({
        schemaVersion: "2.4",
        status: "degraded",
        service: "ti-scale",
        startup: {
          status: "initializing",
          executionAdmission: "closed",
        },
      });
      const mutationResponse = await fetch(`http://127.0.0.1:${port}/api/v2/missions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${operatorToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
        signal: AbortSignal.timeout(1_000),
      });
      expect(mutationResponse.status).toBe(503);
      expect(await mutationResponse.json()).toMatchObject({
        error: {
          code: "ti_scale_startup_initializing",
          retryable: true,
          details: { executionAdmission: "closed" },
        },
      });
      const started = performance.now();
      expect(child.kill("SIGTERM")).toBe(true);
      await delay(25);
      expect(child.kill("SIGTERM")).toBe(true);
      expect(await waitForExit(child, 6_000)).toBe(0);
      expect(performance.now() - started).toBeLessThan(5_000);
      expect(stdout).toContain("Ti-Scale received SIGTERM during startup");
      expect(stdout).toMatch(/Ti-Scale startup shutdown completed in [0-9]+ms/u);
      expect(stdout).not.toContain("operational admission ready");
      expect(`${stdout}\n${stderr}`).not.toContain(operatorToken);

      await expect(fetch(`http://127.0.0.1:${port}/api/v2/health`, {
        signal: AbortSignal.timeout(250),
      })).rejects.toBeDefined();
      const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
      try {
        const leases = database.prepare(`
          SELECT released_at, release_reason
          FROM canonical_database_leases
          WHERE operation = 'standalone-service-runtime'
          ORDER BY acquired_at DESC
        `).all() as Array<{ released_at: string | null; release_reason: string | null }>;
        expect(leases).toHaveLength(1);
        expect(leases[0]?.released_at).not.toBeNull();
        expect(leases[0]?.release_reason).toBe("service-shutdown:SIGTERM");
        expect(database.pragma("integrity_check", { simple: true })).toBe("ok");
      } finally {
        database.close();
      }
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await waitForExit(child, 2_000).catch(() => undefined);
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 20_000);
});
