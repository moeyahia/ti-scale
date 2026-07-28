import { spawn, type ChildProcess } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../server/db";
import { StaticArtifactReleaseStore } from "../../server/static-release";
import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.auth.early-startup";
const PROJECT_ROOT = resolve(import.meta.dirname, "../..");
const STARTUP_DEADLINE_MS = 8_000;
const OPERATOR_TOKEN = "isolated-early-auth-browser-token-2026";

interface SlowStartupServer {
  readonly child: ChildProcess;
  readonly origin: string;
  readonly workspace: string;
  readonly startedAt: number;
  logs(): string;
}

function makeWritable(path: string): void {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeWritable(join(path, name));
  } else chmodSync(path, 0o600);
}

async function availablePort(): Promise<number> {
  const reservation = createServer();
  await new Promise<void>((resolveListen, rejectListen) => {
    reservation.once("error", rejectListen);
    reservation.listen(0, "127.0.0.1", () => {
      reservation.off("error", rejectListen);
      resolveListen();
    });
  });
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve early-auth browser port");
  await new Promise<void>((resolveClose, rejectClose) => {
    reservation.close((error) => error ? rejectClose(error) : resolveClose());
  });
  return address.port;
}

async function startSlowStartupServer(): Promise<SlowStartupServer> {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-static-server-integration-browser-"));
  const databasePath = join(workspace, "data", "ti-scale.sqlite");
  const releaseRoot = join(workspace, "static-releases");
  const vaultRoot = join(workspace, "vaults");
  const scriptSourceRoot = join(workspace, "artifacts", "script-sources");
  mkdirSync(join(workspace, "data"), { recursive: true });
  mkdirSync(vaultRoot, { recursive: true });
  mkdirSync(scriptSourceRoot, { recursive: true });
  if (!existsSync(join(PROJECT_ROOT, "dist", "index.html"))) {
    throw new Error("The early-auth browser gate requires the production client build");
  }
  const releaseId = `early-auth-browser-${process.pid}-${Date.now()}`;
  const staticReleaseStore = new StaticArtifactReleaseStore({
    releaseRoot,
  });
  staticReleaseStore.stageRelease({
    releaseId,
    sourceDirectory: join(PROJECT_ROOT, "dist"),
  });
  staticReleaseStore.activateRelease(releaseId);
  const database = createDatabaseConnection({ filename: databasePath, verifyIntegrity: false });
  try { migrateDatabase(database); }
  finally { database.close(); }

  const port = await availablePort();
  let stdout = "";
  let stderr = "";
  const startedAt = performance.now();
  const child = spawn("bun", ["run", "server/index.ts"], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: "test",
      TI_SCALE_HOST: "127.0.0.1",
      TI_SCALE_PORT: String(port),
      TI_SCALE_DATABASE_PATH: databasePath,
      TI_SCALE_VAULT_ROOT: vaultRoot,
      TI_SCALE_SCRIPT_SOURCE_ROOT: scriptSourceRoot,
      TI_SCALE_STATIC_RELEASE_ROOT: releaseRoot,
      TI_SCALE_SERVE_STATIC: "true",
      TI_SCALE_PREVIEW: "true",
      TI_SCALE_SECURE_COOKIES: "false",
      TI_SCALE_KILL_SWITCH: "false",
      TI_SCALE_OPERATOR_TOKEN: OPERATOR_TOKEN,
      TI_SCALE_OPERATOR_ID: "operator:early-auth-browser",
      TI_SCALE_UI_ORIGIN: `http://127.0.0.1:${String(port)}`,
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "false",
      TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
      TI_SCALE_TEST_SLOW_STARTUP_INTEGRITY: "true",
      NO_COLOR: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
  child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  return {
    child,
    origin: `http://127.0.0.1:${String(port)}`,
    workspace,
    startedAt,
    logs: () => `${stdout}\n${stderr}`.replaceAll(OPERATOR_TOKEN, "[REDACTED]"),
  };
}

async function waitForEarlySession(server: SlowStartupServer): Promise<{
  readonly elapsedMs: number;
  readonly body: unknown;
}> {
  const deadline = server.startedAt + STARTUP_DEADLINE_MS;
  let lastError = "listener not reached";
  while (performance.now() < deadline) {
    if (server.child.exitCode !== null || server.child.signalCode !== null) {
      throw new Error(`Slow-start server exited before authentication admission: ${server.logs()}`);
    }
    try {
      const response = await fetch(`${server.origin}/api/v2/auth/session`, {
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(500),
      });
      const body = await response.json();
      if (response.status !== 200) {
        throw new Error(`session returned HTTP ${String(response.status)}`);
      }
      return { elapsedMs: performance.now() - server.startedAt, body };
    } catch (error) {
      lastError = error instanceof Error ? error.message : "session request failed";
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
  throw new Error(
    `Authentication admission exceeded ${String(STARTUP_DEADLINE_MS)}ms (${lastError}): ${server.logs()}`,
  );
}

async function stopSlowStartupServer(server: SlowStartupServer): Promise<void> {
  if (server.child.exitCode === null && server.child.signalCode === null) server.child.kill("SIGTERM");
  let cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  let stopError: unknown;
  try {
    await Promise.race([
      new Promise<void>((resolveExit) => {
        if (server.child.exitCode !== null || server.child.signalCode !== null) resolveExit();
        else server.child.once("exit", () => resolveExit());
      }),
      new Promise<never>((_resolve, reject) => {
        cleanupTimer = setTimeout(
          () => reject(new Error("Slow-start server did not stop within its cleanup bound")),
          6_000,
        );
      }),
    ]);
  } catch (error) {
    stopError = error;
    if (server.child.exitCode === null && server.child.signalCode === null) server.child.kill("SIGKILL");
  } finally {
    if (cleanupTimer) clearTimeout(cleanupTimer);
    makeWritable(server.workspace);
    rmSync(server.workspace, { recursive: true, force: true });
  }
  if (stopError) throw stopError;
}

test.use({ storageState: { cookies: [], origins: [] } });

test(`${TEST_ID} renders the real LoginSurface while integrity remains fail-closed`, async ({
  page,
  browserAudit,
}) => {
  test.setTimeout(25_000);
  const server = await startSlowStartupServer();
  try {
    const admission = await waitForEarlySession(server);
    expect(admission.elapsedMs).toBeLessThan(STARTUP_DEADLINE_MS);
    expect(admission.body).toEqual({
      schemaVersion: "2.4",
      configured: true,
      authenticated: false,
    });

    const healthResponse = await fetch(`${server.origin}/api/v2/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(1_000),
    });
    expect(healthResponse.status).toBe(200);
    expect(await healthResponse.json()).toMatchObject({
      schemaVersion: "2.4",
      status: "degraded",
      startup: {
        status: "initializing",
        phase: "database_integrity",
        executionAdmission: "closed",
      },
    });

    const navigationStartedAt = performance.now();
    await page.goto(server.origin, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Enter Ti-Scale", exact: true }))
      .toBeVisible({ timeout: 4_000 });
    expect(performance.now() - navigationStartedAt).toBeLessThan(STARTUP_DEADLINE_MS);
    await expect(page.getByLabel("Local operator token", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in to Ti-Scale", exact: true })).toBeEnabled();
    await expect(page.getByText(
      "Authenticate locally before mission, evidence, memory, or runtime data is loaded. The token is exchanged for an HttpOnly, same-site session and is never stored in browser storage.",
      { exact: true },
    )).toBeVisible();
    expect(await page.evaluate(() => ({ ...localStorage, ...sessionStorage }))).toEqual({});
    expect(server.logs()).toContain("authentication admission active");
    expect(server.logs()).not.toContain("operational admission ready");
    expect(server.logs()).not.toContain(OPERATOR_TOKEN);

    await browserAudit.closePageBeforeDependencyShutdown(page);
  } finally {
    await stopSlowStartupServer(server);
  }
});
