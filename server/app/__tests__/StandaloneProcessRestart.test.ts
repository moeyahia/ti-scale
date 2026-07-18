import { describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import {
  ActionRepository,
  DurableRunCoordinator,
  type ExecutionPort,
} from "../../orchestration";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const DISPOSABLE_ROOT = join(tmpdir(), "ti-scale-e2e-data");
const LEGACY_HEALTH_URL = process.env.TI_SCALE_TEST_EXTERNAL_HEALTH_URL?.trim()
  || "http://127.0.0.1:3131/api/health";
const LOG_LIMIT_BYTES = 64 * 1_024;

interface CapturedChild {
  readonly child: ChildProcess;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

interface DurableSnapshot {
  readonly actions: readonly string[];
  readonly events: readonly {
    id: string;
    sequence: number;
    eventType: string;
  }[];
  readonly outboxEventIds: readonly string[];
  readonly checkpoints: readonly {
    id: string;
    eventSequence: number;
    classification: string | null;
  }[];
  readonly contextPackIds: readonly string[];
  readonly vaultConnections: readonly {
    id: string;
    status: string;
    vaultPath: string;
  }[];
  readonly vaultSyncNodeIds: readonly string[];
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("Could not reserve a disposable V2 port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return port;
}

function appendLog(target: CapturedChild, stream: "stdout" | "stderr", chunk: Buffer): void {
  const current = target[stream];
  if (Buffer.byteLength(current, "utf8") >= LOG_LIMIT_BYTES) {
    target.truncated = true;
    return;
  }
  const remaining = LOG_LIMIT_BYTES - Buffer.byteLength(current, "utf8");
  const next = chunk.subarray(0, remaining).toString("utf8");
  target[stream] = current + next;
  if (chunk.byteLength > remaining) target.truncated = true;
}

function startServer(input: {
  readonly port: number;
  readonly databasePath: string;
  readonly vaultRoot: string;
  readonly scriptRoot: string;
  readonly operatorToken: string;
  readonly runId?: string;
  readonly recoveryRuntime: boolean;
}): CapturedChild {
  const child = spawn(process.execPath, ["run", "server/index.ts"], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      TI_SCALE_HOST: "127.0.0.1",
      TI_SCALE_PORT: String(input.port),
      TI_SCALE_DATABASE_PATH: input.databasePath,
      TI_SCALE_VAULT_ROOT: input.vaultRoot,
      TI_SCALE_SCRIPT_SOURCE_ROOT: input.scriptRoot,
      TI_SCALE_OPERATOR_TOKEN: input.operatorToken,
      TI_SCALE_OPERATOR_ID: "operator:process-boundary-restart",
      TI_SCALE_UI_ORIGIN: `http://127.0.0.1:${input.port}`,
      TI_SCALE_PREVIEW: "true",
      TI_SCALE_SERVE_STATIC: "false",
      TI_SCALE_SECURE_COOKIES: "false",
      TI_SCALE_KILL_SWITCH: "false",
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: input.recoveryRuntime ? "true" : "false",
      TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: input.recoveryRuntime ? "true" : "false",
      TI_SCALE_E2E_RUN_ID: input.runId ?? "process-boundary-not-started",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const captured: CapturedChild = { child, stdout: "", stderr: "", truncated: false };
  child.stdout?.on("data", (chunk: Buffer) => appendLog(captured, "stdout", chunk));
  child.stderr?.on("data", (chunk: Buffer) => appendLog(captured, "stderr", chunk));
  return captured;
}

function safeDiagnostics(
  captured: CapturedChild,
  operatorToken: string,
  disposableDirectory: string,
): string {
  const raw = `${captured.stdout}\n${captured.stderr}`;
  if (raw.includes(operatorToken)) {
    return "Child output violated the secret-redaction invariant.";
  }
  const sanitized = raw
    .replaceAll(disposableDirectory, "[DISPOSABLE_ROOT]")
    .replaceAll(operatorToken, "[REDACTED]");
  return `${sanitized}${captured.truncated ? "\n[bounded child log truncated]" : ""}`.trim();
}

async function waitForExit(captured: CapturedChild, timeoutMs = 8_000): Promise<void> {
  if (captured.child.exitCode !== null || captured.child.signalCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Disposable V2 child did not exit within the cleanup bound"));
    }, timeoutMs);
    captured.child.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

async function stopChild(captured: CapturedChild, signal: NodeJS.Signals): Promise<void> {
  if (captured.child.exitCode === null && captured.child.signalCode === null) {
    captured.child.kill(signal);
  }
  await waitForExit(captured);
}

async function waitForV2(
  captured: CapturedChild,
  baseUrl: string,
  operatorToken: string,
  disposableDirectory: string,
): Promise<void> {
  const deadline = Date.now() + 12_000;
  let lastStatus = "not reached";
  while (Date.now() < deadline) {
    if (captured.child.exitCode !== null || captured.child.signalCode !== null) {
      throw new Error(`Disposable V2 child exited during startup. ${safeDiagnostics(captured, operatorToken, disposableDirectory)}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/v2/health`, {
        signal: AbortSignal.timeout(750),
      });
      lastStatus = String(response.status);
      if (response.status === 200) return;
    } catch (error) {
      lastStatus = error instanceof Error ? error.name : "fetch failure";
    }
    await delay(50);
  }
  throw new Error(
    `Disposable V2 health did not become ready (last result: ${lastStatus}). ${safeDiagnostics(captured, operatorToken, disposableDirectory)}`,
  );
}

async function authenticate(baseUrl: string, operatorToken: string): Promise<void> {
  const response = await fetch(`${baseUrl}/api/v2/auth/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ operatorToken }),
    signal: AbortSignal.timeout(2_000),
  });
  if (response.status !== 200) {
    throw new Error(`Disposable V2 authentication failed with status ${response.status}`);
  }
  const body = await response.json() as { authenticated?: boolean; actorId?: string };
  expect(body).toMatchObject({
    authenticated: true,
    actorId: "operator:process-boundary-restart",
  });
}

async function apiJson<T>(
  baseUrl: string,
  operatorToken: string,
  path: string,
  init: RequestInit = {},
  expectedStatus = 200,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${operatorToken}`);
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers,
    signal: AbortSignal.timeout(4_000),
  });
  if (response.status !== expectedStatus) {
    const failure = await response.json().catch(() => ({ code: "non_json_error" })) as { code?: string };
    throw new Error(`${path} returned ${response.status} (${failure.code ?? "unknown"})`);
  }
  return await response.json() as T;
}

async function readLegacyHealth(): Promise<{ status: string } | null> {
  try {
    const response = await fetch(LEGACY_HEALTH_URL, {
      method: "GET",
      signal: AbortSignal.timeout(1_000),
    });
    if (!response.ok) return null;
    const body = await response.json() as { status?: unknown };
    return typeof body.status === "string" ? { status: body.status } : null;
  } catch {
    // CI does not have to launch the protected legacy process. An absent
    // service is deliberately omitted rather than probing or starting legacy
    // with unknown data paths; when the read-only route is present, the test
    // requires it to remain responsive across the V2 SIGKILL and restart.
    return null;
  }
}

function seedConfirmedMemory(databasePath: string): void {
  const database = createDatabaseConnection({ filename: databasePath });
  try {
    migrateDatabase(database);
    new MemoryRepository(database).createNode({
      id: "mem-process-boundary-vault",
      nodeType: "procedure",
      title: "Process-boundary Guided restart fixture",
      summary: "Use durable checkpoints and verified local evidence during the authorized restart fixture",
      body: "This operator-confirmed local procedure is safe to retrieve for the Guided process-boundary mission and project into Obsidian.",
      scope: { kind: "global" },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Confirmed for the isolated process-boundary durability fixture",
        sources: [{
          sourceType: "message",
          sourceId: "source-process-boundary-vault",
          acquiredAt: "2026-07-17T00:00:00.000Z",
        }],
      },
      authorType: "operator",
      authorId: "operator:process-boundary-restart",
      retentionPolicy: { allowAutonomous: false, allowGuided: true },
    });
  } finally {
    database.close();
  }
}

function seedExpiredInFlightBoundary(input: {
  readonly databasePath: string;
  readonly missionId: string;
  readonly runId: string;
  readonly contextPackId: string;
}): { actionId: string; checkpointId: string } {
  const database = createDatabaseConnection({
    filename: input.databasePath,
    fileMustExist: true,
  });
  try {
    const execution: ExecutionPort = {
      async dispatch() {},
      async resume() {},
      async cancelRun() {},
    };
    const coordinator = new DurableRunCoordinator(database, execution, {
      leaseTtlMs: 100,
    });
    const lease = coordinator.acquireRunLease(
      input.runId,
      "worker:terminated-process-boundary",
      100,
    );
    const action = new ActionRepository(database).create({
      intent: {
        missionId: input.missionId,
        runId: input.runId,
        // A planning crash can occur before a PlanStep exists. The canonical
        // schema intentionally permits a null action-to-step relationship.
        stepId: null as unknown as string,
        actionType: "process_boundary_probe",
        actionClass: "read-only",
        arguments: { fixture: "isolated-local-state" },
        target: "lab:process-boundary-restart",
        planVersion: 0,
        precedingState: { runStatus: "planning" },
        kind: "tool",
        intentSummary: "Represent one interrupted non-repeatable local fixture action",
        idempotent: false,
        destructive: false,
        contextPackId: input.contextPackId,
      },
      fingerprint: "process-boundary-non-repeatable-action-v1",
      now: new Date().toISOString(),
    });
    const accounted = coordinator.accountUsage({
      lease,
      phase: "process-boundary fixture persisted before abrupt termination",
    });
    return { actionId: action.id, checkpointId: accounted.checkpointId };
  } finally {
    database.close();
  }
}

function durableSnapshot(databasePath: string, runId: string): DurableSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath,
    fileMustExist: true,
    readonly: true,
  });
  try {
    return {
      actions: (database.prepare(`
        SELECT id FROM actions WHERE run_id = ? ORDER BY created_at, id
      `).all(runId) as Array<{ id: string }>).map((row) => row.id),
      events: database.prepare(`
        SELECT id, sequence, event_type AS eventType
        FROM events WHERE run_id = ? ORDER BY sequence
      `).all(runId) as Array<{ id: string; sequence: number; eventType: string }>,
      outboxEventIds: (database.prepare(`
        SELECT outbox.event_id AS id
        FROM event_outbox outbox
        JOIN events event ON event.id = outbox.event_id
        WHERE event.run_id = ? ORDER BY event.sequence
      `).all(runId) as Array<{ id: string }>).map((row) => row.id),
      checkpoints: database.prepare(`
        SELECT id, event_sequence AS eventSequence,
          in_flight_classification AS classification
        FROM checkpoints WHERE run_id = ?
        ORDER BY event_sequence, created_at, id
      `).all(runId) as Array<{
        id: string;
        eventSequence: number;
        classification: string | null;
      }>,
      contextPackIds: (database.prepare(`
        SELECT id FROM memory_context_packs WHERE mission_id = ? ORDER BY created_at, id
      `).all(
        (database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as { mission_id: string }).mission_id,
      ) as Array<{ id: string }>).map((row) => row.id),
      vaultConnections: database.prepare(`
        SELECT id, status, vault_path AS vaultPath
        FROM vault_connections ORDER BY created_at, id
      `).all() as Array<{ id: string; status: string; vaultPath: string }>,
      vaultSyncNodeIds: (database.prepare(`
        SELECT node_id AS id FROM vault_sync_state
        WHERE node_id IS NOT NULL ORDER BY node_id
      `).all() as Array<{ id: string }>).map((row) => row.id),
    };
  } finally {
    database.close();
  }
}

function markdownFiles(root: string): string[] {
  const result: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith(".md")) result.push(path);
    }
  };
  visit(root);
  return result.sort();
}

describe("standalone V2 process-boundary durability", () => {
  test("recovers one interrupted run exactly once and preserves its active Obsidian Vault", async () => {
    mkdirSync(DISPOSABLE_ROOT, { recursive: true });
    const directory = mkdtempSync(join(DISPOSABLE_ROOT, "process-restart-"));
    const databasePath = join(directory, "ti-scale.sqlite");
    const vaultRoot = join(directory, "vault-root");
    const scriptRoot = join(directory, "script-root");
    const operatorToken = `process-boundary-${randomBytes(24).toString("hex")}`;
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const children = new Set<CapturedChild>();

    const launch = (recoveryRuntime: boolean, runId?: string): CapturedChild => {
      const child = startServer({
        port,
        databasePath,
        vaultRoot,
        scriptRoot,
        operatorToken,
        recoveryRuntime,
        ...(runId ? { runId } : {}),
      });
      children.add(child);
      child.child.once("exit", () => children.delete(child));
      return child;
    };

    try {
      seedConfirmedMemory(databasePath);
      const legacyBefore = await readLegacyHealth();

      const first = launch(false);
      await waitForV2(first, baseUrl, operatorToken, directory);
      await authenticate(baseUrl, operatorToken);

      const created = await apiJson<{
        mission: { id: string };
        run: { id: string; status: string };
        intakeContext: { contextPackId: string; status: string };
      }>(baseUrl, operatorToken, "/api/v2/missions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "process-boundary-guided-mission-v1",
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: "Process-boundary Guided restart fixture",
          objective: "Validate durable local state and Vault continuity across one abrupt V2 restart",
          target: "lab:process-boundary-restart",
          engagementId: "eng-process-boundary-restart",
          explanationDepth: "balanced",
          executionPreference: "manual",
          evidenceExpectations: ["immutable process-boundary checkpoint"],
        }),
      }, 201);
      expect(created.run.status).toBe("planning");
      expect(created.intakeContext.contextPackId).toMatch(/^ctx_/u);

      const health = await apiJson<{
        result: { status: string; checks: Record<string, boolean> };
      }>(baseUrl, operatorToken, "/api/v2/brain/vault/health-check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "process-boundary-vault-health-v1",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          permissionGranted: true,
        }),
      });
      expect(health.result).toMatchObject({
        status: "healthy",
        checks: { write: true, read: true, rename: true, delete: true },
      });

      const connected = await apiJson<{
        connection: { id: string; status: string; vaultPath: string };
      }>(baseUrl, operatorToken, "/api/v2/brain/vault/connect", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "process-boundary-vault-connect-v1",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          displayName: "Process Boundary Brain",
          permissionGranted: true,
        }),
      }, 201);
      expect(connected.connection).toMatchObject({
        status: "connected",
        vaultPath: "Operator-Brain",
      });

      const exported = await apiJson<{
        result: { connectionId: string; status: string; message: string };
      }>(baseUrl, operatorToken, "/api/v2/brain/vault/export", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "process-boundary-vault-export-v1",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      });
      expect(exported.result).toMatchObject({
        connectionId: connected.connection.id,
        status: "synced",
      });
      expect(exported.result.message).toMatch(/^Exported [1-9][0-9]* accessible canonical notes/u);

      const vaultPath = join(vaultRoot, "Operator-Brain");
      const projectedFiles = markdownFiles(vaultPath);
      expect(projectedFiles.length).toBeGreaterThanOrEqual(1);
      const projectedNote = projectedFiles.find((path) =>
        readFileSync(path, "utf8").includes("mem-process-boundary-vault"));
      expect(projectedNote).toBeTruthy();
      const projectedBefore = readFileSync(projectedNote!, "utf8");

      const interrupted = seedExpiredInFlightBoundary({
        databasePath,
        missionId: created.mission.id,
        runId: created.run.id,
        contextPackId: created.intakeContext.contextPackId,
      });
      await delay(175);
      const beforeCrash = durableSnapshot(databasePath, created.run.id);
      expect(beforeCrash.actions).toEqual([interrupted.actionId]);
      expect(beforeCrash.checkpoints.map((item) => item.id)).toContain(interrupted.checkpointId);
      expect(beforeCrash.contextPackIds).toContain(created.intakeContext.contextPackId);
      expect(beforeCrash.vaultConnections).toEqual([{
        id: connected.connection.id,
        status: "connected",
        vaultPath,
      }]);
      expect(beforeCrash.vaultSyncNodeIds).toContain("mem-process-boundary-vault");

      await stopChild(first, "SIGKILL");
      const legacyAfterCrash = legacyBefore ? await readLegacyHealth() : null;
      if (legacyBefore) expect(legacyAfterCrash).toEqual({ status: "ok" });

      const restarted = launch(true, created.run.id);
      await waitForV2(restarted, baseUrl, operatorToken, directory);
      await authenticate(baseUrl, operatorToken);

      const runtime = await apiJson<{
        run: { id: string; status: string; statusReason: string; leaseExpiresAt: string | null };
        latestCheckpoint: {
          id: string;
          eventSequence: number;
          state: {
            run: { state: string; leaseOwner: string | null };
            inFlightActions: readonly { id: string; idempotent: boolean }[];
          };
        };
      }>(baseUrl, operatorToken, `/api/v2/runs/${created.run.id}`);
      expect(runtime.run).toMatchObject({
        id: created.run.id,
        status: "blocked",
        leaseExpiresAt: null,
      });
      expect(runtime.run.statusReason).toContain("completion cannot be repeated safely");
      expect(runtime.latestCheckpoint.state).toMatchObject({
        run: { state: "blocked", leaseOwner: null },
        inFlightActions: [{ id: interrupted.actionId, idempotent: false }],
      });

      const context = await apiJson<{
        id: string;
        missionId: string;
      }>(baseUrl, operatorToken, `/api/v2/brain/context-packs/${created.intakeContext.contextPackId}`);
      expect(context).toMatchObject({
        id: created.intakeContext.contextPackId,
        missionId: created.mission.id,
      });

      const vault = await apiJson<{
        connections: readonly { id: string; status: string; vaultPath: string }[];
        syncStates: readonly { nodeId: string }[];
      }>(baseUrl, operatorToken, "/api/v2/brain/vault");
      expect(vault.connections).toContainEqual(expect.objectContaining({
        id: connected.connection.id,
        status: "connected",
        vaultPath: "Operator-Brain",
      }));
      expect(vault.syncStates).toContainEqual(expect.objectContaining({
        nodeId: "mem-process-boundary-vault",
      }));
      expect(readFileSync(projectedNote!, "utf8")).toBe(projectedBefore);

      await delay(350);
      const afterRestart = durableSnapshot(databasePath, created.run.id);
      expect(afterRestart.actions).toEqual(beforeCrash.actions);
      expect(new Set(afterRestart.actions).size).toBe(afterRestart.actions.length);
      expect(afterRestart.events.slice(0, beforeCrash.events.length)).toEqual([...beforeCrash.events]);
      expect(afterRestart.events).toHaveLength(beforeCrash.events.length + 1);
      expect(afterRestart.events.filter((event) => event.eventType === "run.recovery_blocked")).toHaveLength(1);
      expect(new Set(afterRestart.events.map((event) => event.id)).size).toBe(afterRestart.events.length);
      expect(afterRestart.events.map((event) => event.sequence)).toEqual(
        afterRestart.events.map((_event, index) => index + 1),
      );
      expect(afterRestart.outboxEventIds.slice(0, beforeCrash.outboxEventIds.length))
        .toEqual([...beforeCrash.outboxEventIds]);
      expect(afterRestart.outboxEventIds).toHaveLength(beforeCrash.outboxEventIds.length + 1);
      expect(afterRestart.outboxEventIds).toEqual(afterRestart.events.map((event) => event.id));
      expect(new Set(afterRestart.outboxEventIds).size).toBe(afterRestart.outboxEventIds.length);
      expect(afterRestart.checkpoints).toHaveLength(beforeCrash.checkpoints.length + 1);
      expect(afterRestart.checkpoints.at(-1)).toMatchObject({
        eventSequence: runtime.latestCheckpoint.eventSequence,
        classification: "review_required",
      });
      expect(afterRestart.contextPackIds).toEqual(beforeCrash.contextPackIds);
      expect(afterRestart.vaultConnections).toEqual(beforeCrash.vaultConnections);
      expect(afterRestart.vaultSyncNodeIds).toEqual(beforeCrash.vaultSyncNodeIds);

      const legacyAfterRestart = legacyBefore ? await readLegacyHealth() : null;
      if (legacyBefore) expect(legacyAfterRestart).toEqual({ status: "ok" });

      const logs = `${first.stdout}\n${first.stderr}\n${restarted.stdout}\n${restarted.stderr}`;
      if (logs.includes(operatorToken)) {
        throw new Error("Bounded child logs contained the configured operator token");
      }
      expect(Buffer.byteLength(first.stdout, "utf8")).toBeLessThanOrEqual(LOG_LIMIT_BYTES);
      expect(Buffer.byteLength(first.stderr, "utf8")).toBeLessThanOrEqual(LOG_LIMIT_BYTES);
      expect(Buffer.byteLength(restarted.stdout, "utf8")).toBeLessThanOrEqual(LOG_LIMIT_BYTES);
      expect(Buffer.byteLength(restarted.stderr, "utf8")).toBeLessThanOrEqual(LOG_LIMIT_BYTES);
    } finally {
      await Promise.all([...children].map(async (captured) => {
        try {
          await stopChild(captured, "SIGTERM");
        } catch {
          captured.child.kill("SIGKILL");
          await waitForExit(captured).catch(() => undefined);
        }
      }));
      rmSync(directory, { recursive: true, force: true });
    }
  }, 30_000);
});
