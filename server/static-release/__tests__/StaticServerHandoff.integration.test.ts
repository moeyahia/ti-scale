import { afterEach, expect, test } from "bun:test";
import { createServer } from "node:net";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { StaticArtifactReleaseStore } from "../StaticArtifactReleaseStore";

const applicationRoot = resolve(import.meta.dir, "../../..");
const fixtureRoots: string[] = [];
const children: RunningServer[] = [];

interface StreamCapture {
  readonly done: Promise<void>;
  text(): string;
}

interface RunningServer {
  readonly child: ReturnType<typeof Bun.spawn>;
  readonly stdout: StreamCapture;
  readonly stderr: StreamCapture;
  readonly origin: string;
}

function capture(stream: ReadableStream<Uint8Array>): StreamCapture {
  let value = "";
  const decoder = new TextDecoder();
  const done = (async () => {
    const reader = stream.getReader();
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        value += decoder.decode(chunk.value, { stream: true });
      }
      value += decoder.decode();
    } finally {
      reader.releaseLock();
    }
  })();
  return { done, text: () => value };
}

function makeWritable(path: string): void {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    return;
  }
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeWritable(join(path, name));
    return;
  }
  chmodSync(path, 0o600);
}

async function timeout<T>(promise: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds}ms`)), milliseconds);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
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
  if (!address || typeof address === "string") throw new Error("Could not reserve an isolated V2 test port");
  await new Promise<void>((resolveClose, rejectClose) => {
    reservation.close((error) => error ? rejectClose(error) : resolveClose());
  });
  return address.port;
}

function spawnServer(input: {
  readonly port: number;
  readonly databasePath: string;
  readonly releaseRoot: string;
  readonly vaultRoot: string;
  readonly scriptSourceRoot: string;
  readonly slowStartupIntegrity?: boolean;
  readonly preview?: boolean;
}): RunningServer {
  const child = Bun.spawn([process.execPath, "run", "server/index.ts"], {
    cwd: applicationRoot,
    env: {
      ...process.env,
      TI_SCALE_HOST: "127.0.0.1",
      TI_SCALE_PORT: String(input.port),
      TI_SCALE_DATABASE_PATH: input.databasePath,
      TI_SCALE_SCRIPT_SOURCE_ROOT: input.scriptSourceRoot,
      TI_SCALE_VAULT_ROOT: input.vaultRoot,
      TI_SCALE_STATIC_RELEASE_ROOT: input.releaseRoot,
      TI_SCALE_SERVE_STATIC: "true",
      TI_SCALE_PREVIEW: input.preview === false ? "false" : "true",
      TI_SCALE_KILL_SWITCH: "false",
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "false",
      TI_SCALE_SECURE_COOKIES: "false",
      TI_SCALE_OPERATOR_TOKEN: "isolated-static-handoff-test-token",
      TI_SCALE_OPERATOR_ID: "static-handoff-test-operator",
      TI_SCALE_UI_ORIGIN: `http://127.0.0.1:${input.port}`,
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
      ...(input.slowStartupIntegrity ? {
        NODE_ENV: "test",
        TI_SCALE_TEST_SLOW_STARTUP_INTEGRITY: "true",
      } : {}),
      NO_COLOR: "1",
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const running = {
    child,
    stdout: capture(child.stdout),
    stderr: capture(child.stderr),
    origin: `http://127.0.0.1:${input.port}`,
  };
  children.push(running);
  return running;
}

async function waitForDocument(server: RunningServer, marker: string): Promise<string> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (server.child.exitCode !== null) {
      await Promise.all([server.stdout.done, server.stderr.done]);
      throw new Error(
        `V2 server exited before serving ${marker}. stdout=${server.stdout.text()} stderr=${server.stderr.text()}`,
      );
    }
    try {
      const response = await fetch(`${server.origin}/`, {
        cache: "no-store",
        signal: AbortSignal.timeout(500),
      });
      const body = await response.text();
      if (response.status === 200 && body.includes(marker)) return body;
    } catch {
      // The isolated process is still opening its database and verified release.
    }
    await Bun.sleep(50);
  }
  throw new Error(
    `V2 server did not serve ${marker}. stdout=${server.stdout.text()} stderr=${server.stderr.text()}`,
  );
}

async function stopServer(server: RunningServer): Promise<void> {
  if (server.child.exitCode === null) server.child.kill("SIGTERM");
  try {
    await timeout(server.child.exited, 12_000, "V2 server graceful shutdown");
  } catch (error) {
    if (server.child.exitCode === null) server.child.kill("SIGKILL");
    await server.child.exited;
    throw error;
  } finally {
    await Promise.all([server.stdout.done, server.stderr.done]);
    const index = children.indexOf(server);
    if (index >= 0) children.splice(index, 1);
  }
}

afterEach(async () => {
  for (const child of [...children]) {
    try {
      await stopServer(child);
    } catch {
      // Teardown must still remove every disposable V2 path after a failed assertion.
    }
  }
  for (const root of fixtureRoots.splice(0)) {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

test("the pinned authentication shell and session route remain available while database integrity is still running", async () => {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-static-server-integration-"));
  fixtureRoots.push(workspace);
  const sourceDirectory = join(workspace, "ti-scale-built-auth-shell");
  const releaseRoot = join(workspace, "ti-scale-static-releases");
  const dataRoot = join(workspace, "ti-scale-data");
  const databasePath = join(dataRoot, "ti-scale-startup-auth-shell.sqlite");
  const vaultRoot = join(workspace, "ti-scale-obsidian-vault");
  const scriptSourceRoot = join(workspace, "ti-scale-artifacts", "script-sources");
  mkdirSync(sourceDirectory, { recursive: true });
  mkdirSync(vaultRoot, { recursive: true });
  mkdirSync(dataRoot, { recursive: true });
  writeFileSync(
    join(sourceDirectory, "index.html"),
    "<!doctype html><body><main id=\"root\">TI_SCALE_AUTH_SHELL_STARTUP</main></body>\n",
  );
  writeFileSync(join(sourceDirectory, "auth-shell.js"), "export const shell = 'ti-scale';\n");

  const releases = new StaticArtifactReleaseStore({ releaseRoot });
  const release = releases.stageRelease({ releaseId: "startup-auth-shell", sourceDirectory });
  releases.activateRelease(release.releaseId);
  const database = createDatabaseConnection({ filename: databasePath, verifyIntegrity: false });
  try {
    migrateDatabase(database);
  } finally {
    database.close();
  }

  const port = await availablePort();
  const server = spawnServer({
    port,
    databasePath,
    releaseRoot,
    vaultRoot,
    scriptSourceRoot,
    slowStartupIntegrity: true,
  });
  const document = await waitForDocument(server, "TI_SCALE_AUTH_SHELL_STARTUP");
  expect(document).toContain("id=\"root\"");

  const documentResponse = await fetch(`${server.origin}/`, {
    cache: "no-store",
    signal: AbortSignal.timeout(1_000),
  });
  expect(documentResponse.status).toBe(200);
  expect(documentResponse.headers.get("cache-control")).toBe("no-store");
  const assetResponse = await fetch(`${server.origin}/auth-shell.js`, {
    signal: AbortSignal.timeout(1_000),
  });
  expect(assetResponse.status).toBe(200);
  expect(await assetResponse.text()).toContain("ti-scale");

  const sessionResponse = await fetch(`${server.origin}/api/v2/auth/session`, {
    signal: AbortSignal.timeout(1_000),
  });
  expect(sessionResponse.status).toBe(200);
  expect(await sessionResponse.json()).toEqual({
    schemaVersion: "2.4",
    configured: true,
    authenticated: false,
  });

  const healthResponse = await fetch(`${server.origin}/api/v2/health`, {
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

  const mutationResponse = await fetch(`${server.origin}/api/v2/missions`, {
    method: "POST",
    headers: {
      Authorization: "Bearer isolated-static-handoff-test-token",
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
      details: {
        phase: "database_integrity",
        executionAdmission: "closed",
      },
    },
  });

  const protectedReadResponse = await fetch(`${server.origin}/api/v2/brain/summary`, {
    headers: {
      Authorization: "Bearer isolated-static-handoff-test-token",
    },
    signal: AbortSignal.timeout(1_000),
  });
  expect(protectedReadResponse.status).toBe(503);
  expect(await protectedReadResponse.json()).toMatchObject({
    error: {
      code: "ti_scale_startup_initializing",
      retryable: true,
      details: {
        phase: "database_integrity",
        executionAdmission: "closed",
      },
    },
  });
  expect(server.stdout.text()).toContain(`pinned static release ${release.releaseId}`);
  expect(server.stdout.text()).not.toContain("operational admission ready");
  await stopServer(server);
});

test("standalone V2 server pins an immutable static release across pointer changes and fails startup on tamper", async () => {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-static-server-integration-"));
  fixtureRoots.push(workspace);
  const sourceDirectory = join(workspace, "ti-scale-built-dist");
  const releaseRoot = join(workspace, "ti-scale-static-releases");
  const dataRoot = join(workspace, "ti-scale-data");
  const databasePath = join(dataRoot, "ti-scale-static-server.sqlite");
  const vaultRoot = join(workspace, "ti-scale-obsidian-vault");
  const scriptSourceRoot = join(workspace, "ti-scale-artifacts", "script-sources");
  mkdirSync(sourceDirectory, { recursive: true });
  mkdirSync(vaultRoot, { recursive: true });
  mkdirSync(dataRoot, { recursive: true });
  writeFileSync(sourceDirectory + "/index.html", "<!doctype html><body>STATIC_RELEASE_A_PINNED</body>\n");

  const releases = new StaticArtifactReleaseStore({ releaseRoot });
  const releaseA = releases.stageRelease({ releaseId: "server-release-a", sourceDirectory });
  releases.activateRelease(releaseA.releaseId);
  writeFileSync(sourceDirectory + "/index.html", "<!doctype html><body>STATIC_RELEASE_B_AFTER_RESTART</body>\n");
  const releaseB = releases.stageRelease({ releaseId: "server-release-b", sourceDirectory });
  const port = await availablePort();

  const firstProcess = spawnServer({
    port,
    databasePath,
    releaseRoot,
    vaultRoot,
    scriptSourceRoot,
    preview: false,
  });
  expect(await waitForDocument(firstProcess, "STATIC_RELEASE_A_PINNED")).not.toContain(
    "STATIC_RELEASE_B_AFTER_RESTART",
  );
  releases.activateRelease(releaseB.releaseId);
  expect(await waitForDocument(firstProcess, "STATIC_RELEASE_A_PINNED")).not.toContain(
    "STATIC_RELEASE_B_AFTER_RESTART",
  );
  await stopServer(firstProcess);
  expect(firstProcess.stdout.text()).toContain(`pinned static release ${releaseA.releaseId}`);
  expect(firstProcess.stdout.text()).toContain(releaseA.manifestSha256);

  const restartedProcess = spawnServer({
    port,
    databasePath,
    releaseRoot,
    vaultRoot,
    scriptSourceRoot,
    preview: false,
  });
  expect(await waitForDocument(restartedProcess, "STATIC_RELEASE_B_AFTER_RESTART")).not.toContain(
    "STATIC_RELEASE_A_PINNED",
  );
  await stopServer(restartedProcess);
  expect(restartedProcess.stdout.text()).toContain(`pinned static release ${releaseB.releaseId}`);
  expect(restartedProcess.stdout.text()).toContain(releaseB.manifestSha256);

  const activeIndex = join(releaseB.releaseDirectory, "index.html");
  chmodSync(activeIndex, 0o644);
  writeFileSync(activeIndex, "<!doctype html><body>TAMPERED_ACTIVE_RELEASE</body>\n");
  const refusedProcess = spawnServer({ port, databasePath, releaseRoot, vaultRoot, scriptSourceRoot });
  const exitCode = await timeout(refusedProcess.child.exited, 15_000, "tampered V2 startup refusal");
  await Promise.all([refusedProcess.stdout.done, refusedProcess.stderr.done]);
  const refusedIndex = children.indexOf(refusedProcess);
  if (refusedIndex >= 0) children.splice(refusedIndex, 1);
  expect(exitCode).not.toBe(0);
  expect(refusedProcess.stderr.text()).toContain("Ti-Scale failed to start");
  expect(refusedProcess.stderr.text()).toContain("tampered, partial, or contains unmanifested files");
  await expect(fetch(`http://127.0.0.1:${port}/`, {
    signal: AbortSignal.timeout(250),
  })).rejects.toThrow();
  expect(readFileSync(activeIndex, "utf8")).toContain("TAMPERED_ACTIVE_RELEASE");
});
