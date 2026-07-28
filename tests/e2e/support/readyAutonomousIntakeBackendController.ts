import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

const HANDSHAKE = "TI_SCALE_READY_AUTONOMOUS_BACKEND=";
const PROCESS_ENTRY = fileURLToPath(new URL("./readyAutonomousIntakeBackend.ts", import.meta.url));

export interface ReadyAutonomousIntakeBackend {
  readonly baseUrl: string;
  readonly branchFixture: {
    readonly missionId: string;
    readonly runId: string;
    readonly authorization: {
      readonly engagementId: string;
      readonly environmentClassification: "htb";
      readonly allowedTargets: readonly string[];
      readonly prohibitedTargets: readonly string[];
      readonly authorizationConfirmed: true;
      readonly timeWindow: string;
      readonly dataHandling: string;
    };
  };
  readonly productAgents: readonly {
    readonly id: string;
    readonly displayName: string;
    readonly role: string;
  }[];
  readonly memoryNodes: readonly {
    readonly id: string;
    readonly title: string;
  }[];
  stop(): Promise<void>;
}

export type ReadyAutonomousIntakeBackendProfile =
  | "full"
  | "team_boundary";

export interface ReadyAutonomousIntakeBackendOptions {
  readonly profile?: ReadyAutonomousIntakeBackendProfile;
}

interface ReadyMessage {
  readonly baseUrl: string;
  readonly branchFixture: ReadyAutonomousIntakeBackend["branchFixture"];
  readonly productAgents: readonly {
    readonly id: string;
    readonly displayName: string;
    readonly role: string;
  }[];
  readonly memoryNodes: readonly {
    readonly id: string;
    readonly title: string;
  }[];
}

function waitForReady(child: ChildProcess): Promise<ReadyMessage> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      reject(new Error(`Disposable Autonomous intake backend did not become ready within 30 seconds. ${stderr}`));
    }, 30_000);
    timeout.unref();

    const finish = (callback: () => void) => {
      clearTimeout(timeout);
      child.stdout?.off("data", onStdout);
      child.stderr?.off("data", onStderr);
      child.off("exit", onExit);
      callback();
    };
    const onStderr = (chunk: Buffer | string) => {
      stderr += chunk.toString();
      if (stderr.length > 12_000) stderr = stderr.slice(-12_000);
    };
    const onStdout = (chunk: Buffer | string) => {
      stdout += chunk.toString();
      const lines = stdout.split(/\r?\n/u);
      stdout = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith(HANDSHAKE)) continue;
        try {
          const parsed = JSON.parse(line.slice(HANDSHAKE.length)) as ReadyMessage;
          if (
            !parsed.baseUrl.startsWith("http://127.0.0.1:")
            || !parsed.branchFixture
            || !parsed.branchFixture.missionId
            || !parsed.branchFixture.runId
            || parsed.branchFixture.authorization.environmentClassification !== "htb"
            || parsed.branchFixture.authorization.authorizationConfirmed !== true
            || parsed.branchFixture.authorization.allowedTargets.length !== 1
            || parsed.branchFixture.authorization.prohibitedTargets.length !== 1
            || !parsed.branchFixture.authorization.engagementId
            || !parsed.branchFixture.authorization.timeWindow
            || !parsed.branchFixture.authorization.dataHandling
            || !Array.isArray(parsed.productAgents)
            || parsed.productAgents.length !== 12
            || new Set(parsed.productAgents.map(({ id }) => id)).size !== 12
            || parsed.productAgents.some(({ id, displayName, role }) =>
              !id || !displayName || !role)
            || !Array.isArray(parsed.memoryNodes)
            || parsed.memoryNodes.length !== 2
            || parsed.memoryNodes.some(({ id, title }) => !id || !title)
          ) {
            throw new Error("Disposable backend handshake is incomplete");
          }
          finish(() => resolve(parsed));
        } catch (error) {
          finish(() => reject(error));
        }
        return;
      }
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      finish(() => reject(new Error(
        `Disposable Autonomous intake backend exited before readiness (code ${code ?? "none"}, signal ${signal ?? "none"}). ${stderr}`,
      )));
    };
    child.stdout?.on("data", onStdout);
    child.stderr?.on("data", onStderr);
    child.once("exit", onExit);
  });
}

async function terminate(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const graceful = once(child, "exit").then(() => true);
  const timeout = new Promise<false>((resolve) => {
    const timer = setTimeout(() => resolve(false), 5_000);
    timer.unref();
  });
  if (await Promise.race([graceful, timeout])) return;
  child.kill("SIGKILL");
  await once(child, "exit");
}

export async function startReadyAutonomousIntakeBackend(
  instanceId: string,
  options: ReadyAutonomousIntakeBackendOptions = {},
): Promise<ReadyAutonomousIntakeBackend> {
  const child = spawn("bun", [
    "run",
    PROCESS_ENTRY,
    instanceId,
    `--profile=${options.profile ?? "full"}`,
  ], {
    cwd: fileURLToPath(new URL("../../../", import.meta.url)),
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
  });
  try {
    const ready = await waitForReady(child);
    let stopped = false;
    return {
      ...ready,
      async stop(): Promise<void> {
        if (stopped) return;
        stopped = true;
        await terminate(child);
      },
    };
  } catch (error) {
    await terminate(child).catch(() => undefined);
    throw error;
  }
}
