import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HANDSHAKE = "TI_SCALE_MISSION_INTAKE_FIXTURE=";
const PROCESS_ENTRY = fileURLToPath(
  new URL("./missionIntakeDynamicFixtureBackend.ts", import.meta.url),
);
const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

export interface MissionIntakeDynamicFixture {
  readonly agentId: string;
  readonly agentName: string;
  readonly memoryNodeId: string;
  readonly memoryTitle: string;
}

export interface MissionIntakeDynamicFixtureOptions {
  readonly preseedExpiredAttestation?: boolean;
}

function parseHandshake(stdout: string): MissionIntakeDynamicFixture {
  const line = stdout
    .split(/\r?\n/u)
    .find((candidate) => candidate.startsWith(HANDSHAKE));
  if (!line) {
    throw new Error("Disposable mission-intake fixture did not return its bounded handshake");
  }
  const parsed = JSON.parse(line.slice(HANDSHAKE.length)) as Partial<MissionIntakeDynamicFixture>;
  if (
    typeof parsed.agentId !== "string"
    || parsed.agentId.length === 0
    || typeof parsed.agentName !== "string"
    || parsed.agentName.length === 0
    || typeof parsed.memoryNodeId !== "string"
    || parsed.memoryNodeId.length === 0
    || typeof parsed.memoryTitle !== "string"
    || parsed.memoryTitle.length === 0
  ) {
    throw new Error("Disposable mission-intake fixture returned an incomplete handshake");
  }
  return Object.freeze({
    agentId: parsed.agentId,
    agentName: parsed.agentName,
    memoryNodeId: parsed.memoryNodeId,
    memoryTitle: parsed.memoryTitle,
  });
}

/**
 * Seeds the isolated E2E database in a short-lived Bun process while keeping
 * the Playwright worker on Node. This prevents Bun-only SQLite imports from
 * crossing the browser-runner boundary and guarantees that worker failures
 * are reported instead of leaving a defunct child behind.
 */
export function createMissionIntakeDynamicFixture(
  instanceId: string,
  options: MissionIntakeDynamicFixtureOptions = {},
): MissionIntakeDynamicFixture {
  if (!instanceId.trim()) {
    throw new Error("Mission-intake fixture requires one isolated test instance ID");
  }
  const child = spawnSync("bun", [
    "run",
    PROCESS_ENTRY,
    instanceId,
    ...(options.preseedExpiredAttestation
      ? ["--preseed-expired-attestation"]
      : []),
  ], {
    cwd: PROJECT_ROOT,
    env: process.env,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 128 * 1024,
  });
  if (child.error) {
    throw new Error(
      `Disposable mission-intake fixture process failed: ${child.error.message}`,
    );
  }
  if (child.status !== 0) {
    const diagnostic = child.stderr.trim().slice(-2_000);
    throw new Error(
      `Disposable mission-intake fixture process exited ${child.status ?? "without status"}${diagnostic ? `: ${diagnostic}` : ""}`,
    );
  }
  return parseHandshake(child.stdout);
}
