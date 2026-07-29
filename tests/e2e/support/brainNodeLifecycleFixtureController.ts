import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI_RESULT_PREFIX = "TI_SCALE_BRAIN_NODE_FIXTURE=";
const PROCESS_ENTRY = fileURLToPath(new URL("./brainNodeLifecycleFixture.ts", import.meta.url));
const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

export interface BrainNodeLifecycleFixture {
  readonly namespace: string;
  readonly engagementId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly nodeId: string;
  readonly relatedNodeId: string;
  readonly contextPackId: string;
  readonly initialTitle: string;
}

export interface BrainNodeLifecycleState {
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly lifecycleStatus: string;
  readonly sensitivity: string;
  readonly version: number;
  readonly pinned: boolean;
  readonly expiresAt: string | null;
  readonly sourceCount: number;
  readonly versionCount: number;
  readonly edgeCount: number;
  readonly contextItemCount: number;
  readonly representedContextItemCount: number;
  readonly suppressionCount: number;
  readonly forgottenAuditCount: number;
}

function invokeFixture<T>(operation: "create" | "read" | "advance", input: unknown): T {
  const result = spawnSync("bun", ["run", PROCESS_ENTRY, operation, JSON.stringify(input)], {
    cwd: PROJECT_ROOT,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `Brain-node fixture ${operation} failed with status ${String(result.status)}. ${result.stderr.trim()}`,
    );
  }
  const line = result.stdout
    .split(/\r?\n/u)
    .find((candidate) => candidate.startsWith(CLI_RESULT_PREFIX));
  if (!line) {
    throw new Error(`Brain-node fixture ${operation} returned no structured result. ${result.stdout.trim()}`);
  }
  return JSON.parse(line.slice(CLI_RESULT_PREFIX.length)) as T;
}

export function createBrainNodeLifecycleFixture(instanceId: string): BrainNodeLifecycleFixture {
  return invokeFixture<BrainNodeLifecycleFixture>("create", instanceId);
}

export function readBrainNodeLifecycleState(
  fixture: BrainNodeLifecycleFixture,
): BrainNodeLifecycleState {
  return invokeFixture<BrainNodeLifecycleState>("read", fixture);
}

export function advanceBrainNodeVersion(fixture: BrainNodeLifecycleFixture): number {
  return invokeFixture<number>("advance", fixture);
}
