import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI_RESULT_PREFIX = "TI_SCALE_BRAIN_GRAPH_FIXTURE=";
const PROCESS_ENTRY = fileURLToPath(new URL("./brainGraphFixture.ts", import.meta.url));
const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

export const BRAIN_GRAPH_FIXTURE_NODE_COUNT = 276;
export const BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT = 250;

export interface BrainGraphFixture {
  readonly namespace: string;
  readonly engagementId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly operatorNodeId: string;
  readonly operatorTitle: string;
  readonly preferenceNodeId: string;
  readonly preferenceTitle: string;
  readonly secondaryNodeId: string;
  readonly secondaryTitle: string;
  readonly attackTacticNodeId: string;
  readonly attackTacticTitle: string;
  readonly technologyProductNodeId: string;
  readonly technologyProductTitle: string;
  readonly contextPackId: string;
  readonly nodeCount: number;
  readonly edgeCount: number;
}

export interface BrainGraphFixtureState {
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly preferencePinned: boolean;
  readonly contextPackUsedItems: number;
}

function invokeFixture<T>(operation: "create" | "read", input: unknown): T {
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
      `Brain-graph fixture ${operation} failed with status ${String(result.status)}. ${result.stderr.trim()}`,
    );
  }
  const line = result.stdout
    .split(/\r?\n/u)
    .find((candidate) => candidate.startsWith(CLI_RESULT_PREFIX));
  if (!line) {
    throw new Error(`Brain-graph fixture ${operation} returned no structured result. ${result.stdout.trim()}`);
  }
  return JSON.parse(line.slice(CLI_RESULT_PREFIX.length)) as T;
}

export function createBrainGraphFixture(instanceId: string): BrainGraphFixture {
  return invokeFixture<BrainGraphFixture>("create", instanceId);
}

export function readBrainGraphFixtureState(fixture: BrainGraphFixture): BrainGraphFixtureState {
  return invokeFixture<BrainGraphFixtureState>("read", fixture);
}
