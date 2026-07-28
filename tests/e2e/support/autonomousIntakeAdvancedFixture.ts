import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import type {
  AutonomousIntakeAdvancedFixture,
  AutonomousIntakeMemoryFixtureNode,
} from "./autonomousIntakeAdvancedFixtureBackend";

const HANDSHAKE = "TI_SCALE_AUTONOMOUS_INTAKE_ADVANCED_FIXTURE=";
const PROCESS_ENTRY = fileURLToPath(
  new URL("./autonomousIntakeAdvancedFixtureBackend.ts", import.meta.url),
);
const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

function memoryNode(value: unknown): AutonomousIntakeMemoryFixtureNode {
  if (
    !value
    || typeof value !== "object"
    || typeof (value as { id?: unknown }).id !== "string"
    || !(value as { id: string }).id
    || typeof (value as { title?: unknown }).title !== "string"
    || !(value as { title: string }).title
  ) {
    throw new Error("Autonomous intake advanced fixture returned an invalid memory node");
  }
  return {
    id: (value as { id: string }).id,
    title: (value as { title: string }).title,
  };
}

function parseHandshake(stdout: string): AutonomousIntakeAdvancedFixture {
  const line = stdout
    .split(/\r?\n/u)
    .find((candidate) => candidate.startsWith(HANDSHAKE));
  if (!line) {
    throw new Error("Autonomous intake advanced fixture did not return its bounded handshake");
  }
  const parsed = JSON.parse(line.slice(HANDSHAKE.length)) as Partial<AutonomousIntakeAdvancedFixture>;
  if (
    typeof parsed.engagementId !== "string"
    || !parsed.engagementId
    || typeof parsed.otherEngagementId !== "string"
    || !parsed.otherEngagementId
    || !Array.isArray(parsed.eligibleNodes)
    || !Array.isArray(parsed.ineligibleNodes)
  ) {
    throw new Error("Autonomous intake advanced fixture returned an incomplete handshake");
  }
  return Object.freeze({
    engagementId: parsed.engagementId,
    otherEngagementId: parsed.otherEngagementId,
    eligibleNodes: Object.freeze(parsed.eligibleNodes.map(memoryNode)),
    crossEngagementNode: memoryNode(parsed.crossEngagementNode),
    ineligibleNodes: Object.freeze(parsed.ineligibleNodes.map(memoryNode)),
  });
}

export function createAutonomousIntakeAdvancedFixture(
  instanceId: string,
): AutonomousIntakeAdvancedFixture {
  if (!instanceId.trim()) {
    throw new Error("Autonomous intake advanced fixture requires one isolated test instance ID");
  }
  const child = spawnSync("bun", ["run", PROCESS_ENTRY, instanceId], {
    cwd: PROJECT_ROOT,
    env: process.env,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 128 * 1024,
  });
  if (child.error) {
    throw new Error(`Autonomous intake advanced fixture failed: ${child.error.message}`);
  }
  if (child.status !== 0) {
    throw new Error(
      `Autonomous intake advanced fixture exited ${child.status ?? "without status"}: ${child.stderr.trim().slice(-2_000)}`,
    );
  }
  return parseHandshake(child.stdout);
}

export type {
  AutonomousIntakeAdvancedFixture,
  AutonomousIntakeMemoryFixtureNode,
};
