import { createHash } from "node:crypto";
import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import type {
  MemoryLifecycle,
  MemoryNodeType,
  MemoryScope,
  MemorySensitivity,
} from "../../../server/memory/types";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export interface AutonomousIntakeMemoryFixtureNode {
  readonly id: string;
  readonly title: string;
}

export interface AutonomousIntakeAdvancedFixture {
  readonly engagementId: string;
  readonly otherEngagementId: string;
  readonly eligibleNodes: readonly AutonomousIntakeMemoryFixtureNode[];
  readonly crossEngagementNode: AutonomousIntakeMemoryFixtureNode;
  readonly ineligibleNodes: readonly AutonomousIntakeMemoryFixtureNode[];
}

interface MemoryFixtureInput extends AutonomousIntakeMemoryFixtureNode {
  readonly nodeType: MemoryNodeType;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly confirmationState: "pending" | "confirmed" | "not_required";
}

function stableId(namespace: string, label: string): string {
  return `mem_${createHash("sha256")
    .update(`${namespace}:${label}`, "utf8")
    .digest("hex")}`;
}

/**
 * Seeds real canonical memories for the Autonomous intake scope-isolation
 * browser contract. It deliberately includes candidates that the repository
 * must omit: another engagement, an unconfirmed preference, and restricted
 * operational knowledge.
 */
export function createAutonomousIntakeAdvancedFixture(
  instanceId: string,
): AutonomousIntakeAdvancedFixture {
  if (!E2E_DATABASE_PATH) {
    throw new Error("Autonomous intake E2E requires the isolated V2 database path");
  }
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = createHash("sha256")
    .update(namespace, "utf8")
    .digest("hex")
    .slice(0, 12);
  const engagementId = `eng_intake_${suffix}`;
  const otherEngagementId = `eng_other_${suffix}`;
  const inputs: readonly MemoryFixtureInput[] = [
    {
      id: stableId(namespace, "verified-lesson"),
      title: `Verified recovery lesson ${suffix}`,
      nodeType: "lesson",
      scope: { kind: "global" },
      sensitivity: "internal",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
    {
      id: stableId(namespace, "confirmed-attack-knowledge"),
      title: `Confirmed attack procedure ${suffix}`,
      nodeType: "attack_procedure",
      scope: { kind: "global" },
      sensitivity: "internal",
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
    },
    {
      id: stableId(namespace, "verified-attack-knowledge-similar-title"),
      title: `Confirmed attack procedure ${suffix} v4-reviewed`,
      nodeType: "attack_procedure",
      scope: { kind: "global" },
      sensitivity: "internal",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
    {
      id: stableId(namespace, "verified-attack-safety"),
      title: `Verified attack safety gate ${suffix}`,
      nodeType: "operational_hazard",
      scope: { kind: "global" },
      sensitivity: "internal",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
    {
      id: stableId(namespace, "matching-engagement"),
      title: `Matching engagement recovery pattern ${suffix}`,
      nodeType: "lesson",
      scope: { kind: "engagement", engagementId },
      sensitivity: "private",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
    {
      id: stableId(namespace, "cross-engagement"),
      title: `Other engagement procedure ${suffix}`,
      nodeType: "lesson",
      scope: { kind: "engagement", engagementId: otherEngagementId },
      sensitivity: "private",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
    {
      id: stableId(namespace, "candidate-preference"),
      title: `Unconfirmed operator preference ${suffix}`,
      nodeType: "preference",
      scope: { kind: "global" },
      sensitivity: "private",
      lifecycleStatus: "candidate",
      confirmationState: "pending",
    },
    {
      id: stableId(namespace, "restricted-knowledge"),
      title: `Restricted attack procedure ${suffix}`,
      nodeType: "attack_procedure",
      scope: { kind: "global" },
      sensitivity: "restricted",
      lifecycleStatus: "verified",
      confirmationState: "not_required",
    },
  ];
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const memory = new MemoryRepository(database);
    const now = new Date().toISOString();
    for (const input of inputs) {
      if (database.prepare("SELECT id FROM memory_nodes WHERE id = ?").get(input.id)) {
        continue;
      }
      memory.createNode({
        ...input,
        summary: `Autonomous intake scope-isolation fixture for ${input.title}.`,
        body: "This deterministic fixture exists only in the isolated browser-test database.",
        confidence: 0.99,
        provenance: {
          method: "derived",
          explanation: "Created by the isolated Autonomous intake scope fixture.",
          sources: [{
            sourceType: "e2e_fixture",
            sourceId: `source-${input.id}`,
            acquiredAt: now,
          }],
        },
        authorType: "operator",
        authorId: "e2e-local-operator",
        retentionPolicy: {
          allowGuided: true,
          allowAutonomous: true,
          journeys: ["autonomous", "guided"],
        },
      });
    }
  } finally {
    database.close();
  }
  const byLabel = new Map(inputs.map((input) => [input.title, input] as const));
  const node = (title: string): AutonomousIntakeMemoryFixtureNode => {
    const found = byLabel.get(title);
    if (!found) throw new Error(`Autonomous intake fixture node is missing: ${title}`);
    return { id: found.id, title: found.title };
  };
  return {
    engagementId,
    otherEngagementId,
    eligibleNodes: [
      node(`Verified recovery lesson ${suffix}`),
      node(`Confirmed attack procedure ${suffix}`),
      node(`Confirmed attack procedure ${suffix} v4-reviewed`),
      node(`Verified attack safety gate ${suffix}`),
      node(`Matching engagement recovery pattern ${suffix}`),
    ],
    crossEngagementNode: node(`Other engagement procedure ${suffix}`),
    ineligibleNodes: [
      node(`Unconfirmed operator preference ${suffix}`),
      node(`Restricted attack procedure ${suffix}`),
    ],
  };
}

const instanceId = process.argv[2];
if (!instanceId) {
  throw new Error("Autonomous intake advanced fixture requires one isolated test instance ID");
}
process.stdout.write(
  `TI_SCALE_AUTONOMOUS_INTAKE_ADVANCED_FIXTURE=${JSON.stringify(
    createAutonomousIntakeAdvancedFixture(instanceId),
  )}\n`,
);
