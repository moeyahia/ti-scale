import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-21T12:00:00.000Z";
// Playwright-managed Ti-Scale servers authenticate every fixture request as
// this isolated operator. Keeping the row owner identical to that actor proves
// the route's ownership filter instead of accidentally exercising the empty
// state.
const OPERATOR_ID = "e2e-local-operator";

export interface OperatorPreferencesFixture {
  readonly nodeId: string;
  readonly title: string;
  readonly preferenceKey: string;
  readonly sourceId: string;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Operator Preferences E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function createOperatorPreferencesFixture(instanceId: string): OperatorPreferencesFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const nodeId = `mem-operator-preference-${namespace}`;
  const profileId = `profile-operator-preference-${namespace}`;
  const preferenceKey = `explanation_depth_${digest(namespace).slice(0, 8)}`;
  const sourceId = `operator-note-preference-${namespace}`;
  const title = `Evidence-led technical explanations ${digest(namespace).slice(0, 8)}`;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const repository = new MemoryRepository(database, { clock: () => new Date(FIXTURE_TIME) });
    repository.createNode({
      id: nodeId,
      nodeType: "preference",
      title,
      summary: "Use readable technical language and explain operational relevance without oversimplifying it.",
      body: "Prefer concise, evidence-led technical explanations that remain understandable to an operator.",
      scope: { kind: "global" },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "The authenticated operator explicitly confirmed this bounded presentation preference.",
        sources: [{
          sourceType: "operator_note",
          sourceId,
          sourceHash: digest(`${namespace}:${sourceId}`),
          excerptRedacted: "Use readable technical language without making it too basic.",
          acquiredAt: FIXTURE_TIME,
        }],
      },
      authorType: "operator",
      authorId: OPERATOR_ID,
      retentionPolicy: { allowGuided: true, allowAutonomous: true },
    });
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO preference_profiles (
          id, operator_id, scope, engagement_id, mission_type, preference_key,
          value_json, confirmation_state, confidence, source_node_id, consent_policy,
          version, confirmed_at, created_at, updated_at
        ) VALUES (?, ?, 'global', NULL, NULL, ?, ?, 'confirmed', 1, ?,
          'explicit_operator_confirmation', 1, ?, ?, ?)
      `).run(
        profileId,
        OPERATOR_ID,
        preferenceKey,
        JSON.stringify({
          value: { depth: "technical-readable", evidenceFirst: true },
          appliesTo: ["guided_explanations", "runtime_status", "failure_diagnosis"],
        }),
        nodeId,
        FIXTURE_TIME,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
    });
  } finally {
    database.close();
  }
  return { nodeId, title, preferenceKey, sourceId };
}
