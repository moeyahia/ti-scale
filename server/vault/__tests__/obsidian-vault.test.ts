import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
  type FSWatcher,
} from "node:fs";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import {
  MemoryRepository,
  ReusableKnowledgeOutcomeService,
  type MemoryProvenance,
  updateMemoryControlPolicy,
} from "../../memory/index";
import {
  MAX_PROJECTED_PRIVATE_PROVENANCE_IDS,
  OBSIDIAN_V2_4_VAULT_FOLDERS,
  escapeObsidianSingleLineText,
  normalizeObsidianWikilinkTarget,
  ObsidianVaultBridge,
  ObsidianVaultWatcher,
  parseObsidianNote,
  projectPrivateProvenanceIds,
  renderObsidianNote,
  VaultPathPolicy,
} from "../index";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup(syncScope: Record<string, unknown> = {}) {
  const directory = mkdtempSync(join(tmpdir(), "obsidian-bridge-test-"));
  temporaryDirectories.push(directory);
  const db = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(db);
  const memory = new MemoryRepository(db);
  const policy = new VaultPathPolicy(join(directory, "allowed-vaults"));
  const bridge = new ObsidianVaultBridge(db, memory, policy);
  const connection = bridge.connect({
    id: "vault-test",
    vaultPath: "Ti-Scale-Brain",
    displayName: "Test Brain",
    syncScope,
    permissionGranted: true,
  });
  return { directory, db, memory, policy, bridge, connection };
}

function provenance(id: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "Confirmed by the operator",
    sources: [{ sourceType: "message", sourceId: id, acquiredAt: "2026-07-15T10:00:00.000Z" }],
  };
}

function reusableNodeId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function addNode(memory: MemoryRepository, id: string, title: string) {
  return memory.createNode({
    id: reusableNodeId(id),
    nodeType: "attack_technique",
    title,
    summary: `Summary for ${title}`,
    body: `Operational note for ${title}.`,
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 0.95,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator-1",
  });
}

function addVerifiedProcedure(memory: MemoryRepository, id: string, title: string) {
  return memory.createNode({
    id: reusableNodeId(id),
    nodeType: "attack_procedure",
    title,
    summary: `Reviewed reusable procedure for ${title}`,
    body: `Run one bounded ${title} procedure and retain its verified result.`,
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.97,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Generalized through local operator review",
      sources: [{ sourceType: "review_receipt", sourceId: `source-${id}`, acquiredAt: "2026-07-21T12:00:00.000Z" }],
    },
    authorType: "operator",
    authorId: "operator-1",
  });
}

function classifyProcedureBothWays(
  database: ReturnType<typeof createDatabaseConnection>,
  nodeId: string,
): void {
  const now = "2026-07-21T12:00:00.000Z";
  addMission(database, "mission-vault-outcomes");
  database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES ('run-vault-outcomes', 'mission-vault-outcomes', 'guided', 'completed', ?, ?)
  `).run(now, now);
  for (const [suffix, status] of [["success", "succeeded"], ["failed", "failed"]] as const) {
    const attemptId = `attempt-vault-${suffix}`;
    const evidenceId = `evidence-vault-${suffix}`;
    database.prepare(`
      INSERT INTO attack_attempts (
        id, mission_id, run_id, objective, technique_name, action_class,
        prerequisites_json, normalized_parameters_json, status, outcome_summary,
        failure_category, ended_at, created_at, updated_at
      ) VALUES (?, 'mission-vault-outcomes', 'run-vault-outcomes',
        'Validate one exact reusable procedure', 'Bounded validation',
        'exploit-validation', '[]', '{}', ?, ?, ?, ?, ?, ?)
    `).run(
      attemptId,
      status,
      `The exact represented procedure ${status}.`,
      status === "failed" ? "deterministic_tool_error" : null,
      now,
      now,
      now,
    );
    database.prepare(`
      INSERT INTO attack_attempt_knowledge_contexts (
        attack_attempt_id, procedure_node_id, product_node_ids_json,
        version_node_ids_json, stack_node_ids_json, prerequisite_node_ids_json,
        observed_state_node_ids_json, normalized_parameters_json, created_at, updated_at
      ) VALUES (?, ?, '[]', '[]', '[]', '[]', '[]', '{}', ?, ?)
    `).run(attemptId, nodeId, now, now);
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, 'mission-vault-outcomes', 'run-vault-outcomes',
        'local-evaluator', ?, 'redacted fixture', 'exploit_validation_result',
        ?, '{}', 0.98, 'internal', 'verified',
        'Verified result for the exact represented attempt.', 'worker-test', ?)
    `).run(evidenceId, now, createHash("sha256").update(evidenceId).digest("hex"), now);
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'local-evaluator', '{}', ?)
    `).run(`custody-vault-${suffix}`, evidenceId, now);
    database.prepare(`
      INSERT INTO attack_attempt_evidence (
        attack_attempt_id, evidence_id, relationship, created_at
      ) VALUES (?, ?, 'outcome', ?)
    `).run(attemptId, evidenceId, now);
    new ReusableKnowledgeOutcomeService(database, () => new Date(now)).bind({
      memoryNodeId: nodeId,
      attackAttemptId: attemptId,
      evidenceIds: [evidenceId],
      actorId: "operator-1",
      actorType: "operator",
      reason: `Reviewed the exact ${suffix} attempt and verified result.`,
    });
  }
}

function addMission(database: ReturnType<typeof createDatabaseConnection>, id = "mission-vault-attachments") {
  const now = "2026-07-15T10:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, '{}', '[]', '{}', '{}', ?, ?, ?)
  `).run(id, "Attachment test mission", "Verify Obsidian attachment integrity", "engagement-vault", "operator-1", now, now);
  return id;
}

function addMissionNode(
  memory: MemoryRepository,
  id: string,
  title: string,
  _missionId: string,
) {
  return memory.createNode({
    id: reusableNodeId(id),
    nodeType: "attack_procedure",
    title,
    summary: `Summary for ${title}`,
    body: `Operational note for ${title}.`,
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 0.95,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator-1",
  });
}

describe("Obsidian vault bridge", () => {
  test("projects both canonical outcome tags, omits unclassified tags, and ignores forged Vault classifications", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const classified = addVerifiedProcedure(memory, "classified-procedure", "bounded validation");
      classifyProcedureBothWays(db, classified.id);
      const classifiedExport = bridge.exportNode(connection.id, classified.id);
      const classifiedText = readFileSync(
        join(connection.vaultPath, classifiedExport.relativePath),
        "utf8",
      );
      expect(classifiedText).toContain("outcome_tags:\n  - \"success\"\n  - \"failed\"");
      expect(classifiedText).toContain('  - "ti-scale/outcome/success"');
      expect(classifiedText).toContain('  - "ti-scale/outcome/failed"');
      expect(parseObsidianNote(classifiedText).outcomeTags).toEqual(["success", "failed"]);

      const unclassified = addVerifiedProcedure(memory, "unclassified-procedure", "supporting analysis");
      const unclassifiedExport = bridge.exportNode(connection.id, unclassified.id);
      const unclassifiedPath = join(connection.vaultPath, unclassifiedExport.relativePath);
      const unclassifiedText = readFileSync(unclassifiedPath, "utf8");
      expect(unclassifiedText).not.toContain("outcome_tags:");
      expect(unclassifiedText).not.toContain("ti-scale/outcome/");
      expect(parseObsidianNote(unclassifiedText).outcomeTags).toEqual([]);

      const forgedText = unclassifiedText.replace(
        "private_provenance_ids:",
        'outcome_tags:\n  - "success"\nprivate_provenance_ids:',
      );
      writeFileSync(unclassifiedPath, forgedText, "utf8");
      expect(parseObsidianNote(forgedText).outcomeTags).toEqual(["success"]);
      bridge.syncNode(connection.id, unclassified.id, "operator-1");
      expect(db.prepare(`
        SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links
        WHERE memory_node_id = ?
      `).get(unclassified.id)).toEqual({ count: 0 });

      const canonicalRerender = renderObsidianNote(
        memory.requireNode(unclassified.id),
        [],
        [],
      );
      expect(canonicalRerender).not.toContain("outcome_tags:");
      expect(parseObsidianNote(canonicalRerender).outcomeTags).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("round-trips YAML, stable IDs, authorship, and native wikilinks", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const origin = addNode(memory, "node-origin", "Origin Technique");
      const target = addNode(memory, "node-target", "Target Evidence Pattern");
      memory.createEdge({
        sourceNodeId: origin.id,
        targetNodeId: target.id,
        edgeType: "depends_on",
        title: "Origin depends on target",
        summary: "The technique requires the evidence pattern",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "confirmed",
        provenance: provenance("edge-source"),
        explanation: "This prerequisite was confirmed during review",
        authorType: "operator",
      });
      const exported = bridge.exportNode(connection.id, origin.id);
      expect(exported.status).toBe("synced");
      const path = join(connection.vaultPath, exported.relativePath);
      const text = readFileSync(path, "utf8");
      expect(text).not.toContain("[[81 Tools and MCP");
      expect(text).toContain("[[42 Techniques and Procedures/");
      expect(text).toContain("private_provenance_ids:");
      expect(text).not.toContain("source-node-origin");
      expect(text).toContain(`ti-scale-edge:depends_on:${target.id}`);
      const parsed = parseObsidianNote(text);
      expect(parsed.id).toBe(origin.id);
      expect(parsed.authorType).toBe("operator");
      expect(parsed.aliases).toContain(origin.id);
      expect(parsed.sourceIds).toEqual([]);
      expect(parsed.privateProvenanceIds).toHaveLength(1);
      expect(parsed.privateProvenanceIds[0]).toStartWith("msrc_");
      expect(parsed.edges[0]).toMatchObject({ edgeType: "depends_on", targetNodeId: target.id });

      const edited = text.replace(
        "Operational note for Origin Technique.",
        "Operator refined this operational procedure in Obsidian.",
      );
      writeFileSync(path, edited, "utf8");
      const synced = bridge.syncNode(connection.id, origin.id, "operator-1");
      expect(synced.status).toBe("synced");
      const node = memory.requireNode(origin.id);
      expect(node.body).toContain("refined this operational procedure");
      expect(node.version).toBe(2);
      expect(memory.listVersions(node.id)).toHaveLength(2);
    } finally {
      db.close();
    }
  });

  test("projects a small private provenance set completely with parser-verifiable integrity", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const node = addNode(memory, "small-provenance", "Small provenance procedure");
      const canonicalIds = (db.prepare(`
        SELECT id FROM memory_sources WHERE node_id = ? ORDER BY id
      `).all(node.id) as Array<{ id: string }>).map((row) => row.id);
      const expected = projectPrivateProvenanceIds(canonicalIds);
      const exported = bridge.exportNode(connection.id, node.id);
      const text = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      const parsed = parseObsidianNote(text);

      expect(parsed.privateProvenanceIds).toEqual(expected.ids);
      expect(parsed.privateProvenanceSummary).toEqual(expected.summary);
      expect(parsed.privateProvenanceSummary).toMatchObject({
        total: 1,
        projected: 1,
        truncated: false,
      });
      expect(text).toContain("Projection truncated: no");
      expect(text).toContain(`Full-set SHA-256: \`${expected.summary.sha256}\``);

      const forged = text.replace(
        `private_provenance_sha256: \"${expected.summary.sha256}\"`,
        `private_provenance_sha256: \"${"0".repeat(64)}\"`,
      );
      expect(() => parseObsidianNote(forged)).toThrow(
        "YAML private provenance digest does not match its complete reference set",
      );
    } finally {
      db.close();
    }
  });

  test("bounds 3,156 private sources, preserves SQLite custody, and round-trips without leaking locators", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const node = addNode(memory, "high-fanout-provenance", "High-fanout procedure");
      const insert = db.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, acquired_at, created_at
        ) VALUES (?, ?, 'historical_file', ?, ?, ?)
      `);
      const now = "2026-07-21T15:00:00.000Z";
      const addSources = db.transaction(() => {
        for (let index = 0; index < 3_155; index += 1) {
          const suffix = String(index).padStart(4, "0");
          const privateLocator = index === 0
            ? "https://operator:unit-test-authentication-material@private.invalid/raw-evidence"
            : `/root/engagements/private-client/mission-${suffix}/evidence-${suffix}.json`;
          insert.run(`msrc_high_fanout_${suffix}`, node.id, privateLocator, now, now);
        }
      });
      addSources();

      const sourceRows = db.prepare(`
        SELECT id, source_id AS sourceId FROM memory_sources WHERE node_id = ? ORDER BY id
      `).all(node.id) as Array<{ id: string; sourceId: string }>;
      expect(sourceRows).toHaveLength(3_156);
      const expected = projectPrivateProvenanceIds(sourceRows.map((row) => row.id));
      const exported = bridge.exportNode(connection.id, node.id);
      expect(exported.status).toBe("synced");
      const path = join(connection.vaultPath, exported.relativePath);
      const text = readFileSync(path, "utf8");
      const parsed = parseObsidianNote(text);

      expect(Buffer.byteLength(text, "utf8")).toBeLessThan(128 * 1_024);
      expect(parsed.privateProvenanceIds).toHaveLength(MAX_PROJECTED_PRIVATE_PROVENANCE_IDS);
      expect(parsed.privateProvenanceIds).toEqual(expected.ids);
      expect(parsed.privateProvenanceSummary).toEqual(expected.summary);
      expect(parsed.privateProvenanceSummary).toMatchObject({
        total: 3_156,
        projected: MAX_PROJECTED_PRIVATE_PROVENANCE_IDS,
        truncated: true,
      });
      expect(text).toContain("Canonical SQLite source records: 3156");
      expect(text).toContain("Projection truncated: yes");
      expect(text).not.toContain("unit-test-authentication-material");
      expect(text).not.toContain("/root/engagements/");
      expect(text).not.toContain("mission-0001");
      expect(text).not.toContain("evidence-0001");
      expect(text).toContain("source_ids: []");

      writeFileSync(
        path,
        text.replace(
          "Operational note for High-fanout procedure.",
          "Operator refined this high-fanout procedure in Obsidian.",
        ),
        "utf8",
      );
      expect(bridge.syncNode(connection.id, node.id, "operator-1").status).toBe("synced");
      expect(parseObsidianNote(readFileSync(path, "utf8")).privateProvenanceSummary).toEqual(expected.summary);
      expect(db.prepare("SELECT COUNT(*) AS count FROM memory_sources WHERE node_id = ?").get(node.id))
        .toEqual({ count: 3_156 });

      const normalized = readFileSync(path, "utf8");
      const forgedDigest = `${expected.summary.sha256[0] === "0" ? "1" : "0"}${expected.summary.sha256.slice(1)}`;
      writeFileSync(
        path,
        normalized
          .replace(expected.summary.sha256, forgedDigest)
          .replace(expected.summary.sha256, forgedDigest),
        "utf8",
      );
      expect(() => bridge.syncNode(connection.id, node.id, "operator-1")).toThrow(
        "Vault private provenance summary does not match canonical SQLite custody",
      );
      expect(db.prepare("SELECT COUNT(*) AS count FROM memory_sources WHERE node_id = ?").get(node.id))
        .toEqual({ count: 3_156 });
    } finally {
      db.close();
    }
  });

  test("creates the complete V2.4 vault taxonomy for every real connection", () => {
    const { db, connection } = setup();
    try {
      expect(OBSIDIAN_V2_4_VAULT_FOLDERS).toEqual([
        "00 Inbox",
        "20 Technology Products",
        "21 Versions and Fingerprints",
        "22 Software Stacks",
        "23 Security Controls",
        "30 Topology Patterns",
        "40 Vulnerabilities and Weaknesses",
        "41 Attack Vectors",
        "42 Techniques and Procedures",
        "43 Prerequisites and Attributes",
        "44 Discovery and Fingerprints",
        "45 Scripts and Tools",
        "50 Outcomes and Validation",
        "51 Operational Hazards",
        "52 Recovery and Alternatives",
        "53 Detection and Remediation",
        "60 Strategies and Lessons",
        "61 Research",
        "Attachments",
      ]);
      for (const relativePath of OBSIDIAN_V2_4_VAULT_FOLDERS) {
        const path = join(connection.vaultPath, relativePath);
        expect(existsSync(path)).toBe(true);
        expect(statSync(path).isDirectory()).toBe(true);
      }
    } finally {
      db.close();
    }
  });

  test("does not emit wikilinks to lifecycle-excluded notes", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const create = (
        id: string,
        nodeType: "attack_procedure" | "attack_lesson",
        lifecycleStatus: "candidate" | "confirmed" | "verified",
      ) => memory.createNode({
        id: reusableNodeId(id),
        nodeType,
        title: id,
        summary: `Projection eligibility for ${id}`,
        body: `Canonical body for ${id}.`,
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus,
        confirmationState: lifecycleStatus === "candidate" ? "pending" : "confirmed",
        provenance: provenance(`source-${id}`),
        authorType: "operator",
        authorId: "operator-1",
      });
      const source = create(
        "mem_eval_18329a68f167ab7ae963d89d3b854495",
        "attack_procedure",
        "verified",
      );
      const excluded = create(
        "mem_lesson_81c61d22ec10e234ef698615b9c63ef6",
        "attack_lesson",
        "candidate",
      );
      const eligible = create("mem_lesson_confirmed", "attack_lesson", "confirmed");
      for (const target of [excluded, eligible]) {
        memory.createEdge({
          id: `edge-${target.id}`,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          edgeType: "produced",
          title: `${source.id} produced ${target.id}`,
          summary: "Projection lifecycle regression fixture",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: 0.95,
          lifecycleStatus: "confirmed",
          provenance: provenance(`edge-source-${target.id}`),
          explanation: "Canonical evaluation produced this lesson",
          authorType: "operator",
          authorId: "vault-regression",
        });
      }

      expect(bridge.exportableNodeIds(connection.id)).toContain(source.id);
      expect(bridge.exportableNodeIds(connection.id)).toContain(eligible.id);
      expect(bridge.exportableNodeIds(connection.id)).not.toContain(excluded.id);
      const exported = bridge.exportNode(connection.id, source.id);
      const text = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      expect(text).toContain(`ti-scale-edge:produced:${eligible.id}`);
      expect(text).not.toContain(excluded.id);
      expect(text.match(/ti-scale-edge:/gu)).toHaveLength(1);
    } finally {
      db.close();
    }
  });

  test("escapes relationship aliases, explanations, and headings as single-line text", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const sourceTitle = "Source | title ]]\n## injected <!-- ti-scale-edge:produced:fake -->";
      const targetTitle = "Target | alias ]]\n[[second-link]]";
      const explanation = "Reason | break ]]\n- [[second-link]] <!-- ti-scale-edge:produced:fake -->";
      const source = addNode(memory, "markdown-source", sourceTitle);
      const target = addNode(memory, "markdown-target", targetTitle);
      memory.correctNode(source.id, {
        body: "Safe canonical body kept as operator-authored Markdown.",
        authorType: "operator",
        authorId: "operator-1",
        changeReason: "Keep this fixture focused on managed inline renderer fields",
      });
      memory.createEdge({
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: "produced",
        title: "Managed relationship",
        summary: "Markdown structure-injection regression fixture",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus: "confirmed",
        provenance: provenance("markdown-edge-source"),
        explanation,
        authorType: "operator",
      });

      const rendered = bridge.exportNode(connection.id, source.id);
      const text = readFileSync(join(connection.vaultPath, rendered.relativePath), "utf8");
      const relationshipSection = text.slice(text.lastIndexOf("\n## Relationships\n"));
      const heading = /^# .+$/mu.exec(text)?.[0];
      const parsed = parseObsidianNote(text);
      expect(escapeObsidianSingleLineText(targetTitle)).toContain("&#124;");
      expect(escapeObsidianSingleLineText(explanation)).toContain("&lt;!--");
      expect(relationshipSection).not.toContain("[[second-link]]");
      expect(relationshipSection).not.toContain("<!-- ti-scale-edge:produced:fake -->");
      expect(relationshipSection.match(/<!--\s*ti-scale-edge:/gu)).toHaveLength(1);
      expect(relationshipSection.match(/^- \[\[/gmu)).toHaveLength(1);
      expect(heading).not.toContain("\n");
      expect(heading).toContain("&#124;");
      expect(heading).toContain("&lt;!-- ti-scale-edge:produced:fake --&gt;");
      expect(parsed.title).toBe(sourceTitle.replace(/\s+/gu, " "));
      expect(parsed.edges).toHaveLength(1);
      expect(parsed.edges[0]).toMatchObject({
        edgeType: "produced",
        targetNodeId: target.id,
        targetTitle: targetTitle.replace(/\s+/gu, " "),
      });
    } finally {
      db.close();
    }
  });

  test("does not link to verified notes when the live policy projects confirmed notes only", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const current = bridge.memoryControlPolicy();
      updateMemoryControlPolicy({
        database: db,
        expectedVersion: current.version,
        actor: "operator-1",
        policy: { ...current, obsidianSyncScope: "confirmed" },
      });
      const source = addNode(memory, "confirmed-source", "Confirmed Source");
      const target = memory.createNode({
        id: reusableNodeId("verified-target"),
        nodeType: "attack_lesson",
        title: "Verified Target",
        summary: "Excluded by confirmed-only projection policy",
        body: "This verified note is not projected under the current policy.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: provenance("verified-target-source"),
        authorType: "operator",
        authorId: "operator-1",
      });
      memory.createEdge({
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: "produced",
        title: "Confirmed source produced verified target",
        summary: "Live lifecycle policy regression fixture",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus: "confirmed",
        provenance: provenance("confirmed-policy-edge"),
        explanation: "The target is excluded from this vault by live policy",
        authorType: "operator",
      });

      const exported = bridge.exportNode(connection.id, source.id);
      const text = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      expect(bridge.exportableNodeIds(connection.id)).toEqual([source.id]);
      expect(text).not.toContain(target.id);
      expect(text).not.toContain("## Relationships");
    } finally {
      db.close();
    }
  });

  test("does not emit wikilinks to notes excluded by the connection scope", () => {
    const { db, memory, bridge, connection } = setup({ nodeTypes: ["attack_procedure"] });
    try {
      const create = (id: string, nodeType: "attack_procedure" | "attack_lesson") => memory.createNode({
        id: reusableNodeId(id),
        nodeType,
        title: id,
        summary: `Connection projection scope for ${id}`,
        body: `Canonical body for ${id}.`,
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: provenance(`source-${id}`),
        authorType: "operator",
        authorId: "operator-1",
      });
      const source = create("scope-source", "attack_procedure");
      const eligible = create("scope-eligible", "attack_procedure");
      const excluded = create("scope-excluded", "attack_lesson");
      for (const target of [eligible, excluded]) {
        memory.createEdge({
          sourceNodeId: source.id,
          targetNodeId: target.id,
          edgeType: "produced",
          title: `${source.id} produced ${target.id}`,
          summary: "Connection projection scope regression fixture",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: 0.95,
          lifecycleStatus: "confirmed",
          provenance: provenance(`edge-source-${target.id}`),
          explanation: "Only targets exported by this connection may be linked",
          authorType: "operator",
        });
      }

      const text = bridge.renderNode(source.id, connection).text;
      expect(bridge.exportableNodeIds(connection.id)).toEqual([eligible.id, source.id]);
      expect(text).toContain(`ti-scale-edge:produced:${eligible.id}`);
      expect(text).not.toContain(excluded.id);
      expect(text.match(/ti-scale-edge:/gu)).toHaveLength(1);
    } finally {
      db.close();
    }
  });

  test("keeps legacy synchronized target paths in links without moving notes", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const source = addNode(memory, "legacy-link-source", "Legacy Link Source");
      const legacyTarget = addNode(memory, "legacy-link-target", "Legacy Link Target");
      const v24Target = addNode(memory, "v24-link-target", "V2.4 Link Target");
      for (const target of [legacyTarget, v24Target]) {
        memory.createEdge({
          sourceNodeId: source.id,
          targetNodeId: target.id,
          edgeType: "depends_on",
          title: `${source.id} depends on ${target.id}`,
          summary: "Projection-path compatibility fixture",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: 0.95,
          lifecycleStatus: "confirmed",
          provenance: provenance(`edge-source-${target.id}`),
          explanation: "The relationship must resolve to this connection's projected note",
          authorType: "operator",
        });
      }

      const firstTargetProjection = bridge.exportNode(connection.id, legacyTarget.id);
      const v24TargetProjection = bridge.exportNode(connection.id, v24Target.id);
      const legacyRelativePath = `30 Attack Patterns/${basename(firstTargetProjection.relativePath)}`;
      const legacyDirectory = join(connection.vaultPath, "30 Attack Patterns");
      mkdirSync(legacyDirectory, { recursive: true });
      renameSync(
        join(connection.vaultPath, firstTargetProjection.relativePath),
        join(connection.vaultPath, legacyRelativePath),
      );
      db.prepare(`
        UPDATE vault_sync_state SET relative_path = ?
        WHERE connection_id = ? AND node_id = ?
      `).run(legacyRelativePath, connection.id, legacyTarget.id);

      const exported = bridge.exportNode(connection.id, source.id);
      const text = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      expect(text).toContain(`[[${legacyRelativePath.replace(/\.md$/u, "")}|`);
      expect(text).toContain(`[[${v24TargetProjection.relativePath.replace(/\.md$/u, "")}|`);
      expect(v24TargetProjection.relativePath).toStartWith("42 Techniques and Procedures/");
      expect(existsSync(join(connection.vaultPath, legacyRelativePath))).toBe(true);
      expect(existsSync(join(connection.vaultPath, firstTargetProjection.relativePath))).toBe(false);
      expect((db.prepare(`
        SELECT relative_path FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, legacyTarget.id) as { relative_path: string }).relative_path)
        .toBe(legacyRelativePath);

      expect(normalizeObsidianWikilinkTarget(legacyRelativePath))
        .toBe(legacyRelativePath.replace(/\.md$/u, ""));
      for (const unsafeRelativePath of [
        "../outside.md",
        "/absolute.md",
        "C:/outside.md",
        "30 Attack Patterns/injected]]|alias.md",
        "30 Attack Patterns/injected#heading.md",
        "30 Attack Patterns/injected\nheading.md",
        "30 Attack Patterns/injected\u202efilename.md",
        "30\\Attack Patterns\\injected.md",
        "30 Attack Patterns/not-markdown.txt",
        "30 Attack Patterns/../outside.md",
      ]) {
        expect(normalizeObsidianWikilinkTarget(unsafeRelativePath)).toBeUndefined();
        db.prepare(`
          UPDATE vault_sync_state SET relative_path = ?
          WHERE connection_id = ? AND node_id = ?
        `).run(unsafeRelativePath, connection.id, legacyTarget.id);
        const unsafeRendered = bridge.renderNode(source.id, connection).text;
        expect(unsafeRendered).not.toContain(`ti-scale-edge:depends_on:${legacyTarget.id}`);
        expect(unsafeRendered).not.toContain(unsafeRelativePath);
        expect(unsafeRendered).toContain(`ti-scale-edge:depends_on:${v24Target.id}`);
      }
    } finally {
      db.close();
    }
  });

  test("rejects path traversal and vaults outside the configured sandbox", () => {
    const { db, directory, policy, connection } = setup();
    try {
      expect(() => policy.resolveVault("../../outside")).toThrow("escapes");
      expect(() => policy.resolveRelative(connection.vaultPath, "../../auth.json")).toThrow("traversal");
      expect(() => policy.resolveRelative(connection.vaultPath, "/root/.ssh/id_ed25519")).toThrow("relative");
      expect(existsSync(join(directory, "outside"))).toBe(false);
    } finally {
      db.close();
    }
  });

  test("detects concurrent database/vault edits and requires explicit resolution", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const node = addNode(memory, "node-conflict", "Conflict Technique");
      const exported = bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      const vaultText = readFileSync(path, "utf8").replace(
        "Operational note for Conflict Technique.",
        "Vault-side operator edit.",
      );
      writeFileSync(path, vaultText, "utf8");
      memory.correctNode(node.id, {
        body: "Database-side operator edit.",
        authorType: "operator",
        authorId: "operator-1",
        changeReason: "Operator reviewed reusable knowledge",
      });
      const result = bridge.syncNode(connection.id, node.id, "operator-1");
      expect(result.status).toBe("conflict");
      expect(result.conflictId).toBeDefined();
      const conflict = db.prepare("SELECT status FROM vault_conflicts WHERE id = ?").get(result.conflictId) as { status: string };
      expect(conflict.status).toBe("open");
      const synchronizedAgain = bridge.syncNode(connection.id, node.id, "operator-1");
      expect(synchronizedAgain).toMatchObject({
        status: "conflict",
        conflictId: result.conflictId,
      });
      expect(readFileSync(path, "utf8")).toContain("Vault-side operator edit");
      const resolved = bridge.resolveConflict(result.conflictId!, "database", "operator-1");
      expect(resolved.status).toBe("synced");
      expect(readFileSync(path, "utf8")).toContain("Database-side operator edit");
    } finally {
      db.close();
    }
  });

  test("quarantines malformed notes and removes synchronized projections on forgetting", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const inbox = join(connection.vaultPath, "00 Inbox", "malformed.md");
      writeFileSync(inbox, "# no frontmatter", "utf8");
      const imported = bridge.importNote(connection.id, "00 Inbox/malformed.md", "operator-1");
      expect(imported.status).toBe("quarantined");
      expect(existsSync(inbox)).toBe(false);
      expect(existsSync(join(connection.vaultPath, imported.quarantinePath!))).toBe(true);

      const node = addNode(memory, "node-forget-vault", "Forget Vault Technique");
      const exported = bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      expect(existsSync(path)).toBe(true);
      const result = bridge.forgetMemory(node.id, "operator-1");
      expect(result.vaultProjections).toHaveLength(1);
      expect(existsSync(path)).toBe(false);
      expect(memory.requireNode(node.id, true).lifecycleStatus).toBe("forgotten");
    } finally {
      db.close();
    }
  });

  test("quarantines authentication material before candidate, correction, or conflict persistence", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const node = addNode(memory, "node-vault-safety", "Vault Safety Technique");
      const exported = bridge.exportNode(connection.id, node.id);
      const projectionPath = join(connection.vaultPath, exported.relativePath);
      const safeProjection = readFileSync(projectionPath, "utf8");
      const sessionMaterial = ["session_token", ": ", "unit-test-session-material-123456789"].join("");

      const inboxRelative = "00 Inbox/unsafe-authentication-note.md";
      const inboxPath = join(connection.vaultPath, inboxRelative);
      writeFileSync(
        inboxPath,
        safeProjection
          .replace(`id: "${node.id}"`, 'id: "candidate-vault-safety"')
          .replace("Operational note for Vault Safety Technique.", sessionMaterial),
        "utf8",
      );
      const imported = bridge.importNote(connection.id, inboxRelative, "operator-1");
      expect(imported.status).toBe("quarantined");
      expect(existsSync(inboxPath)).toBe(false);
      expect((db.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count).toBe(0);
      const importState = db.prepare(
        "SELECT relative_path, status, error_message FROM vault_sync_state WHERE connection_id = ? AND status = 'quarantined' ORDER BY rowid DESC LIMIT 1",
      ).get(connection.id) as { relative_path: string; status: string; error_message: string };
      expect(importState.status).toBe("quarantined");
      expect(imported.quarantinePath).toBeDefined();
      expect(importState.relative_path).toBe(imported.quarantinePath!);
      expect(importState.relative_path).not.toContain("unsafe-authentication-note");
      expect(importState.error_message).toBe("Vault note rejected by reusable-memory safety policy");
      expect(importState.error_message).not.toContain(sessionMaterial);

      const privateKeyMaterial = [
        ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join(""),
        "unit-test-authentication-material",
        ["-----END OPENSSH ", "PRIVATE KEY-----"].join(""),
      ].join("\n");
      writeFileSync(
        projectionPath,
        safeProjection.replace("Operational note for Vault Safety Technique.", privateKeyMaterial),
        "utf8",
      );
      const synchronized = bridge.syncNode(connection.id, node.id, "operator-1");
      expect(synchronized.status).toBe("quarantined");
      expect(existsSync(projectionPath)).toBe(false);
      expect(memory.requireNode(node.id)).toMatchObject({ version: 1, body: "Operational note for Vault Safety Technique." });
      expect(memory.listVersions(node.id)).toHaveLength(1);
      expect((db.prepare("SELECT COUNT(*) AS count FROM vault_conflicts").get() as { count: number }).count).toBe(0);
      expect(JSON.stringify(db.prepare("SELECT title, summary, body FROM memory_nodes").all()))
        .not.toContain("unit-test-authentication-material");
    } finally {
      db.close();
    }
  });

  test("keeps deep links available while portable archive creation stays disabled", async () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const node = addNode(memory, "node-portable", "Portable Technique");
      const exported = bridge.exportNode(connection.id, node.id);
      const link = bridge.deepLink(connection.id, exported.relativePath);
      expect(link).toStartWith("obsidian://open?");
      expect(link).toContain("vault=Ti-Scale-Brain");
      expect(link).not.toContain(connection.vaultPath);

      await expect(
        bridge.createPortableExport(connection.id, [node.id], "operator-1"),
      ).rejects.toThrow(
        "Portable Vault ZIP creation is disabled by operator no-backup policy",
      );
      expect(existsSync(join(connection.vaultPath, ".ti-scale", "exports")))
        .toBe(false);
    } finally {
      db.close();
    }
  });

  test("keeps private engagement attachments out of reusable attack knowledge", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const missionId = addMission(db);
      const seed = addMissionNode(memory, "node-attachment-seed", "Attachment Seed", missionId);
      const attachmentBytes = Buffer.from([
        0x43, 0x68, 0x69, 0x6c, 0x6c, 0x73, 0x50, 0x77, 0x6e, 0x00, 0xff, 0x10, 0x20,
      ]);
      const firstAttachmentPath = join(connection.vaultPath, "Attachments", "operator-capture.png");
      writeFileSync(firstAttachmentPath, attachmentBytes);

      const template = bridge.renderNode(seed.id).text;
      const firstRelative = "00 Inbox/attachment-import.md";
      writeFileSync(
        join(connection.vaultPath, firstRelative),
        `${template
          .replace(`id: "${seed.id}"`, 'id: "attachment-import"')
          .replace("# Attachment Seed", "# Imported Attachment")
          .replace("Operational note for Attachment Seed.", "Operator supplied a protected mission artifact.")
        }\n![[Attachments/operator-capture.png]]\n`,
        "utf8",
      );

      const imported = bridge.importNote(connection.id, firstRelative, "operator-1");
      expect(imported.status).toBe("quarantined");
      expect(existsSync(join(connection.vaultPath, firstRelative))).toBe(false);
      expect((db.prepare(`
        SELECT COUNT(*) AS count FROM artifacts WHERE artifact_type = 'obsidian_attachment'
      `).get() as { count: number }).count).toBe(0);
      expect((db.prepare(`
        SELECT COUNT(*) AS count FROM memory_candidates
      `).get() as { count: number }).count).toBe(0);
    } finally {
      db.close();
    }
  });

  test("quarantines attachment traversal, symlinks, and mismatched integrity markers", () => {
    const { directory, db, memory, bridge, connection } = setup();
    try {
      const missionId = addMission(db, "mission-vault-attachment-rejection");
      const seed = addMissionNode(memory, "node-attachment-rejection", "Attachment Rejection", missionId);
      const template = bridge.renderNode(seed.id).text;
      const outside = join(directory, "outside.png");
      writeFileSync(outside, Buffer.from("outside attachment"));
      symlinkSync(outside, join(connection.vaultPath, "Attachments", "linked.png"));
      const symlinkRelative = "00 Inbox/symlink-attachment.md";
      writeFileSync(
        join(connection.vaultPath, symlinkRelative),
        `${template.replace(`id: "${seed.id}"`, 'id: "symlink-attachment"')}\n![[Attachments/linked.png]]\n`,
      );
      const symlinkImport = bridge.importNote(connection.id, symlinkRelative, "operator-1");
      expect(symlinkImport.status).toBe("quarantined");
      expect(existsSync(join(connection.vaultPath, symlinkRelative))).toBe(false);

      const safeBytes = Buffer.from("integrity checked attachment");
      writeFileSync(join(connection.vaultPath, "Attachments", "integrity.png"), safeBytes);
      const integrityRelative = "00 Inbox/integrity-attachment.md";
      writeFileSync(
        join(connection.vaultPath, integrityRelative),
        `${template.replace(`id: "${seed.id}"`, 'id: "integrity-attachment"')}\n![[Attachments/integrity.png]] <!-- ti-scale-attachment:artifact-does-not-exist:${"0".repeat(64)} -->\n`,
      );
      const integrityImport = bridge.importNote(connection.id, integrityRelative, "operator-1");
      expect(integrityImport.status).toBe("quarantined");
      expect((db.prepare(`
        SELECT COUNT(*) AS count FROM artifacts WHERE artifact_type = 'obsidian_attachment'
      `).get() as { count: number }).count).toBe(0);
    } finally {
      db.close();
    }
  });

  test("quarantines an attachment added to a reusable attack note", () => {
    const { db, memory, bridge, connection } = setup();
    try {
      const missionId = addMission(db, "mission-vault-attachment-versioning");
      const node = addMissionNode(memory, "node-attachment-versioning", "Attachment Versioning", missionId);
      const exported = bridge.exportNode(connection.id, node.id);
      const notePath = join(connection.vaultPath, exported.relativePath);
      const attachmentBytes = Buffer.from("versioned attachment bytes");
      writeFileSync(join(connection.vaultPath, "Attachments", "versioned.txt"), attachmentBytes);
      writeFileSync(
        notePath,
        `${readFileSync(notePath, "utf8")}\n![[Attachments/versioned.txt]]\n`,
        "utf8",
      );

      const synchronized = bridge.syncNode(connection.id, node.id, "operator-1");
      expect(synchronized.status).toBe("quarantined");
      expect(memory.requireNode(node.id).version).toBe(1);
      expect(memory.listVersions(node.id)).toHaveLength(1);
      expect(existsSync(notePath)).toBe(false);
      expect((db.prepare(`
        SELECT COUNT(*) AS count FROM artifacts WHERE artifact_type = 'obsidian_attachment'
      `).get() as { count: number }).count).toBe(0);
    } finally {
      db.close();
    }
  });

  test("debounces vault edits and stops watching immediately when operator policy disables sync", async () => {
    const { db, memory, bridge, connection } = setup();
    const fake = new EventEmitter() as EventEmitter & { close: () => void; closed: boolean };
    fake.closed = false;
    fake.close = () => { fake.closed = true; };
    let listener: ((eventType: string, filename: string | Buffer | null) => void) | undefined;
    const watcher = new ObsidianVaultWatcher(db, bridge, {
      debounceMs: 10,
      yieldMs: 0,
      watchFactory: (_root, callback) => {
        listener = callback;
        return fake as unknown as FSWatcher;
      },
    });
    try {
      const node = addNode(memory, "node-watched", "Watched Technique");
      const exported = bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      writeFileSync(path, readFileSync(path, "utf8").replace(
        "Operational note for Watched Technique.",
        "Operator edited this note through the watched vault.",
      ));
      watcher.start();
      expect(watcher.watchedConnectionCount).toBe(1);
      listener?.("change", exported.relativePath);
      await new Promise((resolve) => setTimeout(resolve, 30));
      await watcher.waitForIdle();
      expect(memory.requireNode(node.id).body).toContain("watched vault");

      const current = bridge.memoryControlPolicy();
      updateMemoryControlPolicy({
        database: db,
        expectedVersion: current.version,
        actor: "operator-1",
        policy: { ...current, obsidianSyncScope: "disabled" },
      });
      watcher.refreshConnections();
      expect(watcher.watchedConnectionCount).toBe(0);
      expect(fake.closed).toBe(true);
      expect(() => bridge.exportNode(connection.id, node.id)).toThrow("not permitted");
    } finally {
      await watcher.stop();
      db.close();
    }
  });

  test("does not capture stale filesystem events while a connection requires explicit recovery", async () => {
    const { db, bridge, connection } = setup();
    const fake = new EventEmitter() as EventEmitter & { close: () => void; closed: boolean };
    fake.closed = false;
    fake.close = () => { fake.closed = true; };
    let listener: ((eventType: string, filename: string | Buffer | null) => void) | undefined;
    const watcher = new ObsidianVaultWatcher(db, bridge, {
      debounceMs: 10,
      yieldMs: 0,
      watchFactory: (_root, callback) => {
        listener = callback;
        return fake as unknown as FSWatcher;
      },
    });
    try {
      watcher.start();
      const current = db.prepare(`
        SELECT updated_at FROM vault_connections WHERE id = ?
      `).get(connection.id) as { updated_at: string };
      const recoveryVersion = new Date(Date.parse(current.updated_at) + 1).toISOString();
      db.prepare(`
        UPDATE vault_connections SET status = 'error', updated_at = ? WHERE id = ?
      `).run(recoveryVersion, connection.id);

      const relativePath = "operator-note-during-recovery.md";
      const absolutePath = join(connection.vaultPath, relativePath);
      const original = "# Operator bytes remain untouched during recovery\n";
      writeFileSync(absolutePath, original, "utf8");
      listener?.("change", relativePath);
      expect(watcher.pendingCount).toBe(0);

      db.prepare(`
        UPDATE vault_connections SET status = 'degraded' WHERE id = ?
      `).run(connection.id);
      expect(watcher.pendingCount).toBe(0);
      expect(readFileSync(absolutePath, "utf8")).toBe(original);
    } finally {
      await watcher.stop();
      db.close();
    }
  });

  test("quarantines connected edits but discards pending work at the disconnect fence", async () => {
    const { db, bridge, connection } = setup();
    const fake = new EventEmitter() as EventEmitter & { close: () => void; closed: boolean };
    fake.closed = false;
    fake.close = () => { fake.closed = true; };
    let listener: ((eventType: string, filename: string | Buffer | null) => void) | undefined;
    const errors: Error[] = [];
    const watcher = new ObsidianVaultWatcher(db, bridge, {
      debounceMs: 20,
      yieldMs: 0,
      onError: (error) => errors.push(error),
      watchFactory: (_root, callback) => {
        listener = callback;
        return fake as unknown as FSWatcher;
      },
    });
    try {
      watcher.start();

      const connectedRelative = "connected-malformed.md";
      const connectedPath = join(connection.vaultPath, connectedRelative);
      writeFileSync(connectedPath, "# Missing required Ti-Scale frontmatter\n", "utf8");
      listener?.("change", connectedRelative);
      await new Promise((resolve) => setTimeout(resolve, 40));
      await watcher.waitForIdle();
      expect(existsSync(connectedPath)).toBe(false);

      const fencedRelative = "operator-note-at-disconnect.md";
      const fencedPath = join(connection.vaultPath, fencedRelative);
      const fencedText = "# Operator-owned bytes must remain untouched\n";
      writeFileSync(fencedPath, fencedText, "utf8");
      listener?.("change", fencedRelative);
      expect(watcher.pendingCount).toBe(1);

      db.prepare(`
        UPDATE vault_connections SET status = 'disconnected' WHERE id = ?
      `).run(connection.id);
      watcher.refreshConnections();

      expect(fake.closed).toBe(true);
      expect(watcher.watchedConnectionCount).toBe(0);
      expect(watcher.pendingCount).toBe(0);
      await new Promise((resolve) => setTimeout(resolve, 40));
      await watcher.waitForIdle();
      expect(readFileSync(fencedPath, "utf8")).toBe(fencedText);
      expect(errors).toEqual([]);
      expect((db.prepare(`
        SELECT status FROM vault_connections WHERE id = ?
      `).get(connection.id) as { status: string }).status).toBe("disconnected");
    } finally {
      await watcher.stop();
      db.close();
    }
  });

  test("cancels already-debounced queued work when a Vault disconnects", async () => {
    const { db, bridge, connection } = setup();
    const fake = new EventEmitter() as EventEmitter & { close: () => void; closed: boolean };
    fake.closed = false;
    fake.close = () => { fake.closed = true; };
    let listener: ((eventType: string, filename: string | Buffer | null) => void) | undefined;
    const errors: Error[] = [];
    const watcher = new ObsidianVaultWatcher(db, bridge, {
      debounceMs: 10,
      yieldMs: 1_000,
      onError: (error) => errors.push(error),
      watchFactory: (_root, callback) => {
        listener = callback;
        return fake as unknown as FSWatcher;
      },
    });
    try {
      watcher.start();
      const relativePath = "queued-before-disconnect.md";
      const absolutePath = join(connection.vaultPath, relativePath);
      const original = "# Queued operator note remains byte-for-byte intact\n";
      writeFileSync(absolutePath, original, "utf8");
      listener?.("change", relativePath);
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(watcher.pendingCount).toBe(1);

      db.prepare(`
        UPDATE vault_connections SET status = 'disconnected' WHERE id = ?
      `).run(connection.id);
      watcher.refreshConnections();

      expect(watcher.pendingCount).toBe(0);
      expect(fake.closed).toBe(true);
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(readFileSync(absolutePath, "utf8")).toBe(original);
      expect(errors).toEqual([]);
    } finally {
      await watcher.stop();
      db.close();
    }
  });
});
