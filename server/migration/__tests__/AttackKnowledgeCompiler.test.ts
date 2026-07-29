import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import {
  AttackKnowledgeCompiler,
  AttackKnowledgeCompilerInterruptedError,
  type AttackKnowledgeCompilerInput,
  type OperationalHazardKnowledge,
} from "../AttackKnowledgeCompiler";

const NOW = "2026-07-20T15:00:00.000Z";
const HMAC_KEY = "attack-knowledge-compiler-test-key-32-bytes-minimum";
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "attack-knowledge-compiler-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  return {
    database,
    compiler: new AttackKnowledgeCompiler(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    }),
  };
}

function applicationHangKnowledge(): OperationalHazardKnowledge {
  return {
    kind: "operational_hazard",
    product: { name: "Microsoft IIS", exactVersion: "10.0" },
    stack: [
      { nodeType: "framework", name: "ASP.NET", exactVersion: "4.8" },
      { nodeType: "runtime", name: "Embedded JavaScript engine", exactVersion: "1.0" },
      { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022" },
      { nodeType: "waf", name: "ModSecurity", exactVersion: "3.0.12" },
    ],
    procedure: {
      name: "Bounded expression diagnostic sequence",
      version: "v3",
      orderedSteps: [
        "Run one harmless scalar execution probe",
        "Submit one bounded expression diagnostic",
        "Repeat the harmless scalar execution probe",
        "Checkpoint the resulting execution state",
      ],
      normalizedParameters: {
        automaticRetries: 0,
        maximumDiagnosticStages: 1,
        healthProbeRequired: true,
      },
      prerequisites: [
        "Base application page responds",
        "Expression execution health probe succeeds",
      ],
    },
    hazard: {
      name: "Application execution path hangs after known-bad diagnostic sequence",
      observedSymptom: "The base page remains reachable while expression requests stop completing",
      affectedComponent: "Application expression execution worker",
      stateBefore: "Harmless scalar execution probe succeeds",
      stateAfter: "Expression execution requests time out while the base page remains available",
      unsafeRetryConditions: [
        "The harmless expression health probe does not return",
        "The previous bounded diagnostic has no terminal outcome",
      ],
      healthGate: [
        "Recycle the isolated application execution worker",
        "Prove a fresh harmless scalar execution probe succeeds",
      ],
      recoveryActionSummary: "Recycle the application pool and pass the harmless execution health probe",
      recoveryCost: {
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
        serviceRecycleCount: 2,
        operatorMinutes: 18,
      },
      saferAlternative: {
        name: "Single-stage expression validation",
        orderedSteps: [
          "Restore a healthy execution worker",
          "Run one lower-risk diagnostic stage",
          "Re-check execution health before any next stage",
        ],
      },
      concurrencyMinimum: 1,
      timingWindowMs: 120_000,
      freshUntil: "2027-01-20T15:00:00.000Z",
    },
    corroboration: {
      exactProcedureAttemptCount: 3,
      exactProcedureReproducibilityCount: 2,
      exactProcedureEvidenceCount: 2,
    },
  };
}

function kernelHangKnowledge(): OperationalHazardKnowledge {
  return {
    kind: "operational_hazard",
    product: { name: "Linux kernel", exactVersion: "6.1.0" },
    stack: [
      { nodeType: "operating_system", name: "Debian", exactVersion: "12.4" },
      { nodeType: "kernel", name: "Linux kernel", exactVersion: "6.1.0" },
    ],
    procedure: {
      name: "Bounded local privilege boundary probe",
      version: "v2",
      orderedSteps: [
        "Confirm a clean boot and stable process scheduler",
        "Run one bounded local privilege boundary probe",
        "Observe its terminal outcome without automatic retry",
      ],
      normalizedParameters: {
        automaticRetries: 0,
        maximumAttemptsPerBoot: 1,
        requireCleanBoot: true,
      },
      prerequisites: [
        "Kernel build fingerprint matches exactly",
        "A clean boot checkpoint is available",
      ],
    },
    hazard: {
      name: "Kernel privilege procedure hangs after execution begins",
      observedSymptom: "The local procedure begins but does not produce a terminal outcome across separate clean boots",
      affectedComponent: "Kernel privilege transition path",
      stateBefore: "Clean boot remains responsive",
      stateAfter: "Privilege procedure remains in flight without a trustworthy completion signal",
      unsafeRetryConditions: [
        "The previous procedure still has no terminal outcome",
        "The system has not returned to a verified clean boot",
      ],
      healthGate: [
        "Restore a verified clean boot",
        "Confirm no prior procedure process remains",
      ],
      recoveryActionSummary: "Stop the attempt and restore a clean boot checkpoint before analysis",
      recoveryCost: {
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
        requiresDisposableTargetReset: true,
      },
      saferAlternative: {
        name: "Offline kernel applicability review",
        orderedSteps: [
          "Compare the exact kernel build with the affected range",
          "Inspect preconditions without executing the privilege procedure",
        ],
      },
      concurrencyMinimum: 1,
      timingWindowMs: 180_000,
    },
    corroboration: {
      exactProcedureAttemptCount: 2,
      exactProcedureReproducibilityCount: 2,
      exactProcedureEvidenceCount: 2,
    },
  };
}

function source(overrides: Partial<AttackKnowledgeCompilerInput["source"]> = {}): AttackKnowledgeCompilerInput["source"] {
  return {
    privateSourceReference: "/root/htb/boxes/ReaperTwo/notes/private-current-state.md",
    privateLabels: ["ReaperTwo", "10.129.39.191"],
    sourceClass: "historical",
    sourceHash: "a".repeat(64),
    observedAt: NOW,
    evidenceCount: 8,
    ...overrides,
  };
}

function input(
  knowledge: OperationalHazardKnowledge = applicationHangKnowledge(),
  sourceOverrides: Partial<AttackKnowledgeCompilerInput["source"]> = {},
): AttackKnowledgeCompilerInput {
  return { source: source(sourceOverrides), knowledge, confidence: 0.96 };
}

function fingerprintInput(sourceHash: string): AttackKnowledgeCompilerInput {
  return {
    source: source({ sourceHash, evidenceCount: 1 }),
    confidence: 0.92,
    knowledge: {
      kind: "reusable_fact",
      nodeType: "fingerprint_pattern",
      title: "Two-source product fingerprint",
      summary: "Corroborate a product fingerprint through two independent protocol observations.",
    },
  };
}

function allCompilerText(database: SqliteDatabase): string {
  const tables = [
    "attack_knowledge_bundles",
    "attack_knowledge_provenance_receipts",
    "attack_knowledge_bundle_receipts",
    "attack_knowledge_candidate_registry",
    "attack_knowledge_bundle_candidates",
    "attack_knowledge_bundle_edges",
    "attack_knowledge_compiler_runs",
    "attack_knowledge_quarantine_records",
    "memory_candidates",
  ];
  return JSON.stringify(Object.fromEntries(tables.map((table) => [
    table,
    database.prepare(`SELECT * FROM ${table}`).all(),
  ])));
}

describe("AttackKnowledgeCompiler", () => {
  test("preserves immediate compile reconciliation while a bounded historical batch reconciles globally once", () => {
    const immediate = setup().compiler;
    const immediateReconcile = immediate.reconcile.bind(immediate);
    let immediatePasses = 0;
    immediate.reconcile = () => {
      immediatePasses += 1;
      return immediateReconcile();
    };
    const ordinary = immediate.compile(input());
    expect(ordinary.status).toBe("staged");
    expect(ordinary.reconciliation.bundleCount).toBe(1);
    // Preserve the existing staged-compile contract: one persisted snapshot
    // plus the exact returned snapshot.
    expect(immediatePasses).toBe(2);

    const { database, compiler } = setup();
    const reconcile = compiler.reconcile.bind(compiler);
    let deferredPasses = 0;
    compiler.reconcile = () => {
      deferredPasses += 1;
      return reconcile();
    };
    const requestCount = 32;
    const batch = compiler.beginDeferredReconciliationBatch({ maxCompilations: requestCount });
    for (let index = 0; index < requestCount; index += 1) {
      const result = batch.compile(fingerprintInput(index.toString(16).padStart(64, "0")));
      expect(result.status).toBe("staged");
      expect("reconciliation" in result).toBeFalse();
    }
    // This count-based performance assertion is deterministic: corpus size
    // cannot reintroduce a per-record global reconciliation pass.
    expect(deferredPasses).toBe(0);
    const finished = batch.finish();
    expect(deferredPasses).toBe(1);
    expect(finished).toMatchObject({
      compilations: requestCount,
      compilerRunsReconciled: requestCount,
      reconciliationPasses: 1,
      reconciliation: {
        bundleCount: 1,
        receiptCount: requestCount,
        bundleReceiptCount: requestCount,
        orphanedCandidateLinks: 0,
      },
    });
    const runSnapshots = database.prepare(`
      SELECT reconciliation_json FROM attack_knowledge_compiler_runs ORDER BY id
    `).all() as Array<{ readonly reconciliation_json: string }>;
    expect(runSnapshots).toHaveLength(requestCount);
    expect(runSnapshots.map(({ reconciliation_json }) => JSON.parse(reconciliation_json)))
      .toEqual(Array.from({ length: requestCount }, () => finished.reconciliation));
    expect(() => batch.finish()).toThrow("already finished");
    expect(() => batch.compile(input(), { dryRun: true })).toThrow("already finished");
  });

  test("fails closed when a deferred compilation batch exceeds its declared bound", () => {
    const { compiler } = setup();
    expect(() => compiler.beginDeferredReconciliationBatch({ maxCompilations: 0 })).toThrow(TypeError);
    const batch = compiler.beginDeferredReconciliationBatch({ maxCompilations: 1 });
    batch.compile(input(), { dryRun: true });
    expect(() => batch.compile(input(), { dryRun: true })).toThrow("exceeded its compilation bound");
    expect(batch.finish()).toMatchObject({
      compilations: 1,
      compilerRunsReconciled: 0,
      reconciliationPasses: 1,
    });
  });

  test("produces the same canonical compiler state as immediate compilation", () => {
    const immediate = setup();
    const deferred = setup();
    const requests = Array.from({ length: 8 }, (_, index) => (
      fingerprintInput((index + 1).toString(16).padStart(64, "0"))
    ));
    const immediateResults = requests.map((request) => immediate.compiler.compile(request));
    const batch = deferred.compiler.beginDeferredReconciliationBatch({ maxCompilations: requests.length });
    const deferredResults = requests.map((request) => batch.compile(request));
    const finished = batch.finish();

    expect(deferredResults.map(({ candidateIds }) => candidateIds))
      .toEqual(immediateResults.map(({ candidateIds }) => candidateIds));
    expect(finished.reconciliation).toEqual(immediate.compiler.reconcile());
    for (const table of [
      "attack_knowledge_bundles",
      "attack_knowledge_provenance_receipts",
      "attack_knowledge_bundle_receipts",
      "attack_knowledge_bundle_evidence_bindings",
      "attack_knowledge_candidate_registry",
      "attack_knowledge_bundle_candidates",
      "attack_knowledge_bundle_edges",
      "attack_knowledge_quarantine_records",
      "memory_candidates",
    ]) {
      expect(deferred.database.prepare(`SELECT * FROM ${table} ORDER BY 1`).all())
        .toEqual(immediate.database.prepare(`SELECT * FROM ${table} ORDER BY 1`).all());
    }
  });

  test("dry-runs without writes and reports candidate work", () => {
    const { compiler } = setup();
    const result = compiler.compile(input(), { dryRun: true });

    expect(result).toMatchObject({
      status: "dry_run",
      dryRun: true,
      candidatesReused: 0,
      exactProcedureCounts: {
        attempts: 3,
        reproducibleOutcomes: 2,
        evidenceItems: 2,
        exactResets: 2,
        operatorReportedAggregateResetMinimum: 11,
      },
      reconciliation: { bundleCount: 0, receiptCount: 0, candidateRegistryCount: 0 },
    });
    expect(result.candidatesCreated).toBeGreaterThan(10);
    expect(result.edgeProposalsStaged).toBeGreaterThan(15);
    expect(result.provenanceReceiptId).toMatch(/^akpr_[a-f0-9]{64}$/u);
  });

  test("stages two distinct hazards from one private source without merging or leaking source identity", () => {
    const { database, compiler } = setup();
    const application = compiler.compile(input(applicationHangKnowledge()));
    const kernel = compiler.compile(input(kernelHangKnowledge()));

    expect(application.status).toBe("staged");
    expect(kernel.status).toBe("staged");
    expect(application.bundleId).not.toBe(kernel.bundleId);
    expect(application.provenanceReceiptId).toBe(kernel.provenanceReceiptId);
    expect(compiler.reconcile()).toMatchObject({
      bundleCount: 2,
      receiptCount: 1,
      bundleReceiptCount: 2,
      orphanedCandidateLinks: 0,
      quarantineCount: 0,
    });

    const hazards = database.prepare(`
      SELECT bc.bundle_id, c.id, c.status, c.body
      FROM attack_knowledge_bundle_candidates bc
      JOIN attack_knowledge_candidate_registry r ON r.content_fingerprint = bc.content_fingerprint
      JOIN memory_candidates c ON c.id = r.candidate_id
      WHERE bc.role = 'hazard' ORDER BY bc.bundle_id
    `).all() as Array<{ bundle_id: string; id: string; status: string; body: string }>;
    expect(hazards).toHaveLength(2);
    expect(new Set(hazards.map(({ id }) => id)).size).toBe(2);
    expect(hazards.every(({ status }) => status === "pending")).toBe(true);
    expect(hazards.some(({ body }) => body.includes("expression execution"))).toBe(true);
    expect(hazards.some(({ body }) => body.includes("Kernel privilege"))).toBe(true);
    const applicationBody = hazards.find(({ body }) => body.includes("expression execution"))!.body;
    expect(applicationBody).toContain('"attemptCount":3');
    expect(applicationBody).toContain('"exactResetCount":2');
    expect(applicationBody).toContain('"operatorReportedAggregateResetMinimum":11');
    expect(applicationBody).toContain("harmless execution health probe");
    const proposals = database.prepare(`
      SELECT bundle_id, source_role, target_role, edge_type, materialized_edge_id
      FROM attack_knowledge_bundle_edges ORDER BY bundle_id, edge_key
    `).all() as Array<{
      bundle_id: string;
      source_role: string;
      target_role: string;
      edge_type: string;
      materialized_edge_id: string | null;
    }>;
    expect(proposals.length).toBeGreaterThan(30);
    expect(proposals.every(({ materialized_edge_id }) => materialized_edge_id === null)).toBe(true);
    expect(new Set(proposals.map(({ bundle_id }) => bundle_id)).size).toBe(2);
    expect(proposals.some((edge) => (
      edge.bundle_id === application.bundleId && edge.source_role === "product" &&
      edge.edge_type === "protected_by" && edge.target_role === "stack.3"
    ))).toBe(true);
    expect(proposals.some((edge) => (
      edge.bundle_id === application.bundleId && edge.source_role === "stack.3" &&
      edge.edge_type === "has_exact_version" && edge.target_role === "stack.3.version"
    ))).toBe(true);
    for (const bundleId of [application.bundleId!, kernel.bundleId!]) {
      const roles = (database.prepare(`
        SELECT role FROM attack_knowledge_bundle_candidates WHERE bundle_id = ? ORDER BY role
      `).all(bundleId) as Array<{ role: string }>).map(({ role }) => role);
      const graph = new Map<string, Set<string>>(roles.map((role) => [role, new Set()]));
      for (const edge of proposals.filter(({ bundle_id }) => bundle_id === bundleId)) {
        graph.get(edge.source_role)?.add(edge.target_role);
        graph.get(edge.target_role)?.add(edge.source_role);
      }
      const visited = new Set<string>(["hazard"]);
      const queue = ["hazard"];
      while (queue.length > 0) {
        const role = queue.shift()!;
        for (const neighbor of graph.get(role) ?? []) {
          if (visited.has(neighbor)) continue;
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
      expect([...visited].sort()).toEqual([...roles].sort());
    }
    expect(allCompilerText(database)).not.toMatch(/ReaperTwo|10\.129\.39\.191|\/root\/htb\/boxes/u);
  });

  test("is idempotent when the same source is compiled twice", () => {
    const { database, compiler } = setup();
    const first = compiler.compile(input());
    const countsBefore = compiler.reconcile();
    const second = compiler.compile(input());

    expect(second.bundleId).toBe(first.bundleId);
    expect(second.provenanceReceiptId).toBe(first.provenanceReceiptId);
    expect(second.candidatesCreated).toBe(0);
    expect(second.candidatesReused).toBe(first.candidateIds.length);
    expect(compiler.reconcile()).toEqual(countsBefore);
    expect(database.prepare(`
      SELECT occurrence_count FROM attack_knowledge_quarantine_records
    `).all()).toEqual([]);
  });

  test("resumes from a durable interrupted candidate checkpoint without duplicates", () => {
    const { database, compiler } = setup();
    expect(() => compiler.compile(input(), { interruptAfterCandidateWrites: 3 }))
      .toThrow(AttackKnowledgeCompilerInterruptedError);
    expect(compiler.reconcile()).toMatchObject({
      bundleCount: 1,
      receiptCount: 1,
      candidateRegistryCount: 3,
      interruptedRunCount: 1,
    });

    const resumed = compiler.compile(input());
    expect(resumed.status).toBe("staged");
    expect(resumed.candidatesReused).toBeGreaterThanOrEqual(3);
    expect(new Set(resumed.candidateIds).size).toBe(resumed.candidateIds.length);
    expect(compiler.reconcile()).toMatchObject({ interruptedRunCount: 0, orphanedCandidateLinks: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_candidates
    `).get()).toEqual({ count: resumed.candidateIds.length });
  });

  test("quarantines addresses, domains, paths, private labels, and secrets without retaining them", () => {
    const cases: AttackKnowledgeCompilerInput[] = [];
    const address = structuredClone(input());
    (address.knowledge as { hazard: { observedSymptom: string } }).hazard.observedSymptom = "Requests to 10.20.30.40 stop completing";
    cases.push(address);
    const domain = structuredClone(input());
    (domain.knowledge as { product: { name: string } }).product.name = "customer.internal";
    cases.push(domain);
    const publicTarget = structuredClone(input());
    (publicTarget.knowledge as { product: { name: string } }).product.name = "portal.example.com";
    cases.push(publicTarget);
    const path = structuredClone(input());
    (path.knowledge as unknown as { procedure: { orderedSteps: string[] } }).procedure.orderedSteps[0] = "Read /usr/local/bin/private-helper";
    cases.push(path);
    const label = structuredClone(input());
    (label.knowledge as { procedure: { name: string } }).procedure.name = "ReaperTwo diagnostic";
    cases.push(label);
    const secret = structuredClone(input());
    (secret.knowledge as unknown as { procedure: { orderedSteps: string[] } }).procedure.orderedSteps[0] = "Use password=SuperSecretValue123";
    cases.push(secret);

    for (const candidate of cases) {
      const { database, compiler } = setup();
      const result = compiler.compile(candidate);
      expect(result.status).toBe("quarantined");
      expect(result.candidateIds).toEqual([]);
      expect(result.reconciliation.candidateRegistryCount).toBe(0);
      const stored = allCompilerText(database);
      expect(stored).not.toMatch(/10\.20\.30\.40|customer\.internal|portal\.example\.com|ReaperTwo|SuperSecretValue123|\/usr\/local\/bin/u);
    }
  });

  test("quarantines missing or inconsistent corroborating evidence", () => {
    const { compiler } = setup();
    const missing = compiler.compile(input(applicationHangKnowledge(), { evidenceCount: 0 }));
    expect(missing.status).toBe("quarantined");
    expect(missing.reasonCategories).toContain("insufficient_evidence");

    const inconsistentInput = structuredClone(input());
    (inconsistentInput.knowledge as { corroboration: { exactProcedureEvidenceCount: number } })
      .corroboration.exactProcedureEvidenceCount = 1;
    const inconsistent = compiler.compile(inconsistentInput);
    expect(inconsistent.status).toBe("quarantined");
    expect(inconsistent.reasonCategories).toContain("inconsistent_corroboration");
    expect(compiler.reconcile()).toMatchObject({ bundleCount: 0, candidateRegistryCount: 0 });
  });

  test("quarantines topology roles from the versioned stack shape before semantic writes", () => {
    const { compiler } = setup();
    const unsupported = structuredClone(input());
    (unsupported.knowledge as unknown as { stack: Array<Record<string, string>> }).stack.push({
      nodeType: "topology_pattern",
      name: "Segmented application tier",
      exactVersion: "v1",
    });

    const result = compiler.compile(unsupported);
    expect(result.status).toBe("quarantined");
    expect(result.reasonCategories).toContain("unsupported_stack_type");
    expect(result.reconciliation).toMatchObject({
      bundleCount: 0,
      receiptCount: 0,
      candidateRegistryCount: 0,
      edgeProposalCount: 0,
      quarantineCount: 1,
    });
  });

  test("deduplicates reusable meaning across private sources while retaining only opaque source receipts", () => {
    const { database, compiler } = setup();
    const first = compiler.compile(input());
    const second = compiler.compile(input(applicationHangKnowledge(), {
      privateSourceReference: "/private/customer-two/engagement-note.json",
      privateLabels: ["CustomerTwo", "web-01"],
      sourceHash: "b".repeat(64),
      observedAt: "2026-07-21T15:00:00.000Z",
    }));

    expect(second.bundleId).toBe(first.bundleId);
    expect(second.provenanceReceiptId).not.toBe(first.provenanceReceiptId);
    expect(compiler.reconcile()).toMatchObject({ bundleCount: 1, receiptCount: 2, bundleReceiptCount: 2 });
    const stored = allCompilerText(database);
    expect(stored).not.toMatch(/customer-two|CustomerTwo|web-01|private\/customer/u);
    expect(stored).toContain("akpr_");
  });

  test("deduplicates the same source hash even when its private file path changes", () => {
    const { compiler } = setup();
    const first = compiler.compile(input());
    const moved = compiler.compile(input(applicationHangKnowledge(), {
      privateSourceReference: "/private/archive/moved-source-document.json",
    }));

    expect(moved.provenanceReceiptId).toBe(first.provenanceReceiptId);
    expect(moved.bundleId).toBe(first.bundleId);
    expect(moved.candidatesCreated).toBe(0);
    expect(compiler.reconcile()).toMatchObject({
      bundleCount: 1,
      receiptCount: 1,
      bundleReceiptCount: 1,
    });
  });

  test("stages a non-hazard reusable fact with zero procedure counts and no aggregate reset claim", () => {
    const { database, compiler } = setup();
    const result = compiler.compile({
      source: source({ sourceHash: "c".repeat(64) }),
      confidence: 0.91,
      knowledge: {
        kind: "reusable_fact",
        nodeType: "fingerprint_pattern",
        title: "Dual-source service version fingerprint",
        summary: "Confirm a reported service version through two independent observations.",
        body: "Prefer an active protocol response plus a separately parsed service banner.",
      },
    });

    expect(result).toMatchObject({
      status: "staged",
      candidatesCreated: 1,
      exactProcedureCounts: {
        attempts: 0,
        reproducibleOutcomes: 0,
        evidenceItems: 0,
        exactResets: 0,
        operatorReportedAggregateResetMinimum: null,
      },
    });
    expect(database.prepare(`
      SELECT status FROM memory_candidates WHERE id = ?
    `).get(result.candidateIds[0])).toEqual({ status: "pending" });
    expect(database.prepare(`
      SELECT operator_reported_reset_count_minimum AS value
      FROM attack_knowledge_bundles WHERE id = ?
    `).get(result.bundleId)).toEqual({ value: null });
  });

  test("stages one connected reusable bundle and rejects an invalid relationship endpoint", () => {
    const { database, compiler } = setup();
    const knowledge = {
      kind: "reusable_bundle" as const,
      facts: [
        {
          role: "product",
          nodeType: "technology_product" as const,
          title: "Apache HTTP Server",
          summary: "Reusable product identity.",
          body: '{"exactVersion":"2.4.49"}',
        },
        {
          role: "version",
          nodeType: "exact_version_fingerprint" as const,
          title: "Apache HTTP Server 2.4.49",
          summary: "Exact historical fingerprint requiring fresh corroboration.",
          body: '{"exactVersion":"2.4.49","product":"Apache HTTP Server"}',
        },
        {
          role: "vector",
          nodeType: "attack_vector" as const,
          title: "Path traversal",
          summary: "Reusable attack vector.",
        },
      ],
      edges: [
        { sourceRole: "product", edgeType: "has_exact_version" as const, targetRole: "version" },
        { sourceRole: "vector", edgeType: "applicable_to" as const, targetRole: "product" },
      ],
    };
    const staged = compiler.compile({
      source: source({ sourceHash: "d".repeat(64) }),
      confidence: 0.9,
      knowledge,
    });
    expect(staged).toMatchObject({ status: "staged", candidatesCreated: 3, edgeProposalsStaged: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges").get()).toEqual({ count: 2 });

    const invalid = compiler.compile({
      source: source({ sourceHash: "e".repeat(64) }),
      confidence: 0.9,
      knowledge: {
        ...knowledge,
        edges: [{ sourceRole: "product", edgeType: "exploits", targetRole: "version" }],
      },
    });
    expect(invalid.status).toBe("quarantined");
    expect(invalid.reasonCategories).toContain("invalid_reusable_bundle_edge");
  });

  test("keeps compiler IDs opaque when an operator later confirms a staged candidate", () => {
    const { database, compiler } = setup();
    const staged = compiler.compile(input());
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    const node = memory.confirmCandidate(staged.candidateIds[0]!, "operator-reviewer");

    expect(node.id).toMatch(/^mem_[0-9a-f-]{36}$/u);
    expect(node.id).not.toMatch(/Reaper|IIS|application|hazard|10\.129/u);
    expect(node.lifecycleStatus).toBe("confirmed");
    expect(node.confirmationState).toBe("confirmed");
  });
});
