import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { HistoricalAttackKnowledgeExtractionService } from "../HistoricalAttackKnowledgeExtractionService";
import { AttackKnowledgeEvidenceProvenanceGuard } from "../AttackKnowledgeEvidenceProvenanceGuard";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import type {
  LegacyEngagementFile,
  LegacyEngagementManifest,
} from "../LegacyEngagementDiscovery";
import { discoverLegacyEngagements } from "../LegacyEngagementDiscovery";

const HMAC_KEY = "historical-attack-extraction-test-key-more-than-32-bytes";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function setup(): { directory: string; database: SqliteDatabase; service: HistoricalAttackKnowledgeExtractionService } {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-attack-extraction-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "test.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  return {
    directory,
    database,
    service: new HistoricalAttackKnowledgeExtractionService(database, { receiptHmacKey: HMAC_KEY }),
  };
}

function contentMetadata(path: string): Pick<LegacyEngagementFile, "contentClass" | "mediaType"> {
  const extension = extname(path).toLowerCase();
  if ([".json", ".jsonl", ".xml", ".csv", ".yaml", ".yml", ".nmap", ".gnmap"].includes(extension)) {
    return { contentClass: "structured", mediaType: extension === ".json" ? "application/json" : "text/plain" };
  }
  return { contentClass: "text", mediaType: "text/plain" };
}

function manifest(
  root: string,
  engagementName: string,
  definitions: readonly Readonly<{
    relativePath: string;
    kind: LegacyEngagementFile["kind"];
    content: string | Uint8Array;
  }>[],
): LegacyEngagementManifest {
  const engagementDirectory = join(root, engagementName);
  const files = definitions.map((definition) => {
    const absolutePath = join(engagementDirectory, definition.relativePath);
    mkdirSync(join(absolutePath, ".."), { recursive: true });
    writeFileSync(absolutePath, definition.content);
    const state = statSync(absolutePath);
    const bytes = typeof definition.content === "string" ? Buffer.from(definition.content) : definition.content;
    return {
      absolutePath,
      relativePath: definition.relativePath,
      kind: definition.kind,
      ...contentMetadata(absolutePath),
      sha256: sha256(bytes),
      byteSize: bytes.byteLength,
      modifiedAt: state.mtime.toISOString(),
    } satisfies LegacyEngagementFile;
  });
  const engagementKey = sha256(`engagement\0${engagementName}`);
  return {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root,
    rootIdentity: "test-device:test-inode",
    engagementDirectory,
    engagementName,
    engagementKey,
    sha256: sha256(JSON.stringify(files.map(({ sha256: hash, byteSize, modifiedAt, kind }) => ({ hash, byteSize, modifiedAt, kind })))),
    byteSize: files.reduce((sum, file) => sum + file.byteSize, 0),
    modifiedAt: files.map(({ modifiedAt }) => modifiedAt).sort().at(-1) ?? new Date(0).toISOString(),
    files,
    quarantined: [],
  };
}

function candidateText(database: SqliteDatabase): string {
  const rows = database.prepare(`
    SELECT candidate_type, title, summary, body, proposed_scope, source_json, status
    FROM memory_candidates ORDER BY candidate_type, title
  `).all();
  return JSON.stringify(rows);
}

function candidateCount(database: SqliteDatabase): number {
  return Number((database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count);
}

function registerVerifiedReferenceInventory(
  database: SqliteDatabase,
  source: LegacyEngagementManifest,
): string {
  const metadata = new MigrationMetadataRepository(database);
  metadata.ensureSchema();
  const migration = metadata.createRun({
    sourceRoots: [source.root],
    databasePath: "test.sqlite",
    outputDirectory: "test-output",
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const rootState = statSync(source.engagementDirectory);
  const sourceId = metadata.registerSource(migration.id, {
    absolutePath: source.engagementDirectory,
    relativePath: source.engagementName,
    root: source.root,
    type: "engagement_manifest",
    sha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
  }, undefined, {
    retentionMode: "verified-reference",
    device: rootState.dev,
    inode: rootState.ino,
  });
  for (const file of source.files) {
    const state = statSync(file.absolutePath);
    metadata.registerSourceObject({
      migrationId: migration.id,
      sourceId,
      objectKey: `accepted:${file.relativePath}`,
      sourcePath: file.absolutePath,
      objectKind: "accepted",
      classification: file.kind,
      sourceSha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
      sourceDevice: state.dev,
      sourceInode: state.ino,
    });
  }
  return migration.id;
}

describe("HistoricalAttackKnowledgeExtractionService", () => {
  test("owns the verified-reference inventory schema in canonical migration 029", () => {
    const { database } = setup();
    expect(database.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name = 'legacy_migration_source_objects'
    `).get()).toEqual({ name: "legacy_migration_source_objects" });
    const before = Number(database.pragma("schema_version", { simple: true }));
    new MigrationMetadataRepository(database).ensureSchema();
    const after = Number(database.pragma("schema_version", { simple: true }));
    expect(after).toBe(before);
  });

  test("stages Apache version, CVE, script, procedure, and explicitly unclassified historical result candidates", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-box-name", [{
      relativePath: "scripts/traversal.py",
      kind: "script",
      content: [
        "# Apache HTTP Server/2.4.49; CVE-2021-41773; CWE-22",
        "# Path traversal using HTTP GET and double URL encoding.",
        "# Exact version match required. timeout=12 retries=0",
        "# The bounded validation worked once; a later attempt failed with a timeout.",
        "print('bounded local procedure')",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    expect(result).toMatchObject({ status: "completed", dryRun: false, filesParsed: 1, filesQuarantined: 0 });
    expect(result.compilerReconciliationPasses).toBe(1);
    expect(result.compilerRunsReconciled).toBe(result.compilerBundlesStaged);
    expect(result.compilerReconciliation).toMatchObject({
      bundleCount: result.compilerBundlesStaged,
      orphanedCandidateLinks: 0,
    });
    const compilerRunReconciliations = database.prepare(`
      SELECT reconciliation_json FROM attack_knowledge_compiler_runs ORDER BY id
    `).all() as Array<{ readonly reconciliation_json: string }>;
    expect(compilerRunReconciliations.map(({ reconciliation_json }) => JSON.parse(reconciliation_json)))
      .toEqual(Array.from(
        { length: result.compilerRunsReconciled },
        () => result.compilerReconciliation,
      ));
    expect(result.semanticFactsParsed).toBeGreaterThanOrEqual(10);
    const retained = candidateText(database);
    expect(retained).toContain("Apache HTTP Server 2.4.49");
    expect(retained).toContain("CVE-2021-41773");
    expect(retained).toContain("CWE-22");
    expect(retained).toContain("Path traversal procedure for Apache HTTP Server 2.4.49");
    expect(retained).toContain(`sha256:${source.files[0]!.sha256}`);
    expect(retained).toContain('\\"timeout\\":12');
    expect(retained).toContain('\\"retries\\":0');
    expect(retained).toContain(": reported successful result");
    expect(retained).toContain(": reported unsuccessful result");
    const historicalResults = database.prepare(`
      SELECT title, body FROM memory_candidates
      WHERE candidate_type = 'outcome' ORDER BY title
    `).all() as Array<{ title: string; body: string }>;
    expect(historicalResults).toHaveLength(2);
    expect(historicalResults.map(({ body }) => JSON.parse(body))).toEqual([
      expect.objectContaining({
        reportedStatus: "worked",
        outcomeClassification: "unclassified",
        classificationBasis: "historical_text_only",
      }),
      expect.objectContaining({
        reportedStatus: "failed",
        outcomeClassification: "unclassified",
        classificationBasis: "historical_text_only",
      }),
    ]);
    expect(historicalResults.every(({ body }) => !("status" in JSON.parse(body)))).toBeTrue();
    expect(retained).not.toContain("private-box-name");
    expect(retained).not.toContain(source.files[0]!.absolutePath);
    expect(database.prepare("SELECT COUNT(*) AS count FROM missions WHERE status != 'archived'").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT status, created_by FROM missions").get()).toEqual({
      status: "archived",
      created_by: "system:historical-attack-knowledge-import",
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    expect(result.sourceEvidenceCandidatesCreated).toBe(1);
    expect(result.sourceBundleLinks).toBeGreaterThan(0);
    expect(database.prepare("SELECT state, sensitivity FROM evidence_candidates").get()).toEqual({
      state: "candidate",
      sensitivity: "private",
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    const edges = Number((database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges").get() as { count: number }).count);
    expect(edges).toBeGreaterThanOrEqual(8);
    const bundle = database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles").get() as { sanitized_bundle_json: string };
    expect(JSON.parse(bundle.sanitized_bundle_json)).toMatchObject({ knowledge: { kind: "reusable_bundle" } });
  });

  test("captures hang, aggregate reset cost, recovery, and execution-path health semantics without false reset attribution", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "reaper-private-label", [{
      relativePath: "notes/recovery-summary.md",
      kind: "note",
      content: [
        "Microsoft-IIS/10.0 with ASP.NET 4.8 was tested for remote code execution.",
        "The application worker hung and timed out; the base page loads but is not enough to prove recovery.",
        "The environment was reset more than 10 times because retries left the execution path wedged.",
        "Recycle the application pool, require a harmless execution health probe, and confirm no previous request remains in flight before retry.",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    expect(result.filesParsed).toBe(1);
    const rows = database.prepare("SELECT candidate_type, title, summary, body FROM memory_candidates ORDER BY candidate_type, title").all() as Array<Record<string, string>>;
    expect(rows.some((row) => row.candidate_type === "operational_hazard")).toBeTrue();
    expect(rows.some((row) => row.candidate_type === "recovery_pattern" && row.title === "Application worker recycle")).toBeTrue();
    expect(rows.some((row) => row.candidate_type === "health_check" && row.title === "Base-page liveness is insufficient")).toBeTrue();
    const aggregate = rows.find((row) => row.candidate_type === "attack_lesson");
    expect(aggregate?.body).toContain('"operatorReportedRecoveryCountMinimum":11');
    expect(aggregate?.body).toContain('"attribution":"aggregate_only"');
    expect(candidateText(database)).not.toContain("reaper-private-label");
  });

  test("does not bind CVEs, runtimes, or scripts to an unversioned scheduler component by co-occurrence", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-component-scope", [{
      relativePath: "scripts/scheduler-review.sh",
      kind: "script",
      content: [
        "# A cron scheduler invoked this bounded helper.",
        "# CVE-2024-0517 and V8 JavaScript engine 12.2 were reviewed in a separate section.",
        "# Remote code execution was not reproduced.",
        "exit 0",
      ].join("\n"),
    }]);

    service.extract(source);
    const bundles = database.prepare(`
      SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id
    `).all() as Array<{ sanitized_bundle_json: string }>;
    const pairs = bundles.flatMap(({ sanitized_bundle_json }) => {
      const knowledge = (JSON.parse(sanitized_bundle_json) as {
        knowledge: {
          facts?: Array<{ role: string; title: string }>;
          edges?: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
        };
      }).knowledge;
      const titleByRole = new Map((knowledge.facts ?? []).map((item) => [item.role, item.title]));
      return (knowledge.edges ?? []).map(({ sourceRole, edgeType, targetRole }) =>
        `${titleByRole.get(sourceRole)} --${edgeType}--> ${titleByRole.get(targetRole)}`);
    });
    expect(candidateText(database)).toContain("Cron scheduler");
    expect(pairs.some((pair) => pair.includes("Cron scheduler"))).toBeFalse();
  });

  test("does not retain a standalone historical script hash without a typed reusable relationship", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-toolbox", [{
      relativePath: "scripts/unattributed-helper.py",
      kind: "script",
      content: [
        "#!/usr/bin/env python3",
        "# General helper retained in an operator toolbox.",
        "print('local helper')",
      ].join("\n"),
    }]);

    const result = service.extract(source);

    expect(result).toMatchObject({
      filesParsed: 0,
      filesSkipped: 1,
      semanticFactsParsed: 0,
      compilerBundlesStaged: 0,
    });
    expect(candidateText(database)).not.toContain(
      `Python procedure artifact ${source.files[0]!.sha256.slice(0, 16)}`,
    );
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM attack_knowledge_bundles",
    ).get()).toEqual({ count: 0 });
  });

  test("extracts the reviewed kernel and shared-worker attack graph with distinct OS and kernel versions", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "ReaperTwo", [{
      relativePath: "reports/attack-knowledge.md",
      kind: "report",
      content: [
        "# Private provenance",
        "Autonomous mission for ReaperTwo used target 10.129.39.191 and a private source path.",
        "# Technology stack",
        "Microsoft-IIS/10.0 hosted ASP.NET 4.8 with V8 d8 12.2.0 on Windows Server 2022 Build 20348.4171.",
        "ntoskrnl.exe FileVersion 10.0.20348.4163 was the exact Windows kernel image.",
        "A custom signed kernel driver exposed an arbitrary callback and READ_MSR using METHOD_NEITHER raw pointers.",
        "Unauthenticated JavaScript evaluation executed with debug switches enabled.",
        "# Native foothold",
        "V8 d8 12.2.0 Harmony Set type confusion produced AAR/AAW and a WASM native code foothold; the bounded procedure succeeded.",
        "# Failed kernel return",
        "Windows kernel image 10.0.20348.4163 RDX-relative return epilogue failed and hung after KeSetPriorityThread clobbered RDX.",
        "The user metadata was SMAP-unsafe and the attempt reused a hard-pinned LSTAR value. Never retry this unresolved one-shot procedure.",
        "# Successful kernel elevation",
        "Windows kernel image 10.0.20348.4163 used an arbitrary callback, RDMSR IA32_LSTAR for the live KASLR kernel base, PTE U/S permission change, token stealing, and TrapFrame swapgs sysretq; it succeeded and obtained SYSTEM.",
        "# Shared execution worker and recovery",
        "ASP.NET writes each web request to shared input file data.js; an external d8 execution consumer writes shared result file data.txt while the request waits synchronously.",
        "There is no request ID and no file lock, so a stale previous result returned false-fast while new work remained in flight and the execution worker hung until timeout.",
        "HTTP GET works and returns 200 but does not prove execution health; require a harmless POST print(1) execution probe with the expected result.",
        "Wait beyond the execution timeout to drain in-flight work, recycle the application pool if it remains unhealthy, and never refire the retired one-shot package.",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    expect(result).toMatchObject({ filesParsed: 1, filesQuarantined: 0, compilerBundlesStaged: 1 });
    const rows = database.prepare(`
      SELECT candidate_type, title, summary, body, status
      FROM memory_candidates ORDER BY candidate_type, title
    `).all() as Array<Record<string, string>>;
    const byTitle = new Map(rows.map((row) => [row.title, row]));
    expect(byTitle.get("Windows Server")?.body).toContain('"exactVersion":"2022 Build 20348.4171"');
    expect(byTitle.get("Windows Server")?.body).toContain('"versionRole":"operating_system_release"');
    expect(byTitle.get("Windows kernel image")?.body).toContain('"exactVersion":"10.0.20348.4163"');
    expect(byTitle.get("Windows kernel image")?.body).toContain('"versionRole":"kernel_image"');
    expect(byTitle.get("V8 JavaScript engine")?.body).toContain('"exactVersion":"12.2.0"');
    expect(byTitle.has("Custom kernel callback driver")).toBeTrue();
    expect(byTitle.has("Harmony Set type confusion to WASM native foothold")).toBeTrue();
    expect(byTitle.has("Live-LSTAR kernel callback token elevation")).toBeTrue();
    expect(byTitle.has("RDX-relative kernel return attempt")).toBeTrue();
    expect(byTitle.has("Kernel return-register corruption")).toBeTrue();
    expect(byTitle.has("User metadata was unsafe under SMAP")).toBeTrue();
    expect(byTitle.has("Synchronous shared-file execution pipeline")).toBeTrue();
    expect(byTitle.has("Shared state lacks per-request correlation")).toBeTrue();
    expect(byTitle.has("HTTP GET liveness is insufficient")).toBeTrue();
    expect(byTitle.has("Harmless POST execution probe")).toBeTrue();
    expect(byTitle.has("Execution-timeout drain")).toBeTrue();
    expect(byTitle.has("Retire the unresolved one-shot procedure")).toBeTrue();
    expect(rows.every((row) => row.status === "pending")).toBeTrue();

    const edgeTypes = (database.prepare(`
      SELECT edge_type FROM attack_knowledge_bundle_edges ORDER BY edge_type
    `).all() as Array<{ edge_type: string }>).map(({ edge_type }) => edge_type);
    expect(edgeTypes).toEqual(expect.arrayContaining([
      "has_exact_version", "tested_against", "produces_outcome", "failed_because",
      "has_topology_role", "has_attribute", "caused", "avoid_after", "safe_when",
      "requires_recovery", "mitigated_by",
    ]));
    const retained = candidateText(database);
    expect(retained).not.toContain("ReaperTwo");
    expect(retained).not.toContain("10.129.39.191");
    expect(retained).not.toContain("Autonomous");
    expect(retained).not.toContain(source.files[0]!.absolutePath);
  });

  test("rejects IPv4-shaped product versions and contradictory Windows builds while retaining valid fingerprints", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-version-quality", [{
      relativePath: "reports/version-review.md",
      kind: "report",
      content: [
        "# Ambiguous numeric locator",
        "ASP.NET 100.92.5.83 appeared beside an operational endpoint and must not become a reusable version.",
        "# Exact engine fingerprint",
        "V8 JavaScript engine 12.2.281.1 was independently confirmed from local binary metadata.",
        "# Contradictory operating-system label",
        "Windows Server 2016 Build 20348 was copied from an inconsistent historical note.",
        "# Consistent operating-system build",
        "Windows Server 2022 Build 20348.4171 was corroborated by local system metadata.",
        "# Release-only observation",
        "Windows Server 2019 was observed without a build claim.",
      ].join("\n"),
    }]);

    service.extract(source);
    const retained = candidateText(database);
    expect(retained).not.toContain("100.92.5.83");
    expect(retained).not.toContain("100.92.5 build 83");
    expect(retained).toContain("V8 JavaScript engine 12.2.281.1");
    expect(retained).not.toContain("2016 Build 20348");
    expect(retained).toContain("2022 Build 20348.4171");
    expect(retained).toContain('\\"exactVersion\\":\\"2019\\"');
  });

  test("keeps Markdown blocks independent and never binds identity-path techniques to incidental product versions", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-semantic-scope", [{
      relativePath: "reports/mixed-review.md",
      kind: "report",
      content: [
        "# Runtime and identity review",
        "V8 JavaScript engine 12.2.281.1 was confirmed from local binary metadata.",
        "",
        "SQL injection was considered in a separate application note and was not reproduced.",
        "",
        "V8 JavaScript engine 12.2.281.1 and NTLM relay were mentioned together in an inventory summary; lateral movement was not attempted.",
      ].join("\n"),
    }]);

    service.extract(source);
    const raw = database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles").get() as { sanitized_bundle_json: string };
    const knowledge = (JSON.parse(raw.sanitized_bundle_json) as {
      knowledge: {
        facts: Array<{ role: string; nodeType: string; title: string }>;
        edges: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
      };
    }).knowledge;
    const titleByRole = new Map(knowledge.facts.map((item) => [item.role, item.title]));
    expect(knowledge.facts.some(({ nodeType, title }) =>
      nodeType === "attack_technique" && title === "NTLM relay")).toBeTrue();
    expect(knowledge.facts.some(({ nodeType, title }) =>
      nodeType === "attack_technique" && title === "Lateral movement")).toBeTrue();
    expect(knowledge.facts.some(({ nodeType, title }) =>
      nodeType === "attack_procedure" && (
        title.startsWith("NTLM relay procedure for") ||
        title.startsWith("Lateral movement procedure for") ||
        title.startsWith("SQL injection procedure for V8 JavaScript engine")
      ))).toBeFalse();
    expect(knowledge.edges.some(({ sourceRole, edgeType, targetRole }) =>
      ["applicable_to", "tested_against"].includes(edgeType) &&
      ["NTLM relay", "Lateral movement"].includes(titleByRole.get(sourceRole) ?? "") &&
      titleByRole.get(targetRole) === "V8 JavaScript engine")).toBeFalse();
  });

  test("links a procedure only to attack concepts explicitly present in the same semantic scope", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-procedure-scope", [{
      relativePath: "reports/runtime-procedure.md",
      kind: "report",
      content: [
        "V8 JavaScript engine 12.2.0 Harmony Set type confusion produced AAR/AAW and a WASM native execution foothold; the bounded procedure succeeded.",
        "",
        "NTLM relay and lateral movement were explicitly excluded in a separate identity review.",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    const bundles = database.prepare(`
      SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id
    `).all() as Array<{ sanitized_bundle_json: string }>;
    const relationships = bundles.flatMap(({ sanitized_bundle_json }) => {
      const knowledge = (JSON.parse(sanitized_bundle_json) as {
        knowledge: {
          facts?: Array<{ role: string; title: string }>;
          edges?: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
        };
      }).knowledge;
      const titles = new Map((knowledge.facts ?? []).map(({ role, title }) => [role, title]));
      return (knowledge.edges ?? []).map(({ sourceRole, edgeType, targetRole }) => ({
        source: titles.get(sourceRole),
        edgeType,
        target: titles.get(targetRole),
      }));
    });
    const classifications = relationships.filter(({ edgeType }) => edgeType === "classified_as");
    expect(classifications).toEqual(expect.arrayContaining([
      {
        source: "Harmony Set type confusion to WASM native foothold",
        edgeType: "classified_as",
        target: "Harmony Set type confusion",
      },
      {
        source: "Harmony Set type confusion to WASM native foothold",
        edgeType: "classified_as",
        target: "Arbitrary read/write primitive",
      },
      {
        source: "Harmony Set type confusion to WASM native foothold",
        edgeType: "classified_as",
        target: "WASM native-code foothold",
      },
    ]));
    expect(classifications.some(({ target }) => ["NTLM relay", "Lateral movement"].includes(target ?? ""))).toBeFalse();
    expect(result.edgeSourceEvidenceCandidateIds.classified_as).toHaveLength(1);
    expect(result.edgeSourceEvidenceCandidateIds.classified_as?.[0]).toMatch(/^candidate_hak_source_[a-f0-9]{48}$/u);
    const retained = candidateText(database);
    expect(retained).not.toContain("private-procedure-scope");
    expect(retained).not.toContain(source.files[0]!.absolutePath);
  });

  test("binds a script to one explicitly named runtime fingerprint without guessing across products", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-script-runtime", [{
      relativePath: "scripts/offline_decoder.py",
      kind: "script",
      content: [
        "# Offline decoder for V8 JavaScript engine 12.2.0.",
        "print('local deterministic decoder')",
      ].join("\n"),
    }]);

    service.extract(source);
    const raw = database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles").get() as { sanitized_bundle_json: string };
    const knowledge = (JSON.parse(raw.sanitized_bundle_json) as {
      knowledge: {
        facts: Array<{ role: string; title: string }>;
        edges: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
      };
    }).knowledge;
    const titleByRole = new Map(knowledge.facts.map(({ role, title }) => [role, title]));
    const scriptTargets = knowledge.edges
      .filter(({ sourceRole, edgeType }) =>
        edgeType === "tested_against" &&
        titleByRole.get(sourceRole)?.startsWith("Python procedure artifact "))
      .map(({ targetRole }) => titleByRole.get(targetRole));
    expect(scriptTargets).toEqual(expect.arrayContaining([
      "V8 JavaScript engine",
      "V8 JavaScript engine 12.2.0",
    ]));
    expect(scriptTargets).toHaveLength(2);
  });

  test("reconstructs a hash-bound live-layout ROP procedure instead of leaving its script artifact isolated", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-layout-engagement", [{
      relativePath: "scripts/private-ready-after-reset.sh",
      kind: "script",
      content: [
        "#!/bin/sh",
        "# After reset, refresh the live layout and do not reuse stale values.",
        "runner --dump-layout --timeout 60",
        "runner --mode rop_ll --map \"$MAP\" --elems \"$ELEMS\" --timeout 60",
        "# The bounded attempt timed out; reset the disposable environment before another attempt.",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    expect(result).toMatchObject({ filesParsed: 1, filesQuarantined: 0 });
    const bundles = database.prepare(`
      SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id
    `).all() as Array<{ readonly sanitized_bundle_json: string }>;
    const relationships = bundles.flatMap(({ sanitized_bundle_json }) => {
      const knowledge = (JSON.parse(sanitized_bundle_json) as {
        readonly knowledge: {
          readonly facts?: readonly { role: string; title: string }[];
          readonly edges?: readonly { sourceRole: string; edgeType: string; targetRole: string }[];
        };
      }).knowledge;
      const titleByRole = new Map((knowledge.facts ?? []).map(({ role, title }) => [role, title]));
      return (knowledge.edges ?? []).map(({ sourceRole, edgeType, targetRole }) => ({
        source: titleByRole.get(sourceRole),
        edgeType,
        target: titleByRole.get(targetRole),
      }));
    });
    const scriptTitle = `Shell procedure artifact ${source.files[0]!.sha256.slice(0, 16)}`;
    expect(relationships).toEqual(expect.arrayContaining([
      {
        source: "Live-layout refresh before bounded return-oriented execution",
        edgeType: "classified_as",
        target: "Return-oriented programming",
      },
      {
        source: "Live-layout refresh before bounded return-oriented execution",
        edgeType: "implemented_by",
        target: scriptTitle,
      },
      {
        source: scriptTitle,
        edgeType: "produces_outcome",
        target: "Live-layout refresh before bounded return-oriented execution: reported unsuccessful result",
      },
      {
        source: "Live-layout refresh before bounded return-oriented execution: reported unsuccessful result",
        edgeType: "failed_because",
        target: "Execution timeout",
      },
      {
        source: "Execution timeout",
        edgeType: "recovered_with",
        target: "Disposable environment reset",
      },
    ]));
    const retained = candidateText(database);
    expect(retained).not.toContain("private-layout-engagement");
    expect(retained).not.toContain(source.files[0]!.absolutePath);
    expect(retained).not.toContain("private-ready-after-reset.sh");
  });

  test("does not fabricate cross-engagement relationships when reusable facts are deduplicated", () => {
    const { directory, database, service } = setup();
    const runtime = manifest(directory, "private-runtime-engagement", [{
      relativePath: "reports/runtime.md",
      kind: "report",
      content: "V8 JavaScript engine 12.2.0 Harmony Set type confusion produced AAR/AAW and a WASM native execution foothold.",
    }]);
    const identity = manifest(directory, "private-identity-engagement", [{
      relativePath: "reports/identity.md",
      kind: "report",
      content: "nginx 1.24 was recorded from a server header. NTLM relay was not attempted.",
    }]);

    service.extract(runtime);
    service.extract(identity);
    const bundles = database.prepare(`
      SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id
    `).all() as Array<{ sanitized_bundle_json: string }>;
    for (const { sanitized_bundle_json } of bundles) {
      expect(sanitized_bundle_json).not.toContain("private-runtime-engagement");
      expect(sanitized_bundle_json).not.toContain("private-identity-engagement");
      expect(sanitized_bundle_json).not.toContain(runtime.files[0]!.absolutePath);
      expect(sanitized_bundle_json).not.toContain(identity.files[0]!.absolutePath);
      const knowledge = (JSON.parse(sanitized_bundle_json) as {
        knowledge: {
          facts?: Array<{ role: string; title: string }>;
          edges?: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
        };
      }).knowledge;
      const titles = new Map((knowledge.facts ?? []).map(({ role, title }) => [role, title]));
      expect((knowledge.edges ?? []).some(({ sourceRole, targetRole }) => {
        const endpoints = [titles.get(sourceRole), titles.get(targetRole)];
        return endpoints.includes("NTLM relay") && endpoints.some((title) => title?.includes("Harmony Set"));
      })).toBeFalse();
    }
  });

  test("covers the five reviewed cross-stack procedure families without operational identifiers", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-cross-stack-history", [
      {
        relativePath: "reports/freepbx.md",
        kind: "report",
        content: [
          "# Traversal",
          "FreePBX Administration 16.0.40.7 encoded path normalization enabled path traversal and configuration disclosure; the bounded read worked.",
          "# Safe advisory check",
          "FreePBX 16.0.40.7 CVE-2025-57819 detection-only timing validator reported not vulnerable; no intrusive procedure was executed.",
        ].join("\n"),
      },
      {
        relativePath: "reports/linux-web.md",
        kind: "report",
        content: [
          "# Upload boundary",
          "Apache HTTP Server/2.4.52 accepted a multipart filename traversal into a cron-polled script directory and scheduled Python execution worked.",
          "# Environment inheritance",
          "needrestart 3.5 CVE-2024-48990 inherited PYTHONPATH and loaded sitecustomize.py from a real script file; privilege escalation succeeded.",
          "# Failed forms",
          "needrestart 3.5 failed when the selected path was blacklisted, and python3 -c was skipped by the trigger.",
        ].join("\n"),
      },
      {
        relativePath: "reports/php.md",
        kind: "report",
        content: [
          "# CGI validation",
          "PHP 8.2.12 CVE-2024-4577 CGI soft hyphen argument injection was not reproduced under the observed runtime configuration.",
          "# Archive validation",
          "PHP 8.2.12 ZIP-slip archive traversal upload was accepted but no reachable execution path was validated.",
        ].join("\n"),
      },
      {
        relativePath: "reports/checkmk.md",
        kind: "report",
        content: [
          "# Context failure",
          "Checkmk Agent 2.1.0p10 predictable temp cmk_all_ command pre-seed failed because the trigger context used the wrong principal.",
          "# Privileged trigger",
          "Checkmk Agent 2.1.0p10 predictable temporary command pre-seed was consumed by MSI repair under SYSTEM and execution succeeded; MSI exit code 1603 did not negate payload execution.",
        ].join("\n"),
      },
      {
        relativePath: "reports/samba.md",
        kind: "report",
        content: [
          "# Print boundary",
          "Samba 4.15.13 CVE-2026-4480 printer spoolss document-name command injection produced low-privilege execution and worked.",
          "# Identity-boundary write",
          "Samba 4.15.13 wide links=yes with force user and a symlink enabled a file write across the identity boundary; it succeeded.",
          "# Service activation",
          "A writable systemd service drop-in was restarted to create a SUID root helper; privilege escalation succeeded.",
        ].join("\n"),
      },
    ]);

    const result = service.extract(source);
    expect(result).toMatchObject({ filesParsed: 5, filesQuarantined: 0 });
    const retained = candidateText(database);
    [
      "Checkmk Agent 2.1.0p10",
      "needrestart 3.5",
      "Encoded path-normalization traversal",
      "Multipart filename traversal to scheduled execution",
      "Python environment inheritance privilege escalation",
      "PHP CGI argument-injection validation",
      "Archive traversal to execution-path validation",
      "Predictable temporary-command pre-seeding",
      "Printer spool job-name command injection",
      "Samba symlink-mediated identity write",
      "Writable service drop-in privilege escalation",
      "Cron scheduler",
      "systemd service manager",
      "Maintenance trigger-context mismatch",
      "Process exit code is not authoritative attack evidence",
    ].forEach((expected) => expect(retained).toContain(expected));
    expect(retained).not.toContain("FreePBX 16.0.40.7");
    expect(retained).not.toContain("FreePBX 16.0.40 build 7");
    expect(retained).not.toContain(source.engagementName);
    expect(retained).not.toMatch(/\b(?:10\.\d+\.\d+\.\d+|Autonomous|Guided)\b/u);
  });

  test("scopes success and failure to their own procedure sections instead of selecting an arbitrary primary", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-multi-path", [{
      relativePath: "reports/two-paths.md",
      kind: "report",
      content: [
        "# Successful traversal",
        "FreePBX 16.0.40.7 encoded path normalization path traversal worked and disclosed configuration.",
        "# Failed maintenance trigger",
        "Checkmk Agent 2.1.0p10 predictable temporary command pre-seed failed because the trigger context used the wrong principal.",
      ].join("\n"),
    }]);
    service.extract(source);

    const raw = database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles").get() as { sanitized_bundle_json: string };
    const knowledge = (JSON.parse(raw.sanitized_bundle_json) as {
      knowledge: {
        facts: Array<{ role: string; title: string }>;
        edges: Array<{ sourceRole: string; edgeType: string; targetRole: string }>;
      };
    }).knowledge;
    const titleByRole = new Map(knowledge.facts.map((item) => [item.role, item.title]));
    const outcomePairs = knowledge.edges
      .filter(({ edgeType }) => edgeType === "produces_outcome")
      .map(({ sourceRole, targetRole }) => `${titleByRole.get(sourceRole)} -> ${titleByRole.get(targetRole)}`);
    expect(outcomePairs).toContain(
      "Encoded path-normalization traversal -> Encoded path-normalization traversal: reported successful result",
    );
    expect(outcomePairs).toContain(
      "Predictable temporary-command pre-seeding -> Predictable temporary-command pre-seeding on Checkmk Agent 2.1.0p10: reported unsuccessful result",
    );
    expect(outcomePairs.some((pair) => pair.includes("Encoded path-normalization traversal") && pair.includes("Checkmk Agent"))).toBeFalse();
    expect(outcomePairs.some((pair) => pair.includes("Predictable temporary-command pre-seeding") && pair.includes("FreePBX"))).toBeFalse();
  });

  test("deduplicates reusable facts across private engagements while retaining separate opaque receipts", () => {
    const { directory, database, service } = setup();
    const content = "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 via Nmap service scan.";
    const first = manifest(directory, "customer-one", [{ relativePath: "notes/summary.md", kind: "note", content }]);
    const second = manifest(directory, "customer-two", [{ relativePath: "reports/summary.md", kind: "report", content }]);
    const firstResult = service.extract(first);
    const countAfterFirst = candidateCount(database);
    const secondResult = service.extract(second);

    expect(firstResult.candidatesCreated).toBeGreaterThan(0);
    expect(firstResult.sourceEvidenceCandidatesCreated).toBe(1);
    expect(secondResult.candidatesCreated).toBe(0);
    expect(secondResult.candidatesReused).toBe(secondResult.semanticFactsParsed);
    expect(secondResult.sourceEvidenceCandidatesCreated).toBe(0);
    expect(secondResult.sourceEvidenceCandidatesReused).toBe(1);
    expect(candidateCount(database)).toBe(countAfterFirst);
    expect(Number((database.prepare(
      "SELECT COUNT(*) AS count FROM historical_attack_knowledge_source_candidates",
    ).get() as { count: number }).count)).toBe(1);
    expect(Number((database.prepare(
      "SELECT COUNT(*) AS count FROM historical_attack_knowledge_source_occurrences",
    ).get() as { count: number }).count)).toBe(2);
    const receipts = Number((database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts").get() as { count: number }).count);
    expect(receipts).toBe(2);
    expect(candidateText(database)).not.toContain("customer-one");
    expect(candidateText(database)).not.toContain("customer-two");
  });

  test("strips operational identity by construction and quarantines malformed or secret-bearing sources", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "UltraPrivateBox", [
      {
        relativePath: "notes/semantic-summary.md",
        kind: "note",
        content: "Autonomous mission for UltraPrivateBox at 10.129.39.191 observed nginx 1.24 and SQL injection failed with timeout.",
      },
      {
        relativePath: "notes/secret-summary.md",
        kind: "note",
        content: "Apache HTTP Server/2.4.49 API_KEY=sk-secret-material-1234567890 path traversal",
      },
      {
        relativePath: "reports/malformed.json",
        kind: "report",
        content: "{ not valid json",
      },
      {
        relativePath: "logs/raw.log",
        kind: "log",
        content: "nginx 1.24 raw stdout command stream",
      },
    ]);

    const result = service.extract(source);
    expect(result.filesParsed).toBe(1);
    expect(result.filesQuarantined).toBe(2);
    expect(result.filesSkipped).toBe(1);
    expect(result.issues.map(({ reason }) => reason)).toEqual(expect.arrayContaining([
      "secret_bearing_source", "malformed_text", "raw_log_not_summary",
    ]));
    const retained = candidateText(database);
    expect(retained).toContain("nginx 1.24");
    expect(retained).not.toContain("UltraPrivateBox");
    expect(retained).not.toContain("10.129.39.191");
    expect(retained).not.toContain("Autonomous");
    expect(retained).not.toContain("sk-secret");
    expect(JSON.stringify(result)).not.toContain(source.files[0]!.absolutePath);
  });

  test("extracts independent NEXT_ACTIONS sections while quarantining a secret-bearing section", () => {
    const { directory, database, service } = setup();
    const sensitiveValue = ["synthetic", "credential", "material"].join("-");
    const source = manifest(directory, "private-next-actions", [{
      relativePath: "notes/NEXT_ACTIONS.md",
      kind: "note",
      content: [
        "# Current action review",
        "",
        "## Versioned application path",
        "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed with a timeout.",
        "Reset the service and require a health check before retry.",
        "",
        "## Operator-only access material",
        `Apache HTTP Server/2.4.50 SQL injection worked; password=${sensitiveValue}`,
        "",
        "## Independently reviewed alternative",
        "nginx 1.24 command injection worked after a service recycle.",
      ].join("\n"),
    }]);

    const result = service.extract(source);
    expect(result).toMatchObject({ filesParsed: 1, filesQuarantined: 0 });
    expect(result.issues).toContainEqual(expect.objectContaining({
      disposition: "quarantined",
      reason: "secret_bearing_segment",
      count: 1,
    }));
    const retained = candidateText(database);
    expect(retained).toContain("Apache HTTP Server 2.4.49");
    expect(retained).toContain("CVE-2021-41773");
    expect(retained).toContain("nginx 1.24");
    expect(retained).not.toContain("2.4.50");
    expect(retained).not.toContain(sensitiveValue);
    expect(JSON.stringify(result)).not.toContain(sensitiveValue);
    expect(result.sourceEvidenceCandidatesCreated).toBe(1);
    expect(result.sourceBundleLinks).toBe(2);
    const receiptHashes = (database.prepare(`
      SELECT source_hash FROM attack_knowledge_provenance_receipts ORDER BY source_hash
    `).all() as Array<{ source_hash: string }>).map(({ source_hash }) => source_hash);
    expect(receiptHashes).toHaveLength(2);
    expect(new Set(receiptHashes).size).toBe(2);
    expect(receiptHashes.every((value) => /^[a-f0-9]{64}$/u.test(value))).toBeTrue();
  });

  test("isolates council list items so secret and outcome text cannot cross-associate", () => {
    const { directory, database, service } = setup();
    const sensitiveValue = ["synthetic", "session", "material"].join("-");
    const source = manifest(directory, "private-council", [{
      relativePath: "council/review.md",
      kind: "note",
      content: [
        "# Council review",
        "",
        "- Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed with timeout.",
        `- access_token=${sensitiveValue}`,
        "- nginx 1.24 SQL injection worked after a bounded health check.",
      ].join("\n"),
    }]);

    const first = service.extract(source);
    const retained = candidateText(database);
    expect(first).toMatchObject({ filesParsed: 1, filesQuarantined: 0 });
    expect(first.issues).toContainEqual(expect.objectContaining({
      reason: "secret_bearing_segment",
      count: 1,
    }));
    expect(retained).toContain("Path traversal procedure for Apache HTTP Server 2.4.49 on Apache HTTP Server 2.4.49: reported unsuccessful result");
    expect(retained).not.toContain("Path traversal procedure for Apache HTTP Server 2.4.49 on Apache HTTP Server 2.4.49: reported successful result");
    expect(retained).toContain("SQL injection procedure for nginx 1.24 on nginx 1.24: reported successful result");
    expect(retained).not.toContain(sensitiveValue);

    const candidateTotal = candidateCount(database);
    const receiptTotal = Number((database.prepare(
      "SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts",
    ).get() as { count: number }).count);
    const replay = service.extract(source);
    expect(replay.candidatesCreated).toBe(0);
    expect(candidateCount(database)).toBe(candidateTotal);
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts",
    ).get()).toEqual({ count: receiptTotal });
  });

  test("recovers safe Markdown blocks from discovery quarantine without admitting the source itself", async () => {
    const { directory, database, service } = setup();
    const engagementDirectory = join(directory, "mixed-history");
    const sourcePath = join(engagementDirectory, "notes", "NEXT_ACTIONS.md");
    const sensitiveValue = ["synthetic", "operator", "material"].join("-");
    mkdirSync(join(sourcePath, ".."), { recursive: true });
    writeFileSync(sourcePath, [
      "# Review",
      "",
      "## Reusable result",
      "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed with timeout.",
      "",
      "## Private material",
      `password=${sensitiveValue}`,
    ].join("\n"));

    const discovery = await discoverLegacyEngagements([directory]);
    const discovered = discovery.manifests.find(({ engagementName }) => engagementName === "mixed-history");
    expect(discovered).toBeDefined();
    expect(discovered!.files).toHaveLength(0);
    expect(discovered!.quarantined).toHaveLength(1);
    expect(discovered!.quarantined[0]).toMatchObject({
      category: "sensitive_content",
      sourceKind: "regular_file",
    });

    const result = service.extract(discovered!);
    expect(result).toMatchObject({ filesDiscovered: 1, filesParsed: 1, filesQuarantined: 0 });
    expect(result.issues).toContainEqual(expect.objectContaining({
      reason: "secret_bearing_segment",
      count: 1,
    }));
    const retained = candidateText(database);
    expect(retained).toContain("Apache HTTP Server 2.4.49");
    expect(retained).toContain("CVE-2021-41773");
    expect(retained).not.toContain(sensitiveValue);
    expect(JSON.stringify(result)).not.toContain(sourcePath);
  });

  test("supports bounded cursor resume and whole-manifest idempotent replay", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-history", [
      { relativePath: "notes/apache-summary.md", kind: "note", content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773." },
      { relativePath: "notes/kernel-summary.md", kind: "note", content: "Linux kernel 6.1.0 privilege escalation failed with a hang; reset and health check before retry." },
    ]);

    const first = service.extract(source, { maxFilesThisRun: 1 });
    expect(first.status).toBe("partial");
    expect(first.nextResumeAfterSourceKey).toMatch(/^[a-f0-9]{64}$/u);
    const second = service.extract(source, { resumeAfterSourceKey: first.nextResumeAfterSourceKey });
    expect(second.status).toBe("completed");
    const count = candidateCount(database);
    const replay = service.extract(source);
    expect(replay.status).toBe("completed");
    expect(replay.candidatesCreated).toBe(0);
    expect(candidateCount(database)).toBe(count);
  });

  test("leaves a cumulative-byte-budget boundary file for the next resume batch", () => {
    const { directory, database } = setup();
    const service = new HistoricalAttackKnowledgeExtractionService(database, {
      receiptHmacKey: HMAC_KEY,
      maxTotalBytes: 100,
    });
    const source = manifest(directory, "private-byte-budget", [
      {
        relativePath: "notes/apache.md",
        kind: "note",
        content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773.".padEnd(100, " "),
      },
      {
        relativePath: "notes/nginx.md",
        kind: "note",
        content: "nginx 1.24 SQL injection CVE-2024-12345 failed with timeout.".padEnd(100, " "),
      },
    ]);

    const first = service.extract(source);
    expect(first).toMatchObject({ status: "partial", filesParsed: 1, filesSkipped: 0 });
    const second = service.extract(source, { resumeAfterSourceKey: first.nextResumeAfterSourceKey });
    expect(second).toMatchObject({ status: "completed", filesParsed: 1, filesSkipped: 0 });
    expect([...first.issues, ...second.issues].some(({ reason }) => reason === "total_budget_exceeded")).toBeFalse();
  });

  test("makes every file beyond the 2,000-file batch boundary reachable by cursor resume", () => {
    const { directory, service } = setup();
    const modifiedAt = new Date("2026-07-20T00:00:00.000Z").toISOString();
    const sourceHash = sha256("unsupported fixture bytes");
    const files = Array.from({ length: 2_001 }, (_, index) => ({
      absolutePath: join(directory, `unsupported-${index}.bin`),
      relativePath: `captures/unsupported-${index}.bin`,
      kind: "capture" as const,
      contentClass: "binary" as const,
      mediaType: "application/octet-stream",
      sha256: sourceHash,
      byteSize: 25,
      modifiedAt,
    }));
    const engagementKey = sha256("large-private-history");
    const source: LegacyEngagementManifest = {
      id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
      root: directory,
      rootIdentity: "test-large-fixture",
      engagementDirectory: directory,
      engagementName: "large-private-history",
      engagementKey,
      sha256: sha256("large-private-history-manifest"),
      byteSize: 2_001 * 25,
      modifiedAt,
      files,
      quarantined: [],
    };

    const first = service.extract(source);
    expect(first).toMatchObject({ status: "partial", filesDiscovered: 2_001, filesSkipped: 2_000 });
    expect(first.nextResumeAfterSourceKey).toMatch(/^[a-f0-9]{64}$/u);
    const second = service.extract(source, { resumeAfterSourceKey: first.nextResumeAfterSourceKey });
    expect(second).toMatchObject({ status: "completed", filesDiscovered: 2_001, filesSkipped: 1 });
    expect(first.filesParsed + first.filesSkipped + first.filesQuarantined +
      second.filesParsed + second.filesSkipped + second.filesQuarantined).toBe(2_001);
  });

  test("never creates cross-file relationships between unrelated technology stacks", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "isolated-private-history", [
      { relativePath: "notes/apache-summary.md", kind: "note", content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 via Nmap service scan." },
      { relativePath: "notes/nginx-summary.md", kind: "note", content: "nginx 1.24 SQL injection CVE-2024-12345 via server header." },
    ]);
    service.extract(source);
    const bundles = (database.prepare("SELECT id, sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id").all() as Array<{ id: string; sanitized_bundle_json: string }>);
    expect(bundles).toHaveLength(2);
    for (const bundle of bundles) {
      const text = bundle.sanitized_bundle_json;
      expect(text.includes("Apache HTTP Server") && text.includes("nginx")).toBeFalse();
      const roles = new Set((database.prepare("SELECT role FROM attack_knowledge_bundle_candidates WHERE bundle_id = ?").all(bundle.id) as Array<{ role: string }>).map(({ role }) => role));
      const edges = database.prepare("SELECT source_role, target_role FROM attack_knowledge_bundle_edges WHERE bundle_id = ?").all(bundle.id) as Array<{ source_role: string; target_role: string }>;
      expect(edges.length).toBeGreaterThan(0);
      expect(edges.every(({ source_role, target_role }) => roles.has(source_role) && roles.has(target_role))).toBeTrue();
    }
  });

  test("retains a versioned security-control bypass and reusable topology shape without operational locators", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-network-label", [{
      relativePath: "reports/topology-summary.md",
      kind: "report",
      content: [
        "Apache HTTP Server/2.4.49 behind ModSecurity/3.0.12 and a reverse proxy.",
        "Path traversal with double URL encoding bypassed the web application firewall.",
        "The active service scan confirmed the version and the procedure worked.",
      ].join("\n"),
    }]);
    service.extract(source);
    const nodes = candidateText(database);
    expect(nodes).toContain("Layered service topology");
    expect(nodes).toContain("ModSecurity");
    expect(nodes).toContain("Control bypass observed");
    expect(nodes).not.toContain(source.engagementName);
    const edgeTypes = (database.prepare(`
      SELECT edge_type FROM attack_knowledge_bundle_edges ORDER BY edge_type
    `).all() as Array<{ edge_type: string }>).map(({ edge_type }) => edge_type);
    expect(edgeTypes).toEqual(expect.arrayContaining([
      "bypasses", "has_topology_role", "protected_by", "has_exact_version",
    ]));
  });

  test("dry run reports work without writing candidates or compiler receipts", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "dry-private", [{
      relativePath: "notes/summary.md",
      kind: "note",
      content: "nginx 1.24 server header and CVE-2024-12345.",
    }]);
    const result = service.extract(source, { dryRun: true });
    expect(result).toMatchObject({ dryRun: true, filesParsed: 1, status: "completed" });
    expect(result.candidatesCreated).toBeGreaterThan(0);
    expect(candidateCount(database)).toBe(0);
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts").get()).toEqual({ count: 0 });
  });

  test("binds every staged bundle to private source custody and verifies only after explicit local operator review", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-custody-label", [{
      relativePath: "notes/summary.md",
      kind: "note",
      content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed with timeout; health check before retry.",
    }]);
    registerVerifiedReferenceInventory(database, source);

    const extraction = service.extract(source);
    expect(extraction.sourceEvidenceCandidatesCreated).toBe(1);
    expect(extraction.sourceBundleLinks).toBeGreaterThan(0);
    const evidenceCandidateId = extraction.sourceEvidenceCandidateIds[0]!;
    expect(database.prepare("SELECT state FROM evidence_candidates WHERE id = ?").get(evidenceCandidateId)).toEqual({ state: "candidate" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });

    const started = service.beginSourceEvidenceReview({
      candidateId: evidenceCandidateId,
      actorId: "operator-reviewer",
      reason: "Review the exact local source and generalized claims.",
    });
    expect(started.status).toBe("validating");
    const verified = service.verifySourceEvidence({
      candidateId: evidenceCandidateId,
      actorId: "operator-reviewer",
      reason: "The local hash and reusable semantic claims were independently reviewed.",
      expectedSourceHash: source.files[0]!.sha256,
    });
    expect(verified.status).toBe("verified");
    expect(verified.bundleBindingsCreated).toBeGreaterThan(0);
    expect(database.prepare("SELECT verification_state, content_hash FROM evidence WHERE id = ?").get(verified.evidenceId)).toEqual({
      verification_state: "verified",
      content_hash: source.files[0]!.sha256,
    });
    const bundle = database.prepare("SELECT id FROM attack_knowledge_bundles").get() as { id: string };
    expect(new AttackKnowledgeEvidenceProvenanceGuard(database).assess(bundle.id, [verified.evidenceId])).toEqual({
      valid: true,
      reasonCategories: [],
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    const publicRows = JSON.stringify(database.prepare(`
      SELECT label, meaning, promotion_reason FROM evidence_candidates WHERE id = ?
    `).get(evidenceCandidateId));
    expect(publicRows).not.toContain(source.engagementName);
    expect(publicRows).not.toContain(source.files[0]!.absolutePath);

    const replay = service.verifySourceEvidence({
      candidateId: evidenceCandidateId,
      actorId: "operator-reviewer",
      reason: "Idempotent verification replay.",
      expectedSourceHash: source.files[0]!.sha256,
    });
    expect(replay).toMatchObject({ status: "replayed", evidenceId: verified.evidenceId });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 1 });
  });

  test("refuses a symlink replacement instead of following a reviewed source path", () => {
    const { directory, database, service } = setup();
    const source = manifest(directory, "private-path-race", [{
      relativePath: "notes/summary.md",
      kind: "note",
      content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed with timeout.",
    }]);
    registerVerifiedReferenceInventory(database, source);
    const extraction = service.extract(source);
    const candidateId = extraction.sourceEvidenceCandidateIds[0]!;
    service.beginSourceEvidenceReview({
      candidateId,
      actorId: "operator-reviewer",
      reason: "Begin review before the negative path-race fixture.",
    });
    const originalPath = source.files[0]!.absolutePath;
    const movedPath = `${originalPath}.moved`;
    renameSync(originalPath, movedPath);
    symlinkSync(movedPath, originalPath);

    expect(() => service.verifySourceEvidence({
      candidateId,
      actorId: "operator-reviewer",
      reason: "This verification must fail closed after path replacement.",
      expectedSourceHash: source.files[0]!.sha256,
    })).toThrow();
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT state FROM evidence_candidates WHERE id = ?").get(candidateId)).toEqual({ state: "validating" });
  });
});
