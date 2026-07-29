import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { custodyCompleteVerifiedEvidenceSql } from "../domain/evidence-semantics";
import { OperationsApiError, conflict, notFound } from "../operations/errors";
import { missionScopeSql, sensitivitySql } from "../operations/scope";
import type {
  OperationsAccessPolicy,
  OperationsActor,
  OperationsSensitivity,
} from "../operations/types";
import { canonicalJson, parseJson, sanitizeJson, sha256 } from "../operations/validation";

type Row = Record<string, unknown>;

export const CANONICAL_REPORT_SCHEMA_VERSION = "2.4-report.1" as const;
export const CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION =
  "ti-scale.canonical-report-presentation.v1" as const;
export const CANONICAL_REPORT_ARTIFACT_COMMITMENT_SCHEMA_VERSION =
  "ti-scale.canonical-report-artifact-commitment.v1" as const;
const REPORT_RECORD_LIMIT = 1_000;
const REPORT_MAXIMUM_BYTES = 16 * 1024 * 1024;
export const CANONICAL_REPORT_ARTIFACT_TYPES = Object.freeze({
  markdown: "mission_report_markdown",
  json: "mission_report_json",
} as const);

export type CanonicalReportFormat = keyof typeof CANONICAL_REPORT_ARTIFACT_TYPES;
export type CanonicalReportArtifactType =
  (typeof CANONICAL_REPORT_ARTIFACT_TYPES)[CanonicalReportFormat];

/**
 * An in-transaction promise made by the canonical report closeout owner.
 *
 * The terminal evaluator may account for these artifacts before their bytes
 * are materialized because the outer compensated transaction verifies the
 * promise before commit. It cannot describe arbitrary artifact types/counts.
 */
export interface CanonicalReportArtifactCommitment {
  readonly schemaVersion: typeof CANONICAL_REPORT_ARTIFACT_COMMITMENT_SCHEMA_VERSION;
  readonly runId: string;
  readonly reportVersion: number;
  readonly artifactTypes: readonly [
    typeof CANONICAL_REPORT_ARTIFACT_TYPES.markdown,
    typeof CANONICAL_REPORT_ARTIFACT_TYPES.json,
  ];
}

export function createCanonicalReportArtifactCommitment(
  runId: string,
  reportVersion: number,
): CanonicalReportArtifactCommitment {
  if (!runId.trim()) throw new TypeError("Canonical report commitment run ID is required");
  if (!Number.isSafeInteger(reportVersion) || reportVersion < 1 || reportVersion > 999) {
    throw new TypeError("Canonical report commitment version is invalid");
  }
  const artifactTypes: CanonicalReportArtifactCommitment["artifactTypes"] = [
    CANONICAL_REPORT_ARTIFACT_TYPES.markdown,
    CANONICAL_REPORT_ARTIFACT_TYPES.json,
  ];
  return Object.freeze({
    schemaVersion: CANONICAL_REPORT_ARTIFACT_COMMITMENT_SCHEMA_VERSION,
    runId: runId.trim(),
    reportVersion,
    artifactTypes: Object.freeze(artifactTypes),
  });
}

/**
 * A presentation-only projection selected by a trusted local caller.
 * It may change ordering and explanatory copy, but never record selection,
 * evidence classification, finding verification, redaction, or deliverables.
 */
export interface CanonicalReportPresentation {
  readonly schemaVersion: typeof CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION;
  readonly contextPackId: string;
  readonly narrativeStyle: "technical_readable" | "canonical";
  readonly evidencePresentation: "evidence_first" | "canonical";
  readonly appliedPreferenceNodeIds: readonly string[];
  readonly appliedPreferenceKeys: readonly string[];
}

interface MissionRunRow {
  readonly mission_id: string;
  readonly mission_name: string;
  readonly engagement_id: string | null;
  readonly mission_journey: "autonomous" | "guided";
  readonly mission_status: string;
  readonly mission_objective: string;
  readonly mission_scope_json: string;
  readonly success_criteria_json: string;
  readonly mission_control_plane: "legacy" | "ti_scale";
  readonly mission_created_at: string;
  readonly mission_updated_at: string;
  readonly run_id: string;
  readonly run_journey: "autonomous" | "guided";
  readonly run_status: string;
  readonly run_status_reason: string | null;
  readonly run_progress: number;
  readonly current_plan_id: string | null;
  readonly current_step_id: string | null;
  readonly next_action_summary: string | null;
  readonly run_control_plane: "legacy" | "ti_scale";
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly run_created_at: string;
  readonly run_updated_at: string;
}

interface StoredReportRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly journey: "autonomous" | "guided";
  readonly artifact_type: string;
  readonly storage_uri: string;
  readonly content_hash: string;
  readonly byte_size: number;
  readonly media_type: string | null;
  readonly sensitivity: OperationsSensitivity;
  readonly metadata_json: string;
  readonly created_at: string;
}

export interface CanonicalReportArtifact {
  readonly id: string;
  readonly format: CanonicalReportFormat;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly downloadUrl: string;
}

export interface CanonicalReportGeneration {
  readonly schemaVersion: "2.4";
  readonly reportSchemaVersion: typeof CANONICAL_REPORT_SCHEMA_VERSION;
  readonly missionId: string;
  readonly runId: string;
  readonly reportVersion: number;
  readonly sourceSnapshotHash: string;
  readonly snapshotThrough: string;
  readonly idempotent: true;
  readonly artifacts: readonly CanonicalReportArtifact[];
}

export interface CanonicalReportDownload {
  readonly artifactId: string;
  readonly filename: string;
  readonly mediaType: "text/markdown; charset=utf-8" | "application/json; charset=utf-8";
  readonly body: Buffer;
  readonly byteSize: number;
  readonly contentHash: string;
}

export interface CanonicalMissionReportServiceOptions {
  readonly artifactRoot?: string;
  readonly clock?: () => Date;
}

function rowText(value: unknown): string {
  const safe = sanitizeJson(String(value ?? ""));
  return typeof safe === "string" ? safe : String(safe ?? "");
}

type ReportTopologyLabelDisclosure =
  | "included_authorized_scope"
  | "withheld_non_authorized_scope";

function reportTopologyLabel(item: Row): Readonly<{
  label: string;
  disclosure: ReportTopologyLabelDisclosure;
}> {
  if (item.scope_status === "allowed") {
    return {
      label: rowText(item.primary_label),
      disclosure: "included_authorized_scope",
    };
  }
  const nodeType = rowText(item.node_type).replaceAll("_", " ").trim();
  const readableType = nodeType
    ? `${nodeType[0]!.toUpperCase()}${nodeType.slice(1)}`
    : "Topology node";
  return {
    label: `${readableType} identity withheld`,
    disclosure: "withheld_non_authorized_scope",
  };
}

function safeJson(value: unknown): unknown {
  return sanitizeJson(typeof value === "string" ? parseJson(value) : value);
}

/**
 * Evaluation scores and metrics are canonical flat scalar records. Preserve
 * harmless metric names such as `tokenEfficiency` while still sanitizing
 * every string value and refusing nested/unbounded payloads.
 */
function safeEvaluationRecord(
  value: unknown,
): Readonly<Record<string, string | number | boolean | null>> {
  const parsed = typeof value === "string" ? parseJson(value) : value;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }
  const result: Record<string, string | number | boolean | null> = {};
  for (const [key, candidate] of Object.entries(parsed)) {
    if (
      !/^[A-Za-z][A-Za-z0-9._-]{0,119}$/u.test(key)
      || Object.keys(result).length >= 256
    ) continue;
    if (
      candidate === null
      || typeof candidate === "boolean"
      || (typeof candidate === "number" && Number.isFinite(candidate))
    ) {
      result[key] = candidate;
    } else if (typeof candidate === "string") {
      result[key] = rowText(candidate);
    }
  }
  return result;
}

function markdownText(value: unknown): string {
  return rowText(value)
    .replaceAll("\\", "\\\\")
    .replace(/([`*_{}\[\]<>#+.!|])/gu, "\\$1")
    .replace(/[\r\n]+/gu, " ")
    .trim();
}

/** Inline-code value that preserves stable identifiers exactly in the report. */
function markdownCode(value: unknown): string {
  return rowText(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("`", "\\`")
    .replace(/[\r\n]+/gu, " ")
    .trim();
}

function boundedRows(rows: readonly Row[]): { readonly records: readonly Row[]; readonly truncated: boolean } {
  return { records: rows.slice(0, REPORT_RECORD_LIMIT), truncated: rows.length > REPORT_RECORD_LIMIT };
}

function reportArtifactId(missionId: string, runId: string, reportVersion: number, format: CanonicalReportFormat): string {
  return `report_${sha256(`${missionId}\n${runId}\n${reportVersion}\n${format}`).slice(0, 40)}`;
}

function reportStorageUri(format: CanonicalReportFormat, hash: string): string {
  return `ti-scale-report://sha256/${hash}/${format}`;
}

function formatForArtifactType(type: string): CanonicalReportFormat | null {
  if (type === CANONICAL_REPORT_ARTIFACT_TYPES.markdown) return "markdown";
  if (type === CANONICAL_REPORT_ARTIFACT_TYPES.json) return "json";
  return null;
}

function mediaType(format: CanonicalReportFormat): CanonicalReportDownload["mediaType"] {
  return format === "markdown"
    ? "text/markdown; charset=utf-8"
    : "application/json; charset=utf-8";
}

function resolveArtifactRoot(database: SqliteDatabase, configured?: string): string {
  const candidate = configured?.trim();
  if (candidate && !isAbsolute(candidate)) {
    throw new TypeError("Canonical report artifact root must be absolute");
  }
  const databaseName = typeof database.name === "string" ? database.name : "";
  if (!candidate && (!databaseName || databaseName === ":memory:" || !isAbsolute(databaseName))) {
    throw new TypeError("An absolute canonical report artifact root is required for an in-memory database");
  }
  const stem = databaseName && databaseName !== ":memory:"
    ? basename(databaseName, extname(databaseName)).replace(/[^A-Za-z0-9._-]/gu, "-") || "canonical"
    : "canonical";
  const root = resolve(candidate || join(dirname(resolve(databaseName)), "ti-scale-artifacts", stem, "reports"));
  if (!root.split(/[\\/]+/u).some((segment) => /(?:^|[-_.])ti[-_]?scale(?:$|[-_.])/iu.test(segment))) {
    throw new TypeError("Canonical report artifact root must use a Ti-Scale namespace");
  }
  return root;
}

function ensureArtifactRoot(root: string): void {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const details = statSync(root);
  if (!details.isDirectory()) throw new Error("Canonical report artifact root is not a directory");
}

function contentPath(root: string, hash: string, format: CanonicalReportFormat): string {
  if (!/^[a-f0-9]{64}$/u.test(hash)) throw new TypeError("Invalid canonical report hash");
  return join(root, `${hash}.${format === "markdown" ? "md" : "json"}`);
}

interface ContentMaterialization {
  readonly path: string;
  readonly created: boolean;
}

function contentMatches(path: string, hash: string, body: Buffer): boolean {
  const existing = readFileSync(path);
  return existing.length === body.length
    && createHash("sha256").update(existing).digest("hex") === hash;
}

function materializeContent(
  root: string,
  hash: string,
  format: CanonicalReportFormat,
  body: Buffer,
): ContentMaterialization {
  ensureArtifactRoot(root);
  const destination = contentPath(root, hash, format);
  if (existsSync(destination)) {
    if (!contentMatches(destination, hash, body)) {
      throw conflict(
        "The content-addressed report file does not match its expected SHA-256.",
        "Quarantine the conflicting file and regenerate a new report version.",
      );
    }
    return { path: destination, created: false };
  }
  const temporary = join(root, `.${hash}.${process.pid}.${randomUUID()}.tmp`);
  let created = false;
  try {
    writeFileSync(temporary, body, { flag: "wx", mode: 0o600 });
    try {
      // A hard link publishes without replacing a content-addressed file that
      // another process won concurrently. The temporary file lives in the
      // same directory, so the operation remains on one filesystem.
      linkSync(temporary, destination);
      created = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (!contentMatches(destination, hash, body)) {
        throw conflict(
          "The content-addressed report file does not match its expected SHA-256.",
          "Quarantine the conflicting file and regenerate a new report version.",
        );
      }
    }
    chmodSync(destination, 0o600);
    return { path: destination, created };
  } catch (error) {
    if (created) rmSync(destination, { force: true });
    throw error;
  } finally {
    rmSync(temporary, { force: true });
  }
}

function reportFilename(runId: string, reportVersion: number, format: CanonicalReportFormat): string {
  const safeRun = runId.replace(/[^A-Za-z0-9._-]/gu, "_").slice(0, 96) || "run";
  return `ti-scale-${safeRun}-report-v${reportVersion}.${format === "markdown" ? "md" : "json"}`;
}

function listSection(title: string, records: readonly string[], empty: string): string[] {
  return [
    `## ${title}`,
    "",
    ...(records.length > 0 ? records : [`_${empty}_`]),
    "",
  ];
}

function validatedPresentation(
  value: CanonicalReportPresentation | undefined,
): CanonicalReportPresentation | undefined {
  if (!value) return undefined;
  const nodeIds = [...new Set(value.appliedPreferenceNodeIds)];
  const keys = [...new Set(value.appliedPreferenceKeys)];
  if (
    value.schemaVersion !== CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION
    || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value.contextPackId)
    || (value.narrativeStyle !== "technical_readable" && value.narrativeStyle !== "canonical")
    || (value.evidencePresentation !== "evidence_first"
      && value.evidencePresentation !== "canonical")
    || nodeIds.length < 1
    || nodeIds.length !== value.appliedPreferenceNodeIds.length
    || keys.length < 1
    || keys.length !== value.appliedPreferenceKeys.length
    || nodeIds.some((id) => !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(id))
    || keys.some((key) => !/^[a-z][a-z0-9_.-]{0,119}$/u.test(key))
    || (value.narrativeStyle === "canonical"
      && value.evidencePresentation === "canonical")
  ) {
    throw new TypeError("Canonical report presentation is invalid");
  }
  return Object.freeze({
    ...value,
    appliedPreferenceNodeIds: Object.freeze(nodeIds),
    appliedPreferenceKeys: Object.freeze(keys),
  });
}

function renderMarkdown(report: Record<string, unknown>): string {
  const mission = report.mission as Record<string, unknown>;
  const run = report.run as Record<string, unknown>;
  const plan = report.plan as { records: readonly Record<string, unknown>[] };
  const actions = report.actions as { records: readonly Record<string, unknown>[] };
  const logs = report.engagementLogs as { records: readonly Record<string, unknown>[] };
  const observations = report.observations as { records: readonly Record<string, unknown>[] };
  const evidence = report.verifiedEvidence as { records: readonly Record<string, unknown>[] };
  const findings = report.findings as { verified: readonly Record<string, unknown>[]; reviewRequired: readonly Record<string, unknown>[] };
  const topology = report.topology as { nodes: readonly Record<string, unknown>[]; edges: readonly Record<string, unknown>[] };
  const failures = report.failureDiagnoses as { records: readonly Record<string, unknown>[] };
  const evaluation = report.evaluation as Record<string, unknown> | null;
  const context = report.contextPacks as { records: readonly Record<string, unknown>[] };
  const presentation = report.presentation as CanonicalReportPresentation | undefined;
  const technicalReadable = presentation?.narrativeStyle === "technical_readable";
  const evidenceFirst = presentation?.evidencePresentation === "evidence_first";
  const evidenceLines = evidence.records.map((item) => technicalReadable
    ? [
        `- **Observed:** ${markdownText(item.summary)}`,
        `  - **Evidence ID:** \`${markdownCode(item.id)}\``,
        `  - **Evidence type:** ${markdownText(item.evidenceType)}`,
        `  - **Confidence:** ${Math.round(Number(item.confidence ?? 0) * 100)}%`,
        `  - **Source and target:** ${markdownText(item.source)}${item.target ? ` → ${markdownText(item.target)}` : ""}`,
        `  - **Integrity:** SHA-256 \`${markdownText(item.contentHash)}\``,
      ].join("\n")
    : `- **${markdownText(item.summary)}** — Evidence ID \`${markdownCode(item.id)}\`; ${markdownText(item.evidenceType)}, SHA-256 \`${markdownText(item.contentHash)}\`.`);
  const findingLines = findings.verified.map((item) => technicalReadable
    ? [
        `- **${markdownText(item.title)}** (${markdownText(item.severity)})`,
        `  - **What it means:** ${markdownText(item.description)}`,
        `  - **Why it matters:** ${markdownText(item.impact)}`,
        `  - **Confidence:** ${Math.round(Number(item.confidence ?? 0) * 100)}%`,
        ...(item.remediation ? [`  - **Recommended action:** ${markdownText(item.remediation)}`] : []),
      ].join("\n")
    : `- **${markdownText(item.title)}** (${markdownText(item.severity)}) — ${markdownText(item.description)}`);
  const planAndActivitySections = [
    ...listSection("Plan", plan.records.map((item) =>
      `- **${markdownText(item.title)}** — ${markdownText(item.objective)} _(${markdownText(item.status)})_`), "No plan steps were recorded."),
    ...listSection("Actions", actions.records.map((item) =>
      `- **${markdownText(item.intent)}** — ${markdownText(item.result) || "No result summary."} _(${markdownText(item.status)})_`), "No actions were recorded."),
    ...listSection("Engagement Log (not evidence)", logs.records.map((item) =>
      `- ${markdownText(item.occurredAt)} — ${markdownText(item.summary)} _(${markdownText(item.domain)})_`), "No semantic log records were retained."),
    ...listSection("Observations (not automatically verified)", observations.records.map((item) =>
      `- ${markdownText(item.statement)} — confidence ${markdownText(item.confidence)}, state ${markdownText(item.verificationState)}.`), "No parsed observations were retained."),
  ];
  const evidenceAndFindingSections = [
    ...listSection("Verified Evidence", evidenceLines, "No verified evidence met the canonical evidence gate."),
    ...listSection("Verified Findings", findingLines, "No finding has both verified review state and supporting verified evidence."),
    ...listSection("Review required (not asserted as fact)", findings.reviewRequired.map((item) =>
      `- **${markdownText(item.title)}** — ${markdownText(item.reviewReason)}`), "No unresolved finding claims were recorded."),
  ];
  const lines = [
    `# ${markdownText(mission.name)} — Mission Report`,
    "",
    `- **Mission:** ${markdownText(mission.id)}`,
    `- **Run:** ${markdownText(run.id)}`,
    `- **Journey:** ${markdownText(run.journey)}`,
    `- **Run status:** ${markdownText(run.status)}`,
    `- **Report version:** ${markdownText(report.reportVersion)}`,
    `- **Snapshot through:** ${markdownText(report.snapshotThrough)}`,
    `- **Imported provenance:** ${mission.imported === true ? "Yes" : "No"}`,
    ...(presentation ? [
      `- **Presentation Context Pack:** \`${markdownText(presentation.contextPackId)}\``,
      `- **Applied presentation preferences:** ${presentation.appliedPreferenceKeys.map(markdownText).join(", ")}`,
    ] : []),
    "",
    "## Objective and result",
    "",
    `**Authorized objective:** ${markdownText(mission.objective) || "Not recorded."}`,
    "",
    `**Current result:** ${markdownText(run.statusReason) || `Run is ${markdownText(run.status)}.`}`,
    "",
    "> Evidence policy: raw command output is an Engagement Log, parsed output is an Observation, and only independently verified canonical evidence supports a verified finding.",
    "",
    ...(evidenceFirst
      ? [...evidenceAndFindingSections, ...planAndActivitySections]
      : [...planAndActivitySections, ...evidenceAndFindingSections]),
    ...listSection("Discovered environment", topology.nodes.map((item) =>
      `- **${markdownText(item.label)}** — node \`${markdownCode(item.id)}\`; ${markdownText(item.nodeType)}, scope ${markdownText(item.scopeStatus)}, ${markdownText(item.verificationState)}, confidence ${markdownText(item.confidence)}.`), "No topology nodes were recorded."),
    ...listSection("Evidence-backed relationships", topology.edges.map((item) =>
      `- ${markdownText(item.sourceNodeId)} → ${markdownText(item.edgeType)} → ${markdownText(item.targetNodeId)} _(${markdownText(item.verificationState)})_`), "No topology relationships were recorded."),
    ...listSection("Failures and recovery", failures.records.map((item) =>
      `- **${markdownText(item.reason)}** — ${markdownText(item.remediation)} _(${markdownText(item.state)})_`), "No structured failure diagnosis was recorded."),
    "## Evaluation",
    "",
    ...(evaluation ? [
      `${markdownText(evaluation.retrospective)}`,
      "",
      `Evidence coverage: ${Math.round(Number(evaluation.evidenceCoverage ?? 0) * 100)}%.`,
    ] : ["_No canonical terminal evaluation is available for this run._"]),
    "",
    ...listSection("Second Brain Context Packs", context.records.map((item) =>
      `- \`${markdownText(item.id)}\` — ${markdownText(item.purpose)}; ${markdownText(item.itemCount)} scoped item(s), ${markdownText(item.usedItemCount)} used.`), "No Context Packs were recorded for this run."),
    "## Privacy and integrity",
    "",
    "This report intentionally excludes raw technical payloads, command output bodies, extracted evidence text, topology identities outside confirmed authorized scope, provider prompts/responses, credentials, secrets, cookies, tokens, and unrestricted memory-note content. Credential-like fragments in included human summaries are deterministically redacted.",
    "",
  ];
  return `${lines.join("\n").replace(/\n{3,}/gu, "\n\n")}\n`;
}

/**
 * Builds immutable, bounded report artifacts from canonical V2 records only.
 * It never reads legacy source paths or provider transcripts and never treats
 * process output or a merely parsed observation as verified evidence.
 */
export class CanonicalMissionReportService {
  readonly #database: SqliteDatabase;
  readonly #configuredArtifactRoot: string | undefined;
  readonly #clock: () => Date;
  readonly #materializationCompensationScopes: Set<string>[] = [];

  constructor(database: SqliteDatabase, options: CanonicalMissionReportServiceOptions = {}) {
    this.#database = database;
    this.#configuredArtifactRoot = options.artifactRoot;
    this.#clock = options.clock ?? (() => new Date());
  }

  /**
   * Compensates content files when a caller owns a wider synchronous database
   * transaction than `generate`. The opaque scope records only files created
   * by this service call; pre-existing content-addressed files are never
   * removed. Existing HTTP generation does not need this wrapper because
   * `generate` owns its complete database transaction there.
   */
  withMaterializationCompensation<T>(operation: () => T): T {
    const created = new Set<string>();
    this.#materializationCompensationScopes.push(created);
    try {
      const result = operation();
      if (
        result !== null
        && typeof result === "object"
        && typeof (result as { readonly then?: unknown }).then === "function"
      ) {
        throw new TypeError("Canonical report materialization compensation must be synchronous");
      }
      this.#materializationCompensationScopes.pop();
      const parent = this.#materializationCompensationScopes.at(-1);
      if (parent) for (const path of created) parent.add(path);
      return result;
    } catch (error) {
      this.#materializationCompensationScopes.pop();
      for (const path of created) rmSync(path, { force: true });
      throw error;
    }
  }

  generate(
    runId: string,
    reportVersion: number,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
    idempotencyKey: string,
    presentationInput?: CanonicalReportPresentation,
  ): CanonicalReportGeneration {
    if (this.#database.inTransaction && this.#materializationCompensationScopes.length === 0) {
      throw new TypeError(
        "Canonical report generation inside a caller-owned transaction requires materialization compensation",
      );
    }
    if (!Number.isSafeInteger(reportVersion) || reportVersion < 1 || reportVersion > 999) {
      throw new OperationsApiError(400, "invalid_report_version", "Report version is invalid", {
        humanMessage: "Report version must be a whole number from 1 through 999.",
        category: "invalid_input",
      });
    }
    const scope = missionScopeSql("m", access);
    const run = this.#database.prepare(`
      SELECT m.id AS mission_id, m.name AS mission_name, m.engagement_id,
        m.journey AS mission_journey, m.status AS mission_status,
        m.objective AS mission_objective, m.scope_json AS mission_scope_json,
        m.success_criteria_json, m.control_plane AS mission_control_plane,
        m.created_at AS mission_created_at, m.updated_at AS mission_updated_at,
        r.id AS run_id, r.journey AS run_journey, r.status AS run_status,
        r.status_reason AS run_status_reason, r.progress AS run_progress,
        r.current_plan_id, r.current_step_id, r.next_action_summary,
        r.control_plane AS run_control_plane, r.started_at, r.ended_at,
        r.created_at AS run_created_at, r.updated_at AS run_updated_at
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND ${scope.sql}
    `).get(runId, ...scope.params) as MissionRunRow | undefined;
    if (!run) throw notFound("Run");
    if (run.run_journey !== run.mission_journey) {
      throw conflict("The run and mission journey records require reconciliation before reporting.");
    }

    const presentation = validatedPresentation(presentationInput);
    const snapshot = this.#snapshot(run, reportVersion, access);
    const report = presentation ? { ...snapshot, presentation } : snapshot;
    const sourceSnapshotHash = sha256(canonicalJson(report));
    const jsonBody = Buffer.from(`${canonicalJson({ ...report, sourceSnapshotHash })}\n`, "utf8");
    const markdownBody = Buffer.from(renderMarkdown({ ...report, sourceSnapshotHash }), "utf8");
    if (jsonBody.length > REPORT_MAXIMUM_BYTES || markdownBody.length > REPORT_MAXIMUM_BYTES) {
      throw new OperationsApiError(413, "report_size_limit_exceeded", "Canonical report exceeds the bounded size limit", {
        humanMessage: "The report is too large to generate safely within the local 16 MiB artifact limit.",
        category: "budget_exhausted",
        remediation: "Create a new report version with narrower canonical retention or archive older operational records.",
      });
    }
    const bodies = { markdown: markdownBody, json: jsonBody } as const;
    const artifactRoot = resolveArtifactRoot(this.#database, this.#configuredArtifactRoot);
    const now = this.#clock().toISOString();
    const createdForCleanup: string[] = [];
    try {
      const artifacts = (["markdown", "json"] as const).map((format) => {
        const body = bodies[format];
        const contentHash = createHash("sha256").update(body).digest("hex");
        const id = reportArtifactId(run.mission_id, run.run_id, reportVersion, format);
        const referencedBefore = Boolean(this.#database.prepare(`
          SELECT 1 AS present FROM artifacts
          WHERE content_hash = ? AND storage_uri = ? LIMIT 1
        `).get(contentHash, reportStorageUri(format, contentHash)));
        const materialized = materializeContent(artifactRoot, contentHash, format, body);
        if (materialized.created && !referencedBefore) createdForCleanup.push(materialized.path);
        return {
          id,
          format,
          mediaType: mediaType(format),
          contentHash,
          byteSize: body.length,
          downloadUrl: `/api/v2/reports/${encodeURIComponent(id)}/download`,
        } satisfies CanonicalReportArtifact;
      });

      let inserted = false;
      inImmediateTransaction(this.#database, () => {
        for (const artifact of artifacts) {
          const existing = this.#database.prepare(`
            SELECT id, mission_id, run_id, journey, artifact_type, storage_uri,
              content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
            FROM artifacts WHERE id = ?
          `).get(artifact.id) as StoredReportRow | undefined;
          const metadata = {
            schemaVersion: CANONICAL_REPORT_SCHEMA_VERSION,
            reportVersion,
            format: artifact.format,
            sourceSnapshotHash,
            snapshotThrough: run.run_updated_at,
            boundedRecordLimit: REPORT_RECORD_LIMIT,
            idempotency: { missionId: run.mission_id, runId: run.run_id, reportVersion },
            privacy: {
              rawPayloadsExcluded: true,
              secretsRedacted: true,
              unverifiedFindingsNotAsserted: true,
            },
            downloadUrl: artifact.downloadUrl,
            pairedArtifactIds: artifacts.map((item) => item.id),
          };
          if (existing) {
            const expected = {
              missionId: run.mission_id,
              runId: run.run_id,
              journey: run.run_journey,
              artifactType: CANONICAL_REPORT_ARTIFACT_TYPES[artifact.format],
              storageUri: reportStorageUri(artifact.format, artifact.contentHash),
              contentHash: artifact.contentHash,
              byteSize: artifact.byteSize,
              mediaType: artifact.mediaType,
            };
            if (
              existing.mission_id !== expected.missionId
              || existing.run_id !== expected.runId
              || existing.journey !== expected.journey
              || existing.artifact_type !== expected.artifactType
              || existing.storage_uri !== expected.storageUri
              || existing.content_hash !== expected.contentHash
              || existing.byte_size !== expected.byteSize
              || existing.media_type !== expected.mediaType
            ) {
              throw conflict(
                "This mission, run, and report version already identify a different immutable artifact.",
                "Generate a new report version after canonical records change.",
              );
            }
            continue;
          }
          this.#database.prepare(`
            INSERT INTO artifacts (
              id, mission_id, run_id, step_id, action_id, journey, artifact_type,
              storage_uri, content_hash, byte_size, media_type, sensitivity,
              metadata_json, created_at
            ) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, 'private', ?, ?)
          `).run(
            artifact.id,
            run.mission_id,
            run.run_id,
            run.run_journey,
            CANONICAL_REPORT_ARTIFACT_TYPES[artifact.format],
            reportStorageUri(artifact.format, artifact.contentHash),
            artifact.contentHash,
            artifact.byteSize,
            artifact.mediaType,
            canonicalJson(metadata),
            now,
          );
          inserted = true;
        }
        if (inserted) {
          this.#appendAudit(run, reportVersion, sourceSnapshotHash, artifacts, actor, idempotencyKey, now);
        }
      });

      const compensation = this.#materializationCompensationScopes.at(-1);
      if (compensation) for (const path of createdForCleanup) compensation.add(path);
      return {
        schemaVersion: "2.4",
        reportSchemaVersion: CANONICAL_REPORT_SCHEMA_VERSION,
        missionId: run.mission_id,
        runId: run.run_id,
        reportVersion,
        sourceSnapshotHash,
        snapshotThrough: run.run_updated_at,
        idempotent: true,
        artifacts,
      };
    } catch (error) {
      for (const path of createdForCleanup) rmSync(path, { force: true });
      throw error;
    }
  }

  download(artifactId: string, access: OperationsAccessPolicy): CanonicalReportDownload {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("a.sensitivity", access);
    const row = this.#database.prepare(`
      SELECT a.id, a.mission_id, a.run_id, a.journey, a.artifact_type,
        a.storage_uri, a.content_hash, a.byte_size, a.media_type,
        a.sensitivity, a.metadata_json, a.created_at
      FROM artifacts a JOIN missions m ON m.id = a.mission_id
      WHERE a.id = ? AND ${scope.sql} AND ${sensitivity.sql}
    `).get(artifactId, ...scope.params, ...sensitivity.params) as StoredReportRow | undefined;
    if (!row) throw notFound("Report artifact");
    const format = formatForArtifactType(row.artifact_type);
    if (!format) throw notFound("Report artifact");
    const expectedUri = reportStorageUri(format, row.content_hash);
    if (row.storage_uri !== expectedUri || !/^[a-f0-9]{64}$/u.test(row.content_hash)) {
      throw conflict("The canonical report storage reference requires reconciliation.");
    }
    if (!Number.isSafeInteger(row.byte_size) || row.byte_size < 0 || row.byte_size > REPORT_MAXIMUM_BYTES) {
      throw conflict("The canonical report byte-size record requires reconciliation.");
    }
    const artifactRoot = resolveArtifactRoot(this.#database, this.#configuredArtifactRoot);
    const path = contentPath(artifactRoot, row.content_hash, format);
    let descriptor: number | undefined;
    let body: Buffer;
    try {
      descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const before = fstatSync(descriptor);
      if (!before.isFile() || before.size !== row.byte_size || before.size > REPORT_MAXIMUM_BYTES) {
        throw new Error("report_size_or_type_mismatch");
      }
      body = readFileSync(descriptor);
      const after = fstatSync(descriptor);
      if (!after.isFile() || after.size !== before.size || body.length !== row.byte_size) {
        throw new Error("report_changed_during_read");
      }
      if (createHash("sha256").update(body).digest("hex") !== row.content_hash) {
        throw new Error("report_hash_mismatch");
      }
    } catch {
      throw new OperationsApiError(409, "report_integrity_reconciliation_required", "The report failed containment or integrity verification", {
        humanMessage: "The report could not be downloaded because its contained file, byte size, or SHA-256 no longer matches the canonical artifact record.",
        category: "reconciliation_required",
        remediation: "Restore the content-addressed report from a trusted backup or generate a new report version.",
      });
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
    const metadata = safeJson(row.metadata_json) as Record<string, unknown> | null;
    const reportVersion = Number(metadata?.reportVersion ?? 1);
    return {
      artifactId: row.id,
      filename: reportFilename(String(row.run_id ?? "mission"), reportVersion, format),
      mediaType: mediaType(format),
      body,
      byteSize: body.length,
      contentHash: row.content_hash,
    };
  }

  #snapshot(run: MissionRunRow, reportVersion: number, access: OperationsAccessPolicy): Record<string, unknown> {
    const evidenceSensitivity = sensitivitySql("e.sensitivity", access);
    const logSensitivity = sensitivitySql("l.sensitivity", access);
    const observationSensitivity = sensitivitySql("o.sensitivity", access);
    const topologyNodeSensitivity = sensitivitySql("n.sensitivity", access);
    const topologyEdgeSensitivity = sensitivitySql("edge.sensitivity", access);
    const plans = boundedRows(this.#database.prepare(`
      SELECT p.id, p.version, p.status, p.strategy_summary, p.rationale_summary,
        p.plan_hash, p.created_at, p.activated_at
      FROM plans p WHERE p.run_id = ? ORDER BY p.version, p.id LIMIT ?
    `).all(run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);
    const steps = boundedRows(this.#database.prepare(`
      SELECT ps.id, ps.plan_id, ps.ordinal, ps.phase, ps.title, ps.objective,
        ps.status, ps.action_class, ps.risk_class, ps.started_at, ps.ended_at
      FROM plan_steps ps WHERE ps.run_id = ?
      ORDER BY ps.plan_id, ps.ordinal, ps.id LIMIT ?
    `).all(run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);
    const actions = boundedRows(this.#database.prepare(`
      SELECT a.id, a.step_id, a.action_type, a.action_class, a.scoped_target,
        a.status, a.intent_summary, a.result_summary, a.error_category,
        a.retry_count, a.started_at, a.ended_at
      FROM actions a WHERE a.run_id = ?
      ORDER BY a.created_at, a.id LIMIT ?
    `).all(run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);
    const logs = boundedRows(this.#database.prepare(`
      SELECT l.id, l.severity, l.domain, l.record_type, l.human_summary,
        l.occurred_at, l.sensitivity
      FROM engagement_log_records l
      WHERE l.run_id = ? AND ${logSensitivity.sql}
      ORDER BY l.occurred_at, l.id LIMIT ?
    `).all(run.run_id, ...logSensitivity.params, REPORT_RECORD_LIMIT + 1) as Row[]);
    const observations = boundedRows(this.#database.prepare(`
      SELECT o.id, o.observation_type, o.statement, o.confidence,
        o.verification_state, o.source_tool, o.first_seen_at, o.last_seen_at
      FROM observations o
      WHERE o.run_id = ? AND ${observationSensitivity.sql}
      ORDER BY o.first_seen_at, o.id LIMIT ?
    `).all(run.run_id, ...observationSensitivity.params, REPORT_RECORD_LIMIT + 1) as Row[]);
    const evidence = boundedRows(this.#database.prepare(`
      SELECT e.id, e.evidence_type, e.summary, e.content_hash, e.confidence,
        e.verification_state, e.source, e.target, e.acquired_at
      FROM evidence e
      WHERE e.run_id = ? AND ${custodyCompleteVerifiedEvidenceSql("e")}
        AND ${evidenceSensitivity.sql}
      ORDER BY e.acquired_at, e.id LIMIT ?
    `).all(run.run_id, ...evidenceSensitivity.params, REPORT_RECORD_LIMIT + 1) as Row[]);
    const findings = boundedRows(this.#database.prepare(`
      SELECT f.id, f.title, f.severity, f.confidence, f.affected_scope,
        f.description, f.impact, f.remediation, f.review_status, f.version,
        SUM(CASE WHEN fe.relationship = 'supports'
          AND ${custodyCompleteVerifiedEvidenceSql("e")}
          AND ${evidenceSensitivity.sql} THEN 1 ELSE 0 END) AS verified_support_count
      FROM findings f
      LEFT JOIN finding_evidence fe ON fe.finding_id = f.id
      LEFT JOIN evidence e ON e.id = fe.evidence_id
      WHERE f.run_id = ?
      GROUP BY f.id ORDER BY f.created_at, f.id LIMIT ?
    `).all(...evidenceSensitivity.params, run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);
    const nodes = boundedRows(this.#database.prepare(`
      SELECT n.id, n.node_type, n.primary_label, n.scope_status,
        n.lifecycle_state, n.confidence, n.verification_state,
        n.originating_tool, n.first_seen_at, n.last_seen_at
      FROM topology_nodes n
      WHERE n.mission_id = ? AND (n.run_id IS NULL OR n.run_id = ?)
        AND ${topologyNodeSensitivity.sql}
      ORDER BY n.first_seen_at, n.id LIMIT ?
    `).all(run.mission_id, run.run_id, ...topologyNodeSensitivity.params, REPORT_RECORD_LIMIT + 1) as Row[]);
    const edges = boundedRows(this.#database.prepare(`
      SELECT edge.id, edge.source_node_id, edge.target_node_id, edge.edge_type,
        edge.confidence, edge.verification_state, edge.first_seen_at, edge.last_seen_at
      FROM topology_edges edge
      WHERE edge.mission_id = ? AND ${topologyEdgeSensitivity.sql}
      ORDER BY edge.first_seen_at, edge.id LIMIT ?
    `).all(run.mission_id, ...topologyEdgeSensitivity.params, REPORT_RECORD_LIMIT + 1) as Row[]);
    const failures = boundedRows(this.#database.prepare(`
      SELECT fd.id, fd.subject_type, fd.subject_id, fd.human_reason,
        fd.category, fd.code, fd.retryable, fd.remediation,
        fd.objective_impact, fd.state, fd.created_at, fd.resolved_at
      FROM failure_diagnoses fd
      WHERE fd.run_id = ? ORDER BY fd.created_at, fd.id LIMIT ?
    `).all(run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);
    const evaluation = this.#database.prepare(`
      SELECT id, scores_json, metrics_json, retrospective, evidence_coverage,
        created_by, created_at FROM run_evaluations WHERE run_id = ?
    `).get(run.run_id) as Row | undefined;
    const contextPacks = boundedRows(this.#database.prepare(`
      SELECT cp.id, cp.purpose, cp.journey, cp.context_budget, cp.created_by,
        cp.created_at, COUNT(ci.node_id) AS item_count,
        SUM(CASE WHEN ci.used = 1 THEN 1 ELSE 0 END) AS used_item_count,
        SUM(CASE WHEN ci.corrected = 1 THEN 1 ELSE 0 END) AS corrected_item_count
      FROM memory_context_packs cp
      LEFT JOIN memory_context_items ci ON ci.context_pack_id = cp.id
      WHERE cp.run_id = ? GROUP BY cp.id ORDER BY cp.created_at, cp.id LIMIT ?
    `).all(run.run_id, REPORT_RECORD_LIMIT + 1) as Row[]);

    const verifiedFindings = findings.records.filter((item) =>
      item.review_status === "verified" && Number(item.verified_support_count ?? 0) > 0);
    const reviewFindings = findings.records.filter((item) => !verifiedFindings.includes(item));
    const sectionTruncation = {
      plans: plans.truncated,
      steps: steps.truncated,
      actions: actions.truncated,
      engagementLogs: logs.truncated,
      observations: observations.truncated,
      verifiedEvidence: evidence.truncated,
      findings: findings.truncated,
      topologyNodes: nodes.truncated,
      topologyEdges: edges.truncated,
      failureDiagnoses: failures.truncated,
      contextPacks: contextPacks.truncated,
    };
    return {
      schemaVersion: CANONICAL_REPORT_SCHEMA_VERSION,
      reportVersion,
      snapshotThrough: run.run_updated_at,
      mission: {
        id: run.mission_id,
        name: rowText(run.mission_name),
        engagementId: run.engagement_id,
        journey: run.mission_journey,
        status: run.mission_status,
        objective: rowText(run.mission_objective),
        scope: safeJson(run.mission_scope_json),
        successCriteria: safeJson(run.success_criteria_json),
        imported: run.mission_control_plane === "legacy",
        controlPlane: run.mission_control_plane,
        createdAt: run.mission_created_at,
        updatedAt: run.mission_updated_at,
      },
      run: {
        id: run.run_id,
        journey: run.run_journey,
        status: run.run_status,
        statusReason: run.run_status_reason ? rowText(run.run_status_reason) : null,
        progress: Number(run.run_progress),
        currentPlanId: run.current_plan_id,
        currentStepId: run.current_step_id,
        nextAction: run.next_action_summary ? rowText(run.next_action_summary) : null,
        controlPlane: run.run_control_plane,
        startedAt: run.started_at,
        endedAt: run.ended_at,
        createdAt: run.run_created_at,
        updatedAt: run.run_updated_at,
      },
      plan: {
        records: steps.records.map((item) => ({
          id: item.id,
          planId: item.plan_id,
          ordinal: Number(item.ordinal),
          phase: rowText(item.phase),
          title: rowText(item.title),
          objective: rowText(item.objective),
          status: item.status,
          actionClass: item.action_class,
          riskClass: item.risk_class,
        })),
        versions: plans.records.map((item) => ({
          id: item.id,
          version: Number(item.version),
          status: item.status,
          strategySummary: rowText(item.strategy_summary),
          rationaleSummary: item.rationale_summary ? rowText(item.rationale_summary) : null,
          planHash: item.plan_hash,
        })),
        truncated: plans.truncated || steps.truncated,
      },
      actions: {
        records: actions.records.map((item) => ({
          id: item.id,
          stepId: item.step_id,
          actionType: item.action_type,
          actionClass: item.action_class,
          target: item.scoped_target ? rowText(item.scoped_target) : null,
          status: item.status,
          intent: rowText(item.intent_summary),
          result: item.result_summary ? rowText(item.result_summary) : null,
          errorCategory: item.error_category,
          retryCount: Number(item.retry_count),
          startedAt: item.started_at,
          endedAt: item.ended_at,
        })),
        truncated: actions.truncated,
      },
      engagementLogs: {
        classification: "technical_record_not_evidence",
        records: logs.records.map((item) => ({
          id: item.id,
          severity: item.severity,
          domain: item.domain,
          recordType: item.record_type,
          summary: rowText(item.human_summary),
          occurredAt: item.occurred_at,
        })),
        rawPayloadsOmitted: true,
        truncated: logs.truncated,
      },
      observations: {
        classification: "parsed_statement_not_automatically_verified",
        records: observations.records.map((item) => ({
          id: item.id,
          observationType: item.observation_type,
          statement: rowText(item.statement),
          confidence: Number(item.confidence),
          verificationState: item.verification_state,
          sourceTool: item.source_tool,
          firstSeenAt: item.first_seen_at,
          lastSeenAt: item.last_seen_at,
        })),
        rawValuesOmitted: true,
        truncated: observations.truncated,
      },
      verifiedEvidence: {
        classification: "canonical_verified_evidence_only",
        records: evidence.records.map((item) => ({
          id: item.id,
          evidenceType: item.evidence_type,
          summary: rowText(item.summary),
          contentHash: item.content_hash,
          confidence: Number(item.confidence),
          source: rowText(item.source),
          target: item.target ? rowText(item.target) : null,
          acquiredAt: item.acquired_at,
        })),
        extractedTextOmitted: true,
        provenancePayloadOmitted: true,
        truncated: evidence.truncated,
      },
      findings: {
        verified: verifiedFindings.map((item) => ({
          id: item.id,
          title: rowText(item.title),
          severity: item.severity,
          confidence: Number(item.confidence),
          affectedScope: rowText(item.affected_scope),
          description: rowText(item.description),
          impact: rowText(item.impact),
          remediation: item.remediation ? rowText(item.remediation) : null,
          verifiedSupportCount: Number(item.verified_support_count),
        })),
        reviewRequired: reviewFindings.map((item) => ({
          id: item.id,
          title: rowText(item.title),
          severity: item.severity,
          reviewStatus: item.review_status,
          verifiedSupportCount: Number(item.verified_support_count ?? 0),
          reviewReason: item.review_status !== "verified"
            ? `Finding review state is ${rowText(item.review_status)}.`
            : "No supporting verified evidence passed the canonical evidence gate.",
        })),
        unverifiedClaimsNotAsserted: true,
        truncated: findings.truncated,
      },
      topology: {
        nodes: nodes.records.map((item) => {
          const label = reportTopologyLabel(item);
          return {
            id: item.id,
            nodeType: item.node_type,
            label: label.label,
            labelDisclosure: label.disclosure,
            scopeStatus: item.scope_status,
            lifecycleState: item.lifecycle_state,
            confidence: Number(item.confidence),
            verificationState: item.verification_state,
            originatingTool: item.originating_tool,
            firstSeenAt: item.first_seen_at,
            lastSeenAt: item.last_seen_at,
          };
        }),
        edges: edges.records.map((item) => ({
          id: item.id,
          sourceNodeId: item.source_node_id,
          targetNodeId: item.target_node_id,
          edgeType: item.edge_type,
          confidence: Number(item.confidence),
          verificationState: item.verification_state,
          firstSeenAt: item.first_seen_at,
          lastSeenAt: item.last_seen_at,
        })),
        propertiesOmitted: true,
        identitiesOutsideAuthorizedScopeOmitted: true,
        truncated: nodes.truncated || edges.truncated,
      },
      failureDiagnoses: {
        records: failures.records.map((item) => ({
          id: item.id,
          subjectType: item.subject_type,
          subjectId: item.subject_id,
          reason: rowText(item.human_reason),
          category: item.category,
          code: item.code,
          retryable: Boolean(item.retryable),
          remediation: rowText(item.remediation),
          objectiveImpact: rowText(item.objective_impact),
          state: item.state,
          createdAt: item.created_at,
          resolvedAt: item.resolved_at,
        })),
        rawErrorsOmitted: true,
        truncated: failures.truncated,
      },
      evaluation: evaluation ? {
        id: evaluation.id,
        scores: safeEvaluationRecord(evaluation.scores_json),
        metrics: safeEvaluationRecord(evaluation.metrics_json),
        retrospective: rowText(evaluation.retrospective),
        evidenceCoverage: Number(evaluation.evidence_coverage),
        createdBy: evaluation.created_by,
        createdAt: evaluation.created_at,
      } : null,
      contextPacks: {
        records: contextPacks.records.map((item) => ({
          id: item.id,
          purpose: rowText(item.purpose),
          journey: item.journey,
          contextBudget: Number(item.context_budget),
          itemCount: Number(item.item_count),
          usedItemCount: Number(item.used_item_count ?? 0),
          correctedItemCount: Number(item.corrected_item_count ?? 0),
          createdBy: item.created_by,
          createdAt: item.created_at,
        })),
        memoryContentOmitted: true,
        truncated: contextPacks.truncated,
      },
      bounds: { maximumRecordsPerSection: REPORT_RECORD_LIMIT, truncation: sectionTruncation },
      privacy: {
        redacted: true,
        omitted: [
          "raw command and tool output",
          "technical payload JSON",
          "normalized action arguments",
          "evidence extracted text and provenance payloads",
          "topology identities outside confirmed authorized scope",
          "provider prompts and responses",
          "memory node bodies and rejected context",
          "credentials, secrets, cookies, private keys, and tokens",
        ],
      },
    };
  }

  #appendAudit(
    run: MissionRunRow,
    reportVersion: number,
    sourceSnapshotHash: string,
    artifacts: readonly CanonicalReportArtifact[],
    actor: OperationsActor,
    idempotencyKey: string,
    occurredAt: string,
  ): void {
    const previous = this.#database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { readonly record_hash: string } | undefined;
    const id = `audit_${randomUUID()}`;
    const details = {
      reportVersion,
      sourceSnapshotHash,
      artifactIds: artifacts.map((item) => item.id),
      contentHashes: artifacts.map((item) => item.contentHash),
      idempotencyKeyHash: sha256(idempotencyKey),
      rawPayloadsExcluded: true,
      unverifiedFindingsNotAsserted: true,
    };
    const record = {
      id,
      missionId: run.mission_id,
      runId: run.run_id,
      journey: run.run_journey,
      actorType: actor.type,
      actorId: actor.id,
      action: "report.generated",
      resourceType: "run",
      resourceId: run.run_id,
      reason: "Generated deterministic redacted Markdown and JSON mission report artifacts.",
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt,
    };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(record)}`);
    this.#database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      run.mission_id,
      run.run_id,
      run.run_journey,
      actor.type,
      actor.id,
      record.action,
      record.resourceType,
      record.resourceId,
      record.reason,
      canonicalJson(details),
      record.previousHash,
      recordHash,
      occurredAt,
    );
  }
}
