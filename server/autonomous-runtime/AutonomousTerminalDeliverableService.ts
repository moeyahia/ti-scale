import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import type { DeliverableId } from "../domain/catalog-ids";
import { AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS } from "../domain/autonomous-outcome-registry";
import { EventRepository } from "../events";
import { OperationalTruthService } from "../intelligence-v24";
import { MemoryRepository } from "../memory";
import { OperationsApiError } from "../operations/errors";
import type { OperationsAccessPolicy } from "../operations/types";
import { canonicalJson } from "../operations/validation";
import {
  CANONICAL_REPORT_ARTIFACT_TYPES,
  CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION,
  CanonicalMissionReportService,
  createCanonicalReportArtifactCommitment,
  type CanonicalReportArtifactCommitment,
  type CanonicalReportPresentation,
  type CanonicalReportGeneration,
} from "../reports";
import {
  AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
} from "./AutonomousIpEvidenceVerifier";
import {
  AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID,
  AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION,
} from "./AutonomousDeterministicFindingPolicy";
import {
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
} from "./AutonomousIpSafeRecon";

export const AUTONOMOUS_TERMINAL_DELIVERABLE_SCHEMA_VERSION =
  "ti-scale.autonomous-terminal-deliverables.v1" as const;
export const AUTONOMOUS_TERMINAL_REPORT_VERSION = 1 as const;
export const AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_SCHEMA_VERSION =
  "ti-scale.autonomous-terminal-report-preferences.v1" as const;
export const AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_EVENT_TYPE =
  "brain.terminal_report_preferences_resolved" as const;

/** Deliverables truthfully fulfilled by the existing paired Markdown/JSON report. */
export const AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS:
  readonly DeliverableId[] = AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS;

const REPORT_DELIVERABLE_IDS = new Set<string>(AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS);
const MAX_FINDING_POLICY_EVIDENCE = 1_000;
const SYSTEM_ACTOR = Object.freeze({
  id: "system:autonomous-terminal-deliverables",
  type: "system" as const,
});
const SYSTEM_ACCESS: OperationsAccessPolicy = Object.freeze({
  maximumSensitivity: "restricted",
  allEngagements: true,
  allowGlobalKnowledge: true,
  allowUnscopedSystemData: true,
});

interface TerminalRunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
  readonly control_plane: "legacy" | "ti_scale";
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly budget_json: string;
  readonly budget_usage_json: string;
  readonly mission_journey: "autonomous" | "guided";
  readonly mission_status: string;
  readonly mission_control_plane: "legacy" | "ti_scale";
  readonly contract_version: number | null;
  readonly contract_hash: string | null;
  readonly contract_state: string | null;
  readonly action_policy_json: string | null;
  readonly contract_budgets_json: string | null;
  readonly deliverables_json: string | null;
}

interface EvidenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly action_id: string;
  readonly source: string;
  readonly target: string;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly confidence: number;
  readonly extracted_text: string;
  readonly created_by: string;
  readonly action_status: string;
  readonly acquired_count: number;
  readonly verified_count: number;
}

interface ObservationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly observation_type: string;
  readonly normalized_value_json: string;
  readonly confidence: number;
  readonly verification_state: string;
  readonly source_tool: string | null;
}

interface DeterministicFinding {
  readonly id: string;
  readonly evidenceId: string;
  readonly title: string;
  readonly severity: "low";
  readonly confidence: number;
  readonly affectedScope: string;
  readonly description: string;
  readonly impact: string;
  readonly remediation: string;
}

interface TerminalProjectionEventRow {
  readonly payload_json: string;
}

interface TerminalPreferenceRow {
  readonly node_id: string;
  readonly relevance_reason: string;
  readonly preference_key: string;
  readonly value_json: string;
}

interface TerminalReportPreferenceResolution {
  readonly contextPackId: string;
  readonly presentation: CanonicalReportPresentation | null;
}

export interface AutonomousTerminalDeliverableResult {
  readonly schemaVersion: typeof AUTONOMOUS_TERMINAL_DELIVERABLE_SCHEMA_VERSION;
  readonly runId: string;
  readonly selectedDeliverableIds: readonly DeliverableId[];
  readonly findingIds: readonly string[];
  readonly report: CanonicalReportGeneration | null;
  readonly idempotent: true;
}

export interface AutonomousTerminalCommit<T> {
  readonly terminal: T;
  readonly deliverables: AutonomousTerminalDeliverableResult;
}

export interface AutonomousTerminalDeliverablePort {
  /**
   * Owns the outer synchronous transaction and invokes `commitTerminal`
   * before reading the provisional terminal state. A thrown callback or
   * closeout failure rolls back the terminal transition, findings, artifact
   * rows, and newly materialized report files as one compensated operation.
   */
  completeAtomically<T>(
    runId: string,
    commitTerminal: (reportCommitment: CanonicalReportArtifactCommitment | null) => T,
  ): AutonomousTerminalCommit<T>;
}

export class AutonomousTerminalDeliverableError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly retryable: boolean,
    readonly category:
      | "invalid_state"
      | "policy_denied"
      | "budget_exhausted"
      | "dependency_unavailable"
      | "reconciliation_required",
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "AutonomousTerminalDeliverableError";
  }
}

export interface AutonomousTerminalDeliverableServiceOptions {
  /** Optional absolute override; file-backed databases use the canonical report default. */
  readonly artifactRoot?: string;
  readonly clock?: () => Date;
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseRecord(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plainRecord(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new AutonomousTerminalDeliverableError(
      "autonomous_terminal_contract_malformed",
      `The canonical ${label} is malformed; terminal deliverables were not created.`,
      false,
      "reconciliation_required",
    );
  }
}

function parseStringArray(value: string | null, label: string): readonly string[] {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (
      !Array.isArray(parsed)
      || parsed.some((item) => typeof item !== "string" || item.trim() !== item || !item)
      || new Set(parsed).size !== parsed.length
    ) throw new Error("not a unique string array");
    return parsed as string[];
  } catch {
    throw new AutonomousTerminalDeliverableError(
      "autonomous_terminal_deliverables_malformed",
      `The canonical ${label} is malformed; terminal deliverables were not created.`,
      false,
      "reconciliation_required",
    );
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function stringArray(value: unknown): readonly string[] | null {
  return Array.isArray(value)
    && value.every((item) => typeof item === "string")
    ? value as readonly string[]
    : null;
}

function canonicalReportPreference(
  row: TerminalPreferenceRow,
): "technical_readable" | "evidence_first" | null {
  let profile: Readonly<Record<string, unknown>>;
  try {
    const parsed = JSON.parse(row.value_json) as unknown;
    if (!plainRecord(parsed)) return null;
    profile = parsed;
  } catch {
    return null;
  }
  const appliesTo = stringArray(profile.appliesTo);
  const value = plainRecord(profile.value) ? profile.value : null;
  if (!appliesTo || !value || !appliesTo.includes("reports")) return null;
  if (
    row.preference_key === "communication.technical_readability"
    && appliesTo.includes("evidence_presentation")
    && value.style === "technical_readable"
  ) return "technical_readable";
  const structure = stringArray(value.structure);
  if (
    row.preference_key === "communication.evidence_first"
    && appliesTo.includes("evidence_presentation")
    && value.rawLogs === "not_automatically_evidence"
    && structure?.join("\n")
      === ["observation", "meaning", "confidence", "uncertainty", "next justified action"].join("\n")
  ) return "evidence_first";
  return null;
}

function normalizedHost(value: unknown): string | null {
  if (typeof value !== "string" || !value || value.length > 253) return null;
  if (isIP(value) > 0) return value.toLocaleLowerCase("en-US");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/u.test(value)) return null;
  return value.toLocaleLowerCase("en-US");
}

function telnetPorts(value: unknown): readonly number[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.flatMap((candidate) => {
    if (!plainRecord(candidate)) return [];
    if (
      candidate.transport !== "tcp"
      || candidate.state !== "open"
      || typeof candidate.port !== "number"
      || !Number.isSafeInteger(candidate.port)
      || candidate.port < 1
      || candidate.port > 65_535
      || typeof candidate.service !== "string"
      || candidate.service.toLocaleLowerCase("en-US") !== "telnet"
    ) return [];
    return [candidate.port];
  }))].sort((left, right) => left - right);
}

function hasFindingPolicyReference(provenance: Readonly<Record<string, unknown>>): boolean {
  const references = provenance.deterministicFindingPolicyReferences;
  if (!Array.isArray(references)) return false;
  return references.some((reference) => plainRecord(reference)
    && exactKeys(reference, ["policyId", "schemaVersion"])
    && reference.schemaVersion === AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION
    && reference.policyId === AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID);
}

function sameNumbers(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/**
 * Deterministic pre-terminal closeout for the local Autonomous runtime.
 *
 * Raw logs, ordinary observations, successful exits, and even generic
 * verified evidence never become findings here. The only current finding
 * policy requires an explicit verifier-issued policy reference plus matching,
 * custody-complete service-fingerprint evidence and its attributable
 * canonical observation.
 */
export class AutonomousTerminalDeliverableService implements AutonomousTerminalDeliverablePort {
  readonly #reports: CanonicalMissionReportService;
  readonly #events: EventRepository;
  readonly #memory: MemoryRepository;
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    options: AutonomousTerminalDeliverableServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#events = new EventRepository(database);
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
    this.#reports = new CanonicalMissionReportService(database, {
      ...(options.artifactRoot === undefined ? {} : { artifactRoot: options.artifactRoot }),
      clock: this.#clock,
    });
  }

  completeAtomically<T>(
    runId: string,
    commitTerminal: (reportCommitment: CanonicalReportArtifactCommitment | null) => T,
  ): AutonomousTerminalCommit<T> {
    if (!runId.trim()) throw new TypeError("Autonomous terminal run ID is required");
    if (this.database.inTransaction) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_outer_transaction_required",
        "Autonomous terminal deliverables must own the outer transaction for filesystem compensation.",
        false,
        "invalid_state",
      );
    }
    return this.#reports.withMaterializationCompensation(() =>
      inImmediateTransaction(this.database, () => {
        const reportCommitment = this.#reportCommitment(runId.trim());
        const terminal = commitTerminal(reportCommitment);
        const deliverables = this.#closeout(runId.trim());
        this.#assertReportCommitmentFulfilled(reportCommitment, deliverables);
        return { terminal, deliverables };
      }));
  }

  #reportCommitment(runId: string): CanonicalReportArtifactCommitment | null {
    const row = this.database.prepare(`
      SELECT r.id, r.mission_id, r.journey, r.control_plane,
        r.contract_id, r.contract_version_bound, r.contract_hash_bound,
        m.journey AS mission_journey,
        m.control_plane AS mission_control_plane,
        mc.version AS contract_version, mc.contract_hash,
        mc.state AS contract_state, mc.action_policy_json,
        mc.deliverables_json
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      LEFT JOIN mission_contracts mc
        ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      WHERE r.id = ?
    `).get(runId) as Pick<
      TerminalRunRow,
      | "id"
      | "mission_id"
      | "journey"
      | "control_plane"
      | "contract_id"
      | "contract_version_bound"
      | "contract_hash_bound"
      | "mission_journey"
      | "mission_control_plane"
      | "contract_version"
      | "contract_hash"
      | "contract_state"
      | "action_policy_json"
      | "deliverables_json"
    > | undefined;
    if (!row) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_run_missing",
        "The Autonomous run disappeared before its terminal report commitment was bound.",
        false,
        "reconciliation_required",
      );
    }
    if (
      row.journey !== "autonomous"
      || row.mission_journey !== "autonomous"
      || row.control_plane !== "ti_scale"
      || row.mission_control_plane !== "ti_scale"
      || !row.contract_id
      || row.contract_state !== "confirmed"
      || row.contract_version === null
      || row.contract_version !== row.contract_version_bound
      || row.contract_hash === null
      || row.contract_hash !== row.contract_hash_bound
      || !row.deliverables_json
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_commitment_boundary_mismatch",
        "The run, mission, and signed contract do not form one exact Autonomous report commitment boundary.",
        false,
        "reconciliation_required",
      );
    }
    const policy = parseRecord(row.action_policy_json, "contract action policy");
    if (policy.reportingFormat !== "ti_scale_json" || policy.dataHandlingPolicy !== "local_private") {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_reporting_policy_mismatch",
        "The signed contract does not authorize the local canonical Ti-Scale report path.",
        false,
        "policy_denied",
      );
    }
    const selected = parseStringArray(row.deliverables_json, "contract deliverables");
    const unsupported = selected.filter((id) => !REPORT_DELIVERABLE_IDS.has(id));
    if (unsupported.length > 0) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_deliverable_unsupported",
        `The signed contract selects terminal deliverables without a canonical producer: ${unsupported.join(", ")}.`,
        false,
        "policy_denied",
      );
    }
    return selected.length > 0
      ? createCanonicalReportArtifactCommitment(runId, AUTONOMOUS_TERMINAL_REPORT_VERSION)
      : null;
  }

  #assertReportCommitmentFulfilled(
    commitment: CanonicalReportArtifactCommitment | null,
    deliverables: AutonomousTerminalDeliverableResult,
  ): void {
    if (!commitment) {
      if (deliverables.report !== null) {
        throw new AutonomousTerminalDeliverableError(
          "autonomous_terminal_uncommitted_report",
          "Terminal report artifacts were created without a matching in-transaction commitment.",
          false,
          "reconciliation_required",
        );
      }
      return;
    }
    const report = deliverables.report;
    if (
      !report
      || report.runId !== commitment.runId
      || report.reportVersion !== commitment.reportVersion
      || report.artifacts.length !== commitment.artifactTypes.length
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_report_commitment_unfulfilled",
        "The canonical report did not fulfill its exact terminal artifact commitment.",
        false,
        "reconciliation_required",
      );
    }
    const expectedFormats = ["markdown", "json"] as const;
    const expectedTypes = new Map([
      ["markdown", CANONICAL_REPORT_ARTIFACT_TYPES.markdown],
      ["json", CANONICAL_REPORT_ARTIFACT_TYPES.json],
    ] as const);
    const byFormat = new Map(report.artifacts.map((artifact) => [artifact.format, artifact]));
    if (
      expectedFormats.some((format) => !byFormat.has(format))
      || new Set(report.artifacts.map(({ id }) => id)).size !== report.artifacts.length
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_report_commitment_unfulfilled",
        "The canonical report artifact pair is incomplete or duplicated.",
        false,
        "reconciliation_required",
      );
    }
    for (const format of expectedFormats) {
      const artifact = byFormat.get(format)!;
      const row = this.database.prepare(`
        SELECT artifact_type,
          json_extract(metadata_json, '$.reportVersion') AS report_version
        FROM artifacts
        WHERE id = ? AND run_id = ? AND content_hash = ? AND byte_size = ?
      `).get(
        artifact.id,
        commitment.runId,
        artifact.contentHash,
        artifact.byteSize,
      ) as {
        readonly artifact_type: string;
        readonly report_version: number | null;
      } | undefined;
      if (
        row?.artifact_type !== expectedTypes.get(format)
        || row?.report_version !== commitment.reportVersion
      ) {
        throw new AutonomousTerminalDeliverableError(
          "autonomous_terminal_report_commitment_unfulfilled",
          "A committed canonical report artifact is missing or has the wrong immutable type.",
          false,
          "reconciliation_required",
        );
      }
    }
  }

  #closeout(runId: string): AutonomousTerminalDeliverableResult {
    const run = this.#terminalRun(runId);
    const selected = parseStringArray(run.deliverables_json, "contract deliverables");
    const unsupported = selected.filter((id) => !REPORT_DELIVERABLE_IDS.has(id));
    if (unsupported.length > 0) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_deliverable_unsupported",
        `The signed contract selects terminal deliverables without a canonical producer: ${unsupported.join(", ")}.`,
        false,
        "policy_denied",
      );
    }
    const selectedDeliverableIds = selected as DeliverableId[];
    const findingIds = this.#materializeDeterministicFindings(run);
    const report = selected.length > 0
      ? this.#generateReport(run, this.#resolveTerminalReportPreferences(run))
      : null;
    return Object.freeze({
      schemaVersion: AUTONOMOUS_TERMINAL_DELIVERABLE_SCHEMA_VERSION,
      runId,
      selectedDeliverableIds: Object.freeze([...selectedDeliverableIds]),
      findingIds: Object.freeze(findingIds),
      report,
      idempotent: true,
    });
  }

  #terminalRun(runId: string): TerminalRunRow {
    const row = this.database.prepare(`
      SELECT r.id, r.mission_id, r.journey, r.status, r.control_plane,
        r.contract_id, r.contract_version_bound, r.contract_hash_bound,
        r.budget_json, r.budget_usage_json,
        m.journey AS mission_journey, m.status AS mission_status,
        m.control_plane AS mission_control_plane,
        mc.version AS contract_version, mc.contract_hash,
        mc.state AS contract_state, mc.action_policy_json,
        mc.budgets_json AS contract_budgets_json, mc.deliverables_json
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      LEFT JOIN mission_contracts mc
        ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      WHERE r.id = ?
    `).get(runId) as TerminalRunRow | undefined;
    if (!row) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_run_missing",
        "The Autonomous run disappeared before terminal deliverables were created.",
        false,
        "reconciliation_required",
      );
    }
    const missionStatus = row.status === "completed" ? "completed" : "failed";
    if (
      row.journey !== "autonomous"
      || row.mission_journey !== "autonomous"
      || row.control_plane !== "ti_scale"
      || row.mission_control_plane !== "ti_scale"
      || (row.status !== "completed" && row.status !== "failed")
      || row.mission_status !== missionStatus
      || !row.contract_id
      || row.contract_state !== "confirmed"
      || row.contract_version === null
      || row.contract_version !== row.contract_version_bound
      || row.contract_hash === null
      || row.contract_hash !== row.contract_hash_bound
      || !row.deliverables_json
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_boundary_mismatch",
        "The provisional terminal run, mission, and signed contract do not form one exact Autonomous closeout boundary.",
        false,
        "reconciliation_required",
      );
    }
    const policy = parseRecord(row.action_policy_json, "contract action policy");
    if (policy.reportingFormat !== "ti_scale_json" || policy.dataHandlingPolicy !== "local_private") {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_reporting_policy_mismatch",
        "The signed contract does not authorize the local canonical Ti-Scale report path.",
        false,
        "policy_denied",
      );
    }
    const evaluation = this.database.prepare(`
      SELECT 1 AS present FROM run_evaluations
      WHERE run_id = ? AND mission_id = ? AND journey = 'autonomous'
      LIMIT 1
    `).get(row.id, row.mission_id);
    if (!evaluation) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_evaluation_missing",
        "The canonical terminal evaluation is not yet available for report generation.",
        true,
        "dependency_unavailable",
      );
    }
    return row;
  }

  #materializeDeterministicFindings(run: TerminalRunRow): readonly string[] {
    const rows = this.database.prepare(`
      SELECT e.id, e.mission_id, e.run_id, e.step_id, e.action_id,
        e.source, e.target, e.evidence_type, e.content_hash,
        e.provenance_json, e.confidence, e.extracted_text, e.created_by,
        a.status AS action_status,
        (SELECT COUNT(*) FROM evidence_chain_events acquired
          WHERE acquired.evidence_id = e.id AND acquired.event_type = 'acquired') AS acquired_count,
        (SELECT COUNT(*) FROM evidence_chain_events verified
          WHERE verified.evidence_id = e.id AND verified.event_type = 'verified') AS verified_count
      FROM evidence e
      JOIN actions a ON a.id = e.action_id AND a.run_id = e.run_id
      WHERE e.run_id = ? AND e.mission_id = ? AND ${verifiedEvidenceSql("e")}
        AND json_type(e.provenance_json, '$.deterministicFindingPolicyReferences') = 'array'
      ORDER BY e.acquired_at, e.id
      LIMIT ?
    `).all(run.id, run.mission_id, MAX_FINDING_POLICY_EVIDENCE + 1) as EvidenceRow[];
    if (rows.length > MAX_FINDING_POLICY_EVIDENCE) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_finding_policy_limit_exceeded",
        "The bounded deterministic finding-policy evidence limit was exceeded.",
        false,
        "budget_exhausted",
      );
    }
    const truth = new OperationalTruthService(this.database, { clock: this.#clock });
    const findingIds: string[] = [];
    for (const evidence of rows) {
      for (const finding of this.#telnetFindings(evidence)) {
        const existing = this.database.prepare("SELECT 1 AS present FROM findings WHERE id = ?")
          .get(finding.id);
        if (!existing) {
          const now = this.#clock().toISOString();
          this.database.prepare(`
          INSERT INTO findings (
            id, mission_id, run_id, title, severity, confidence,
            affected_scope, description, impact, remediation,
            review_status, operator_override, version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'under_review', 0, 1, ?, ?)
        `).run(
            finding.id,
            run.mission_id,
            run.id,
            finding.title,
            finding.severity,
            finding.confidence,
            finding.affectedScope,
            finding.description,
            finding.impact,
            finding.remediation,
            now,
            now,
          );
          truth.linkEvidenceToFinding({
            findingId: finding.id,
            evidenceId: finding.evidenceId,
            relationship: "supports",
            actor: SYSTEM_ACTOR,
            reason: `Apply the explicit ${AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID} policy only to its exact custody-complete verified evidence.`,
          });
          const readiness = truth.verifyFinding({
            findingId: finding.id,
            expectedVersion: 1,
            actor: SYSTEM_ACTOR,
            reason: "The allowlisted deterministic finding policy and its exact verified observation/evidence binding both passed.",
          });
          if (!readiness.sufficient) {
            throw new AutonomousTerminalDeliverableError(
              "autonomous_terminal_finding_evidence_insufficient",
              "A deterministic finding failed the canonical evidence-readiness gate.",
              false,
              "reconciliation_required",
            );
          }
        } else {
          this.#assertExistingFinding(finding, run);
        }
        findingIds.push(finding.id);
      }
    }
    return Object.freeze([...new Set(findingIds)].sort());
  }

  #telnetFindings(evidence: EvidenceRow): readonly DeterministicFinding[] {
    if (
      evidence.action_status !== "succeeded"
      || evidence.evidence_type !== AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE
      || evidence.created_by !== "autonomous-ip-evidence-verifier"
      || !evidence.source.startsWith("specialist:")
      || !/^[a-f0-9]{64}$/u.test(evidence.content_hash)
      || evidence.acquired_count < 1
      || evidence.verified_count < 1
      || sha256(evidence.extracted_text) !== evidence.content_hash
    ) return [];
    let provenance: Readonly<Record<string, unknown>>;
    let extracted: Readonly<Record<string, unknown>>;
    try {
      const provenanceValue = JSON.parse(evidence.provenance_json) as unknown;
      const extractedValue = JSON.parse(evidence.extracted_text) as unknown;
      if (!plainRecord(provenanceValue) || !plainRecord(extractedValue)) return [];
      provenance = provenanceValue;
      extracted = extractedValue;
    } catch {
      return [];
    }
    if (
      provenance.schemaVersion !== AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION
      || provenance.method !== "deterministic_reviewed_ip_result_validation"
      || provenance.actionId !== evidence.action_id
      || provenance.toolId !== AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID
      || typeof provenance.specialistAgentId !== "string"
      || evidence.source !== `specialist:${provenance.specialistAgentId}`
      || provenance.rawOutputPromoted !== false
      || provenance.cveClaimsCreated !== false
      || typeof provenance.observationId !== "string"
      || typeof provenance.logRecordId !== "string"
      || !hasFindingPolicyReference(provenance)
    ) return [];
    const observation = this.database.prepare(`
      SELECT id, mission_id, run_id, step_id, observation_type,
        normalized_value_json, confidence, verification_state, source_tool
      FROM observations WHERE id = ?
    `).get(provenance.observationId) as ObservationRow | undefined;
    if (
      !observation
      || observation.mission_id !== evidence.mission_id
      || observation.run_id !== evidence.run_id
      || observation.step_id !== evidence.step_id
      || observation.observation_type !== "tcp_service_scan"
      || observation.verification_state !== "corroborated"
      || observation.source_tool !== AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID
    ) return [];
    const attributableLog = this.database.prepare(`
      SELECT 1 AS present
      FROM observation_log_sources os
      JOIN engagement_log_records l ON l.id = os.log_record_id
      WHERE os.observation_id = ? AND os.log_record_id = ?
        AND l.mission_id = ? AND l.run_id = ? AND l.step_id = ?
      LIMIT 1
    `).get(
      observation.id,
      provenance.logRecordId,
      evidence.mission_id,
      evidence.run_id,
      evidence.step_id,
    );
    if (!attributableLog) return [];
    let normalized: Readonly<Record<string, unknown>>;
    try {
      const parsed = JSON.parse(observation.normalized_value_json) as unknown;
      if (!plainRecord(parsed)) return [];
      normalized = parsed;
    } catch {
      return [];
    }
    const host = normalizedHost(normalized.host);
    const extractedHost = normalizedHost(extracted.host);
    const target = normalizedHost(evidence.target);
    const observationPorts = telnetPorts(normalized.openPorts);
    const evidencePorts = telnetPorts(extracted.fingerprints);
    if (
      normalized.schemaVersion !== AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION
      || normalized.rawOutputPromoted !== false
      || normalized.cveClaimsCreated !== false
      || normalized.actionId !== evidence.action_id
      || normalized.toolId !== AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID
      || !host
      || host !== extractedHost
      || host !== target
      || observationPorts.length === 0
      || !sameNumbers(observationPorts, evidencePorts)
    ) return [];
    return observationPorts.map((port) => {
      const affectedScope = `${host}:${port}/tcp`;
      return Object.freeze({
        id: `finding_auto_${sha256(`${evidence.run_id}\n${AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID}\n${evidence.id}\n${affectedScope}`).slice(0, 40)}`,
        evidenceId: evidence.id,
        title: `Cleartext Telnet service observed on ${affectedScope}`,
        severity: "low" as const,
        confidence: Math.min(0.95, evidence.confidence, observation.confidence),
        affectedScope,
        description: `A reviewed deterministic TCP service scan identified an open Telnet service at the exact authorized target ${affectedScope}.`,
        impact: "Telnet does not provide transport encryption; credentials and session data may be exposed if the service is used over an untrusted path.",
        remediation: "Disable Telnet where unnecessary or replace it with an encrypted, authenticated management protocol; then verify that the Telnet port is closed.",
      });
    });
  }

  #assertExistingFinding(finding: DeterministicFinding, run: TerminalRunRow): void {
    const existing = this.database.prepare(`
      SELECT mission_id, run_id, title, severity, confidence, affected_scope,
        description, impact, remediation, review_status, operator_override, version
      FROM findings WHERE id = ?
    `).get(finding.id) as Readonly<Record<string, unknown>> | undefined;
    const linked = this.database.prepare(`
      SELECT 1 AS present FROM finding_evidence
      WHERE finding_id = ? AND evidence_id = ? AND relationship = 'supports'
    `).get(finding.id, finding.evidenceId);
    if (
      !existing
      || existing.mission_id !== run.mission_id
      || existing.run_id !== run.id
      || existing.title !== finding.title
      || existing.severity !== finding.severity
      || existing.confidence !== finding.confidence
      || existing.affected_scope !== finding.affectedScope
      || existing.description !== finding.description
      || existing.impact !== finding.impact
      || existing.remediation !== finding.remediation
      || existing.review_status !== "verified"
      || existing.operator_override !== 0
      || existing.version !== 2
      || !linked
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_finding_id_conflict",
        "A deterministic finding ID already identifies different or incomplete canonical state.",
        false,
        "reconciliation_required",
      );
    }
  }

  #resolveTerminalReportPreferences(
    run: TerminalRunRow,
  ): CanonicalReportPresentation | undefined {
    const projection = this.database.prepare(`
      SELECT payload_json FROM events
      WHERE run_id = ? AND event_type = 'brain.terminal_projection_context_selected'
      ORDER BY sequence DESC LIMIT 1
    `).get(run.id) as TerminalProjectionEventRow | undefined;
    if (!projection) return undefined;
    let projectionPayload: Readonly<Record<string, unknown>>;
    try {
      const parsed = JSON.parse(projection.payload_json) as unknown;
      if (!plainRecord(parsed) || typeof parsed.reportingContextPackId !== "string") {
        throw new Error("invalid projection payload");
      }
      projectionPayload = parsed;
    } catch (error) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_reporting_context_malformed",
        "The terminal reporting Context Pack selection is malformed.",
        false,
        "reconciliation_required",
        { cause: error },
      );
    }
    const contextPackId = String(projectionPayload.reportingContextPackId);
    const stored = this.#storedTerminalReportPreferenceResolution(run, contextPackId);
    if (stored) return stored.presentation ?? undefined;

    let pack: ReturnType<MemoryRepository["requireContextPack"]>;
    try {
      pack = this.#memory.requireContextPack(contextPackId);
    } catch (error) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_reporting_context_missing",
        "The selected terminal reporting Context Pack is unavailable.",
        false,
        "reconciliation_required",
        { cause: error },
      );
    }
    if (
      pack.missionId !== run.mission_id
      || pack.runId !== run.id
      || pack.journey !== "autonomous"
      || pack.releaseDataClass !== "canonical"
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_reporting_context_mismatch",
        "The selected terminal reporting Context Pack does not belong to this exact canonical Autonomous run.",
        false,
        "reconciliation_required",
      );
    }
    const now = this.#clock().toISOString();
    const rows = this.database.prepare(`
      SELECT n.id AS node_id, ci.relevance_reason,
        profile.preference_key, profile.value_json
      FROM memory_context_items ci
      JOIN memory_nodes n ON n.id = ci.node_id
      JOIN preference_profiles profile ON profile.source_node_id = n.id
      WHERE ci.context_pack_id = ?
        AND n.node_type = 'preference'
        AND n.lifecycle_status = 'confirmed'
        AND n.confirmation_state = 'confirmed'
        AND n.author_type = 'operator'
        AND (n.expires_at IS NULL OR n.expires_at > ?)
        AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.confirmed_at IS NOT NULL
        AND (profile.expires_at IS NULL OR profile.expires_at > ?)
        AND NOT EXISTS (
          SELECT 1 FROM preference_profiles newer
          WHERE newer.source_node_id = profile.source_node_id
            AND newer.preference_key = profile.preference_key
            AND newer.confirmation_state = 'confirmed'
            AND (newer.expires_at IS NULL OR newer.expires_at > ?)
            AND newer.version > profile.version
        )
      ORDER BY ci.rank, n.id, profile.preference_key
    `).all(contextPackId, now, now, now) as TerminalPreferenceRow[];

    let narrativeStyle: CanonicalReportPresentation["narrativeStyle"] = "canonical";
    let evidencePresentation:
      CanonicalReportPresentation["evidencePresentation"] = "canonical";
    const appliedRows: TerminalPreferenceRow[] = [];
    const appliedPreferenceKeys = new Set<string>();
    const appliedPreferenceNodeIds = new Set<string>();
    for (const row of rows) {
      const preference = canonicalReportPreference(row);
      if (!preference || appliedPreferenceKeys.has(row.preference_key)) continue;
      if (preference === "technical_readable") narrativeStyle = preference;
      if (preference === "evidence_first") evidencePresentation = preference;
      appliedRows.push(row);
      appliedPreferenceKeys.add(row.preference_key);
      appliedPreferenceNodeIds.add(row.node_id);
    }
    const presentation: CanonicalReportPresentation | null =
      appliedPreferenceNodeIds.size > 0
        ? Object.freeze({
            schemaVersion: CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION,
            contextPackId,
            narrativeStyle,
            evidencePresentation,
            appliedPreferenceNodeIds: Object.freeze([...appliedPreferenceNodeIds]),
            appliedPreferenceKeys: Object.freeze([...appliedPreferenceKeys]),
          })
        : null;

    for (const row of appliedRows) {
      this.#memory.setContextItemDisposition(contextPackId, {
        nodeId: row.node_id,
        used: true,
        relevanceReason: row.relevance_reason,
        influenceSummary:
          row.preference_key === "communication.evidence_first"
            ? "Placed canonical verified evidence and evidence-supported findings before activity detail; raw logs and observations retained their non-evidence classifications."
            : "Rendered the canonical report in readable technical language with explicit observation, confidence, integrity, impact, and remediation labels.",
      });
    }
    const eventId = `event_terminal_report_preferences_${sha256(`${run.id}\n${contextPackId}`).slice(0, 40)}`;
    this.#events.append({
      id: eventId,
      missionId: run.mission_id,
      runId: run.id,
      journey: "autonomous",
      eventType: AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_EVENT_TYPE,
      occurredAt: now,
      actorType: "system",
      actorId: SYSTEM_ACTOR.id,
      summary: presentation
        ? "Confirmed presentation preferences changed the terminal report layout without changing evidence or policy truth."
        : "The terminal reporting Context Pack contained no supported confirmed presentation preference; canonical defaults were retained.",
      contextPackId,
      payload: {
        schemaVersion: AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_SCHEMA_VERSION,
        contextPackId,
        presentation: presentation
          ? {
              schemaVersion: presentation.schemaVersion,
              contextPackId: presentation.contextPackId,
              narrativeStyle: presentation.narrativeStyle,
              evidencePresentation: presentation.evidencePresentation,
              appliedPreferenceNodeIds: [...presentation.appliedPreferenceNodeIds],
              appliedPreferenceKeys: [...presentation.appliedPreferenceKeys],
            }
          : null,
        safetyBoundary:
          "presentation_only_no_evidence_finding_scope_policy_or_deliverable_change",
      },
    });
    return presentation ?? undefined;
  }

  #storedTerminalReportPreferenceResolution(
    run: TerminalRunRow,
    contextPackId: string,
  ): TerminalReportPreferenceResolution | null {
    const row = this.database.prepare(`
      SELECT payload_json FROM events
      WHERE run_id = ? AND event_type = ?
      ORDER BY sequence DESC LIMIT 1
    `).get(
      run.id,
      AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_EVENT_TYPE,
    ) as TerminalProjectionEventRow | undefined;
    if (!row) return null;
    try {
      const payload = JSON.parse(row.payload_json) as unknown;
      if (
        !plainRecord(payload)
        || payload.schemaVersion !== AUTONOMOUS_TERMINAL_REPORT_PREFERENCE_SCHEMA_VERSION
        || payload.contextPackId !== contextPackId
        || payload.safetyBoundary
          !== "presentation_only_no_evidence_finding_scope_policy_or_deliverable_change"
      ) throw new Error("stored preference resolution does not match the terminal Context Pack");
      if (payload.presentation === null) return { contextPackId, presentation: null };
      if (!plainRecord(payload.presentation)) throw new Error("stored presentation is malformed");
      const nodeIds = stringArray(payload.presentation.appliedPreferenceNodeIds);
      const keys = stringArray(payload.presentation.appliedPreferenceKeys);
      if (
        payload.presentation.schemaVersion !== CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION
        || payload.presentation.contextPackId !== contextPackId
        || (payload.presentation.narrativeStyle !== "technical_readable"
          && payload.presentation.narrativeStyle !== "canonical")
        || (payload.presentation.evidencePresentation !== "evidence_first"
          && payload.presentation.evidencePresentation !== "canonical")
        || !nodeIds
        || nodeIds.length < 1
        || new Set(nodeIds).size !== nodeIds.length
        || !keys
        || keys.length < 1
        || new Set(keys).size !== keys.length
      ) throw new Error("stored presentation is malformed");
      return {
        contextPackId,
        presentation: Object.freeze({
          schemaVersion: CANONICAL_REPORT_PRESENTATION_SCHEMA_VERSION,
          contextPackId,
          narrativeStyle: payload.presentation.narrativeStyle,
          evidencePresentation: payload.presentation.evidencePresentation,
          appliedPreferenceNodeIds: Object.freeze(nodeIds),
          appliedPreferenceKeys: Object.freeze(keys),
        }),
      };
    } catch (error) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_report_preference_resolution_malformed",
        "The persisted terminal report preference resolution requires reconciliation.",
        false,
        "reconciliation_required",
        { cause: error },
      );
    }
  }

  #generateReport(
    run: TerminalRunRow,
    presentation?: CanonicalReportPresentation,
  ): CanonicalReportGeneration {
    const before = new Set((this.database.prepare(`
      SELECT id FROM artifacts WHERE run_id = ?
    `).all(run.id) as Array<{ readonly id: string }>).map(({ id }) => id));
    let report: CanonicalReportGeneration;
    try {
      report = this.#reports.generate(
        run.id,
        AUTONOMOUS_TERMINAL_REPORT_VERSION,
        SYSTEM_ACTOR,
        SYSTEM_ACCESS,
        `autonomous-terminal-${sha256(run.id).slice(0, 32)}-v${AUTONOMOUS_TERMINAL_REPORT_VERSION}`,
        presentation,
      );
    } catch (error) {
      const deterministic = error instanceof TypeError
        || (error instanceof OperationsApiError && error.options.retryable !== true);
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_report_generation_failed",
        error instanceof Error ? error.message : "Canonical terminal report generation failed.",
        !deterministic,
        deterministic ? "reconciliation_required" : "dependency_unavailable",
        { cause: error },
      );
    }
    const newArtifactBytes = report.artifacts
      .filter(({ id }) => !before.has(id))
      .reduce((total, { byteSize }) => total + byteSize, 0);
    const runBudget = parseRecord(run.budget_json, "run budget");
    const contractBudget = parseRecord(run.contract_budgets_json, "contract budget");
    const usage = { ...parseRecord(run.budget_usage_json, "run budget usage") };
    const runLimit = runBudget.artifactBytes;
    const contractLimit = contractBudget.artifactBytes;
    if (
      typeof runLimit !== "number"
      || !Number.isSafeInteger(runLimit)
      || runLimit < 0
      || contractLimit !== runLimit
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_artifact_budget_mismatch",
        "The signed contract and durable run do not carry one exact artifact byte budget.",
        false,
        "reconciliation_required",
      );
    }
    if (
      usage.artifactBytes !== undefined
      && (typeof usage.artifactBytes !== "number"
        || !Number.isSafeInteger(usage.artifactBytes)
        || usage.artifactBytes < 0)
    ) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_artifact_usage_malformed",
        "The durable run artifact-byte usage requires reconciliation.",
        false,
        "reconciliation_required",
      );
    }
    const priorUsage = typeof usage.artifactBytes === "number" ? usage.artifactBytes : 0;
    const storedBytes = Number((this.database.prepare(`
      SELECT COALESCE(SUM(byte_size), 0) AS bytes FROM artifacts WHERE run_id = ?
    `).get(run.id) as { readonly bytes: number }).bytes);
    const accountedBytes = Math.max(storedBytes, priorUsage + newArtifactBytes);
    if (!Number.isSafeInteger(accountedBytes) || accountedBytes > runLimit) {
      throw new AutonomousTerminalDeliverableError(
        "autonomous_terminal_artifact_budget_exhausted",
        "The selected canonical terminal report exceeds the signed artifact byte budget.",
        false,
        "budget_exhausted",
      );
    }
    usage.artifactBytes = accountedBytes;
    this.database.prepare(`
      UPDATE runs SET budget_usage_json = ? WHERE id = ?
    `).run(canonicalJson(usage), run.id);
    return report;
  }
}
