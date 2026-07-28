import { isIP } from "node:net";
import type { SqliteDatabase } from "../db";
import { digestCanonicalJson } from "../mcp";
import type { DurableAction } from "../orchestration";
import {
  AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
} from "./AutonomousFullTcpBaseline";
import {
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION,
  deriveAutonomousWebOrigins,
  type AutonomousWebSurfacePlanningConfiguration,
  type VerifiedTcpServiceFingerprint,
} from "./AutonomousWebSurfaceBaseline";
import type { AutonomousWebSurfacePhase } from "./AutonomousWebSurfaceExecution";

export const AUTONOMOUS_DERIVED_WEB_ORIGIN_AUTHORIZATION_SCHEMA_VERSION =
  "ti-scale.autonomous-derived-web-origin-authorization.v1" as const;

export class AutonomousWebOriginAuthorizationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AutonomousWebOriginAuthorizationError";
  }
}

export interface AuthorizedDerivedWebOrigins {
  readonly schemaVersion: typeof AUTONOMOUS_DERIVED_WEB_ORIGIN_AUTHORIZATION_SCHEMA_VERSION;
  readonly phase: AutonomousWebSurfacePhase;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly parentTarget: string;
  readonly origins: readonly string[];
  readonly sourceEvidenceIds: readonly string[];
  readonly outcome: "contact_required" | "not_applicable";
  readonly authorizationSha256: string;
}

export interface AuthorizedPostWhatWebOrigins {
  readonly parentTarget: string;
  readonly origins: readonly string[];
  readonly sourceEvidenceIds: readonly string[];
  readonly sourceWebAuthorizationSha256: string;
}

interface EvidenceRow {
  readonly id: string;
  readonly extracted_text: string | null;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly target: string | null;
  readonly source_ordinal: number | null;
  readonly current_ordinal: number;
  readonly source_plan_id: string | null;
  readonly current_plan_id: string;
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseObject(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plain(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_source_malformed",
      `The verified ${label} record is malformed.`,
    );
  }
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_ip_required",
      "Derived-origin authorization requires one exact canonical IP parent target.",
    );
  }
  const hostname = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (normalized !== value.toLowerCase()) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_ip_not_canonical",
      "Derived-origin authorization requires the canonical IP spelling in mission scope.",
    );
  }
  return normalized;
}

function sourceRow(
  database: SqliteDatabase,
  action: DurableAction,
  actionType: string,
  evidenceType: string,
): EvidenceRow {
  const rows = database.prepare(`
    SELECT e.id, e.extracted_text, e.content_hash, e.provenance_json,
      source.scoped_target AS target, source_step.ordinal AS source_ordinal,
      current_step.ordinal AS current_ordinal, source_step.plan_id AS source_plan_id,
      current_step.plan_id AS current_plan_id
    FROM actions current
    JOIN plan_steps current_step ON current_step.id = current.step_id
    JOIN evidence e ON e.mission_id = current.mission_id AND e.run_id = current.run_id
      AND e.verification_state = 'verified' AND e.evidence_type = ?
    JOIN actions source ON source.id = e.action_id AND source.run_id = current.run_id
      AND source.mission_id = current.mission_id AND source.action_type = ?
    JOIN plan_steps source_step ON source_step.id = source.step_id
    WHERE current.id = ? AND source.status = 'succeeded'
      AND source.scoped_target = current.scoped_target
    ORDER BY e.acquired_at DESC, e.id DESC LIMIT 2
  `).all(evidenceType, actionType, action.id) as EvidenceRow[];
  if (rows.length !== 1) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_source_evidence_missing_or_ambiguous",
      `The web phase requires exactly one current verified ${evidenceType} source record.`,
    );
  }
  const row = rows[0]!;
  if (row.source_plan_id !== row.current_plan_id || row.source_ordinal === null
    || row.source_ordinal >= row.current_ordinal || row.target !== action.target) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_source_order_invalid",
      "The verified source evidence does not precede this action in the same immutable plan.",
    );
  }
  const content = parseObject(row.extracted_text, `${evidenceType} content`);
  if (digestCanonicalJson(content, { maxBytes: 4 * 1024 * 1024, maxDepth: 32 }).sha256
    !== row.content_hash) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_source_hash_changed",
      "The verified source evidence no longer matches its immutable content hash.",
    );
  }
  return row;
}

function fullTcpOrigins(
  database: SqliteDatabase,
  action: DurableAction,
  configuration: AutonomousWebSurfacePlanningConfiguration,
): Readonly<{ origins: readonly string[]; sourceEvidenceIds: readonly string[] }> {
  const row = sourceRow(
    database, action, AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  );
  const content = parseObject(row.extracted_text, "Full-TCP service fingerprint");
  const provenance = parseObject(row.provenance_json, "Full-TCP provenance");
  if (content.target !== canonicalIp(action.target)
    || content.discoveredPortCoverageComplete !== true
    || !Array.isArray(content.fingerprints)
    || provenance.method !== "deterministic_full_tcp_artifact_and_coverage_validation"
    || provenance.compositeToolId !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
    || provenance.rawProcessOutputPromoted !== false
    || !Array.isArray(provenance.successCriterionReferences)) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_full_tcp_proof_invalid",
      "The preceding Full-TCP record does not carry the complete verified coverage and provenance proof required to derive web origins.",
    );
  }
  return Object.freeze({
    origins: deriveAutonomousWebOrigins(
      action.target,
      content.fingerprints as unknown as VerifiedTcpServiceFingerprint[],
      configuration.maximumOrigins,
    ),
    sourceEvidenceIds: Object.freeze([row.id]),
  });
}

function requirePriorNotApplicableOutcome(
  database: SqliteDatabase,
  action: DurableAction,
  sourceActionType: string,
  successCriterion: string,
  phaseLabel: string,
  sourceEvidenceIds: readonly string[],
): void {
  const rows = database.prepare(`
    SELECT ev.payload_json, source.scoped_target, source.status,
      source_step.ordinal AS source_ordinal, current_step.ordinal AS current_ordinal,
      source_step.plan_id AS source_plan_id, current_step.plan_id AS current_plan_id
    FROM actions current JOIN plan_steps current_step ON current_step.id = current.step_id
    JOIN actions source ON source.run_id = current.run_id
      AND source.mission_id = current.mission_id AND source.action_type = ?
    JOIN plan_steps source_step ON source_step.id = source.step_id
    JOIN events ev ON ev.run_id = source.run_id AND ev.mission_id = source.mission_id
      AND ev.event_type = 'autonomous_criterion_not_applicable'
      AND json_extract(ev.payload_json, '$.actionId') = source.id
    WHERE current.id = ?
    ORDER BY ev.sequence DESC LIMIT 2
  `).all(sourceActionType, action.id) as Array<{
    readonly payload_json: string;
    readonly scoped_target: string | null;
    readonly status: string;
    readonly source_ordinal: number;
    readonly current_ordinal: number;
    readonly source_plan_id: string;
    readonly current_plan_id: string;
  }>;
  if (rows.length !== 1) throw new AutonomousWebOriginAuthorizationError(
    "autonomous_web_http_na_missing_or_ambiguous",
    `${phaseLabel} requires one exact prior not-applicable outcome for an empty verified web surface.`,
  );
  const row = rows[0]!;
  let payload: Readonly<Record<string, unknown>>;
  try { payload = JSON.parse(row.payload_json) as Readonly<Record<string, unknown>>; } catch {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_http_na_malformed",
      "The prior HTTP not-applicable outcome is malformed.",
    );
  }
  if (!plain(payload) || row.status !== "succeeded" || row.scoped_target !== action.target
    || row.source_plan_id !== row.current_plan_id || row.source_ordinal >= row.current_ordinal
    || payload.schemaVersion !== AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION
    || payload.method !== "verified_source_evidence_not_applicable"
    || payload.criterionId !== autonomousSuccessCriterionId(
      successCriterion,
    )
    || payload.outcome !== "not_applicable"
    || !Array.isArray(payload.sourceEvidenceIds)
    || payload.sourceEvidenceIds.join("\u0000") !== sourceEvidenceIds.join("\u0000")
    || typeof payload.outcomeReceiptSha256 !== "string") {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_http_na_invalid",
      "The prior HTTP not-applicable outcome does not match this plan and verified Full-TCP lineage.",
    );
  }
  const { outcomeReceiptSha256, ...body } = payload;
  if (digestCanonicalJson(body, { maxBytes: 2 * 1024 * 1024, maxDepth: 24 }).sha256
    !== outcomeReceiptSha256) throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_http_na_hash_changed",
      "The prior HTTP not-applicable outcome receipt changed.",
    );
}

/**
 * Extends the responding-origin proof through the completed WhatWeb phase.
 * This deliberately does not require endpoint discovery to be configured:
 * vulnerability assessment consumes verified technology-phase lineage, not a
 * later path-enumeration policy.
 */
export function authorizeAutonomousPostWhatWebOrigins(
  database: SqliteDatabase,
  action: DurableAction,
  configuration: AutonomousWebSurfacePlanningConfiguration,
): AuthorizedPostWhatWebOrigins {
  const responding = authorizeAutonomousDerivedWebOrigins(
    database,
    action,
    configuration,
    "whatweb_fingerprint",
  );
  if (responding.origins.length === 0) {
    requirePriorNotApplicableOutcome(
      database,
      action,
      AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
      configuration.whatwebSuccessCriterion,
      "Vulnerability assessment",
      responding.sourceEvidenceIds,
    );
    return Object.freeze({
      parentTarget: responding.parentTarget,
      origins: Object.freeze([]),
      sourceEvidenceIds: responding.sourceEvidenceIds,
      sourceWebAuthorizationSha256: responding.authorizationSha256,
    });
  }
  const fingerprint = sourceRow(
    database,
    action,
    AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  );
  const content = parseObject(fingerprint.extracted_text, "WhatWeb fingerprint");
  const provenance = parseObject(fingerprint.provenance_json, "WhatWeb provenance");
  if (content.parentTarget !== canonicalIp(action.target)
    || content.phase !== "whatweb_fingerprint"
    || !Array.isArray(content.derivedOrigins)
    || content.derivedOrigins.some((origin) => typeof origin !== "string")
    || (content.derivedOrigins as string[]).join("\u0000")
      !== responding.origins.join("\u0000")
    || !Array.isArray(content.responses)
    || provenance.schemaVersion !== AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION
    || provenance.method !== "deterministic_derived_origin_local_process_validation"
    || provenance.virtualToolId !== AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
    || provenance.rawProcessOutputPromoted !== false
    || !Array.isArray(provenance.sourceEvidenceIds)
    || provenance.sourceEvidenceIds.join("\u0000")
      !== responding.sourceEvidenceIds.join("\u0000")) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_vulnerability_fingerprint_proof_invalid",
      "Vulnerability assessment requires the exact completed WhatWeb result from this plan.",
    );
  }
  const fingerprintedOrigins = (content.responses as unknown[]).flatMap((candidate) =>
    plain(candidate) && typeof candidate.origin === "string" ? [candidate.origin] : []);
  if (new Set(fingerprintedOrigins).size !== responding.origins.length
    || responding.origins.some((origin) => !fingerprintedOrigins.includes(origin))) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_vulnerability_fingerprint_proof_incomplete",
      "The preceding technology phase does not cover every origin selected for assessment.",
    );
  }
  return Object.freeze({
    parentTarget: responding.parentTarget,
    origins: responding.origins,
    sourceEvidenceIds: Object.freeze([
      ...responding.sourceEvidenceIds,
      fingerprint.id,
    ]),
    sourceWebAuthorizationSha256: responding.authorizationSha256,
  });
}

function unsigned(
  input: Omit<AuthorizedDerivedWebOrigins, "authorizationSha256">,
): Readonly<Record<string, unknown>> {
  return input;
}

/** Re-derives the closed origin set from canonical verified evidence. */
export function authorizeAutonomousDerivedWebOrigins(
  database: SqliteDatabase,
  action: DurableAction,
  configuration: AutonomousWebSurfacePlanningConfiguration,
  phase: AutonomousWebSurfacePhase,
): AuthorizedDerivedWebOrigins {
  const tcp = fullTcpOrigins(database, action, configuration);
  let origins = tcp.origins;
  let sourceEvidenceIds = tcp.sourceEvidenceIds;
  if (phase === "whatweb_fingerprint" || phase === "endpoint_discovery") {
    if (tcp.origins.length === 0) {
      requirePriorNotApplicableOutcome(
        database,
        action,
        AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
        configuration.httpMetadataSuccessCriterion,
        phase === "whatweb_fingerprint" ? "WhatWeb" : "Endpoint discovery",
        tcp.sourceEvidenceIds,
      );
    } else {
    const metadata = sourceRow(
      database, action, AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
      AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
    );
    const content = parseObject(metadata.extracted_text, "HTTP metadata");
    const provenance = parseObject(metadata.provenance_json, "HTTP metadata provenance");
    if (content.parentTarget !== canonicalIp(action.target)
      || !Array.isArray(content.derivedOrigins)
      || content.derivedOrigins.some((origin) => typeof origin !== "string")
      || !Array.isArray(content.responses)
      || provenance.schemaVersion !== AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION
      || provenance.method !== "deterministic_derived_origin_local_process_validation"
      || provenance.virtualToolId !== AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      || provenance.rawProcessOutputPromoted !== false
      || !Array.isArray(provenance.sourceEvidenceIds)
      || provenance.sourceEvidenceIds.join("\u0000") !== tcp.sourceEvidenceIds.join("\u0000")) {
      throw new AutonomousWebOriginAuthorizationError(
        "autonomous_web_http_proof_invalid",
        "WhatWeb requires the exact prior verified HTTP metadata result from this plan.",
      );
    }
    const responded = new Set((content.responses as unknown[]).flatMap((candidate) =>
      plain(candidate) && typeof candidate.origin === "string" ? [candidate.origin] : []));
    origins = Object.freeze((content.derivedOrigins as string[]).filter((origin) => responded.has(origin)));
    if (origins.some((origin) => !tcp.origins.includes(origin))) {
      throw new AutonomousWebOriginAuthorizationError(
        "autonomous_web_origin_expansion_detected",
        "The HTTP phase contains an origin that cannot be re-derived from the verified Full-TCP baseline.",
      );
    }
    sourceEvidenceIds = Object.freeze([...tcp.sourceEvidenceIds, metadata.id]);
    }
  }
  if (phase === "endpoint_discovery") {
    if (!configuration.endpointDiscoverySuccessCriterion) {
      throw new AutonomousWebOriginAuthorizationError(
        "autonomous_endpoint_discovery_not_configured",
        "The trusted Autonomous web configuration does not enable endpoint discovery.",
      );
    }
    if (origins.length === 0) {
      requirePriorNotApplicableOutcome(
        database,
        action,
        AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
        configuration.whatwebSuccessCriterion,
        "Endpoint discovery",
        sourceEvidenceIds,
      );
    } else {
      const fingerprint = sourceRow(
        database,
        action,
        AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
        AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
      );
      const content = parseObject(fingerprint.extracted_text, "WhatWeb fingerprint");
      const provenance = parseObject(fingerprint.provenance_json, "WhatWeb provenance");
      if (content.parentTarget !== canonicalIp(action.target)
        || content.phase !== "whatweb_fingerprint"
        || !Array.isArray(content.derivedOrigins)
        || content.derivedOrigins.some((origin) => typeof origin !== "string")
        || (content.derivedOrigins as string[]).join("\u0000") !== origins.join("\u0000")
        || !Array.isArray(content.responses)
        || provenance.schemaVersion !== AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION
        || provenance.method !== "deterministic_derived_origin_local_process_validation"
        || provenance.virtualToolId !== AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
        || provenance.rawProcessOutputPromoted !== false
        || !Array.isArray(provenance.sourceEvidenceIds)
        || provenance.sourceEvidenceIds.join("\u0000") !== sourceEvidenceIds.join("\u0000")) {
        throw new AutonomousWebOriginAuthorizationError(
          "autonomous_endpoint_discovery_fingerprint_proof_invalid",
          "Endpoint discovery requires the exact preceding verified technology-fingerprint result from this plan.",
        );
      }
      const fingerprintedOrigins = (content.responses as unknown[]).flatMap((candidate) =>
        plain(candidate) && typeof candidate.origin === "string" ? [candidate.origin] : []);
      if (new Set(fingerprintedOrigins).size !== origins.length
        || origins.some((origin) => !fingerprintedOrigins.includes(origin))) {
        throw new AutonomousWebOriginAuthorizationError(
          "autonomous_endpoint_discovery_origin_proof_incomplete",
          "The preceding technology phase does not cover every exact origin selected for endpoint discovery.",
        );
      }
      sourceEvidenceIds = Object.freeze([...sourceEvidenceIds, fingerprint.id]);
    }
  }
  const body = Object.freeze({
    schemaVersion: AUTONOMOUS_DERIVED_WEB_ORIGIN_AUTHORIZATION_SCHEMA_VERSION,
    phase,
    actionId: action.id,
    actionFingerprint: action.fingerprint,
    parentTarget: canonicalIp(action.target),
    origins: Object.freeze([...origins]),
    sourceEvidenceIds: Object.freeze([...sourceEvidenceIds]),
    outcome: origins.length === 0 ? "not_applicable" as const : "contact_required" as const,
  });
  return Object.freeze({
    ...body,
    authorizationSha256: digestCanonicalJson(unsigned(body), {
      maxBytes: 4 * 1024 * 1024, maxDepth: 24,
    }).sha256,
  });
}

export function verifyAutonomousDerivedWebOriginAuthorization(
  database: SqliteDatabase,
  action: DurableAction,
  configuration: AutonomousWebSurfacePlanningConfiguration,
  authorization: AuthorizedDerivedWebOrigins,
): AuthorizedDerivedWebOrigins {
  const current = authorizeAutonomousDerivedWebOrigins(
    database, action, configuration, authorization.phase,
  );
  if (current.authorizationSha256 !== authorization.authorizationSha256) {
    throw new AutonomousWebOriginAuthorizationError(
      "autonomous_web_authorization_changed",
      "The derived origin authorization changed before target contact.",
    );
  }
  return current;
}
