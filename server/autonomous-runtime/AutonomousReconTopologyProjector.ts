import { isIP } from "node:net";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import type { Observation, Sensitivity } from "../intelligence-v24";
import {
  PageCaptureRepository,
  type PageCaptureArtifactProjection,
  type PageCaptureRecord,
} from "../page-captures";
import {
  ReconDigitalTwinService,
  runScopedTopologyIdentity,
  type CreateTopologyEdgeInput,
  type CreateTopologyNodeInput,
  type RecordOsiObservationInput,
  type TopologyNode,
  type TopologyScopeStatus,
} from "../run-intelligence";
import {
  canonicalObject,
  hashCanonical,
  type JsonObject,
} from "../run-intelligence/serialization";
import {
  AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
} from "./AutonomousDnsSafeRecon";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
} from "./AutonomousWebSurfaceBaseline";

export const AUTONOMOUS_RECON_TOPOLOGY_PROJECTOR_SCHEMA_VERSION =
  "ti-scale.autonomous-recon-topology-projector.v1" as const;

const DNS_EVIDENCE_SCHEMA_VERSION =
  "ti-scale.autonomous-dns-evidence-verifier.v1" as const;
const WEB_EVIDENCE_SCHEMA_VERSION =
  "ti-scale.autonomous-web-evidence-verifier.v1" as const;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAXIMUM_WEB_ORIGINS = 32;
const MAXIMUM_TECHNOLOGY_SIGNALS = 256;
const MAXIMUM_PAGE_CAPTURE_ARTIFACTS = 64;
const PAGE_CAPTURE_ARTIFACT_EVIDENCE_SCHEMA_VERSION =
  "ti-scale.page-capture-artifact-evidence.v1" as const;
const REVIEWED_FFUF_PATHS = Object.freeze([
  "admin",
  "api",
  "assets",
  "docs",
  "health",
  "images",
  "index.html",
  "login",
  "robots.txt",
  "static",
  "status",
  "swagger",
  "uploads",
  ".well-known/security.txt",
] as const);
const SCREENSHOT_ARTIFACT_TYPES = new Set([
  "screenshot",
  "page_capture",
  "web_page_capture",
  "full_page_capture",
]);
const SCREENSHOT_MEDIA_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/avif",
]);
const CAPTURE_TOOL = /^[A-Za-z0-9._:/-]{1,240}$/u;
const PAGE_CAPTURE_ASSET_NODE_TYPES = new Set([
  "asset",
  "host",
  "network_device",
  "cloud_asset",
  "container",
  "cluster",
]);
const PAGE_CAPTURE_SERVICE_NODE_TYPES = new Set([
  "service",
  "application",
  "website",
  "web_application",
  "endpoint",
]);

type ProjectionSkipReason =
  | "unsupported_observation"
  | "not_run_scoped"
  | "observation_not_current"
  | "evidence_not_verified"
  | "evidence_scope_mismatch"
  | "evidence_custody_incomplete"
  | "source_binding_invalid"
  | "normalized_result_invalid"
  | "target_not_allowed";

export interface AutonomousReconTopologyProjection {
  readonly status: "materialized" | "skipped";
  readonly reason: "verified_dns_projection" | "verified_web_projection" | ProjectionSkipReason;
  readonly nodeIds: readonly string[];
  readonly edgeIds: readonly string[];
  readonly osiObservationIds: readonly string[];
}

interface EvidenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly action_id: string | null;
  readonly target: string | null;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly confidence: number;
  readonly verification_state: "unverified" | "verified" | "disputed" | "rejected";
  readonly extracted_text: string | null;
  readonly artifact_id: string | null;
  readonly source: string;
  readonly sensitivity: Sensitivity;
  readonly created_by: string;
  readonly acquired_at: string;
}

interface ValidatedEvidence {
  readonly row: EvidenceRow;
  readonly extracted: Readonly<Record<string, unknown>>;
  readonly provenance: Readonly<Record<string, unknown>>;
}

interface MissionTargetRow {
  readonly id: string;
  readonly target: string;
  readonly target_type: string;
  readonly normalized_target: string;
  readonly disposition: "allowed" | "prohibited";
}

interface WebOrigin {
  readonly href: string;
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly port: number;
}

interface WebEndpointMatch {
  readonly origin: WebOrigin;
  readonly path: string;
  readonly url: string;
  readonly status: number;
  readonly length: number | null;
  readonly words: number | null;
  readonly lines: number | null;
  /** Location text stays out of topology; only its presence is projected. */
  readonly redirectLocationObserved: boolean;
}

interface WebPhaseProperties {
  readonly properties: JsonObject;
  readonly stack: readonly Readonly<{ category: string; value: string }>[];
  readonly technologySignals: readonly Readonly<{ category: string; value: string }>[];
  readonly endpoints: readonly WebEndpointMatch[];
}

interface ArtifactRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly action_id: string | null;
  readonly artifact_type: string;
  readonly content_hash: string;
  readonly byte_size: number;
  readonly media_type: string | null;
  readonly sensitivity: Sensitivity;
}

interface VerifiedPageCaptureArtifact {
  readonly capture: PageCaptureRecord;
  readonly artifact: PageCaptureArtifactProjection;
  readonly artifactRole: "viewport" | "full_page";
  readonly evidence: EvidenceRow;
}

interface OsiExistingRow {
  readonly id: string;
  readonly derivation: string;
  readonly confidence: number;
  readonly evidence_id: string | null;
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parsedRecord(value: string | null): Readonly<Record<string, unknown>> | undefined {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    return plain(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function boundedText(value: unknown, maximum: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001F\u007F]/u.test(normalized)) {
    return undefined;
  }
  return normalized;
}

function canonicalIp(value: unknown): string | undefined {
  const candidate = boundedText(value, 64);
  if (!candidate || isIP(candidate) === 0) return undefined;
  const hostname = new URL(`http://${isIP(candidate) === 6 ? `[${candidate}]` : candidate}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  return normalized === candidate.toLowerCase() ? normalized : undefined;
}

function canonicalDomain(value: unknown): string | undefined {
  const candidate = boundedText(value, 254);
  if (!candidate) return undefined;
  const normalized = (candidate.endsWith(".") ? candidate.slice(0, -1) : candidate)
    .toLocaleLowerCase("en-US");
  if (!normalized || normalized.length > 253) return undefined;
  return normalized.split(".").every((label) =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(label))
    ? normalized
    : undefined;
}

function ipv4Number(value: string): number | undefined {
  if (isIP(value) !== 4) return undefined;
  return value.split(".").reduce((total, item) => total * 256 + Number(item), 0) >>> 0;
}

function ipv4CidrContains(cidr: string, hostname: string): boolean {
  const [networkValue, prefixValue, extra] = cidr.split("/");
  if (!networkValue || !prefixValue || extra !== undefined
    || !/^\d+$/u.test(prefixValue)) return false;
  const network = ipv4Number(networkValue);
  const address = ipv4Number(hostname);
  const prefix = Number(prefixValue);
  if (network === undefined || address === undefined || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffff_ffff << (32 - prefix)) >>> 0;
  return (network & mask) === (address & mask);
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/gu, "\\$&")
    .replaceAll("*", ".*")
    .replaceAll("?", ".");
  try {
    return new RegExp(`^${escaped}$`, "iu").test(value);
  } catch {
    return false;
  }
}

function pathContains(parent: string, child: string): boolean {
  if (parent === "/") return true;
  const root = parent.endsWith("/") ? parent : `${parent}/`;
  return child === parent || child.startsWith(root);
}

function missionTargetMatchesWebUrl(target: MissionTargetRow, endpoint: URL): boolean {
  const normalized = target.normalized_target.trim();
  if (target.target_type === "url" || /^https?:\/\//iu.test(normalized)) {
    let targetUrl: URL;
    try {
      targetUrl = new URL(normalized);
    } catch {
      return false;
    }
    return targetUrl.protocol === endpoint.protocol
      && targetUrl.origin === endpoint.origin
      && pathContains(targetUrl.pathname, endpoint.pathname)
      && (!targetUrl.search || targetUrl.search === endpoint.search);
  }
  const lower = normalized.toLocaleLowerCase("en-US");
  if (target.target_type === "cidr") {
    return ipv4CidrContains(lower, endpoint.hostname);
  }
  if (target.target_type === "pattern") {
    return globMatches(lower, endpoint.hostname.toLocaleLowerCase("en-US"))
      || globMatches(lower, endpoint.toString());
  }
  return lower.replace(/^\[|\]$/gu, "")
    === endpoint.hostname.toLocaleLowerCase("en-US").replace(/^\[|\]$/gu, "");
}

function webOrigin(value: unknown, parentTarget: string): WebOrigin | undefined {
  const candidate = boundedText(value, 1_000);
  if (!candidate) return undefined;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return undefined;
  }
  const scheme = url.protocol === "http:" ? "http"
    : url.protocol === "https:" ? "https" : undefined;
  const host = url.hostname.startsWith("[")
    ? url.hostname.slice(1, -1).toLowerCase()
    : url.hostname.toLowerCase();
  const port = url.port
    ? Number(url.port)
    : scheme === "http" ? 80 : scheme === "https" ? 443 : 0;
  if (!scheme || url.href !== candidate || host !== parentTarget || url.pathname !== "/"
    || url.username || url.password || url.search || url.hash
    || !Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    return undefined;
  }
  return { href: candidate, scheme, host, port };
}

function skipped(reason: ProjectionSkipReason): AutonomousReconTopologyProjection {
  return {
    status: "skipped",
    reason,
    nodeIds: Object.freeze([]),
    edgeIds: Object.freeze([]),
    osiObservationIds: Object.freeze([]),
  };
}

function unique(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)]);
}

/**
 * Projects only the normalized facts carried by canonical verified Autonomous
 * evidence. Raw process output remains in Engagement Logs. The projector never
 * creates evidence, findings, CVE claims, contact authority, or inferred OS
 * facts.
 */
export class AutonomousReconTopologyProjector {
  readonly #topology: ReconDigitalTwinService;
  readonly #pageCaptures: PageCaptureRepository;

  constructor(private readonly database: SqliteDatabase) {
    this.#topology = new ReconDigitalTwinService(database);
    this.#pageCaptures = new PageCaptureRepository(database);
  }

  project(
    observation: Observation,
    verifiedEvidenceIds: readonly string[],
  ): AutonomousReconTopologyProjection {
    return inImmediateTransaction(this.database, () => {
      if (!observation.runId) return skipped("not_run_scoped");
      if (observation.verificationState === "rejected"
        || observation.verificationState === "stale") {
        return skipped("observation_not_current");
      }
      const runScopedObservation = observation as Observation & Readonly<{ runId: string }>;
      if (observation.observationType === "dns_record_query"
        && observation.sourceTool === AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID) {
        return this.#projectDns(runScopedObservation, verifiedEvidenceIds);
      }
      if ((observation.observationType === "http_metadata"
          && observation.sourceTool === AUTONOMOUS_HTTP_METADATA_ACTION_TYPE)
        || (observation.observationType === "web_technology_fingerprint"
          && observation.sourceTool === AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE)
        || (observation.observationType === "web_endpoint_discovery"
          && observation.sourceTool === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE)) {
        return this.#projectWeb(runScopedObservation, verifiedEvidenceIds);
      }
      return skipped("unsupported_observation");
    });
  }

  #custodyComplete(evidenceId: string): boolean {
    const rows = this.database.prepare(`
      SELECT event_type, details_json FROM evidence_chain_events
      WHERE evidence_id = ? ORDER BY occurred_at, id
    `).all(evidenceId) as Array<{
      readonly event_type: string;
      readonly details_json: string;
    }>;
    return rows.some(({ event_type }) => event_type === "acquired")
      && rows.some(({ event_type }) => event_type === "verified");
  }

  #validatedEvidence(
    observation: Observation,
    evidenceIds: readonly string[],
    evidenceType: string,
  ): ValidatedEvidence | ProjectionSkipReason {
    if (evidenceIds.length !== 1 || new Set(evidenceIds).size !== 1) {
      return "evidence_not_verified";
    }
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, step_id, action_id, target, evidence_type,
        content_hash, provenance_json, confidence, verification_state, extracted_text,
        artifact_id, source, sensitivity, created_by, acquired_at
      FROM evidence WHERE id = ?
    `).get(evidenceIds[0]!) as EvidenceRow | undefined;
    if (!row || row.verification_state !== "verified"
      || row.evidence_type !== evidenceType) {
      return "evidence_not_verified";
    }
    if (row.mission_id !== observation.missionId || row.run_id !== observation.runId
      || (row.step_id ?? undefined) !== observation.stepId
      || row.sensitivity !== observation.sensitivity) {
      return "evidence_scope_mismatch";
    }
    if (!this.#custodyComplete(row.id)) return "evidence_custody_incomplete";
    const extracted = parsedRecord(row.extracted_text);
    const evidenceProvenance = parsedRecord(row.provenance_json);
    if (!extracted || !evidenceProvenance
      || !SHA256.test(row.content_hash)
      || hashCanonical(extracted) !== row.content_hash) {
      return "source_binding_invalid";
    }
    const sourceLogIds = new Set(observation.sources.map(({ logRecordId }) => logRecordId));
    const custodyRows = this.database.prepare(`
      SELECT details_json FROM evidence_chain_events
      WHERE evidence_id = ? AND event_type = 'acquired'
    `).all(row.id) as Array<{ readonly details_json: string }>;
    const custodyBindsObservation = custodyRows.some(({ details_json }) => {
      const details = parsedRecord(details_json);
      return details?.observationId === observation.id
        && typeof details.logRecordId === "string"
        && sourceLogIds.has(details.logRecordId);
    });
    if (!custodyBindsObservation) return "source_binding_invalid";
    return { row, extracted, provenance: evidenceProvenance };
  }

  #missionTargets(missionId: string): readonly MissionTargetRow[] {
    return this.database.prepare(`
      SELECT id, target, target_type, normalized_target, disposition
      FROM mission_targets WHERE mission_id = ? ORDER BY created_at, id
    `).all(missionId) as MissionTargetRow[];
  }

  #allowedTarget(
    missionId: string,
    value: string,
    normalize: (candidate: unknown) => string | undefined,
  ): MissionTargetRow | undefined {
    const matching = this.#missionTargets(missionId).filter((candidate) =>
      normalize(candidate.target) === value || normalize(candidate.normalized_target) === value);
    if (matching.some(({ disposition }) => disposition === "prohibited")) return undefined;
    return matching.find(({ disposition }) => disposition === "allowed");
  }

  #derivedScope(
    missionId: string,
    value: string,
    normalize: (candidate: unknown) => string | undefined,
  ): TopologyScopeStatus {
    const matching = this.#missionTargets(missionId).filter((candidate) =>
      normalize(candidate.target) === value || normalize(candidate.normalized_target) === value);
    if (matching.some(({ disposition }) => disposition === "prohibited")) return "prohibited";
    if (matching.some(({ disposition }) => disposition === "allowed")) return "allowed";
    return "unknown";
  }

  #derivedWebEndpointScope(
    targets: readonly MissionTargetRow[],
    endpointUrl: string,
  ): TopologyScopeStatus {
    const endpoint = new URL(endpointUrl);
    const matching = targets.filter((target) =>
      missionTargetMatchesWebUrl(target, endpoint));
    if (matching.some(({ disposition }) => disposition === "prohibited")) {
      return "prohibited";
    }
    if (matching.some(({ disposition }) => disposition === "allowed")) {
      return "allowed";
    }
    return "unknown";
  }

  #ensureNode(input: CreateTopologyNodeInput): TopologyNode {
    return this.#topology.repository.findNodeByIdentity({
      missionId: input.missionId,
      runId: input.runId ?? null,
      nodeType: input.nodeType,
      normalizedIdentity: input.normalizedIdentity,
    }) ?? this.#topology.createNode(input);
  }

  #ensureEdge(input: CreateTopologyEdgeInput) {
    return this.#topology.repository.findEdge({
      missionId: input.missionId,
      sourceNodeId: input.sourceNodeId,
      targetNodeId: input.targetNodeId,
      edgeType: input.edgeType,
    }) ?? this.#topology.createEdge(input);
  }

  #ensureOsi(input: RecordOsiObservationInput): string {
    const existing = this.database.prepare(`
      SELECT id, derivation, confidence, evidence_id
      FROM asset_layer_observations
      WHERE asset_node_id = ? AND osi_layer = ? AND category = ?
        AND value = ? AND observed_at = ?
      LIMIT 1
    `).get(
      input.assetNodeId,
      input.layer,
      input.category,
      input.value,
      input.observedAt,
    ) as OsiExistingRow | undefined;
    if (existing) {
      if (existing.evidence_id !== input.evidenceId
        || existing.derivation !== input.derivation
        || existing.confidence !== input.confidence) {
        throw new Error("Existing OSI projection conflicts with verified Autonomous evidence");
      }
      return existing.id;
    }
    return this.#topology.recordOsiObservation(input).id;
  }

  #sourceProvenance(observation: Observation, evidenceId: string, method: string) {
    return {
      method,
      sourceRef: evidenceId,
      ...(observation.sourceAgentId ? { sourceAgentId: observation.sourceAgentId } : {}),
      sourceTool: observation.sourceTool!,
      observationIds: [observation.id],
    } as const;
  }

  #projectDns(
    observation: Observation & Readonly<{ runId: string }>,
    evidenceIds: readonly string[],
  ): AutonomousReconTopologyProjection {
    const verified = this.#validatedEvidence(
      observation,
      evidenceIds,
      AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
    );
    if (typeof verified === "string") return skipped(verified);
    const normalized = plain(observation.normalizedValue)
      ? observation.normalizedValue : undefined;
    const queryName = canonicalDomain(normalized?.queryName);
    const noRecord = normalized?.noRecord;
    const answers = normalized?.answers;
    const logRecordId = boundedText(verified.extracted.logRecordId, 512);
    const outputSha256 = boundedText(normalized?.outputSha256, 64);
    if (!normalized || normalized.schemaVersion !== DNS_EVIDENCE_SCHEMA_VERSION
      || normalized.recordType !== "A" || normalized.toolId !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
      || !queryName || typeof noRecord !== "boolean" || !Array.isArray(answers)
      || answers.length > 100 || normalized.answerCount !== answers.length
      || !logRecordId || !outputSha256 || !SHA256.test(outputSha256)
      || verified.row.target === null || canonicalDomain(verified.row.target) !== queryName
      || verified.extracted.queryName !== queryName
      || verified.extracted.recordType !== "A"
      || verified.extracted.noRecord !== noRecord
      || verified.extracted.observationId !== observation.id
      || verified.extracted.logRecordId !== logRecordId
      || verified.extracted.outputSha256 !== outputSha256
      || !Array.isArray(verified.extracted.answers)
      || hashCanonical(verified.extracted.answers) !== hashCanonical(answers)
      || verified.provenance.schemaVersion !== DNS_EVIDENCE_SCHEMA_VERSION
      || verified.provenance.method !== "deterministic_reviewed_dns_result_validation"
      || verified.provenance.observationId !== observation.id
      || verified.provenance.logRecordId !== logRecordId
      || verified.provenance.toolId !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
      || noRecord !== (answers.length === 0)) {
      return skipped("normalized_result_invalid");
    }
    const parsedAnswers: Array<Readonly<{
      kind: "address" | "alias";
      value: string;
    }>> = [];
    for (const value of answers) {
      if (!plain(value)) continue;
      if (value.kind === "address") {
        const address = canonicalIp(value.value);
        if (address && isIP(address) === 4) {
          parsedAnswers.push({ kind: "address", value: address });
        }
      } else if (value.kind === "alias") {
        const alias = canonicalDomain(value.value);
        if (alias) parsedAnswers.push({ kind: "alias", value: alias });
      }
    }
    if (parsedAnswers.length !== answers.length) {
      return skipped("normalized_result_invalid");
    }
    const target = this.#allowedTarget(observation.missionId, queryName, canonicalDomain);
    if (!target) return skipped("target_not_allowed");

    const evidence = Object.freeze([{
      evidenceId: verified.row.id,
      relationship: "supports" as const,
    }]);
    const provenance = this.#sourceProvenance(
      observation,
      verified.row.id,
      "verified_autonomous_dns_projection",
    );
    const nodeIds: string[] = [];
    const edgeIds: string[] = [];
    const osiObservationIds: string[] = [];
    const domain = this.#ensureNode({
      missionId: observation.missionId,
      runId: observation.runId,
      nodeType: "domain",
      primaryLabel: queryName,
      normalizedIdentity: runScopedTopologyIdentity(
        observation.runId,
        "domain",
        queryName,
      ),
      scopeStatus: "allowed",
      lifecycleState: "observed",
      properties: {
        domain: queryName,
        missionTargetId: target.id,
        dnsRecordType: "A",
        dnsNoRecord: noRecord,
        answerCount: answers.length,
      },
      provenance,
      confidence: observation.confidence,
      verificationState: "verified",
      sensitivity: observation.sensitivity,
      firstSeenAt: observation.firstSeenAt,
      lastSeenAt: observation.lastSeenAt,
      evidence,
    });
    nodeIds.push(domain.id);
    for (const answer of parsedAnswers) {
      const kind = answer.kind === "address" ? "asset" as const : "domain" as const;
      const node = this.#ensureNode({
        missionId: observation.missionId,
        runId: observation.runId,
        nodeType: kind,
        primaryLabel: answer.value,
        normalizedIdentity: runScopedTopologyIdentity(
          observation.runId,
          kind,
          answer.value,
        ),
        scopeStatus: this.#derivedScope(
          observation.missionId,
          answer.value,
          answer.kind === "address" ? canonicalIp : canonicalDomain,
        ),
        lifecycleState: "observed",
        properties: answer.kind === "address"
          ? {
              address: answer.value,
              addressFamily: "ipv4",
              discoveredFromDnsTarget: queryName,
              contactAuthorityGrantedByDnsObservation: false,
            }
          : {
              domain: answer.value,
              discoveredFromDnsTarget: queryName,
              contactAuthorityGrantedByDnsObservation: false,
            },
        provenance,
        confidence: observation.confidence,
        verificationState: "verified",
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      nodeIds.push(node.id);
      if (node.id !== domain.id) {
        const edge = this.#ensureEdge({
          missionId: observation.missionId,
          sourceNodeId: domain.id,
          targetNodeId: node.id,
          edgeType: answer.kind === "address" ? "resolves_to" : "aliases_to",
          properties: {
            recordType: answer.kind === "address" ? "A" : "CNAME",
            contactAuthorityGrantedByDnsObservation: false,
          },
          provenance,
          confidence: observation.confidence,
          verificationState: "verified",
          sensitivity: observation.sensitivity,
          firstSeenAt: observation.firstSeenAt,
          lastSeenAt: observation.lastSeenAt,
          evidence,
        });
        edgeIds.push(edge.id);
      }
      if (answer.kind === "address") {
        osiObservationIds.push(this.#ensureOsi({
          assetNodeId: node.id,
          layer: 3,
          category: "dns.a_record",
          value: `${queryName} → ${answer.value}`,
          derivation: "observed",
          confidence: observation.confidence,
          evidenceId: verified.row.id,
          observedAt: observation.lastSeenAt,
        }));
      }
    }
    return {
      status: "materialized",
      reason: "verified_dns_projection",
      nodeIds: unique(nodeIds),
      edgeIds: unique(edgeIds),
      osiObservationIds: unique(osiObservationIds),
    };
  }

  #sourceEvidenceComplete(
    observation: Observation & Readonly<{ runId: string }>,
    evidenceIds: readonly string[],
  ): boolean {
    if (evidenceIds.length < 1 || evidenceIds.length > 8
      || new Set(evidenceIds).size !== evidenceIds.length) return false;
    return evidenceIds.every((evidenceId) => {
      const row = this.database.prepare(`
        SELECT mission_id, run_id, verification_state
        FROM evidence WHERE id = ?
      `).get(evidenceId) as {
        readonly mission_id: string;
        readonly run_id: string | null;
        readonly verification_state: string;
      } | undefined;
      return row?.mission_id === observation.missionId
        && row.run_id === observation.runId
        && row.verification_state === "verified"
        && this.#custodyComplete(evidenceId);
    });
  }

  #webSourceBindingComplete(
    observation: Observation & Readonly<{ runId: string }>,
    evidence: ValidatedEvidence,
    parentTarget: string,
    virtualTool: string,
    physicalTool: string,
    normalized: Readonly<Record<string, unknown>>,
  ): boolean {
    const contextPackId = boundedText(normalized.contextPackId, 240);
    const resultSha256 = boundedText(normalized.resultSha256, 64);
    const manifestSha256 = boundedText(evidence.provenance.manifestSha256, 64);
    const parentActionId = boundedText(evidence.provenance.parentActionId, 240);
    const parentActionFingerprint = boundedText(
      evidence.provenance.parentActionFingerprint,
      64,
    );
    const rawLogRecordIds = evidence.provenance.rawLogRecordIds;
    const derivedOrigins = normalized.derivedOrigins;
    if (!contextPackId || !resultSha256 || !SHA256.test(resultSha256)
      || evidence.provenance.contextPackId !== contextPackId
      || evidence.provenance.resultSha256 !== resultSha256
      || !manifestSha256 || !SHA256.test(manifestSha256)
      || !parentActionId || evidence.row.action_id !== parentActionId
      || !parentActionFingerprint || !SHA256.test(parentActionFingerprint)
      || !observation.sourceAgentId
      || evidence.row.source !== `specialist:${observation.sourceAgentId}`
      || evidence.row.created_by !== "autonomous-web-evidence-verifier"
      || evidence.row.acquired_at !== observation.lastSeenAt
      || evidence.row.confidence !== observation.confidence
      || observation.sources.length !== 1
      || observation.sources[0]?.parserId
        !== "ti-scale.autonomous-web-deterministic-verifier"
      || observation.sources[0]?.parserVersion !== "1.0.0"
      || !Array.isArray(rawLogRecordIds)
      || rawLogRecordIds.length < 1
      || rawLogRecordIds.length > MAXIMUM_WEB_ORIGINS
      || new Set(rawLogRecordIds).size !== rawLogRecordIds.length
      || rawLogRecordIds.some((id) => typeof id !== "string")
      || !Array.isArray(derivedOrigins)
      || derivedOrigins.length !== rawLogRecordIds.length
      || derivedOrigins.some((origin) => typeof origin !== "string")) {
      return false;
    }
    const action = this.database.prepare(`
      SELECT mission_id, run_id, step_id, action_type, fingerprint, scoped_target
      FROM actions WHERE id = ?
    `).get(parentActionId) as {
      readonly mission_id: string;
      readonly run_id: string;
      readonly step_id: string;
      readonly action_type: string;
      readonly fingerprint: string;
      readonly scoped_target: string;
    } | undefined;
    if (!action || action.mission_id !== observation.missionId
      || action.run_id !== observation.runId
      || action.step_id !== observation.stepId
      || action.action_type !== virtualTool
      || action.fingerprint !== parentActionFingerprint
      || action.scoped_target !== parentTarget) {
      return false;
    }
    const context = this.database.prepare(`
      SELECT mission_id, run_id, journey
      FROM memory_context_packs WHERE id = ?
    `).get(contextPackId) as {
      readonly mission_id: string | null;
      readonly run_id: string | null;
      readonly journey: string;
    } | undefined;
    if (!context || context.mission_id !== observation.missionId
      || context.run_id !== observation.runId || context.journey !== "autonomous") {
      return false;
    }
    const sourceLogs = this.database.prepare(`
      SELECT id, mission_id, run_id, step_id, action_id, record_type,
        technical_payload_json, sensitivity
      FROM engagement_log_records
      WHERE id IN (${rawLogRecordIds.map(() => "?").join(",")})
    `).all(...rawLogRecordIds) as Array<{
      readonly id: string;
      readonly mission_id: string;
      readonly run_id: string | null;
      readonly step_id: string | null;
      readonly action_id: string | null;
      readonly record_type: string;
      readonly technical_payload_json: string;
      readonly sensitivity: Sensitivity;
    }>;
    const observedOrigins = new Set<string>();
    if (sourceLogs.length !== rawLogRecordIds.length) return false;
    for (const log of sourceLogs) {
      const payload = parsedRecord(log.technical_payload_json);
      const origin = boundedText(payload?.origin, 1_000);
      if (log.mission_id !== observation.missionId
        || log.run_id !== observation.runId
        || log.step_id !== observation.stepId
        || log.action_id !== parentActionId
        || log.record_type !== "bounded_child_process_output"
        || log.sensitivity !== observation.sensitivity
        || !origin || payload?.toolId !== physicalTool
        || payload.rawProcessOutputPromoted !== false
        || typeof payload.outputSha256 !== "string"
        || !SHA256.test(payload.outputSha256)
        || observedOrigins.has(origin)
        || !(derivedOrigins as readonly string[]).includes(origin)) {
        return false;
      }
      observedOrigins.add(origin);
    }
    if (observedOrigins.size !== derivedOrigins.length) return false;
    const observationLog = this.database.prepare(`
      SELECT mission_id, run_id, step_id, action_id, domain, record_type,
        sensitivity
      FROM engagement_log_records WHERE id = ?
    `).get(observation.sources[0]!.logRecordId) as {
      readonly mission_id: string;
      readonly run_id: string | null;
      readonly step_id: string | null;
      readonly action_id: string | null;
      readonly domain: string;
      readonly record_type: string;
      readonly sensitivity: Sensitivity;
    } | undefined;
    if (!observationLog || observationLog.mission_id !== observation.missionId
      || observationLog.run_id !== observation.runId
      || observationLog.step_id !== observation.stepId
      || observationLog.action_id !== parentActionId
      || observationLog.domain !== "autonomous_web_surface"
      || observationLog.record_type !== "verified_derived_origin_result"
      || observationLog.sensitivity !== observation.sensitivity) {
      return false;
    }
    const acquired = this.database.prepare(`
      SELECT details_json FROM evidence_chain_events
      WHERE evidence_id = ? AND event_type = 'acquired'
    `).all(evidence.row.id) as Array<{ readonly details_json: string }>;
    return acquired.some(({ details_json }) => {
      const details = parsedRecord(details_json);
      return details?.observationId === observation.id
        && details.logRecordId === observation.sources[0]!.logRecordId
        && details.resultSha256 === resultSha256;
    });
  }

  #captureTopologyBindingsValid(
    capture: PageCaptureRecord,
    observation: Observation & Readonly<{ runId: string }>,
  ): boolean {
    if (!capture.assetNodeId && !capture.serviceNodeId) return false;
    for (const [kind, nodeId] of [
      ["asset", capture.assetNodeId],
      ["service", capture.serviceNodeId],
    ] as const) {
      if (!nodeId) continue;
      const node = this.database.prepare(`
        SELECT mission_id, run_id, node_type, scope_status
        FROM topology_nodes WHERE id = ?
      `).get(nodeId) as {
        readonly mission_id: string;
        readonly run_id: string | null;
        readonly node_type: string;
        readonly scope_status: string;
      } | undefined;
      const allowedTypes = kind === "asset"
        ? PAGE_CAPTURE_ASSET_NODE_TYPES
        : PAGE_CAPTURE_SERVICE_NODE_TYPES;
      if (!node || node.mission_id !== observation.missionId
        || node.run_id !== observation.runId || node.scope_status !== "allowed"
        || !allowedTypes.has(node.node_type)) {
        return false;
      }
    }
    return true;
  }

  #captureCustodyComplete(
    evidenceId: string,
    capture: PageCaptureRecord,
    artifact: PageCaptureArtifactProjection,
    observation: Observation,
  ): boolean {
    const events = this.database.prepare(`
      SELECT event_type, actor, details_json, occurred_at
      FROM evidence_chain_events
      WHERE evidence_id = ?
      ORDER BY occurred_at, id
    `).all(evidenceId) as Array<{
      readonly event_type: string;
      readonly actor: string;
      readonly details_json: string;
      readonly occurred_at: string;
    }>;
    const exactDetails = (detailsJson: string, method?: string): boolean => {
      const details = parsedRecord(detailsJson);
      return details?.schemaVersion === PAGE_CAPTURE_ARTIFACT_EVIDENCE_SCHEMA_VERSION
        && details.pageCaptureId === capture.id
        && details.artifactId === artifact.artifactId
        && details.observationId === observation.id
        && details.captureTool === capture.captureTool
        && details.contentHash === artifact.contentHash
        && (method === undefined || details.method === method);
    };
    const acquired = events.filter(({ event_type, actor, details_json, occurred_at }) =>
      event_type === "acquired"
      && actor === capture.capturedByAgentId
      && occurred_at === capture.capturedAt
      && exactDetails(details_json));
    const verified = events.filter(({ event_type, details_json }) =>
      event_type === "verified"
      && exactDetails(details_json, "verified_page_capture_artifact"));
    return acquired.some((acquisition) => verified.some((verification) =>
      Date.parse(verification.occurred_at) >= Date.parse(acquisition.occurred_at)));
  }

  #verifiedCaptureEvidence(
    observation: Observation & Readonly<{ runId: string }>,
    capture: PageCaptureRecord,
    artifact: PageCaptureArtifactProjection,
    artifactRow: ArtifactRow,
  ): EvidenceRow | undefined {
    const rows = this.database.prepare(`
      SELECT id, mission_id, run_id, step_id, action_id, target, evidence_type,
        content_hash, provenance_json, confidence, verification_state, extracted_text,
        artifact_id, source, sensitivity, created_by, acquired_at
      FROM evidence
      WHERE artifact_id = ? AND mission_id = ? AND run_id = ?
        AND evidence_type = 'web_page_capture'
        AND verification_state = 'verified'
      ORDER BY acquired_at, id
    `).all(
      artifact.artifactId,
      observation.missionId,
      observation.runId,
    ) as EvidenceRow[];
    if (rows.length !== 1) return undefined;
    const evidence = rows[0]!;
    const provenance = parsedRecord(evidence.provenance_json);
    const sourceAction = evidence.action_id
      ? this.database.prepare(`
          SELECT mission_id, run_id, step_id FROM actions WHERE id = ?
        `).get(evidence.action_id) as {
          readonly mission_id: string;
          readonly run_id: string;
          readonly step_id: string;
        } | undefined
      : undefined;
    if ((evidence.step_id ?? undefined) !== capture.stepId
      || evidence.action_id !== artifactRow.action_id
      || (evidence.action_id !== null
        && (!sourceAction
          || sourceAction.mission_id !== observation.missionId
          || sourceAction.run_id !== observation.runId
          || sourceAction.step_id !== capture.stepId))
      || evidence.target !== capture.normalizedUrl
      || evidence.content_hash !== artifact.contentHash
      || evidence.sensitivity !== capture.sensitivity
      || evidence.created_by !== capture.capturedByAgentId
      || evidence.source !== `specialist:${capture.capturedByAgentId}`
      || evidence.acquired_at !== capture.capturedAt
      || !provenance
      || provenance.schemaVersion !== PAGE_CAPTURE_ARTIFACT_EVIDENCE_SCHEMA_VERSION
      || provenance.method !== "verified_page_capture_artifact"
      || provenance.artifactId !== artifact.artifactId
      || provenance.observationId !== observation.id
      || provenance.captureTool !== capture.captureTool
      || provenance.captureContentHash !== capture.contentHash
      || provenance.redactionState !== capture.redactionState
      || !capture.related.evidenceIds.includes(evidence.id)
      || !this.#captureCustodyComplete(
        evidence.id,
        capture,
        artifact,
        observation,
      )) {
      return undefined;
    }
    return evidence;
  }

  #validatedPageCaptureArtifacts(
    observation: Observation & Readonly<{ runId: string }>,
    endpointEvidenceId: string,
    endpoints: readonly WebEndpointMatch[],
  ): readonly VerifiedPageCaptureArtifact[] {
    // FFUF does not create screenshots. This is deliberately a read-only,
    // bounded join over captures supplied through the canonical ingestion
    // boundary after the endpoint observation existed. Missing or ambiguous
    // artifact evidence leaves the capture unprojected.
    if (endpoints.length === 0) return Object.freeze([]);
    const endpointByUrl = new Map(endpoints.map((endpoint) => [endpoint.url, endpoint]));
    const candidateRows = this.database.prepare(`
      SELECT pc.id
      FROM page_captures pc
      WHERE pc.mission_id = ? AND pc.run_id = ?
        AND (pc.step_id IS NULL OR pc.step_id = ?)
        AND EXISTS (
          SELECT 1
          FROM json_each(pc.certificate_metadata_json, '$.related.evidenceIds') linked
          WHERE linked.type = 'text' AND linked.value = ?
        )
        AND EXISTS (
          SELECT 1
          FROM json_each(pc.certificate_metadata_json, '$.related.observationIds') linked
          WHERE linked.type = 'text' AND linked.value = ?
        )
      ORDER BY pc.captured_at, pc.id
      LIMIT ?
    `).all(
      observation.missionId,
      observation.runId,
      observation.stepId ?? null,
      endpointEvidenceId,
      observation.id,
      MAXIMUM_PAGE_CAPTURE_ARTIFACTS + 1,
    ) as Array<{ readonly id: string }>;
    if (candidateRows.length > MAXIMUM_PAGE_CAPTURE_ARTIFACTS) {
      return Object.freeze([]);
    }

    const verified: VerifiedPageCaptureArtifact[] = [];
    for (const { id } of candidateRows) {
      let capture: PageCaptureRecord;
      try {
        capture = this.#pageCaptures.get(id);
      } catch {
        continue;
      }
      const endpoint = endpointByUrl.get(capture.normalizedUrl);
      if (!endpoint || capture.missionId !== observation.missionId
        || capture.runId !== observation.runId
        || (capture.stepId !== undefined
          && capture.stepId !== observation.stepId)
        || capture.responseStatus !== endpoint.status
        || !SHA256.test(capture.contentHash)
        || !capture.screenshot
        || !capture.screenshotHash
        || !SHA256.test(capture.screenshotHash)
        || capture.viewport.fullPage !== Boolean(capture.fullPageScreenshot)
        || Boolean(capture.fullPageScreenshot)
          !== Boolean(capture.fullPageScreenshotHash)
        || (capture.fullPageScreenshotHash !== undefined
          && !SHA256.test(capture.fullPageScreenshotHash))
        || (capture.fullPageScreenshot?.artifactId
          === capture.screenshot.artifactId)
        || !capture.capturedByAgentId
        || !CAPTURE_TOOL.test(capture.captureTool)
        || !Number.isFinite(Date.parse(capture.capturedAt))
        || capture.related.evidenceIds.filter((value) =>
          value === endpointEvidenceId).length !== 1
        || capture.related.observationIds.filter((value) =>
          value === observation.id).length !== 1
        || !this.#captureTopologyBindingsValid(capture, observation)
        || !this.database.prepare("SELECT 1 FROM agents WHERE id = ?")
          .get(capture.capturedByAgentId)) {
        continue;
      }
      const artifacts = [
        ...(capture.screenshot
          ? [{
              artifact: capture.screenshot,
              expectedHash: capture.screenshotHash,
              artifactRole: "viewport" as const,
            }]
          : []),
        ...(capture.fullPageScreenshot
          ? [{
              artifact: capture.fullPageScreenshot,
              expectedHash: capture.fullPageScreenshotHash,
              artifactRole: "full_page" as const,
            }]
          : []),
      ];
      for (const { artifact, expectedHash, artifactRole } of artifacts) {
        const artifactRow = this.database.prepare(`
          SELECT id, mission_id, run_id, step_id, action_id, artifact_type,
            content_hash, byte_size, media_type, sensitivity
          FROM artifacts WHERE id = ?
        `).get(artifact.artifactId) as ArtifactRow | undefined;
        if (!artifactRow || artifactRow.mission_id !== observation.missionId
          || artifactRow.run_id !== observation.runId
          || (artifactRow.step_id ?? undefined) !== capture.stepId
          || !SCREENSHOT_ARTIFACT_TYPES.has(artifactRow.artifact_type)
          || !artifactRow.media_type
          || !SCREENSHOT_MEDIA_TYPES.has(artifactRow.media_type)
          || artifactRow.byte_size <= 0
          || artifactRow.content_hash !== artifact.contentHash
          || artifactRow.content_hash !== expectedHash
          || artifactRow.media_type !== artifact.mediaType
          || artifactRow.byte_size !== artifact.byteSize
          || artifactRow.sensitivity !== capture.sensitivity) {
          continue;
        }
        const captureEvidence = this.#verifiedCaptureEvidence(
          observation,
          capture,
          artifact,
          artifactRow,
        );
        if (!captureEvidence) continue;
        verified.push({
          capture,
          artifact,
          artifactRole,
          evidence: captureEvidence,
        });
        if (verified.length > MAXIMUM_PAGE_CAPTURE_ARTIFACTS) {
          return Object.freeze([]);
        }
      }
    }
    return Object.freeze(verified);
  }

  #projectWeb(
    observation: Observation & Readonly<{ runId: string }>,
    evidenceIds: readonly string[],
  ): AutonomousReconTopologyProjection {
    const phase = observation.observationType === "http_metadata"
      ? "http_metadata" as const
      : observation.observationType === "web_technology_fingerprint"
        ? "whatweb_fingerprint" as const
        : "endpoint_discovery" as const;
    const evidenceType = phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE
      : phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_EVIDENCE_TYPE
        : AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE;
    const virtualTool = phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      : phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
        : AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE;
    const physicalTool = phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_TOOL_ID
      : phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_TOOL_ID
        : AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
    const verified = this.#validatedEvidence(observation, evidenceIds, evidenceType);
    if (typeof verified === "string") return skipped(verified);
    const normalized = plain(observation.normalizedValue)
      ? observation.normalizedValue : undefined;
    const parentTarget = canonicalIp(normalized?.parentTarget);
    const derivedOrigins = normalized?.derivedOrigins;
    const responses = normalized?.responses;
    const sourceEvidenceIds = normalized?.sourceEvidenceIds;
    if (!normalized || normalized.schemaVersion !== WEB_EVIDENCE_SCHEMA_VERSION
      || normalized.phase !== phase || !parentTarget
      || !Array.isArray(derivedOrigins) || derivedOrigins.length < 1
      || derivedOrigins.length > MAXIMUM_WEB_ORIGINS
      || new Set(derivedOrigins).size !== derivedOrigins.length
      || !Array.isArray(responses) || responses.length !== derivedOrigins.length
      || !Array.isArray(sourceEvidenceIds)
      || sourceEvidenceIds.some((id) => typeof id !== "string")
      || normalized.redirectPolicy !== "never"
      || normalized.rawProcessOutputPromoted !== false
      || normalized.cveApplicability !== "not_evaluated"
      || hashCanonical(normalized) !== verified.row.content_hash
      || hashCanonical(verified.extracted) !== hashCanonical(normalized)
      || verified.row.target !== parentTarget
      || verified.provenance.schemaVersion !== WEB_EVIDENCE_SCHEMA_VERSION
      || verified.provenance.method !== "deterministic_derived_origin_local_process_validation"
      || verified.provenance.parentTarget !== parentTarget
      || verified.provenance.virtualToolId !== virtualTool
      || !Array.isArray(verified.provenance.constituentToolIds)
      || hashCanonical(verified.provenance.constituentToolIds)
        !== hashCanonical([physicalTool])
      || verified.provenance.rawProcessOutputPromoted !== false
      || verified.provenance.derivedOriginCount !== derivedOrigins.length
      || !Array.isArray(verified.provenance.sourceEvidenceIds)
      || hashCanonical(verified.provenance.sourceEvidenceIds)
        !== hashCanonical(sourceEvidenceIds)
      || !this.#webSourceBindingComplete(
        observation,
        verified,
        parentTarget,
        virtualTool,
        physicalTool,
        normalized,
      )
      || !this.#sourceEvidenceComplete(
        observation,
        sourceEvidenceIds as readonly string[],
      )) {
      return skipped("normalized_result_invalid");
    }
    const target = this.#allowedTarget(observation.missionId, parentTarget, canonicalIp);
    if (!target) return skipped("target_not_allowed");
    const origins = derivedOrigins.map((value) => webOrigin(value, parentTarget));
    if (origins.some((origin) => !origin)) {
      return skipped("normalized_result_invalid");
    }
    const prepared = (origins as WebOrigin[]).map((origin, index) => {
      const response = responses[index];
      if (!plain(response) || response.origin !== origin.href) return undefined;
      const phaseProperties = phase === "http_metadata"
        ? this.#httpProperties(response, origin)
        : phase === "whatweb_fingerprint"
          ? this.#whatWebProperties(response, origin)
          : this.#endpointProperties(response, origin);
      return phaseProperties ? { origin, phaseProperties } : undefined;
    });
    if (prepared.some((item) => !item)
      || prepared.reduce(
        (count, item) => count + (item?.phaseProperties.technologySignals.length ?? 0),
        0,
      ) > MAXIMUM_TECHNOLOGY_SIGNALS) {
      return skipped("normalized_result_invalid");
    }
    const preparedItems = prepared as Array<NonNullable<(typeof prepared)[number]>>;
    const endpointMatches = Object.freeze(
      preparedItems.flatMap(({ phaseProperties }) => phaseProperties.endpoints),
    );
    const missionTargets = this.#missionTargets(observation.missionId);
    const endpointScopeByUrl = new Map(endpointMatches.map((endpoint) => [
      endpoint.url,
      this.#derivedWebEndpointScope(missionTargets, endpoint.url),
    ]));
    const pageCaptureArtifacts = phase === "endpoint_discovery"
      ? this.#validatedPageCaptureArtifacts(
          observation,
          verified.row.id,
          endpointMatches.filter((endpoint) =>
            endpointScopeByUrl.get(endpoint.url) === "allowed"),
        )
      : Object.freeze([]);
    const pageCaptureArtifactsByUrl = new Map<string, VerifiedPageCaptureArtifact[]>();
    for (const captureArtifact of pageCaptureArtifacts) {
      const existing = pageCaptureArtifactsByUrl.get(
        captureArtifact.capture.normalizedUrl,
      ) ?? [];
      existing.push(captureArtifact);
      pageCaptureArtifactsByUrl.set(
        captureArtifact.capture.normalizedUrl,
        existing,
      );
    }

    const evidence = Object.freeze([{
      evidenceId: verified.row.id,
      relationship: "supports" as const,
    }]);
    const provenance = this.#sourceProvenance(
      observation,
      verified.row.id,
      phase === "http_metadata"
        ? "verified_autonomous_http_metadata_projection"
        : phase === "whatweb_fingerprint"
          ? "verified_autonomous_whatweb_projection"
          : "verified_autonomous_endpoint_discovery_projection",
    );
    const asset = this.#ensureNode({
      missionId: observation.missionId,
      runId: observation.runId,
      nodeType: "asset",
      primaryLabel: parentTarget,
      normalizedIdentity: runScopedTopologyIdentity(
        observation.runId,
        "asset",
        parentTarget,
      ),
      scopeStatus: "allowed",
      lifecycleState: "observed",
      properties: {
        address: parentTarget,
        missionTargetId: target.id,
        verifiedWebSurfaceObserved: true,
      },
      provenance,
      confidence: observation.confidence,
      verificationState: "verified",
      sensitivity: observation.sensitivity,
      firstSeenAt: observation.firstSeenAt,
      lastSeenAt: observation.lastSeenAt,
      evidence,
    });
    const nodeIds: string[] = [asset.id];
    const edgeIds: string[] = [];
    const osiObservationIds: string[] = [];

    for (const item of preparedItems) {
      const { origin, phaseProperties } = item;
      const endpoint = `${parentTarget}:${origin.port}/tcp`;
      const service = this.#ensureNode({
        missionId: observation.missionId,
        runId: observation.runId,
        nodeType: "service",
        primaryLabel: `${origin.scheme} · ${origin.port}/tcp`,
        normalizedIdentity: runScopedTopologyIdentity(
          observation.runId,
          "service",
          endpoint,
        ),
        scopeStatus: "allowed",
        lifecycleState: "observed",
        properties: {
          host: parentTarget,
          port: origin.port,
          transport: "tcp",
          state: "open",
          service: origin.scheme,
          origin: origin.href,
          originDerivation: "verified_service_evidence",
        },
        provenance,
        confidence: observation.confidence,
        verificationState: "verified",
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      nodeIds.push(service.id);
      const exposed = this.#ensureEdge({
        missionId: observation.missionId,
        sourceNodeId: asset.id,
        targetNodeId: service.id,
        edgeType: "exposes",
        properties: {
          port: origin.port,
          transport: "tcp",
          service: origin.scheme,
          origin: origin.href,
        },
        provenance,
        confidence: observation.confidence,
        verificationState: "verified",
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      edgeIds.push(exposed.id);

      const webNode = this.#ensureNode({
        missionId: observation.missionId,
        runId: observation.runId,
        nodeType: "web_origin",
        primaryLabel: origin.href,
        normalizedIdentity: runScopedTopologyIdentity(
          observation.runId,
          "web_origin",
          origin.href,
        ),
        scopeStatus: "allowed",
        lifecycleState: "observed",
        properties: phaseProperties.properties,
        provenance,
        confidence: observation.confidence,
        verificationState: "verified",
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      nodeIds.push(webNode.id);
      const serves = this.#ensureEdge({
        missionId: observation.missionId,
        sourceNodeId: service.id,
        targetNodeId: webNode.id,
        edgeType: "serves_web_origin",
        properties: {
          origin: origin.href,
          scheme: origin.scheme,
          port: origin.port,
        },
        provenance,
        confidence: observation.confidence,
        verificationState: "verified",
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      edgeIds.push(serves.id);

      for (const stack of phaseProperties.stack) {
        osiObservationIds.push(this.#ensureOsi({
          assetNodeId: asset.id,
          layer: 7,
          category: stack.category,
          value: `${origin.href} → ${stack.value}`,
          derivation: "actively_verified",
          confidence: observation.confidence,
          evidenceId: verified.row.id,
          observedAt: observation.lastSeenAt,
        }));
      }
      for (const signal of phaseProperties.technologySignals) {
        const signalNode = this.#ensureNode({
          missionId: observation.missionId,
          runId: observation.runId,
          nodeType: "technology_signal",
          primaryLabel: signal.value,
          normalizedIdentity: runScopedTopologyIdentity(
            observation.runId,
            "technology_signal",
            `${origin.href}\0${signal.category}\0${signal.value}`,
          ),
          scopeStatus: "unknown",
          lifecycleState: "observed",
          properties: {
            origin: origin.href,
            signalType: signal.category,
            value: signal.value,
            claimBoundary: "verified_fingerprint_signal_not_confirmed_software",
          },
          provenance,
          confidence: observation.confidence,
          verificationState: "verified",
          sensitivity: observation.sensitivity,
          firstSeenAt: observation.firstSeenAt,
          lastSeenAt: observation.lastSeenAt,
          evidence,
        });
        nodeIds.push(signalNode.id);
        const signalEdge = this.#ensureEdge({
          missionId: observation.missionId,
          sourceNodeId: webNode.id,
          targetNodeId: signalNode.id,
          edgeType: "has_fingerprint_signal",
          properties: { signalType: signal.category },
          provenance,
          confidence: observation.confidence,
          verificationState: "verified",
          sensitivity: observation.sensitivity,
          firstSeenAt: observation.firstSeenAt,
          lastSeenAt: observation.lastSeenAt,
          evidence,
        });
        edgeIds.push(signalEdge.id);
      }
      for (const match of phaseProperties.endpoints) {
        const endpointScope = endpointScopeByUrl.get(match.url) ?? "unknown";
        const endpointNode = this.#ensureNode({
          missionId: observation.missionId,
          runId: observation.runId,
          nodeType: "endpoint",
          primaryLabel: match.url,
          normalizedIdentity: runScopedTopologyIdentity(
            observation.runId,
            "endpoint",
            match.url,
          ),
          scopeStatus: endpointScope,
          lifecycleState: "observed",
          properties: {
            origin: origin.href,
            path: match.path,
            url: match.url,
            statusCode: match.status,
            ...(match.length === null ? {} : { contentLength: match.length }),
            ...(match.words === null ? {} : { wordCount: match.words }),
            ...(match.lines === null ? {} : { lineCount: match.lines }),
            dictionaryVersion: "ti-scale.web-paths.v1",
            requestBudget: REVIEWED_FFUF_PATHS.length,
            recursive: false,
            redirectFollowed: false,
            redirectLocationObserved: match.redirectLocationObserved,
            redirectLocationRetention: match.redirectLocationObserved
              ? "redacted_from_topology"
              : "not_present",
            rawProcessOutputPromoted: false,
            contactAuthorityGrantedByProjection: false,
            sensitivity: observation.sensitivity,
            redactionState: match.redirectLocationObserved
              ? "redacted"
              : "not_required",
          },
          provenance,
          confidence: observation.confidence,
          verificationState: "verified",
          sensitivity: observation.sensitivity,
          firstSeenAt: observation.firstSeenAt,
          lastSeenAt: observation.lastSeenAt,
          evidence,
        });
        nodeIds.push(endpointNode.id);
        const endpointEdge = this.#ensureEdge({
          missionId: observation.missionId,
          sourceNodeId: webNode.id,
          targetNodeId: endpointNode.id,
          edgeType: "exposes_endpoint",
          properties: {
            origin: origin.href,
            path: match.path,
            statusCode: match.status,
            evidenceBoundary: "fixed_dictionary_verified_response",
            rawProcessOutputPromoted: false,
            endpointScopeStatus: endpointScope,
            contactAuthorityGrantedByProjection: false,
          },
          provenance,
          confidence: observation.confidence,
          verificationState: "verified",
          sensitivity: observation.sensitivity,
          firstSeenAt: observation.firstSeenAt,
          lastSeenAt: observation.lastSeenAt,
          evidence,
        });
        edgeIds.push(endpointEdge.id);
        osiObservationIds.push(this.#ensureOsi({
          assetNodeId: asset.id,
          layer: 7,
          category: "ffuf.endpoint_status",
          value: `${match.url} → HTTP ${match.status}`,
          derivation: "actively_verified",
          confidence: observation.confidence,
          evidenceId: verified.row.id,
          observedAt: observation.lastSeenAt,
        }));

        for (const captureArtifact of
          pageCaptureArtifactsByUrl.get(match.url) ?? []) {
          const capture = captureArtifact.capture;
          const artifact = captureArtifact.artifact;
          const captureEvidence = captureArtifact.evidence;
          const captureConfidence = Math.min(
            observation.confidence,
            captureEvidence.confidence,
          );
          const captureEvidenceLinks = Object.freeze([
            {
              evidenceId: verified.row.id,
              relationship: "source" as const,
            },
            {
              evidenceId: captureEvidence.id,
              relationship: "supports" as const,
            },
          ]);
          const captureProvenance = {
            method: "verified_page_capture_artifact_projection",
            sourceRef: captureEvidence.id,
            sourceAgentId: capture.capturedByAgentId!,
            sourceTool: capture.captureTool,
            observationIds: [observation.id],
          } as const;
          const previewAvailable = capture.redactionState === "not_required"
            || capture.redactionState === "redacted";
          const captureNode = this.#ensureNode({
            missionId: observation.missionId,
            runId: observation.runId,
            nodeType: "page_capture_artifact",
            primaryLabel: `${match.path} · ${captureArtifact.artifactRole} capture`,
            normalizedIdentity: runScopedTopologyIdentity(
              observation.runId,
              "page_capture_artifact",
              artifact.artifactId,
            ),
            scopeStatus: "allowed",
            lifecycleState: "observed",
            properties: {
              pageCaptureId: capture.id,
              url: capture.normalizedUrl,
              responseStatus: capture.responseStatus!,
              artifactId: artifact.artifactId,
              artifactRole: captureArtifact.artifactRole,
              artifactContentHash: artifact.contentHash,
              captureContentHash: capture.contentHash,
              mediaType: artifact.mediaType,
              byteSize: artifact.byteSize,
              captureTool: capture.captureTool,
              sensitivity: capture.sensitivity,
              redactionState: capture.redactionState,
              previewAvailable,
              rawArtifactBytesPromoted: false,
            },
            provenance: captureProvenance,
            confidence: captureConfidence,
            verificationState: "verified",
            sensitivity: capture.sensitivity,
            firstSeenAt: capture.capturedAt,
            lastSeenAt: capture.capturedAt,
            evidence: captureEvidenceLinks,
          });
          nodeIds.push(captureNode.id);
          const captureEdge = this.#ensureEdge({
            missionId: observation.missionId,
            sourceNodeId: endpointNode.id,
            targetNodeId: captureNode.id,
            edgeType: "has_page_capture_artifact",
            properties: {
              pageCaptureId: capture.id,
              artifactRole: captureArtifact.artifactRole,
              redactionState: capture.redactionState,
              previewAvailable,
              rawArtifactBytesPromoted: false,
            },
            provenance: captureProvenance,
            confidence: captureConfidence,
            verificationState: "verified",
            sensitivity: capture.sensitivity,
            firstSeenAt: capture.capturedAt,
            lastSeenAt: capture.capturedAt,
            evidence: captureEvidenceLinks,
          });
          edgeIds.push(captureEdge.id);
          osiObservationIds.push(this.#ensureOsi({
            assetNodeId: asset.id,
            layer: 7,
            category: "web.page_capture_artifact",
            value: `${match.url} → ${captureArtifact.artifactRole} capture (${capture.redactionState})`,
            derivation: "actively_verified",
            confidence: captureConfidence,
            evidenceId: captureEvidence.id,
            observedAt: capture.capturedAt,
          }));
        }
      }
    }
    return {
      status: "materialized",
      reason: "verified_web_projection",
      nodeIds: unique(nodeIds),
      edgeIds: unique(edgeIds),
      osiObservationIds: unique(osiObservationIds),
    };
  }

  #httpProperties(
    candidate: Readonly<Record<string, unknown>>,
    origin: WebOrigin,
  ): WebPhaseProperties | undefined {
    const request = plain(candidate.request) ? candidate.request : undefined;
    const response = plain(candidate.response) ? candidate.response : undefined;
    const statusCode = response?.statusCode;
    const statusReason = response?.statusReason === null
      ? null : boundedText(response?.statusReason, 240);
    const server = response?.server === null ? null : boundedText(response?.server, 240);
    const contentType = response?.contentType === null
      ? null : boundedText(response?.contentType, 240);
    const contentLength = response?.contentLength === null
      ? null : boundedText(response?.contentLength, 20);
    const allow = response?.allow === null ? null : boundedText(response?.allow, 240);
    const outputSha256 = boundedText(response?.responseOutputSha256, 64);
    const headerNames = response?.headerNames;
    if (!request || !response || request.method !== "HEAD" || request.url !== origin.href
      || request.redirectPolicy !== "never" || request.credentialsSent !== false
      || !Number.isSafeInteger(statusCode) || Number(statusCode) < 100
      || Number(statusCode) > 599 || !outputSha256 || !SHA256.test(outputSha256)
      || !Array.isArray(headerNames) || headerNames.length > 256
      || headerNames.some((name) => !boundedText(name, 80))
      || (response.statusReason !== null && !statusReason)
      || (response.server !== null && !server)
      || (response.contentType !== null && !contentType)
      || (response.contentLength !== null
        && (!contentLength || !/^\d{1,20}$/u.test(contentLength)))
      || (response.allow !== null && !allow)) {
      return undefined;
    }
    const status = `${statusCode}${statusReason ? ` ${statusReason}` : ""}`;
    const stack = [
      { category: "http.status", value: status },
      ...(server ? [{ category: "http.server_header", value: server }] : []),
      ...(contentType ? [{ category: "http.content_type", value: contentType }] : []),
      ...(allow ? [{ category: "http.allow_header", value: allow }] : []),
    ];
    return {
      properties: canonicalObject({
        origin: origin.href,
        scheme: origin.scheme,
        host: origin.host,
        port: origin.port,
        requestMethod: "HEAD",
        redirectPolicy: "never",
        credentialsSent: false,
        statusCode: Number(statusCode),
        ...(statusReason ? { statusReason } : {}),
        headerNames: [...new Set(headerNames as string[])].sort(),
        ...(server ? { server } : {}),
        ...(contentType ? { contentType } : {}),
        ...(contentLength ? { contentLength } : {}),
        ...(allow ? { allow } : {}),
      }),
      stack,
      technologySignals: Object.freeze([]),
      endpoints: Object.freeze([]),
    };
  }

  #whatWebProperties(
    candidate: Readonly<Record<string, unknown>>,
    origin: WebOrigin,
  ): WebPhaseProperties | undefined {
    const fingerprint = plain(candidate.fingerprint) ? candidate.fingerprint : undefined;
    if (!fingerprint) return undefined;
    const stringArray = (value: unknown, maximum: number): readonly string[] | undefined => {
      if (!Array.isArray(value) || value.length > maximum) return undefined;
      const normalized = value.map((item) => boundedText(item, 300));
      return normalized.some((item) => !item)
        ? undefined
        : Object.freeze([...new Set(normalized as string[])]);
    };
    const serverSignals = stringArray(fingerprint.httpServerSignals, 64);
    const titleSignals = stringArray(fingerprint.titleSignals, 64);
    const poweredBySignals = stringArray(fingerprint.poweredBySignals, 64);
    const statusSignals = stringArray(fingerprint.statusSignals, 64);
    const strength = boundedText(fingerprint.identificationStrength, 120);
    const outputSha256 = boundedText(fingerprint.responseOutputSha256, 64);
    if (!serverSignals || !titleSignals || !poweredBySignals || !statusSignals
      || !statusSignals.every((value) => /^[0-9]{3}$/u.test(value))
      || typeof fingerprint.html5Observed !== "boolean"
      || !strength || !["bounded_banner_and_markup_signals", "no_positive_signal"].includes(strength)
      || !outputSha256 || !SHA256.test(outputSha256)) {
      return undefined;
    }
    const technologySignals = [
      ...serverSignals.map((value) => ({ category: "whatweb.http_server_signal", value })),
      ...poweredBySignals.map((value) => ({ category: "whatweb.powered_by_signal", value })),
      ...(fingerprint.html5Observed
        ? [{ category: "whatweb.markup_signal", value: "HTML5" }]
        : []),
    ];
    const stack = [
      { category: "whatweb.identification_strength", value: strength },
      ...technologySignals,
      ...statusSignals.map((value) => ({ category: "whatweb.http_status_signal", value })),
    ];
    return {
      properties: canonicalObject({
        origin: origin.href,
        scheme: origin.scheme,
        host: origin.host,
        port: origin.port,
        identificationStrength: strength,
        httpServerSignals: serverSignals,
        titleSignals,
        poweredBySignals,
        html5Observed: fingerprint.html5Observed,
        statusSignals,
      }),
      stack,
      technologySignals,
      endpoints: Object.freeze([]),
    };
  }

  #endpointProperties(
    candidate: Readonly<Record<string, unknown>>,
    origin: WebOrigin,
  ): WebPhaseProperties | undefined {
    const discovery = plain(candidate.discovery) ? candidate.discovery : undefined;
    if (!discovery) return undefined;
    const checkedPaths = discovery.checkedPaths;
    const matches = discovery.matches;
    const outputSha256 = boundedText(discovery.responseOutputSha256, 64);
    if (discovery.dictionaryVersion !== "ti-scale.web-paths.v1"
      || !Array.isArray(checkedPaths)
      || hashCanonical(checkedPaths) !== hashCanonical(REVIEWED_FFUF_PATHS)
      || discovery.requestBudget !== REVIEWED_FFUF_PATHS.length
      || discovery.maximumConcurrency !== 2
      || discovery.maximumRatePerSecond !== 10
      || discovery.recursive !== false
      || discovery.redirectFollowed !== false
      || !Array.isArray(matches)
      || matches.length > REVIEWED_FFUF_PATHS.length
      || discovery.matchCount !== matches.length
      || !outputSha256
      || !SHA256.test(outputSha256)) {
      return undefined;
    }
    const endpoints: WebEndpointMatch[] = [];
    const observedUrls = new Set<string>();
    for (const candidateMatch of matches) {
      if (!plain(candidateMatch)) return undefined;
      const path = boundedText(candidateMatch.path, 1_000);
      const url = boundedText(candidateMatch.url, 2_048);
      const status = candidateMatch.status;
      const permittedStatus = Number.isSafeInteger(status)
        && ((Number(status) >= 200 && Number(status) <= 399)
          || status === 401 || status === 403 || status === 405);
      const expectedUrl = path && REVIEWED_FFUF_PATHS.includes(
        path as (typeof REVIEWED_FFUF_PATHS)[number],
      )
        ? new URL(path, origin.href).href
        : undefined;
      const nonNegativeIntegerOrNull = (value: unknown): value is number | null =>
        value === null || (Number.isSafeInteger(value) && Number(value) >= 0);
      const redirectLocation = candidateMatch.redirectLocation === null
        ? null
        : boundedText(candidateMatch.redirectLocation, 1_000);
      if (!path || !url || !expectedUrl || url !== expectedUrl
        || observedUrls.has(url) || !permittedStatus
        || !nonNegativeIntegerOrNull(candidateMatch.length)
        || !nonNegativeIntegerOrNull(candidateMatch.words)
        || !nonNegativeIntegerOrNull(candidateMatch.lines)
        || (candidateMatch.redirectLocation !== null && !redirectLocation)) {
        return undefined;
      }
      const parsed = new URL(url);
      if (parsed.origin !== new URL(origin.href).origin
        || parsed.username || parsed.password || parsed.search || parsed.hash) {
        return undefined;
      }
      observedUrls.add(url);
      endpoints.push(Object.freeze({
        origin,
        path,
        url,
        status: Number(status),
        length: candidateMatch.length,
        words: candidateMatch.words,
        lines: candidateMatch.lines,
        redirectLocationObserved: redirectLocation !== null,
      }));
    }
    return {
      properties: canonicalObject({
        origin: origin.href,
        scheme: origin.scheme,
        host: origin.host,
        port: origin.port,
        endpointDictionaryVersion: "ti-scale.web-paths.v1",
        checkedPathCount: REVIEWED_FFUF_PATHS.length,
        requestBudget: REVIEWED_FFUF_PATHS.length,
        maximumConcurrency: 2,
        maximumRatePerSecond: 10,
        recursive: false,
        redirectFollowed: false,
        matchCount: endpoints.length,
        rawProcessOutputPromoted: false,
      }),
      stack: Object.freeze([{
        category: "ffuf.fixed_dictionary_check",
        value: `${REVIEWED_FFUF_PATHS.length} paths checked; ${endpoints.length} matches`,
      }]),
      technologySignals: Object.freeze([]),
      endpoints: Object.freeze(endpoints),
    };
  }
}
