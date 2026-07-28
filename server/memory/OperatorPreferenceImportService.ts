import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import type { TrustedLocalFileReceipt } from "../trusted-runtime-config";
import type { MemoryCandidate, MemoryNode, MemoryProvenance } from "./types";
import { MemoryRepository } from "./MemoryRepository";
import { SecondBrainService } from "./SecondBrainService";
import type {
  OperatorPreferenceManifest,
  OperatorPreferenceManifestItem,
} from "./OperatorPreferenceManifest";

export const OPERATOR_PREFERENCE_IMPORT_PREVIEW_SCHEMA_VERSION =
  "ti-scale.operator-preference-import-preview.v1" as const;
export const OPERATOR_PREFERENCE_IMPORT_RESULT_SCHEMA_VERSION =
  "ti-scale.operator-preference-import-result.v1" as const;

type CandidateDisposition = "missing" | "pending" | "confirmed";

export interface OperatorPreferenceImportPlanItem {
  readonly preferenceId: string;
  readonly preferenceKey: string;
  readonly category: OperatorPreferenceManifestItem["category"];
  readonly candidateId: string;
  readonly profileId: string;
  readonly observationId: string;
  readonly auditRecordId: string;
  readonly candidateDisposition: CandidateDisposition;
  readonly nodeId?: string;
  readonly contentSha256: string;
  readonly node: Readonly<{
    nodeType: "preference";
    title: string;
    summary: string;
    body: string;
    scope: Readonly<{ kind: "global" }>;
    sensitivity: "internal" | "private";
    confidence: 1;
    lifecycleStatus: "confirmed";
    confirmationState: "confirmed";
    authorType: "operator";
    authorId: string;
    provenance: MemoryProvenance;
  }>;
  readonly profile: Readonly<{
    operatorId: string;
    scope: "global";
    preferenceKey: string;
    value: Readonly<Record<string, unknown>>;
    confirmationState: "confirmed";
    confidence: 1;
    consentPolicy: "explicit_operator_confirmation";
    version: 1;
  }>;
}

interface OperatorPreferenceGraphNodePlan {
  readonly id: string;
  readonly key: string;
  readonly node: Readonly<{
    nodeType: "operator" | "entity";
    title: string;
    summary: string;
    body: string;
    scope: Readonly<{ kind: "global" }>;
    sensitivity: "internal" | "private";
    confidence: 1;
    lifecycleStatus: "confirmed";
    confirmationState: "confirmed";
    authorType: "operator";
    authorId: string;
    provenance: MemoryProvenance;
  }>;
}

interface OperatorPreferenceGraphEdgePlan {
  readonly id: string;
  readonly preferenceCandidateId: string;
  readonly targetApplicabilityNodeId?: string;
  readonly edgeType: "prefers" | "applies_to";
  readonly title: string;
  readonly summary: string;
  readonly explanation: string;
  readonly sensitivity: "private";
  readonly provenance: MemoryProvenance;
}

interface OperatorPreferenceGraphPlan {
  readonly operator: OperatorPreferenceGraphNodePlan;
  readonly applicability: readonly OperatorPreferenceGraphNodePlan[];
  readonly edges: readonly OperatorPreferenceGraphEdgePlan[];
}

export interface OperatorPreferenceImportPreview {
  readonly schemaVersion: typeof OPERATOR_PREFERENCE_IMPORT_PREVIEW_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly manifestSha256: string;
  readonly canonicalManifestSha256: string;
  readonly operatorId: string;
  readonly preferenceCount: number;
  readonly previewHash: string;
  readonly items: readonly OperatorPreferenceImportPlanItem[];
  readonly graph: OperatorPreferenceGraphPlan;
}

export interface OperatorPreferenceImportResult {
  readonly schemaVersion: typeof OPERATOR_PREFERENCE_IMPORT_RESULT_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly manifestSha256: string;
  readonly previewHash: string;
  readonly operatorId: string;
  readonly createdCandidates: number;
  readonly confirmedCandidates: number;
  readonly replayedCandidates: number;
  readonly createdProfiles: number;
  readonly replayedProfiles: number;
  readonly createdObservations: number;
  readonly replayedObservations: number;
  readonly createdAudits: number;
  readonly replayedAudits: number;
  readonly operatorNodeId: string;
  readonly createdGraphNodes: number;
  readonly replayedGraphNodes: number;
  readonly createdGraphEdges: number;
  readonly replayedGraphEdges: number;
  readonly nodeIds: readonly string[];
}

interface PreferenceProfileRow {
  readonly id: string;
  readonly operator_id: string;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_type: string | null;
  readonly preference_key: string;
  readonly value_json: string;
  readonly confirmation_state: string;
  readonly confidence: number;
  readonly source_node_id: string | null;
  readonly consent_policy: string;
  readonly version: number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableId(prefix: string, material: string): string {
  return `${prefix}_${sha256(material).slice(0, 48)}`;
}

function canonical(value: unknown, maximumBytes = 256 * 1_024): string {
  return digestCanonicalJson(value, { maxBytes: maximumBytes, maxDepth: 16 }).canonicalJson;
}

function profileValue(item: OperatorPreferenceManifestItem): Readonly<Record<string, unknown>> {
  return Object.freeze({
    category: item.category,
    value: item.value,
    appliesTo: item.appliesTo,
  });
}

function candidateDisposition(candidate: MemoryCandidate | undefined): CandidateDisposition {
  if (!candidate) return "missing";
  if (candidate.status === "pending") return "pending";
  if ((candidate.status === "confirmed" || candidate.status === "edited_confirmed")
      && candidate.proposedNodeId) return "confirmed";
  throw new Error(`Preference candidate ${candidate.id} has a terminal non-confirmed disposition`);
}

function candidateShape(input: {
  readonly manifest: OperatorPreferenceManifest;
  readonly receipt: TrustedLocalFileReceipt;
  readonly item: OperatorPreferenceManifestItem;
  readonly actorId: string;
}) {
  const sourceId = `${input.manifest.source.sourceId}:${input.item.id}`;
  const provenance = Object.freeze({
    method: "operator_statement" as const,
    explanation: "The operator explicitly confirmed this preference in a reviewed, hash-pinned local manifest.",
    sources: Object.freeze([Object.freeze({
      sourceType: input.manifest.source.sourceType,
      sourceId,
      sourceHash: input.receipt.sourceSha256,
      acquiredAt: input.manifest.source.acquiredAt,
      excerptRedacted: input.item.summary,
    })]),
  });
  return Object.freeze({
    nodeType: "preference" as const,
    title: input.item.title,
    summary: input.item.summary,
    body: input.item.body,
    scope: Object.freeze({ kind: "global" as const }),
    sensitivity: input.item.sensitivity,
    confidence: 1 as const,
    provenance,
    proposedBy: input.actorId,
  });
}

function humanLabel(value: string): string {
  const normalized = value.replaceAll("_", " ").replaceAll("-", " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function graphProvenance(input: {
  readonly manifest: OperatorPreferenceManifest;
  readonly receipt: TrustedLocalFileReceipt;
  readonly sourceSuffix: string;
  readonly summary: string;
}): MemoryProvenance {
  return Object.freeze({
    method: "operator_statement" as const,
    explanation: "This profile relationship was explicitly approved in the hash-pinned operator preference manifest.",
    sources: Object.freeze([Object.freeze({
      sourceType: input.manifest.source.sourceType,
      sourceId: `${input.manifest.source.sourceId}:${input.sourceSuffix}`,
      sourceHash: input.receipt.sourceSha256,
      acquiredAt: input.manifest.source.acquiredAt,
      excerptRedacted: input.summary,
    })]),
  });
}

function preferenceGraphPlan(input: {
  readonly manifest: OperatorPreferenceManifest;
  readonly receipt: TrustedLocalFileReceipt;
  readonly actorId: string;
  readonly items: readonly OperatorPreferenceImportPlanItem[];
}): OperatorPreferenceGraphPlan {
  const operatorId = stableId("mem_operator", input.actorId);
  const operatorSummary = "Canonical root for this operator's explicitly confirmed collaboration preferences.";
  const operator: OperatorPreferenceGraphNodePlan = Object.freeze({
    id: operatorId,
    key: input.actorId,
    node: Object.freeze({
      nodeType: "operator" as const,
      title: "Operator Profile",
      summary: operatorSummary,
      body: "This private profile root connects only explicit operator-confirmed preferences. It cannot weaken authorization, evidence, disclosure, or runtime safety policy.",
      scope: Object.freeze({ kind: "global" as const }),
      sensitivity: "private" as const,
      confidence: 1 as const,
      lifecycleStatus: "confirmed" as const,
      confirmationState: "confirmed" as const,
      authorType: "operator" as const,
      authorId: input.actorId,
      provenance: graphProvenance({
        ...input,
        sourceSuffix: "operator-profile",
        summary: operatorSummary,
      }),
    }),
  });
  const applicabilityKeys = [...new Set(input.manifest.preferences.flatMap(({ appliesTo }) => appliesTo))]
    .sort();
  const applicability = Object.freeze(applicabilityKeys.map((key): OperatorPreferenceGraphNodePlan => {
    const title = humanLabel(key);
    const summary = `Preference applicability domain: ${title}.`;
    return Object.freeze({
      id: stableId("mem_prefdomain", key),
      key,
      node: Object.freeze({
        nodeType: "entity" as const,
        title,
        summary,
        body: "A reviewed product surface that one or more explicit operator preferences may influence. Policy and safety controls remain authoritative.",
        scope: Object.freeze({ kind: "global" as const }),
        sensitivity: "internal" as const,
        confidence: 1 as const,
        lifecycleStatus: "confirmed" as const,
        confirmationState: "confirmed" as const,
        authorType: "operator" as const,
        authorId: input.actorId,
        provenance: graphProvenance({
          ...input,
          sourceSuffix: `applicability:${key}`,
          summary,
        }),
      }),
    });
  }));
  const applicabilityByKey = new Map(applicability.map((item) => [item.key, item.id]));
  const edges: OperatorPreferenceGraphEdgePlan[] = [];
  for (const item of input.items) {
    const manifestItem = input.manifest.preferences.find(({ id }) => id === item.preferenceId)!;
    const preferenceSource = graphProvenance({
      ...input,
      sourceSuffix: `preference-link:${manifestItem.id}`,
      summary: manifestItem.summary,
    });
    edges.push(Object.freeze({
      id: stableId("medge_opref", `${input.actorId}\0prefers\0${item.candidateId}`),
      preferenceCandidateId: item.candidateId,
      edgeType: "prefers" as const,
      title: "Prefers",
      summary: "The operator explicitly confirmed this collaboration preference.",
      explanation: "The reviewed preference manifest establishes this operator-owned preference without inferring personal attributes.",
      sensitivity: "private" as const,
      provenance: preferenceSource,
    }));
    for (const applicabilityKey of manifestItem.appliesTo) {
      edges.push(Object.freeze({
        id: stableId("medge_opref", `${item.candidateId}\0applies_to\0${applicabilityKey}`),
        preferenceCandidateId: item.candidateId,
        targetApplicabilityNodeId: applicabilityByKey.get(applicabilityKey)!,
        edgeType: "applies_to" as const,
        title: "Applies to",
        summary: `This preference applies to ${humanLabel(applicabilityKey)}.`,
        explanation: "The applicability was explicitly selected in the reviewed preference manifest.",
        sensitivity: "private" as const,
        provenance: preferenceSource,
      }));
    }
  }
  return Object.freeze({ operator, applicability, edges: Object.freeze(edges) });
}

function assertCandidateMatches(
  candidate: MemoryCandidate,
  expected: ReturnType<typeof candidateShape>,
): void {
  const actual = {
    nodeType: candidate.nodeType,
    title: candidate.title,
    summary: candidate.summary,
    body: candidate.body,
    scope: candidate.scope,
    sensitivity: candidate.sensitivity,
    confidence: candidate.confidence,
    provenance: candidate.provenance,
    proposedBy: candidate.proposedBy,
  };
  if (canonical(actual) !== canonical(expected)) {
    throw new Error(`Preference candidate ${candidate.id} conflicts with the reviewed manifest`);
  }
}

function assertNodeMatches(
  node: MemoryNode,
  expected: ReturnType<typeof candidateShape>,
  actorId: string,
): void {
  const actual = {
    nodeType: node.nodeType,
    title: node.title,
    summary: node.summary,
    body: node.body,
    scope: node.scope,
    sensitivity: node.sensitivity,
    confidence: node.confidence,
    lifecycleStatus: node.lifecycleStatus,
    confirmationState: node.confirmationState,
    provenance: node.provenance,
    authorType: node.authorType,
    authorId: node.authorId,
  };
  const planned = {
    nodeType: expected.nodeType,
    title: expected.title,
    summary: expected.summary,
    body: expected.body,
    scope: expected.scope,
    sensitivity: expected.sensitivity,
    confidence: expected.confidence,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: expected.provenance,
    authorType: "operator",
    authorId: actorId,
  };
  if (canonical(actual) !== canonical(planned)) {
    throw new Error(`Confirmed preference node ${node.id} conflicts with the reviewed manifest`);
  }
}

function assertGraphNodeMatches(node: MemoryNode, plan: OperatorPreferenceGraphNodePlan): void {
  const actual = {
    nodeType: node.nodeType,
    title: node.title,
    summary: node.summary,
    body: node.body,
    scope: node.scope,
    sensitivity: node.sensitivity,
    confidence: node.confidence,
    lifecycleStatus: node.lifecycleStatus,
    confirmationState: node.confirmationState,
    authorType: node.authorType,
    authorId: node.authorId,
    provenance: node.provenance,
  };
  if (canonical(actual) !== canonical(plan.node)) {
    throw new Error(`Operator preference graph node ${plan.id} conflicts with the reviewed manifest`);
  }
}

export class OperatorPreferenceImportService {
  readonly #repository: MemoryRepository;
  readonly #brain: SecondBrainService;
  readonly #clock: () => Date;

  constructor(
    private readonly database: SqliteDatabase,
    options: Readonly<{ clock?: () => Date }> = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#repository = new MemoryRepository(database, { clock: this.#clock });
    this.#brain = new SecondBrainService(this.#repository);
  }

  preview(input: {
    readonly manifest: OperatorPreferenceManifest;
    readonly receipt: TrustedLocalFileReceipt;
    readonly actorId: string;
  }): OperatorPreferenceImportPreview {
    if (input.actorId !== input.manifest.operatorId) {
      throw new Error("Preference manifest operator does not match the authenticated execution actor");
    }
    const items = input.manifest.preferences.map((item) => {
      const identity = `${input.actorId}\n${item.id}`;
      const candidateId = stableId("mcand_opref", identity);
      const existingCandidate = this.#repository.getCandidate(candidateId);
      const expected = candidateShape({ ...input, item });
      if (existingCandidate) assertCandidateMatches(existingCandidate, expected);
      const disposition = candidateDisposition(existingCandidate);
      const nodeId = disposition === "confirmed" ? existingCandidate?.proposedNodeId : undefined;
      if (nodeId) assertNodeMatches(this.#repository.requireNode(nodeId), expected, input.actorId);

      const existingProfile = this.#latestProfile(input.actorId, item.preferenceKey);
      const profileId = existingProfile?.id ?? stableId(
        "pprof_opref",
        `${input.actorId}\nglobal\n${item.preferenceKey}`,
      );
      const value = profileValue(item);
      if (existingProfile) this.#assertProfileMatches(existingProfile, value, nodeId);
      const plan = Object.freeze({
        preferenceId: item.id,
        preferenceKey: item.preferenceKey,
        category: item.category,
        candidateId,
        profileId,
        observationId: stableId("pobs_opref", `${input.receipt.sourceSha256}\n${item.id}`),
        auditRecordId: stableId("audit_opref", `${input.receipt.sourceSha256}\n${item.id}`),
        candidateDisposition: disposition,
        ...(nodeId ? { nodeId } : {}),
        contentSha256: sha256(canonical({ expected, value })),
        node: Object.freeze({
          nodeType: "preference" as const,
          title: expected.title,
          summary: expected.summary,
          body: expected.body,
          scope: expected.scope,
          sensitivity: expected.sensitivity,
          confidence: 1 as const,
          lifecycleStatus: "confirmed" as const,
          confirmationState: "confirmed" as const,
          authorType: "operator" as const,
          authorId: input.actorId,
          provenance: expected.provenance,
        }),
        profile: Object.freeze({
          operatorId: input.actorId,
          scope: "global" as const,
          preferenceKey: item.preferenceKey,
          value,
          confirmationState: "confirmed" as const,
          confidence: 1 as const,
          consentPolicy: item.consentPolicy,
          version: 1 as const,
        }),
      });
      return plan;
    });
    const graph = preferenceGraphPlan({ ...input, items });
    const review = {
      schemaVersion: OPERATOR_PREFERENCE_IMPORT_PREVIEW_SCHEMA_VERSION,
      manifestVersion: input.manifest.manifestVersion,
      manifestSha256: input.receipt.sourceSha256,
      canonicalManifestSha256: input.receipt.canonicalSha256,
      operatorId: input.actorId,
      preferenceCount: items.length,
      graph,
      items: items.map((item) => ({
        preferenceId: item.preferenceId,
        preferenceKey: item.preferenceKey,
        category: item.category,
        candidateId: item.candidateId,
        profileId: item.profileId,
        observationId: item.observationId,
        auditRecordId: item.auditRecordId,
        contentSha256: item.contentSha256,
        node: item.node,
        profile: item.profile,
      })),
    };
    return Object.freeze({
      ...review,
      previewHash: sha256(canonical(review)),
      items: Object.freeze(items),
      graph,
    });
  }

  execute(input: {
    readonly manifest: OperatorPreferenceManifest;
    readonly receipt: TrustedLocalFileReceipt;
    readonly actorId: string;
    readonly expectedPreviewHash: string;
    readonly reason: string;
  }): OperatorPreferenceImportResult {
    if (!/^[a-f0-9]{64}$/u.test(input.expectedPreviewHash)) {
      throw new Error("Expected preference preview hash must be a lowercase SHA-256");
    }
    const reason = input.reason.trim();
    if (reason.length < 4 || reason.length > 1_200) {
      throw new Error("Preference import reason must contain 4 to 1200 characters");
    }
    const preview = this.preview(input);
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new Error("Preference import preview changed; review and authorize the current hash");
    }

    return inImmediateTransaction(this.database, () => {
      const counts = {
        createdCandidates: 0,
        confirmedCandidates: 0,
        replayedCandidates: 0,
        createdProfiles: 0,
        replayedProfiles: 0,
        createdObservations: 0,
        replayedObservations: 0,
        createdAudits: 0,
        replayedAudits: 0,
        createdGraphNodes: 0,
        replayedGraphNodes: 0,
        createdGraphEdges: 0,
        replayedGraphEdges: 0,
      };
      const nodeIds: string[] = [];
      const preferenceNodes = new Map<string, MemoryNode>();
      for (const graphNode of [preview.graph.operator, ...preview.graph.applicability]) {
        const created = this.#upsertGraphNode(graphNode);
        counts[created ? "createdGraphNodes" : "replayedGraphNodes"] += 1;
      }
      for (const plan of preview.items) {
        const item = input.manifest.preferences.find(({ id }) => id === plan.preferenceId)!;
        const expected = candidateShape({ ...input, item });
        let candidate = this.#repository.getCandidate(plan.candidateId);
        if (!candidate) {
          candidate = this.#brain.proposeMemory({ id: plan.candidateId, ...expected });
          counts.createdCandidates += 1;
        } else {
          assertCandidateMatches(candidate, expected);
        }
        let node: MemoryNode;
        if (candidate.status === "pending") {
          node = this.#brain.confirmCandidate(candidate.id, input.actorId);
          counts.confirmedCandidates += 1;
        } else if ((candidate.status === "confirmed" || candidate.status === "edited_confirmed")
            && candidate.proposedNodeId) {
          node = this.#repository.requireNode(candidate.proposedNodeId);
          counts.replayedCandidates += 1;
        } else {
          throw new Error(`Preference candidate ${candidate.id} cannot be confirmed`);
        }
        assertNodeMatches(node, expected, input.actorId);
        nodeIds.push(node.id);
        preferenceNodes.set(plan.candidateId, node);

        const profileCreated = this.#upsertProfile(plan, node, this.#clock().toISOString());
        counts[profileCreated ? "createdProfiles" : "replayedProfiles"] += 1;
        const observationCreated = this.#upsertObservation(
          plan,
          input.manifest,
          input.receipt,
          this.#clock().toISOString(),
        );
        counts[observationCreated ? "createdObservations" : "replayedObservations"] += 1;
        const auditCreated = this.#appendAudit(
          plan,
          node,
          input.receipt,
          input.actorId,
          reason,
          this.#clock().toISOString(),
        );
        counts[auditCreated ? "createdAudits" : "replayedAudits"] += 1;
      }
      for (const graphEdge of preview.graph.edges) {
        const preferenceNode = preferenceNodes.get(graphEdge.preferenceCandidateId);
        if (!preferenceNode) {
          throw new Error(`Preference graph edge ${graphEdge.id} has no confirmed preference node`);
        }
        const sourceNodeId = graphEdge.edgeType === "prefers"
          ? preview.graph.operator.id
          : preferenceNode.id;
        const targetNodeId = graphEdge.edgeType === "prefers"
          ? preferenceNode.id
          : graphEdge.targetApplicabilityNodeId!;
        const created = this.#upsertGraphEdge(graphEdge, sourceNodeId, targetNodeId, input.actorId);
        counts[created ? "createdGraphEdges" : "replayedGraphEdges"] += 1;
      }
      return Object.freeze({
        schemaVersion: OPERATOR_PREFERENCE_IMPORT_RESULT_SCHEMA_VERSION,
        manifestVersion: input.manifest.manifestVersion,
        manifestSha256: input.receipt.sourceSha256,
        previewHash: preview.previewHash,
        operatorId: input.actorId,
        operatorNodeId: preview.graph.operator.id,
        ...counts,
        nodeIds: Object.freeze(nodeIds),
      });
    });
  }

  #upsertGraphNode(plan: OperatorPreferenceGraphNodePlan): boolean {
    const existing = this.#repository.getNode(plan.id);
    if (existing) {
      assertGraphNodeMatches(existing, plan);
      return false;
    }
    const created = this.#repository.createNode({ id: plan.id, ...plan.node });
    assertGraphNodeMatches(created, plan);
    return true;
  }

  #upsertGraphEdge(
    plan: OperatorPreferenceGraphEdgePlan,
    sourceNodeId: string,
    targetNodeId: string,
    actorId: string,
  ): boolean {
    const existing = this.database.prepare(`
      SELECT source_node_id, target_node_id, edge_type, title, summary,
        sensitivity, confidence, lifecycle_status, provenance_json,
        explanation, author_type, author_id, scope, engagement_id, mission_id
      FROM memory_edges WHERE id = ?
    `).get(plan.id) as {
      readonly source_node_id: string;
      readonly target_node_id: string;
      readonly edge_type: string;
      readonly title: string;
      readonly summary: string;
      readonly sensitivity: string;
      readonly confidence: number;
      readonly lifecycle_status: string;
      readonly provenance_json: string;
      readonly explanation: string;
      readonly author_type: string;
      readonly author_id: string | null;
      readonly scope: string;
      readonly engagement_id: string | null;
      readonly mission_id: string | null;
    } | undefined;
    const expected = {
      sourceNodeId,
      targetNodeId,
      edgeType: plan.edgeType,
      title: plan.title,
      summary: plan.summary,
      scope: "global",
      engagementId: null,
      missionId: null,
      sensitivity: plan.sensitivity,
      confidence: 1,
      lifecycleStatus: "confirmed",
      provenance: plan.provenance,
      explanation: plan.explanation,
      authorType: "operator",
      authorId: actorId,
    };
    if (existing) {
      const actual = {
        sourceNodeId: existing.source_node_id,
        targetNodeId: existing.target_node_id,
        edgeType: existing.edge_type,
        title: existing.title,
        summary: existing.summary,
        scope: existing.scope,
        engagementId: existing.engagement_id,
        missionId: existing.mission_id,
        sensitivity: existing.sensitivity,
        confidence: existing.confidence,
        lifecycleStatus: existing.lifecycle_status,
        provenance: JSON.parse(existing.provenance_json) as unknown,
        explanation: existing.explanation,
        authorType: existing.author_type,
        authorId: existing.author_id,
      };
      if (canonical(actual) !== canonical(expected)) {
        throw new Error(`Operator preference graph edge ${plan.id} conflicts with the reviewed manifest`);
      }
      return false;
    }
    this.#repository.createEdge({
      id: plan.id,
      sourceNodeId,
      targetNodeId,
      edgeType: plan.edgeType,
      title: plan.title,
      summary: plan.summary,
      scope: { kind: "global" },
      sensitivity: plan.sensitivity,
      confidence: 1,
      lifecycleStatus: "confirmed",
      provenance: plan.provenance,
      explanation: plan.explanation,
      authorType: "operator",
      authorId: actorId,
    });
    return true;
  }

  #latestProfile(operatorId: string, preferenceKey: string): PreferenceProfileRow | undefined {
    return this.database.prepare(`
      SELECT id, operator_id, scope, engagement_id, mission_type, preference_key,
        value_json, confirmation_state, confidence, source_node_id, consent_policy, version
      FROM preference_profiles
      WHERE operator_id = ? AND scope = 'global' AND engagement_id IS NULL
        AND mission_type IS NULL AND preference_key = ?
      ORDER BY version DESC LIMIT 1
    `).get(operatorId, preferenceKey) as PreferenceProfileRow | undefined;
  }

  #assertProfileMatches(
    profile: PreferenceProfileRow,
    value: Readonly<Record<string, unknown>>,
    nodeId?: string,
  ): void {
    if (profile.scope !== "global" || profile.engagement_id !== null || profile.mission_type !== null
        || profile.confirmation_state !== "confirmed" || profile.confidence !== 1
        || profile.consent_policy !== "explicit_operator_confirmation"
        || profile.version !== 1 || profile.value_json !== canonical(value, 16 * 1_024)
        || (nodeId !== undefined && profile.source_node_id !== nodeId)) {
      throw new Error(`Existing preference profile ${profile.id} conflicts with the reviewed manifest`);
    }
  }

  #upsertProfile(
    plan: OperatorPreferenceImportPlanItem,
    node: MemoryNode,
    now: string,
  ): boolean {
    const existing = this.#latestProfile(plan.profile.operatorId, plan.preferenceKey);
    if (existing) {
      this.#assertProfileMatches(existing, plan.profile.value, node.id);
      return false;
    }
    this.database.prepare(`
      INSERT INTO preference_profiles (
        id, operator_id, scope, engagement_id, mission_type, preference_key,
        value_json, confirmation_state, confidence, source_node_id, consent_policy,
        version, confirmed_at, created_at, updated_at
      ) VALUES (?, ?, 'global', NULL, NULL, ?, ?, 'confirmed', 1, ?, ?, 1, ?, ?, ?)
    `).run(
      plan.profileId,
      plan.profile.operatorId,
      plan.preferenceKey,
      canonical(plan.profile.value, 16 * 1_024),
      node.id,
      plan.profile.consentPolicy,
      now,
      now,
      now,
    );
    return true;
  }

  #upsertObservation(
    plan: OperatorPreferenceImportPlanItem,
    manifest: OperatorPreferenceManifest,
    receipt: TrustedLocalFileReceipt,
    now: string,
  ): boolean {
    const expectedValue = canonical(plan.profile.value, 16 * 1_024);
    const existing = this.database.prepare(`
      SELECT profile_id, preference_key, observed_value_json, source_type, source_id,
        confidence, consent_state FROM preference_observations WHERE id = ?
    `).get(plan.observationId) as {
      profile_id: string | null;
      preference_key: string;
      observed_value_json: string;
      source_type: string;
      source_id: string;
      confidence: number;
      consent_state: string;
    } | undefined;
    const sourceId = `${manifest.source.sourceId}:${plan.preferenceId}:${receipt.sourceSha256}`;
    if (existing) {
      if (existing.profile_id !== plan.profileId || existing.preference_key !== plan.preferenceKey
          || existing.observed_value_json !== expectedValue
          || existing.source_type !== manifest.source.sourceType || existing.source_id !== sourceId
          || existing.confidence !== 1 || existing.consent_state !== "granted") {
        throw new Error(`Preference observation ${plan.observationId} conflicts with the reviewed manifest`);
      }
      return false;
    }
    this.database.prepare(`
      INSERT INTO preference_observations (
        id, profile_id, preference_key, observed_value_json, source_type,
        source_id, confidence, consent_state, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 'granted', ?)
    `).run(
      plan.observationId,
      plan.profileId,
      plan.preferenceKey,
      expectedValue,
      manifest.source.sourceType,
      sourceId,
      now,
    );
    return true;
  }

  #appendAudit(
    plan: OperatorPreferenceImportPlanItem,
    node: MemoryNode,
    receipt: TrustedLocalFileReceipt,
    actorId: string,
    reason: string,
    occurredAt: string,
  ): boolean {
    const details = Object.freeze({
      schemaVersion: "ti-scale.operator-preference-import-audit.v2",
      manifestSha256: receipt.sourceSha256,
      canonicalManifestSha256: receipt.canonicalSha256,
      preferenceId: plan.preferenceId,
      preferenceKey: plan.preferenceKey,
      category: plan.category,
      candidateId: plan.candidateId,
      profileId: plan.profileId,
      observationId: plan.observationId,
      nodeContentSha256: plan.contentSha256,
      scope: "global",
      confirmationState: "confirmed",
    });
    const existing = this.database.prepare(`
      SELECT actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json FROM audit_records WHERE id = ?
    `).get(plan.auditRecordId) as {
      actor_type: string;
      actor_id: string | null;
      action: string;
      resource_type: string;
      resource_id: string | null;
      reason: string | null;
      details_json: string;
    } | undefined;
    const detailsJson = canonical(details);
    if (existing) {
      if (existing.actor_type !== "operator" || existing.actor_id !== actorId
          || existing.action !== "memory.preference.confirmed_from_manifest"
          || existing.resource_type !== "memory_node" || existing.resource_id !== node.id
          || existing.reason !== reason || existing.details_json !== detailsJson) {
        throw new Error(`Preference audit ${plan.auditRecordId} conflicts with the reviewed manifest`);
      }
      return false;
    }
    const previous = this.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const hashMaterial = {
      id: plan.auditRecordId,
      actor: actorId,
      action: "memory.preference.confirmed_from_manifest",
      resourceType: "memory_node",
      resourceId: node.id,
      reason,
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt,
    };
    const recordHash = sha256(canonical(hashMaterial));
    this.database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, 'operator', ?, 'memory.preference.confirmed_from_manifest',
        'memory_node', ?, ?, ?, ?, ?, ?)
    `).run(
      plan.auditRecordId,
      actorId,
      node.id,
      reason,
      detailsJson,
      previous?.record_hash ?? null,
      recordHash,
      occurredAt,
    );
    return true;
  }
}
