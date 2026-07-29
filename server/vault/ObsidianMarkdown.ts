import { createHash } from "node:crypto";
import type { MemoryEdge, MemoryNode, ProvenanceSource } from "../memory/types";
import {
  isAttackCentricReusableNodeType,
  MEMORY_EDGE_TYPES,
  validateConfidence,
  validateEdgeType,
  validateLifecycle,
  validateNodeType,
  validateScope,
  validateSensitivity,
} from "../memory/index";
import type {
  VaultNote,
  VaultNoteAttachment,
  VaultNoteEdge,
  VaultPrivateProvenanceSummary,
} from "./types";
import {
  canonicalReusableKnowledgeOutcomeTags,
  isReusableKnowledgeOutcomeTag,
  type ReusableKnowledgeOutcomeTag,
} from "../domain/reusable-knowledge-outcomes";
import {
  historicalReportedOutcomeTag,
  isHistoricalReportedOutcomeClassification,
  type HistoricalReportedOutcomeSummary,
} from "../domain/historical-reported-outcomes";
import { safeVaultSegment } from "./VaultPathPolicy";
import {
  ATTACK_BRAIN_ATLAS_VAULT_FOLDERS,
  attackBrainAtlasMapping,
  operatorProfileBrainAtlasMapping,
} from "./AttackBrainAtlasMappingRegistry";
import { OPERATOR_PROFILE_VAULT_FOLDER } from "./OperatorProfileVaultProjection";

const EDGE_MARKER = /<!--\s*ti-scale-edge:([a-z_]+):([A-Za-z0-9._:-]+)\s*-->/g;
const WIKILINK = /\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|([^\]]+))?\]\]/g;
const OBSIDIAN_ATTACHMENT = /!\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\](?:\s*<!--\s*ti-scale-attachment:([A-Za-z0-9._:-]+):([a-f0-9]{64})\s*-->)?/giu;
const MARKDOWN_ATTACHMENT = /!\[[^\]]*\]\(([^)\s]+)\)/gu;
const PRIVATE_PROVENANCE_SECTION_MARKER = /<!--\s*ti-scale-private-provenance-summary:v1:(\d+):(\d+):([a-f0-9]{64}):(complete|truncated)\s*-->/gu;
const PRIVATE_PROVENANCE_ID = /^msrc_[A-Za-z0-9._:-]+$/u;

export const PRIVATE_PROVENANCE_SCHEMA = "ti-scale/private-provenance/v1" as const;
export const MAX_PROJECTED_PRIVATE_PROVENANCE_IDS = 32;

export interface PrivateProvenanceProjection {
  readonly ids: readonly string[];
  readonly summary: VaultPrivateProvenanceSummary;
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

/**
 * Produce a stable, bounded view of opaque source-custody row IDs. The digest
 * binds the complete canonical set, including IDs omitted from Markdown.
 */
export function projectPrivateProvenanceIds(ids: readonly string[]): PrivateProvenanceProjection {
  const canonical = [...ids];
  if (canonical.some((id) => !PRIVATE_PROVENANCE_ID.test(id))) {
    throw new TypeError("Canonical private provenance reference is malformed");
  }
  canonical.sort(compareUtf8);
  if (canonical.some((id, index) => index > 0 && id === canonical[index - 1])) {
    throw new TypeError("Canonical private provenance references must be unique");
  }
  const sha256 = createHash("sha256")
    .update(`${PRIVATE_PROVENANCE_SCHEMA}\n`, "utf8")
    .update(canonical.join("\n"), "utf8")
    .update("\n", "utf8")
    .digest("hex");
  const projectedIds = canonical.slice(0, MAX_PROJECTED_PRIVATE_PROVENANCE_IDS);
  return {
    ids: projectedIds,
    summary: {
      schema: PRIVATE_PROVENANCE_SCHEMA,
      total: canonical.length,
      projected: projectedIds.length,
      sha256,
      truncated: canonical.length > projectedIds.length,
    },
  };
}

/**
 * Stable V2.4 human-facing vault taxonomy. These directories are created for
 * every connection even when a particular canonical domain has no notes yet,
 * so the vault remains predictable in Obsidian and future typed projections
 * do not depend on whichever screen happened to create a note first.
 */
export const OBSIDIAN_V2_4_VAULT_FOLDERS = [
  "00 Inbox",
  ...ATTACK_BRAIN_ATLAS_VAULT_FOLDERS,
  "Attachments",
] as const;

/**
 * Convert a canonical, vault-relative Markdown note path into an Obsidian
 * wikilink target. Persisted sync paths may originate from operator filenames,
 * so reject rather than escape anything that could alter Markdown structure or
 * resolve outside the vault. A rejected optional target causes its relationship
 * line to be omitted; it never falls back to a different, potentially missing
 * projection path.
 */
export function normalizeObsidianWikilinkTarget(relativePath: string): string | undefined {
  if (
    relativePath.length === 0
    || relativePath.length > 1_024
    || relativePath !== relativePath.trim()
    || relativePath.startsWith("/")
    || relativePath.includes("\\")
    || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(relativePath)
    || /[\[\]|#]/u.test(relativePath)
    || /^[A-Za-z]:/u.test(relativePath)
    || !relativePath.toLowerCase().endsWith(".md")
  ) return undefined;
  const segments = relativePath.split("/");
  if (
    segments.length < 2
    || segments.some((segment) => (
      segment.length === 0
      || segment !== segment.trim()
      || segment === "."
      || segment === ".."
    ))
    || segments.at(-1)?.toLowerCase() === ".md"
  ) return undefined;
  return relativePath.slice(0, -3);
}

/**
 * Produce one human-readable Markdown inline value without allowing canonical
 * node/edge text to create another wikilink, HTML comment, code span, or line.
 * HTML entities are deliberate: Obsidian renders the original punctuation,
 * while the Markdown source retains an unambiguous managed structure.
 */
export function escapeObsidianSingleLineText(value: string): string {
  return value
    .normalize("NFC")
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .replaceAll("&", "&amp;")
    .replaceAll("\\", "&#92;")
    .replaceAll("`", "&#96;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("[", "&#91;")
    .replaceAll("]", "&#93;")
    .replaceAll("|", "&#124;");
}

function decodeObsidianSingleLineText(value: string): string {
  return value
    .replaceAll("&#92;", "\\")
    .replaceAll("&#96;", "`")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&#91;", "[")
    .replaceAll("&#93;", "]")
    .replaceAll("&#124;", "|")
    // Decode ampersand last so operator-authored entity-looking text survives
    // a render/parse round trip as text rather than becoming structure.
    .replaceAll("&amp;", "&");
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function yamlList(key: string, values: readonly string[]): string[] {
  if (values.length === 0) return [`${key}: []`];
  return [`${key}:`, ...values.map((value) => `  - ${yamlString(value)}`)];
}

function parseScalar(value: string): string | number | boolean | null | string[] {
  const trimmed = value.trim();
  if (trimmed === "") return "";
  if (trimmed === "null" || trimmed === "~") return null;
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed);
  if (trimmed === "[]") return [];
  if (trimmed.startsWith('"')) {
    const parsed = JSON.parse(trimmed) as unknown;
    if (typeof parsed !== "string") throw new Error("YAML scalar must be a string");
    return parsed;
  }
  if (/[[\]{}&*!>|%@`]/.test(trimmed)) throw new Error("Unsupported YAML syntax");
  return trimmed;
}

function parseFrontmatter(source: string): { properties: Record<string, unknown>; markdown: string } {
  const normalized = source.replaceAll("\r\n", "\n");
  if (!normalized.startsWith("---\n")) throw new Error("Obsidian note is missing YAML frontmatter");
  const end = normalized.indexOf("\n---\n", 4);
  if (end < 0) throw new Error("Obsidian note has unterminated YAML frontmatter");
  const properties: Record<string, unknown> = {};
  const lines = normalized.slice(4, end).split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const match = /^([a-zA-Z][a-zA-Z0-9_]*):(?:\s*(.*))?$/.exec(line);
    if (!match) throw new Error(`Unsupported YAML line ${index + 1}`);
    const key = match[1]!;
    const raw = match[2] ?? "";
    if (Object.hasOwn(properties, key)) throw new Error(`Duplicate YAML property: ${key}`);
    if (raw.trim()) {
      properties[key] = parseScalar(raw);
      continue;
    }
    const values: string[] = [];
    while (index + 1 < lines.length) {
      const item = /^\s{2}-\s+(.*)$/.exec(lines[index + 1]!);
      if (!item) break;
      const parsed = parseScalar(item[1]!);
      if (typeof parsed !== "string") throw new Error(`YAML list ${key} must contain strings`);
      values.push(parsed);
      index += 1;
    }
    properties[key] = values;
  }
  return { properties, markdown: normalized.slice(end + 5) };
}

function requiredString(properties: Record<string, unknown>, key: string): string {
  const value = properties[key];
  if (typeof value !== "string" || !value.trim()) throw new Error(`YAML property ${key} is required`);
  return value;
}

function stringList(properties: Record<string, unknown>, key: string): string[] {
  const value = properties[key];
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`YAML property ${key} must be a string list`);
  }
  return value as string[];
}

function privateProvenanceSummary(
  properties: Record<string, unknown>,
  privateProvenanceIds: readonly string[],
): VaultPrivateProvenanceSummary | undefined {
  const keys = [
    "private_provenance_schema",
    "private_provenance_total",
    "private_provenance_projected",
    "private_provenance_sha256",
    "private_provenance_truncated",
  ] as const;
  const present = keys.filter((key) => properties[key] !== undefined);
  if (present.length === 0) return undefined;
  if (present.length !== keys.length) {
    throw new Error("YAML private provenance summary is incomplete");
  }
  const schema = requiredString(properties, "private_provenance_schema");
  if (schema !== PRIVATE_PROVENANCE_SCHEMA) {
    throw new Error("YAML private provenance schema is unsupported");
  }
  const total = properties.private_provenance_total;
  const projected = properties.private_provenance_projected;
  const sha256 = requiredString(properties, "private_provenance_sha256");
  const truncated = properties.private_provenance_truncated;
  if (!Number.isSafeInteger(total) || Number(total) < 0) {
    throw new Error("YAML private_provenance_total is invalid");
  }
  if (!Number.isSafeInteger(projected) || Number(projected) < 0) {
    throw new Error("YAML private_provenance_projected is invalid");
  }
  if (!/^[a-f0-9]{64}$/u.test(sha256)) {
    throw new Error("YAML private_provenance_sha256 is invalid");
  }
  if (typeof truncated !== "boolean") {
    throw new Error("YAML private_provenance_truncated is invalid");
  }
  const canonicalVisible = projectPrivateProvenanceIds(privateProvenanceIds);
  if (
    canonicalVisible.ids.length !== privateProvenanceIds.length
    || canonicalVisible.ids.some((id, index) => id !== privateProvenanceIds[index])
  ) {
    throw new Error("YAML private provenance references are not in canonical order");
  }
  if (
    Number(projected) !== privateProvenanceIds.length
    || Number(projected) > MAX_PROJECTED_PRIVATE_PROVENANCE_IDS
    || Number(total) < Number(projected)
    || truncated !== (Number(total) > Number(projected))
  ) {
    throw new Error("YAML private provenance summary counts are inconsistent");
  }
  if (!truncated && (Number(total) !== privateProvenanceIds.length || sha256 !== canonicalVisible.summary.sha256)) {
    throw new Error("YAML private provenance digest does not match its complete reference set");
  }
  return {
    schema: PRIVATE_PROVENANCE_SCHEMA,
    total: Number(total),
    projected: Number(projected),
    sha256,
    truncated,
  };
}

function stripManagedAttachmentReferences(source: string): string {
  OBSIDIAN_ATTACHMENT.lastIndex = 0;
  let stripped = source.replace(OBSIDIAN_ATTACHMENT, (match, relativePath: string) => (
    relativePath.trim().startsWith("Attachments/") ? "" : match
  ));
  MARKDOWN_ATTACHMENT.lastIndex = 0;
  stripped = stripped.replace(MARKDOWN_ATTACHMENT, (match, relativePath: string) => (
    relativePath.trim().startsWith("Attachments/") ? "" : match
  ));
  return stripped.replace(/\n{3,}/gu, "\n\n").trim();
}

function notePath(node: Pick<MemoryNode, "id" | "title" | "nodeType">): string {
  const operationalFolder: Partial<Record<MemoryNode["nodeType"], string>> = {
    operator: "10 Operator",
    preference: "10 Operator",
    mission: "21 Missions",
    run: "22 Runs",
    plan: "40 Attack Plans",
    phase: "40 Attack Plans",
    step: "40 Attack Plans",
    tactic: "41 Attack Paths",
    technique: "41 Attack Paths",
    procedure: "41 Attack Paths",
    tool: "81 Tools and MCP",
    mcp_capability: "81 Tools and MCP",
    evidence: "50 Evidence",
    finding: "51 Findings",
    failure: "60 Failures and Recoveries",
    recovery: "60 Failures and Recoveries",
    lesson: "70 Lessons",
    agent: "80 Agents",
    report: "90 Reports",
    evaluation: "70 Lessons",
    artifact: "53 Artifacts",
    target: "30 Assets",
    asset: "30 Assets",
    entity: "30 Assets",
    decision: "40 Attack Plans",
    source: "00 Inbox",
  };
  const operatorPreferenceDomain = node.nodeType === "entity"
    && node.id.startsWith("mem_prefdomain_");
  const folder = operatorPreferenceDomain
    ? OPERATOR_PROFILE_VAULT_FOLDER
    : isAttackCentricReusableNodeType(node.nodeType)
    ? attackBrainAtlasMapping(node.nodeType).folder
    : operationalFolder[node.nodeType] ?? "00 Inbox";
  const slug = safeVaultSegment(node.title, "memory");
  return `${folder}/${slug}--${safeVaultSegment(node.id, "node")}.md`;
}

export function vaultRelativePath(node: Pick<MemoryNode, "id" | "title" | "nodeType">): string {
  return notePath(node);
}

export function renderObsidianNote(
  node: MemoryNode,
  sources: readonly (Pick<ProvenanceSource, "sourceId"> & {
    readonly privateProvenanceId?: string;
  })[],
  edges: readonly {
    readonly edge: MemoryEdge;
    readonly target: MemoryNode;
    /** Preserve a connection's already-synchronized legacy projection path. */
    readonly relativePath?: string;
  }[],
  attachments: readonly {
    readonly artifactId: string;
    readonly contentHash: string;
    readonly relativePath: string;
  }[] = [],
  backlinks: readonly {
    readonly edge: MemoryEdge;
    readonly source: MemoryNode;
    /** Preserve a connection's already-synchronized legacy projection path. */
    readonly relativePath?: string;
  }[] = [],
  outcomeTags: readonly ReusableKnowledgeOutcomeTag[] = [],
  reportedOutcome?: HistoricalReportedOutcomeSummary,
): string {
  const attackKnowledge = isAttackCentricReusableNodeType(node.nodeType);
  const operatorProfileAtlas = attackKnowledge
    ? undefined
    : operatorProfileBrainAtlasMapping(node);
  const brainRegion = attackKnowledge
    ? attackBrainAtlasMapping(node.nodeType).region
    : operatorProfileAtlas?.region;
  const privateProvenance = attackKnowledge
    ? projectPrivateProvenanceIds(sources.map((source) => {
      if (!source.privateProvenanceId) {
        throw new TypeError("Reusable attack knowledge requires canonical private provenance references");
      }
      return source.privateProvenanceId;
    }))
    : undefined;
  const canonicalOutcomeTags = canonicalReusableKnowledgeOutcomeTags(outcomeTags);
  const edgeLines = edges.flatMap(({ edge, target, relativePath }) => {
    const targetPath = normalizeObsidianWikilinkTarget(relativePath ?? notePath(target));
    if (!targetPath) return [];
    const alias = escapeObsidianSingleLineText(target.title);
    const explanation = escapeObsidianSingleLineText(edge.explanation);
    return [`- [[${targetPath}|${alias}]] — ${edge.edgeType}: ${explanation} <!-- ti-scale-edge:${edge.edgeType}:${target.id} -->`];
  });
  const backlinkLines = backlinks.flatMap(({ edge, source, relativePath }) => {
    const sourcePath = normalizeObsidianWikilinkTarget(relativePath ?? notePath(source));
    if (!sourcePath) return [];
    const alias = escapeObsidianSingleLineText(source.title);
    const explanation = escapeObsidianSingleLineText(edge.explanation);
    // This is a native graph backlink, not a canonical edge declaration. The
    // distinct marker lets Obsidian connect high-fanout artifacts to their run
    // without a later Vault import creating a reversed memory edge.
    return [`- [[${sourcePath}|${alias}]] — incoming ${edge.edgeType}: ${explanation} <!-- ti-scale-backlink:${edge.edgeType}:${source.id} -->`];
  });
  const lines = [
    "---",
    `id: ${yamlString(node.id)}`,
    `type: ${yamlString(node.nodeType)}`,
    ...(operatorProfileAtlas
      ? [`operator_profile_class: ${yamlString(operatorProfileAtlas.profileClass)}`]
      : []),
    ...(brainRegion
      ? [`brain_region: ${yamlString(brainRegion)}`]
      : []),
    `status: ${yamlString(node.lifecycleStatus)}`,
    `scope: ${yamlString(node.scope.kind)}`,
    ...(node.scope.engagementId ? [`engagement_id: ${yamlString(node.scope.engagementId)}`] : []),
    ...(node.scope.missionId ? [`mission_id: ${yamlString(node.scope.missionId)}`] : []),
    `confidence: ${node.confidence}`,
    `sensitivity: ${yamlString(node.sensitivity)}`,
    `confirmation_state: ${yamlString(node.confirmationState)}`,
    `summary: ${yamlString(node.summary)}`,
    `author: ${yamlString(node.authorType)}`,
    ...(node.authorId ? [`author_id: ${yamlString(node.authorId)}`] : []),
    `version: ${node.version}`,
    `created_at: ${yamlString(node.createdAt)}`,
    `updated_at: ${yamlString(node.updatedAt)}`,
    ...(node.expiresAt ? [`expires_at: ${yamlString(node.expiresAt)}`] : []),
    ...(canonicalOutcomeTags.length > 0
      ? yamlList("outcome_tags", canonicalOutcomeTags)
      : []),
    ...(reportedOutcome ? [
      `reported_outcome: ${yamlString(reportedOutcome.classification)}`,
      `reported_outcome_confidence: ${reportedOutcome.classificationConfidence}`,
      `reported_outcome_claim_count: ${reportedOutcome.claimCount}`,
      `reported_outcome_source_count: ${reportedOutcome.sourceCount}`,
      `reported_outcome_policy: ${yamlString(reportedOutcome.policyVersion)}`,
    ] : []),
    // Reusable attack knowledge never exposes a mission path, run ID, target
    // locator, or evidence ID. High-fanout custody remains complete in SQLite;
    // this Markdown projection is bounded and bound to the full set by digest.
    ...(privateProvenance ? [
      `private_provenance_schema: ${yamlString(privateProvenance.summary.schema)}`,
      `private_provenance_total: ${privateProvenance.summary.total}`,
      `private_provenance_projected: ${privateProvenance.summary.projected}`,
      `private_provenance_sha256: ${yamlString(privateProvenance.summary.sha256)}`,
      `private_provenance_truncated: ${privateProvenance.summary.truncated}`,
    ] : []),
    ...yamlList(
      "private_provenance_ids",
      privateProvenance?.ids ?? [],
    ),
    ...yamlList("source_ids", attackKnowledge ? [] : sources.map((source) => source.sourceId)),
    ...yamlList("attachment_ids", attachments.map((attachment) => attachment.artifactId)),
    ...yamlList("aliases", [node.id]),
    ...yamlList("tags", [
      `ti-scale/${node.nodeType}`,
      `ti-scale/${node.lifecycleStatus}`,
      ...canonicalOutcomeTags.map((tag) => `ti-scale/outcome/${tag}`),
      ...(reportedOutcome ? [historicalReportedOutcomeTag(reportedOutcome.classification)] : []),
    ]),
    "---",
    "",
    `# ${escapeObsidianSingleLineText(node.title)}`,
    "",
    node.body,
    ...(privateProvenance ? [
      "",
      `<!-- ti-scale-private-provenance-summary:v1:${privateProvenance.summary.total}:${privateProvenance.summary.projected}:${privateProvenance.summary.sha256}:${privateProvenance.summary.truncated ? "truncated" : "complete"} -->`,
      "## Private provenance",
      "",
      `- Canonical SQLite source records: ${privateProvenance.summary.total}`,
      `- Opaque references projected here: ${privateProvenance.summary.projected}`,
      `- Projection truncated: ${privateProvenance.summary.truncated ? "yes" : "no"}`,
      `- Full-set SHA-256: \`${privateProvenance.summary.sha256}\``,
      "- Full private source custody remains canonical and queryable in the local Ti-Scale database.",
    ] : []),
    ...(attachments.length > 0 ? [
      "",
      "## Attachments",
      "",
      ...attachments.map((attachment) => (
        `![[${attachment.relativePath}]] <!-- ti-scale-attachment:${attachment.artifactId}:${attachment.contentHash} -->`
      )),
    ] : []),
    ...(edgeLines.length + backlinkLines.length > 0
      ? ["", "## Relationships", "", ...edgeLines, ...backlinkLines]
      : []),
    "",
  ];
  return lines.join("\n");
}

export function parseObsidianNote(source: string): VaultNote {
  const { properties, markdown } = parseFrontmatter(source);
  const id = requiredString(properties, "id");
  const nodeType = validateNodeType(requiredString(properties, "type"));
  const operatorProfileClass = properties.operator_profile_class === undefined
    ? undefined
    : requiredString(properties, "operator_profile_class");
  const operatorProfileAtlas = operatorProfileBrainAtlasMapping({ id, nodeType });
  if (operatorProfileClass !== undefined) {
    if (!operatorProfileAtlas || operatorProfileClass !== operatorProfileAtlas.profileClass) {
      throw new Error("YAML operator_profile_class is not a valid consent-bound Operator Profile classification");
    }
  }
  const brainRegion = properties.brain_region === undefined
    ? undefined
    : requiredString(properties, "brain_region");
  if (brainRegion !== undefined) {
    if (isAttackCentricReusableNodeType(nodeType)) {
      if (brainRegion !== attackBrainAtlasMapping(nodeType).region) {
        throw new Error("YAML brain_region does not match the reusable attack-knowledge taxonomy");
      }
    } else if (
      !operatorProfileAtlas
      || operatorProfileClass !== operatorProfileAtlas.profileClass
      || brainRegion !== operatorProfileAtlas.region
    ) {
      throw new Error("YAML brain_region is permitted only for reusable attack knowledge or an explicit Operator Profile classification");
    }
  }
  if (operatorProfileClass !== undefined && brainRegion === undefined) {
    throw new Error("YAML Operator Profile classification requires its canonical brain_region");
  }
  if (isAttackCentricReusableNodeType(nodeType) && operatorProfileClass !== undefined) {
    throw new Error("Reusable attack knowledge cannot claim an Operator Profile classification");
  }
  const lifecycleStatus = validateLifecycle(requiredString(properties, "status"));
  const scope = validateScope({
    kind: requiredString(properties, "scope") as "global" | "engagement" | "mission",
    ...(properties.engagement_id ? { engagementId: requiredString(properties, "engagement_id") } : {}),
    ...(properties.mission_id ? { missionId: requiredString(properties, "mission_id") } : {}),
  });
  const confidence = validateConfidence(properties.confidence);
  const sensitivity = validateSensitivity(requiredString(properties, "sensitivity"));
  const confirmationState = requiredString(properties, "confirmation_state") as VaultNote["confirmationState"];
  if (!["not_required", "pending", "confirmed", "rejected"].includes(confirmationState)) {
    throw new Error("YAML confirmation_state is invalid");
  }
  const authorType = requiredString(properties, "author") as VaultNote["authorType"];
  if (!["operator", "agent", "system", "import"].includes(authorType)) throw new Error("YAML author is invalid");
  const version = properties.version;
  if (!Number.isSafeInteger(version) || Number(version) < 1) throw new Error("YAML version is invalid");
  const rawOutcomeTags = stringList(properties, "outcome_tags");
  if (rawOutcomeTags.some((tag) => !isReusableKnowledgeOutcomeTag(tag))) {
    throw new Error("YAML outcome_tags contains an unsupported outcome classification");
  }
  const outcomeTags = canonicalReusableKnowledgeOutcomeTags(
    rawOutcomeTags as ReusableKnowledgeOutcomeTag[],
  );
  const rawReportedOutcome = properties.reported_outcome;
  let reportedOutcome: HistoricalReportedOutcomeSummary | undefined;
  if (rawReportedOutcome !== undefined) {
    if (!isHistoricalReportedOutcomeClassification(rawReportedOutcome)) {
      throw new Error("YAML reported_outcome contains an unsupported historical classification");
    }
    const reportedConfidence = properties.reported_outcome_confidence;
    const claimCount = properties.reported_outcome_claim_count;
    const sourceCount = properties.reported_outcome_source_count;
    const policyVersion = properties.reported_outcome_policy;
    if (
      typeof reportedConfidence !== "number"
      || !Number.isFinite(reportedConfidence)
      || reportedConfidence < 0
      || reportedConfidence > 1
      || !Number.isSafeInteger(claimCount)
      || Number(claimCount) < 1
      || !Number.isSafeInteger(sourceCount)
      || Number(sourceCount) < 1
      || typeof policyVersion !== "string"
      || !policyVersion.trim()
      || policyVersion.length > 128
    ) {
      throw new Error("YAML historical reported-outcome summary is invalid");
    }
    reportedOutcome = {
      classification: rawReportedOutcome,
      classificationConfidence: reportedConfidence,
      claimCount: Number(claimCount),
      sourceCount: Number(sourceCount),
      policyVersion,
    };
  }
  const privateProvenanceIds = stringList(properties, "private_provenance_ids");
  const provenanceSummary = privateProvenanceSummary(properties, privateProvenanceIds);
  const heading = /^#\s+(.+)$/m.exec(markdown);
  if (!heading) throw new Error("Obsidian note requires a level-one title");
  const relationshipsIndex = markdown.search(/^## Relationships\s*$/m);
  const attachmentsIndex = markdown.search(/^## Attachments\s*$/m);
  PRIVATE_PROVENANCE_SECTION_MARKER.lastIndex = 0;
  const provenanceMarkers = [...markdown.matchAll(PRIVATE_PROVENANCE_SECTION_MARKER)];
  PRIVATE_PROVENANCE_SECTION_MARKER.lastIndex = 0;
  if (provenanceSummary) {
    if (provenanceMarkers.length !== 1) {
      throw new Error("Managed private provenance Markdown summary is missing or duplicated");
    }
    const marker = provenanceMarkers[0]!;
    if (
      Number(marker[1]) !== provenanceSummary.total
      || Number(marker[2]) !== provenanceSummary.projected
      || marker[3] !== provenanceSummary.sha256
      || (marker[4] === "truncated") !== provenanceSummary.truncated
    ) {
      throw new Error("Managed private provenance Markdown summary does not match YAML");
    }
  } else if (provenanceMarkers.length > 0) {
    throw new Error("Managed private provenance Markdown summary has no YAML metadata");
  }
  const provenanceIndex = provenanceMarkers[0]?.index ?? -1;
  const afterHeading = markdown.slice((heading.index ?? 0) + heading[0].length).replace(/^\s*\n/, "");
  const sectionIndexes = [relationshipsIndex, attachmentsIndex, provenanceIndex].filter((index) => index >= 0);
  const firstGeneratedSection = sectionIndexes.length > 0 ? Math.min(...sectionIndexes) : -1;
  const bodySource = (firstGeneratedSection >= 0
    ? markdown.slice((heading.index ?? 0) + heading[0].length, firstGeneratedSection)
    : afterHeading).trim();

  const edges: VaultNoteEdge[] = [];
  for (const marker of markdown.matchAll(EDGE_MARKER)) {
    const edgeType = validateEdgeType(marker[1]);
    const targetNodeId = marker[2]!;
    const lineStart = markdown.lastIndexOf("\n", marker.index ?? 0) + 1;
    const line = markdown.slice(lineStart, markdown.indexOf("\n", marker.index ?? 0) < 0 ? undefined : markdown.indexOf("\n", marker.index ?? 0));
    const link = WIKILINK.exec(line);
    WIKILINK.lastIndex = 0;
    edges.push({
      edgeType,
      targetNodeId,
      targetTitle: decodeObsidianSingleLineText(link?.[2] ?? link?.[1] ?? targetNodeId),
      wikilink: link?.[1] ?? targetNodeId,
    });
  }
  const attachments = new Map<string, VaultNoteAttachment>();
  OBSIDIAN_ATTACHMENT.lastIndex = 0;
  for (const match of markdown.matchAll(OBSIDIAN_ATTACHMENT)) {
    const relativePath = match[1]!.trim();
    if (!relativePath.startsWith("Attachments/")) continue;
    attachments.set(relativePath, {
      relativePath,
      ...(match[2] ? { artifactId: match[2] } : {}),
      ...(match[3] ? { contentHash: match[3].toLowerCase() } : {}),
    });
  }
  MARKDOWN_ATTACHMENT.lastIndex = 0;
  for (const match of markdown.matchAll(MARKDOWN_ATTACHMENT)) {
    const relativePath = match[1]!.trim();
    if (relativePath.startsWith("Attachments/") && !attachments.has(relativePath)) {
      attachments.set(relativePath, { relativePath });
    }
  }
  const body = stripManagedAttachmentReferences(bodySource);
  return {
    id,
    nodeType,
    ...(brainRegion ? { brainRegion } : {}),
    ...(operatorProfileClass && operatorProfileAtlas
      ? { operatorProfileClass: operatorProfileAtlas.profileClass }
      : {}),
    lifecycleStatus,
    scope,
    sensitivity,
    confidence,
    confirmationState,
    title: decodeObsidianSingleLineText(heading[1]!.trim()),
    summary: requiredString(properties, "summary"),
    body,
    authorType,
    ...(properties.author_id ? { authorId: requiredString(properties, "author_id") } : {}),
    version: Number(version),
    createdAt: requiredString(properties, "created_at"),
    updatedAt: requiredString(properties, "updated_at"),
    ...(properties.expires_at ? { expiresAt: requiredString(properties, "expires_at") } : {}),
    privateProvenanceIds,
    ...(provenanceSummary ? { privateProvenanceSummary: provenanceSummary } : {}),
    sourceIds: stringList(properties, "source_ids"),
    aliases: stringList(properties, "aliases"),
    tags: stringList(properties, "tags"),
    outcomeTags,
    ...(reportedOutcome ? { reportedOutcome } : {}),
    edges,
    attachments: [...attachments.values()],
  };
}
