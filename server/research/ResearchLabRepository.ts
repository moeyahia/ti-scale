import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, hashCanonical, sha256 } from "../missions/canonical";
import { MissionApiError } from "../missions/errors";
import {
  INITIAL_RESEARCH_CAMPAIGNS,
  INITIAL_RESEARCH_CAMPAIGN_IDS,
  INITIAL_RESEARCH_DIMENSIONS,
  type InitialResearchCampaignId,
  type ResearchBudgets,
} from "./ResearchTypes";

export const DEFAULT_RESEARCH_BUDGETS: ResearchBudgets = {
  maxExperiments: 12,
  maxWallClockMs: 4 * 60 * 60 * 1_000,
  maxPublicLlmTokens: 40_000,
  maxEstimatedCost: 40,
  maxToolCalls: 240,
  maxConcurrentExperiments: 1,
  maxFailures: 4,
  maxRetries: 2,
  maxPatchOperations: 1,
  maxTrialsPerDimension: 6,
  safetyFailureCircuitBreaker: 1,
};

export interface ResearchRuntimeReadiness {
  readonly disposableLabReady: boolean;
  readonly integritySigningKeyReady: boolean;
  readonly isolatedWorkerReady: boolean;
}

export interface ResearchCampaignRecord {
  readonly id: string;
  readonly catalogId: InitialResearchCampaignId;
  readonly name: string;
  readonly purpose: string;
  readonly status: "draft" | "approved" | "running" | "paused" | "completed" | "stopped" | "rejected";
  readonly owner: string;
  readonly budgets: ResearchBudgets;
  readonly dimensionCount: number;
  readonly experimentCount: number;
  readonly charterCount: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ResearchLabSnapshot {
  readonly schemaVersion: "2.4";
  readonly governingPrinciple: string;
  readonly readiness: {
    readonly status: "ready" | "blocked";
    readonly checks: readonly {
      readonly id: string;
      readonly status: "pass" | "fail";
      readonly label: string;
      readonly impact: string;
      readonly remediation?: string;
    }[];
  };
  readonly publicLlmBoundary: {
    readonly role: "proposal_only";
    readonly rawClientEvidenceAllowed: false;
    readonly directToolExecutionAllowed: false;
    readonly authoritativeScoringAllowed: false;
    readonly automaticPromotionAllowed: false;
  };
  readonly promotionPath: readonly [
    "development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified"
  ];
  readonly catalog: readonly {
    readonly id: InitialResearchCampaignId;
    readonly title: string;
    readonly purpose: string;
    readonly primaryMetric: string;
    readonly primaryMetricDirection: "higher_better" | "lower_better";
    readonly mutablePaths: readonly string[];
    readonly existingCampaignIds: readonly string[];
  }[];
  readonly campaigns: readonly ResearchCampaignRecord[];
  readonly experiments: readonly {
    readonly id: string;
    readonly campaignId: string;
    readonly hypothesis: string;
    readonly status: string;
    readonly dimensionId: string;
    readonly candidateStrategyId: string;
    readonly updatedAt: string;
  }[];
  readonly integrity: {
    readonly benchmarkFamilies: number;
    readonly benchmarkSnapshots: number;
    readonly approvedCharters: number;
    readonly integrityReceipts: number;
    readonly providerExposureReceipts: number;
    readonly blockedProviderExposures: number;
  };
}

interface CampaignRow {
  readonly id: string;
  readonly name: string;
  readonly purpose: string;
  readonly status: ResearchCampaignRecord["status"];
  readonly owner: string;
  readonly budgets_json: string;
  readonly dimension_count: number;
  readonly experiment_count: number;
  readonly charter_count: number;
  readonly created_at: string;
  readonly updated_at: string;
}

interface ExperimentRow {
  readonly id: string;
  readonly campaign_id: string;
  readonly hypothesis: string;
  readonly status: string;
  readonly dimension_id: string;
  readonly candidate_strategy_id: string;
  readonly updated_at: string;
}

interface CountRow { readonly count: number }
interface IdempotencyValue<T> { readonly requestHash: string; readonly response: T }

function researchError(
  status: number,
  code: string,
  humanMessage: string,
  category: string,
  remediation?: string,
): MissionApiError {
  return new MissionApiError(status, code, humanMessage, {
    humanMessage,
    category,
    ...(remediation ? { remediation } : {}),
  });
}

function catalogDefinition(id: string) {
  if (!INITIAL_RESEARCH_CAMPAIGN_IDS.includes(id as InitialResearchCampaignId)) {
    throw researchError(
      400,
      "unknown_research_campaign",
      "Choose one of the registered safety and reliability research campaigns.",
      "invalid_input",
    );
  }
  return INITIAL_RESEARCH_CAMPAIGNS.find((campaign) => campaign.id === id)!;
}

function catalogIdForName(name: string): InitialResearchCampaignId {
  return INITIAL_RESEARCH_CAMPAIGNS.find(({ title }) => title === name)?.id
    ?? (() => { throw new Error(`Research campaign ${name} is not registered.`); })();
}

function parseBudgets(value: string): ResearchBudgets {
  return JSON.parse(value) as ResearchBudgets;
}

function campaignRecord(row: CampaignRow): ResearchCampaignRecord {
  return {
    id: row.id,
    catalogId: catalogIdForName(row.name),
    name: row.name,
    purpose: row.purpose,
    status: row.status,
    owner: row.owner,
    budgets: parseBudgets(row.budgets_json),
    dimensionCount: row.dimension_count,
    experimentCount: row.experiment_count,
    charterCount: row.charter_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function count(database: SqliteDatabase, table: string, where = ""): number {
  const allowed = new Set([
    "benchmark_families", "benchmark_snapshots", "research_charters",
    "integrity_receipts", "provider_exposure_receipts",
  ]);
  if (!allowed.has(table)) throw new Error("Unapproved research count table");
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table} ${where}`).get() as CountRow).count;
}

function idempotencySetting(actorId: string, operation: string, key: string): string {
  return `idempotency.research.${operation}.${sha256(actorId)}.${sha256(key)}`;
}

export class ResearchLabRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly readRuntimeReadiness: () => ResearchRuntimeReadiness = () => ({
      disposableLabReady: false,
      integritySigningKeyReady: false,
      isolatedWorkerReady: false,
    }),
    private readonly clock: () => Date = () => new Date(),
  ) {}

  private campaigns(): ResearchCampaignRecord[] {
    const rows = this.database.prepare(`
      SELECT c.*,
        (SELECT COUNT(*) FROM research_dimensions d WHERE d.campaign_id = c.id) AS dimension_count,
        (SELECT COUNT(*) FROM experiments e WHERE e.campaign_id = c.id) AS experiment_count,
        (SELECT COUNT(*) FROM research_charters h WHERE h.campaign_id = c.id) AS charter_count
      FROM research_campaigns c
      ORDER BY c.updated_at DESC, c.id ASC
    `).all() as CampaignRow[];
    return rows.map(campaignRecord);
  }

  snapshot(): ResearchLabSnapshot {
    const campaigns = this.campaigns();
    const runtime = this.readRuntimeReadiness();
    const benchmarkFamilies = count(this.database, "benchmark_families");
    const benchmarkSnapshots = count(this.database, "benchmark_snapshots");
    const approvedCharters = count(this.database, "research_charters");
    const integrityReceipts = count(this.database, "integrity_receipts");
    const providerExposureReceipts = count(this.database, "provider_exposure_receipts");
    const blockedProviderExposures = count(this.database, "provider_exposure_receipts", "WHERE blocked = 1");
    const checks: ResearchLabSnapshot["readiness"]["checks"] = [
      {
        id: "trusted_benchmark_snapshot",
        status: benchmarkSnapshots > 0 ? "pass" : "fail",
        label: "Immutable benchmark snapshot",
        impact: "Candidates cannot be evaluated without a locally trusted fixed benchmark snapshot.",
        ...(benchmarkSnapshots > 0 ? {} : { remediation: "Register and locally verify a benchmark family and snapshot." }),
      },
      {
        id: "approved_research_charter",
        status: approvedCharters > 0 ? "pass" : "fail",
        label: "Human-approved research charter",
        impact: "The mutable strategy surface and budgets must be owned by a named human reviewer.",
        ...(approvedCharters > 0 ? {} : { remediation: "Create a campaign, bind a trusted benchmark, and approve its charter." }),
      },
      {
        id: "disposable_lab",
        status: runtime.disposableLabReady ? "pass" : "fail",
        label: "Disposable local lab",
        impact: "Research never executes against a live client target.",
        ...(runtime.disposableLabReady ? {} : { remediation: "Connect a disposable resettable lab environment." }),
      },
      {
        id: "isolated_worker",
        status: runtime.isolatedWorkerReady ? "pass" : "fail",
        label: "Isolated experiment worker",
        impact: "A candidate must not share production process authority or secrets.",
        ...(runtime.isolatedWorkerReady ? {} : { remediation: "Connect an isolated, quota-bound experiment worker." }),
      },
      {
        id: "integrity_signing_key",
        status: runtime.integritySigningKeyReady ? "pass" : "fail",
        label: "Local integrity signer",
        impact: "Authoritative results require a local signature unavailable to the worker and public model.",
        ...(runtime.integritySigningKeyReady ? {} : { remediation: "Configure the local evaluator integrity key." }),
      },
    ];
    const experimentRows = this.database.prepare(`
      SELECT id, campaign_id, hypothesis, status, dimension_id, candidate_strategy_id, updated_at
      FROM experiments ORDER BY updated_at DESC, id ASC LIMIT 25
    `).all() as ExperimentRow[];
    return {
      schemaVersion: "2.4",
      governingPrinciple: "The public LLM proposes. The local runtime constrains. The lab executes. The immutable evaluator judges. The Brain remembers. A promotion workflow decides what becomes trusted.",
      readiness: { status: checks.every(({ status }) => status === "pass") ? "ready" : "blocked", checks },
      publicLlmBoundary: {
        role: "proposal_only",
        rawClientEvidenceAllowed: false,
        directToolExecutionAllowed: false,
        authoritativeScoringAllowed: false,
        automaticPromotionAllowed: false,
      },
      promotionPath: ["development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified"],
      catalog: INITIAL_RESEARCH_CAMPAIGNS.map((definition) => ({
        ...definition,
        mutablePaths: INITIAL_RESEARCH_DIMENSIONS
          .filter(({ campaignId }) => campaignId === definition.id)
          .map(({ path }) => path),
        existingCampaignIds: campaigns.filter(({ catalogId }) => catalogId === definition.id).map(({ id }) => id),
      })),
      campaigns,
      experiments: experimentRows.map((row) => ({
        id: row.id,
        campaignId: row.campaign_id,
        hypothesis: row.hypothesis,
        status: row.status,
        dimensionId: row.dimension_id,
        candidateStrategyId: row.candidate_strategy_id,
        updatedAt: row.updated_at,
      })),
      integrity: {
        benchmarkFamilies,
        benchmarkSnapshots,
        approvedCharters,
        integrityReceipts,
        providerExposureReceipts,
        blockedProviderExposures,
      },
    };
  }

  private readIdempotency<T>(actorId: string, operation: string, key: string, requestHash: string): T | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencySetting(actorId, operation, key)) as { value_json: string } | undefined;
    if (!row) return undefined;
    const stored = JSON.parse(row.value_json) as IdempotencyValue<T>;
    if (stored.requestHash !== requestHash) {
      throw researchError(409, "research_idempotency_conflict", "This research submission key was already used for a different request.", "conflict", "Retry the materially different request with a new Idempotency-Key.");
    }
    return stored.response;
  }

  private storeIdempotency<T>(actorId: string, operation: string, key: string, requestHash: string, response: T, now: string): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
    `).run(idempotencySetting(actorId, operation, key), canonicalJson({ requestHash, response }), actorId, now);
  }

  private appendAudit(actorId: string, action: string, resourceId: string, reason: string, details: unknown, now: string): void {
    const previous = this.database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
      .get() as { record_hash: string } | undefined;
    const auditId = `audit_${randomUUID()}`;
    const recordHash = hashCanonical({ auditId, previousHash: previous?.record_hash ?? null, actorId, action, resourceId, reason, details, now });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, 'operator', ?, ?, 'research_campaign', ?, ?, ?, ?, ?, ?)
    `).run(auditId, actorId, action, resourceId, reason, canonicalJson(details), previous?.record_hash ?? null, recordHash, now);
  }

  createCampaign(input: {
    readonly catalogId: string;
    readonly ownerAcknowledged: boolean;
    readonly actorId: string;
    readonly idempotencyKey: string;
  }): { readonly schemaVersion: "2.4"; readonly campaign: ResearchCampaignRecord; readonly nextUrl: string } {
    const definition = catalogDefinition(input.catalogId);
    if (!input.ownerAcknowledged) {
      throw researchError(400, "research_ownership_required", "Confirm that a human operator owns this campaign, its budgets, and promotion decisions.", "invalid_input");
    }
    const requestHash = hashCanonical({ catalogId: definition.id, ownerAcknowledged: true });
    const prior = this.readIdempotency<ReturnType<ResearchLabRepository["createCampaign"]>>(input.actorId, "create-campaign", input.idempotencyKey, requestHash);
    if (prior) return prior;
    return inImmediateTransaction(this.database, () => {
      const replay = this.readIdempotency<ReturnType<ResearchLabRepository["createCampaign"]>>(input.actorId, "create-campaign", input.idempotencyKey, requestHash);
      if (replay) return replay;
      const active = this.database.prepare(`
        SELECT id FROM research_campaigns
        WHERE name = ? AND status IN ('draft', 'approved', 'running', 'paused') LIMIT 1
      `).get(definition.title) as { id: string } | undefined;
      if (active) {
        throw researchError(409, "research_campaign_already_active", "An active campaign already exists for this research track.", "conflict", `Open ${active.id} or stop it before creating another campaign.`);
      }
      const now = this.clock().toISOString();
      const campaignId = `research_campaign_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO research_campaigns (id, name, purpose, status, owner, budgets_json, created_at, updated_at)
        VALUES (?, ?, ?, 'draft', ?, ?, ?, ?)
      `).run(campaignId, definition.title, definition.purpose, input.actorId, canonicalJson(DEFAULT_RESEARCH_BUDGETS), now, now);
      const insertDimension = this.database.prepare(`
        INSERT INTO research_dimensions (id, campaign_id, name, schema_path)
        VALUES (?, ?, ?, ?)
      `);
      for (const dimension of INITIAL_RESEARCH_DIMENSIONS.filter(({ campaignId: id }) => id === definition.id)) {
        insertDimension.run(`${campaignId}:${dimension.id}`, campaignId, dimension.id, dimension.path);
      }
      this.appendAudit(input.actorId, "research_campaign.created", campaignId, "Human operator created a bounded draft campaign.", {
        catalogId: definition.id,
        publicLlmRole: "proposal_only",
        liveClientTargetAllowed: false,
        automaticPromotionAllowed: false,
        budgets: DEFAULT_RESEARCH_BUDGETS,
      }, now);
      const campaign = this.campaigns().find(({ id }) => id === campaignId)!;
      const response = { schemaVersion: "2.4" as const, campaign, nextUrl: `/learning?view=research&campaign=${encodeURIComponent(campaignId)}` };
      this.storeIdempotency(input.actorId, "create-campaign", input.idempotencyKey, requestHash, response, now);
      return response;
    });
  }

  stopCampaign(input: {
    readonly campaignId: string;
    readonly expectedUpdatedAt: string;
    readonly reason: string;
    readonly actorId: string;
    readonly idempotencyKey: string;
  }): { readonly schemaVersion: "2.4"; readonly campaign: ResearchCampaignRecord } {
    const reason = input.reason.trim();
    if (reason.length < 3 || reason.length > 1_000) {
      throw researchError(400, "research_stop_reason_required", "Explain why the research campaign should stop.", "invalid_input");
    }
    const requestHash = hashCanonical({ campaignId: input.campaignId, expectedUpdatedAt: input.expectedUpdatedAt, reason });
    const prior = this.readIdempotency<ReturnType<ResearchLabRepository["stopCampaign"]>>(input.actorId, "stop-campaign", input.idempotencyKey, requestHash);
    if (prior) return prior;
    return inImmediateTransaction(this.database, () => {
      const replay = this.readIdempotency<ReturnType<ResearchLabRepository["stopCampaign"]>>(input.actorId, "stop-campaign", input.idempotencyKey, requestHash);
      if (replay) return replay;
      const current = this.campaigns().find(({ id }) => id === input.campaignId);
      if (!current) throw researchError(404, "research_campaign_not_found", "The requested research campaign does not exist.", "not_found");
      if (current.owner !== input.actorId) throw researchError(403, "research_campaign_owner_required", "Only the human campaign owner may stop this research campaign.", "authorization_denied");
      if (current.updatedAt !== input.expectedUpdatedAt) throw researchError(409, "research_campaign_version_conflict", "The campaign changed after this view loaded.", "conflict", "Refresh the Research Lab and review the current campaign state.");
      if (["completed", "stopped", "rejected"].includes(current.status)) throw researchError(409, "research_campaign_already_terminal", `The campaign is already ${current.status}.`, "conflict");
      const now = this.clock().toISOString();
      this.database.prepare("UPDATE research_campaigns SET status = 'stopped', updated_at = ? WHERE id = ?")
        .run(now, current.id);
      this.appendAudit(input.actorId, "research_campaign.stopped", current.id, reason, { previousStatus: current.status }, now);
      const campaign = this.campaigns().find(({ id }) => id === current.id)!;
      const response = { schemaVersion: "2.4" as const, campaign };
      this.storeIdempotency(input.actorId, "stop-campaign", input.idempotencyKey, requestHash, response, now);
      return response;
    });
  }
}
