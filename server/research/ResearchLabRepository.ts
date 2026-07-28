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
import {
  DEFAULT_STRATEGY_BUNDLE,
  FORBIDDEN_STRATEGY_PATH_PREFIXES,
  validateStrategyPatch,
} from "./StrategyBundleSchema";
import {
  builtInResearchCampaignSetup,
  builtInResearchCampaignSeedPreview,
  type BuiltInResearchCampaignSetup,
} from "./BuiltInResearchCampaignSetup";
import {
  ResearchPromotionLifecycleRepository,
  type ResearchPromotionLifecycleRecord,
} from "./ResearchPromotionLifecycleRepository";
import type { PrivateResearchHoldoutRegistry } from "./PrivateResearchHoldout";

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
  readonly executionEnvironment?: {
    readonly kind: "local_bwrap";
    readonly identityHash: string;
    readonly toolManifestHash: string;
    readonly workerSourceHash: string;
  };
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

export interface ResearchCampaignSetupPreview {
  readonly candidatePresetId: string;
  readonly dimensionId: string;
  readonly path: string;
  readonly hypothesis: string;
  readonly patch: readonly {
    readonly op: "replace";
    readonly path: string;
    readonly value: string | number | boolean | null;
  }[];
  readonly developmentScenarioId: string;
  readonly splitCounts: {
    readonly development: 1;
    readonly validation: 1;
    readonly hiddenHoldout:
      | "operator_descriptor_required"
      | "private_descriptor_bound";
  };
  readonly baselineBundleHash: string | null;
  readonly candidateBundleHash: string | null;
  readonly evaluatorHash: string | null;
  readonly toolManifestHash: string | null;
  readonly executionEnvironmentIdentityHash: string | null;
  readonly executionReadiness: "ready" | "blocked";
  readonly executionBoundary: BuiltInResearchCampaignSetup["executionBoundary"];
}

export interface ResearchCampaignSetupRecord {
  readonly charterId: string;
  readonly charterHash: string;
  readonly benchmarkFamilyId: string;
  readonly benchmarkSnapshotId: string;
  readonly benchmarkSnapshotHash: string;
  readonly developmentScenarioId: string;
  readonly baselineStrategyId: string;
  readonly baselineStrategyHash: string;
  readonly candidateStrategyId: string;
  readonly candidateStrategyHash: string;
  readonly strategyPatchId: string;
  readonly strategyPatchHash: string;
  readonly experimentId: string;
  readonly experimentStatus: "queued";
  readonly candidatePresetId: string;
  readonly dimensionId: string;
  readonly hypothesis: string;
  readonly automaticPromotion: false;
  readonly automaticDeployment: false;
}

export interface ResearchCampaignSetupMutation {
  readonly schemaVersion: "2.4";
  readonly campaign: ResearchCampaignRecord;
  readonly setup: ResearchCampaignSetupRecord;
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
    readonly setup: ResearchCampaignSetupPreview;
  }[];
  readonly campaigns: readonly ResearchCampaignRecord[];
  readonly experiments: readonly {
    readonly id: string;
    readonly campaignId: string;
    readonly hypothesis: string;
    readonly status: string;
    readonly dimensionId: string;
    readonly candidateStrategyId: string;
    readonly scenarioId: string;
    readonly latestRun?: {
      readonly id: string;
      readonly status: string;
      readonly startedAt: string | null;
      readonly endedAt: string | null;
    };
    readonly updatedAt: string;
  }[];
  readonly promotions: readonly ResearchPromotionLifecycleRecord[];
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
  readonly scenario_id: string;
  readonly run_id: string | null;
  readonly run_status: string | null;
  readonly run_started_at: string | null;
  readonly run_ended_at: string | null;
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

function publicSetup(
  catalogId: InitialResearchCampaignId,
  runtime: ResearchRuntimeReadiness,
  privateHoldout?: PrivateResearchHoldoutRegistry,
): ResearchCampaignSetupPreview {
  const preview = builtInResearchCampaignSeedPreview(catalogId);
  const setup = runtime.executionEnvironment
    ? builtInResearchCampaignSetup(
        catalogId,
        runtime.executionEnvironment,
        privateHoldout,
      )
    : undefined;
  return {
    candidatePresetId: preview.candidatePresetId,
    dimensionId: preview.dimensionId,
    path: preview.path,
    hypothesis: preview.hypothesis,
    patch: preview.patch,
    developmentScenarioId: preview.developmentScenarioId,
    splitCounts: {
      development: 1,
      validation: 1,
      hiddenHoldout: privateHoldout?.hasCatalog(catalogId)
        ? "private_descriptor_bound"
        : "operator_descriptor_required",
    },
    baselineBundleHash: setup?.baselineBundleHash ?? null,
    candidateBundleHash: setup?.candidateBundleHash ?? null,
    evaluatorHash: setup?.snapshot.evaluatorHash ?? null,
    toolManifestHash: setup?.snapshot.toolManifestHash ?? null,
    executionEnvironmentIdentityHash:
      setup?.executionEnvironment.identityHash ?? null,
    executionReadiness: setup ? "ready" : "blocked",
    executionBoundary: setup?.executionBoundary ?? {
      targetClass: "synthetic_fixture",
      liveClientTargetAllowed: false,
      outboundNetworkAllowed: false,
      publicProviderUsed: false,
      arbitrarySourcePatchAllowed: false,
      automaticPromotionAllowed: false,
      automaticDeploymentAllowed: false,
    },
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
    private readonly privateHoldout?: PrivateResearchHoldoutRegistry,
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
      SELECT
        experiment.id,
        experiment.campaign_id,
        experiment.hypothesis,
        experiment.status,
        dimension.name AS dimension_id,
        experiment.candidate_strategy_id,
        (
          SELECT scenario.id
          FROM benchmark_snapshot_scenarios membership
          JOIN benchmark_scenarios scenario
            ON scenario.id = membership.scenario_id
          WHERE membership.snapshot_id = experiment.benchmark_snapshot_id
            AND scenario.split = 'development'
          ORDER BY membership.ordinal, scenario.id
          LIMIT 1
        ) AS scenario_id,
        latest.id AS run_id,
        latest.status AS run_status,
        latest.started_at AS run_started_at,
        latest.ended_at AS run_ended_at,
        experiment.updated_at
      FROM experiments experiment
      JOIN research_dimensions dimension
        ON dimension.id = experiment.dimension_id
      LEFT JOIN experiment_runs latest ON latest.id = (
        SELECT run.id
        FROM experiment_runs run
        WHERE run.experiment_id = experiment.id
        ORDER BY run.created_at DESC, run.id DESC
        LIMIT 1
      )
      ORDER BY experiment.updated_at DESC, experiment.id ASC
      LIMIT 25
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
        setup: publicSetup(definition.id, runtime, this.privateHoldout),
      })),
      campaigns,
      experiments: experimentRows.map((row) => ({
        id: row.id,
        campaignId: row.campaign_id,
        hypothesis: row.hypothesis,
        status: row.status,
        dimensionId: row.dimension_id,
        candidateStrategyId: row.candidate_strategy_id,
        scenarioId: row.scenario_id,
        ...(row.run_id && row.run_status
          ? {
              latestRun: {
                id: row.run_id,
                status: row.run_status,
                startedAt: row.run_started_at,
                endedAt: row.run_ended_at,
              },
            }
          : {}),
        updatedAt: row.updated_at,
      })),
      promotions: new ResearchPromotionLifecycleRepository(
        this.database,
      ).list(),
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

  approveAndQueueBuiltInExperiment(input: {
    readonly campaignId: string;
    readonly expectedUpdatedAt: string;
    readonly candidatePresetId: string;
    readonly ownerApproval: boolean;
    readonly actorId: string;
    readonly idempotencyKey: string;
  }): ResearchCampaignSetupMutation {
    if (!input.ownerApproval) {
      throw researchError(
        400,
        "research_setup_approval_required",
        "Confirm the exact synthetic benchmark, strategy patch, budgets, and no-deployment boundary before queuing the experiment.",
        "invalid_input",
      );
    }
    const requestHash = hashCanonical({
      campaignId: input.campaignId,
      expectedUpdatedAt: input.expectedUpdatedAt,
      candidatePresetId: input.candidatePresetId,
      ownerApproval: true,
    });
    const prior = this.readIdempotency<ResearchCampaignSetupMutation>(
      input.actorId,
      "approve-and-queue",
      input.idempotencyKey,
      requestHash,
    );
    if (prior) return prior;
    return inImmediateTransaction(this.database, () => {
      const replay = this.readIdempotency<ResearchCampaignSetupMutation>(
        input.actorId,
        "approve-and-queue",
        input.idempotencyKey,
        requestHash,
      );
      if (replay) return replay;
      const current = this.campaigns().find(
        ({ id }) => id === input.campaignId,
      );
      if (!current) {
        throw researchError(
          404,
          "research_campaign_not_found",
          "The requested research campaign does not exist.",
          "not_found",
        );
      }
      if (current.owner !== input.actorId) {
        throw researchError(
          403,
          "research_campaign_owner_required",
          "Only the named human campaign owner may approve and queue this experiment.",
          "authorization_denied",
        );
      }
      if (current.updatedAt !== input.expectedUpdatedAt) {
        throw researchError(
          409,
          "research_campaign_version_conflict",
          "The campaign changed after this setup was reviewed.",
          "conflict",
          "Refresh the Research Lab and review the exact current patch and benchmark bindings.",
        );
      }
      if (current.status !== "draft") {
        throw researchError(
          409,
          "research_campaign_setup_already_decided",
          `This campaign is ${current.status}; only a current draft can be approved and queued.`,
          "conflict",
        );
      }
      const runtime = this.readRuntimeReadiness();
      if (
        !runtime.disposableLabReady
        || !runtime.isolatedWorkerReady
        || !runtime.integritySigningKeyReady
        || !runtime.executionEnvironment
      ) {
        throw researchError(
          409,
          "research_execution_boundary_not_ready",
          "The exact local bwrap execution boundary is not currently attested, so this immutable experiment setup cannot be approved.",
          "readiness",
          "Restore the disposable lab, isolated worker, and local integrity signer, then review the newly bound hashes.",
        );
      }
      const setup = builtInResearchCampaignSetup(
        current.catalogId,
        runtime.executionEnvironment,
        this.privateHoldout,
      );
      const developmentScenario = setup.scenarios.find(
        ({ split }) => split === "development",
      );
      const hiddenScenario = setup.scenarios.find(
        ({ split }) => split === "hidden_holdout",
      );
      if (
        !developmentScenario
        || Boolean(hiddenScenario) !== Boolean(setup.privateHoldoutBinding)
      ) {
        throw researchError(
          500,
          "research_builtin_scenario_set_invalid",
          "The immutable Research setup does not contain a consistent development and private-holdout binding.",
          "integrity",
        );
      }
      if (setup.candidatePresetId !== input.candidatePresetId) {
        throw researchError(
          409,
          "research_candidate_preset_mismatch",
          "The requested candidate is not the exact reviewed preset for this campaign.",
          "integrity",
          "Refresh the Research Lab and review the registered one-operation StrategyBundle patch.",
        );
      }
      const dimensionId = `${current.id}:${setup.dimensionId}`;
      const dimension = this.database.prepare(`
        SELECT id, name, schema_path
        FROM research_dimensions
        WHERE id = ? AND campaign_id = ?
      `).get(dimensionId, current.id) as {
        readonly id: string;
        readonly name: string;
        readonly schema_path: string;
      } | undefined;
      if (
        !dimension
        || dimension.name !== setup.dimensionId
        || dimension.schema_path !== setup.path
      ) {
        throw researchError(
          409,
          "research_dimension_binding_mismatch",
          "The campaign dimension no longer matches its registered StrategyBundle path.",
          "integrity",
        );
      }
      const policyValidation = validateStrategyPatch(setup.patch, {
        approvedMutablePaths: [setup.path],
        forbiddenPathPrefixes: FORBIDDEN_STRATEGY_PATH_PREFIXES,
        maxOperations: 1,
      });
      if (
        !policyValidation.valid
        || policyValidation.normalizedPatch.length !== 1
        || hashCanonical(policyValidation.normalizedPatch) !== setup.patchHash
      ) {
        throw researchError(
          500,
          "research_builtin_patch_invalid",
          "The built-in Research candidate failed its typed strategy policy.",
          "integrity",
        );
      }
      const now = this.clock().toISOString();
      this.database.prepare(`
        INSERT INTO benchmark_families (
          id, name, evaluator_version, hard_gates_json, metrics_json,
          promotion_criteria_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `).run(
        setup.family.id,
        setup.family.name,
        setup.family.evaluatorVersion,
        setup.family.hardGatesJson,
        setup.family.metricsJson,
        setup.family.promotionCriteriaJson,
        now,
      );
      const family = this.database.prepare(`
        SELECT name, evaluator_version, hard_gates_json, metrics_json,
          promotion_criteria_json
        FROM benchmark_families WHERE id = ?
      `).get(setup.family.id) as {
        readonly name: string;
        readonly evaluator_version: string;
        readonly hard_gates_json: string;
        readonly metrics_json: string;
        readonly promotion_criteria_json: string;
      } | undefined;
      if (
        !family
        || family.name !== setup.family.name
        || family.evaluator_version !== setup.family.evaluatorVersion
        || family.hard_gates_json !== setup.family.hardGatesJson
        || family.metrics_json !== setup.family.metricsJson
        || family.promotion_criteria_json
          !== setup.family.promotionCriteriaJson
      ) {
        throw researchError(
          409,
          "research_builtin_benchmark_conflict",
          "A stored benchmark family conflicts with the immutable built-in definition.",
          "integrity",
        );
      }
      const insertScenario = this.database.prepare(`
        INSERT INTO benchmark_scenarios (
          id, family_id, split, name, scenario_hash, ground_truth_ref,
          environment_digest, budget_json, active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(id) DO NOTHING
      `);
      for (const scenario of setup.scenarios) {
        insertScenario.run(
          scenario.id,
          setup.family.id,
          scenario.split,
          scenario.name,
          scenario.scenarioHash,
          scenario.groundTruthRef,
          scenario.environmentDigest,
          scenario.budgetJson,
          now,
        );
        const stored = this.database.prepare(`
          SELECT family_id, split, name, scenario_hash, ground_truth_ref,
            environment_digest, budget_json, active
          FROM benchmark_scenarios WHERE id = ?
        `).get(scenario.id) as {
          readonly family_id: string;
          readonly split: string;
          readonly name: string;
          readonly scenario_hash: string;
          readonly ground_truth_ref: string;
          readonly environment_digest: string;
          readonly budget_json: string;
          readonly active: number;
        } | undefined;
        if (
          !stored
          || stored.family_id !== setup.family.id
          || stored.split !== scenario.split
          || stored.name !== scenario.name
          || stored.scenario_hash !== scenario.scenarioHash
          || stored.ground_truth_ref !== scenario.groundTruthRef
          || stored.environment_digest !== scenario.environmentDigest
          || stored.budget_json !== scenario.budgetJson
          || stored.active !== 1
        ) {
          throw researchError(
            409,
            "research_builtin_scenario_conflict",
            "A stored benchmark scenario conflicts with its immutable local fixture.",
            "integrity",
          );
        }
      }
      this.database.prepare(`
        INSERT INTO benchmark_snapshots (
          id, family_id, evaluator_hash, scenario_set_hash,
          tool_manifest_hash, snapshot_hash, created_at,
          container_image_digest, execution_environment_kind,
          execution_environment_identity_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'legacy_unverified', ?, ?)
        ON CONFLICT(id) DO NOTHING
      `).run(
        setup.snapshot.id,
        setup.family.id,
        setup.snapshot.evaluatorHash,
        setup.snapshot.scenarioSetHash,
        setup.snapshot.toolManifestHash,
        setup.snapshot.snapshotHash,
        now,
        setup.executionEnvironment.kind,
        setup.executionEnvironment.identityHash,
      );
      const snapshot = this.database.prepare(`
        SELECT family_id, evaluator_hash, scenario_set_hash,
          tool_manifest_hash, snapshot_hash, container_image_digest,
          execution_environment_kind, execution_environment_identity_hash
        FROM benchmark_snapshots WHERE id = ?
      `).get(setup.snapshot.id) as {
        readonly family_id: string;
        readonly evaluator_hash: string;
        readonly scenario_set_hash: string;
        readonly tool_manifest_hash: string;
        readonly snapshot_hash: string;
        readonly container_image_digest: string;
        readonly execution_environment_kind: string;
        readonly execution_environment_identity_hash: string;
      } | undefined;
      if (
        !snapshot
        || snapshot.family_id !== setup.family.id
        || snapshot.evaluator_hash !== setup.snapshot.evaluatorHash
        || snapshot.scenario_set_hash !== setup.snapshot.scenarioSetHash
        || snapshot.tool_manifest_hash !== setup.snapshot.toolManifestHash
        || snapshot.snapshot_hash !== setup.snapshot.snapshotHash
        || snapshot.container_image_digest !== "legacy_unverified"
        || snapshot.execution_environment_kind
          !== setup.executionEnvironment.kind
        || snapshot.execution_environment_identity_hash
          !== setup.executionEnvironment.identityHash
      ) {
        throw researchError(
          409,
          "research_builtin_snapshot_conflict",
          "A stored benchmark snapshot conflicts with the immutable evaluator, fixture, or tool binding.",
          "integrity",
        );
      }
      const insertMembership = this.database.prepare(`
        INSERT INTO benchmark_snapshot_scenarios (
          snapshot_id, scenario_id, ordinal
        ) VALUES (?, ?, ?)
        ON CONFLICT(snapshot_id, scenario_id) DO NOTHING
      `);
      setup.scenarios.forEach((scenario, index) => {
        insertMembership.run(setup.snapshot.id, scenario.id, index + 1);
      });
      const memberships = this.database.prepare(`
        SELECT scenario_id, ordinal
        FROM benchmark_snapshot_scenarios
        WHERE snapshot_id = ?
        ORDER BY ordinal
      `).all(setup.snapshot.id) as Array<{
        readonly scenario_id: string;
        readonly ordinal: number;
      }>;
      if (
        memberships.length !== setup.scenarios.length
        || memberships.some((membership, index) =>
          membership.scenario_id !== setup.scenarios[index]!.id
          || membership.ordinal !== index + 1)
      ) {
        throw researchError(
          409,
          "research_snapshot_membership_conflict",
          "The benchmark snapshot no longer contains exactly its immutable scenario set.",
          "integrity",
        );
      }
      if (hiddenScenario && setup.privateHoldoutBinding) {
        const binding = setup.privateHoldoutBinding;
        this.database.prepare(`
          INSERT INTO private_research_holdout_bindings (
            benchmark_snapshot_id, catalog_id,
            descriptor_version_hash, descriptor_source_sha256,
            descriptor_canonical_sha256, scenario_commitment,
            hidden_scenario_hash, opaque_scenario_id_hash, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(benchmark_snapshot_id) DO NOTHING
        `).run(
          setup.snapshot.id,
          current.catalogId,
          binding.descriptorVersionHash,
          binding.descriptorSourceSha256,
          binding.descriptorCanonicalSha256,
          binding.scenarioCommitment,
          hiddenScenario.scenarioHash,
          binding.opaqueScenarioIdHash,
          now,
        );
        const storedBinding = this.database.prepare(`
          SELECT
            catalog_id, descriptor_version_hash,
            descriptor_source_sha256, descriptor_canonical_sha256,
            scenario_commitment, hidden_scenario_hash,
            opaque_scenario_id_hash
          FROM private_research_holdout_bindings
          WHERE benchmark_snapshot_id = ?
        `).get(setup.snapshot.id) as {
          readonly catalog_id: string;
          readonly descriptor_version_hash: string;
          readonly descriptor_source_sha256: string;
          readonly descriptor_canonical_sha256: string;
          readonly scenario_commitment: string;
          readonly hidden_scenario_hash: string;
          readonly opaque_scenario_id_hash: string;
        } | undefined;
        if (
          !storedBinding
          || storedBinding.catalog_id !== current.catalogId
          || storedBinding.descriptor_version_hash
            !== binding.descriptorVersionHash
          || storedBinding.descriptor_source_sha256
            !== binding.descriptorSourceSha256
          || storedBinding.descriptor_canonical_sha256
            !== binding.descriptorCanonicalSha256
          || storedBinding.scenario_commitment
            !== binding.scenarioCommitment
          || storedBinding.hidden_scenario_hash
            !== hiddenScenario.scenarioHash
          || storedBinding.opaque_scenario_id_hash
            !== binding.opaqueScenarioIdHash
        ) {
          throw researchError(
            409,
            "research_private_holdout_binding_conflict",
            "The stored private holdout commitment differs from the trusted local descriptor.",
            "integrity",
            "Create a new campaign against the current private holdout descriptor; immutable experiment snapshots are never rewritten.",
          );
        }
      }
      const charterId = `research_charter_${randomUUID()}`;
      const immutableScope = {
        schemaVersion: "ti-scale.research-charter-scope.v1",
        catalogId: current.catalogId,
        benchmarkFamilyId: setup.family.id,
        benchmarkSnapshotId: setup.snapshot.id,
        benchmarkSnapshotHash: setup.snapshot.snapshotHash,
        evaluatorHash: setup.snapshot.evaluatorHash,
        toolManifestHash: setup.snapshot.toolManifestHash,
        executionEnvironment: {
          kind: setup.executionEnvironment.kind,
          identityHash: setup.executionEnvironment.identityHash,
        },
        scenarioSplits: {
          development: 1,
          validation: 1,
          hiddenHoldout: setup.privateHoldoutBinding
            ? "private_descriptor_bound"
            : "operator_descriptor_required",
        },
        targetClass: "synthetic_fixture",
        liveClientTargetAllowed: false,
        publicProviderExecutionAllowed: false,
        automaticPromotionAllowed: false,
        automaticDeploymentAllowed: false,
      };
      const mutableDimensions = [{
        dimensionId: setup.dimensionId,
        path: setup.path,
        candidatePresetId: setup.candidatePresetId,
        patchHash: setup.patchHash,
      }];
      const charterHash = hashCanonical({
        id: charterId,
        campaignId: current.id,
        version: 1,
        immutableScope,
        mutableDimensions,
        forbiddenPaths: FORBIDDEN_STRATEGY_PATH_PREFIXES,
        budgets: current.budgets,
        approvedBy: input.actorId,
        approvedAt: now,
      });
      this.database.prepare(`
        INSERT INTO research_charters (
          id, campaign_id, version, immutable_scope_json,
          mutable_dimensions_json, forbidden_paths_json, budgets_json,
          charter_hash, approved_by, approved_at
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        charterId,
        current.id,
        canonicalJson(immutableScope),
        canonicalJson(mutableDimensions),
        canonicalJson(FORBIDDEN_STRATEGY_PATH_PREFIXES),
        canonicalJson(current.budgets),
        charterHash,
        input.actorId,
        now,
      );
      const baselineStrategyId = `research_strategy_${randomUUID()}`;
      const candidateStrategyId = `research_strategy_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO strategy_versions (
          id, campaign_id, parent_id, version, bundle_json, bundle_hash,
          status, created_by, created_at
        ) VALUES
          (?, ?, NULL, 1, ?, ?, 'verified', ?, ?),
          (?, ?, ?, 2, ?, ?, 'queued', ?, ?)
      `).run(
        baselineStrategyId,
        current.id,
        canonicalJson(DEFAULT_STRATEGY_BUNDLE),
        setup.baselineBundleHash,
        "ti-scale:built-in-strategy-registry",
        now,
        candidateStrategyId,
        current.id,
        baselineStrategyId,
        canonicalJson(setup.candidateBundle),
        setup.candidateBundleHash,
        input.actorId,
        now,
      );
      const patchId = `research_patch_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO strategy_patches (
          id, strategy_version_id, base_strategy_version_id,
          json_patch_json, policy_validation_json, patch_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        patchId,
        candidateStrategyId,
        baselineStrategyId,
        canonicalJson(policyValidation.normalizedPatch),
        canonicalJson(policyValidation),
        setup.patchHash,
        now,
      );
      const experimentId = `research_experiment_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO experiments (
          id, campaign_id, charter_id, dimension_id,
          baseline_strategy_id, candidate_strategy_id,
          benchmark_snapshot_id, hypothesis, status, public_llm_spec_hash,
          created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', NULL, ?, ?, ?)
      `).run(
        experimentId,
        current.id,
        charterId,
        dimensionId,
        baselineStrategyId,
        candidateStrategyId,
        setup.snapshot.id,
        setup.hypothesis,
        input.actorId,
        now,
        now,
      );
      const contextPackId = `research_context_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO research_context_packs (
          id, experiment_id, purpose, disclosure_policy_version,
          context_hash, created_at
        ) VALUES (?, ?, ?, 'local-built-in-only-v1', ?, ?)
      `).run(
        contextPackId,
        experimentId,
        "Bind the human-reviewed built-in candidate and target-free synthetic benchmark without public-provider context.",
        hashCanonical({
          experimentId,
          candidatePresetId: setup.candidatePresetId,
          selectedMemoryNodeIds: [],
          publicProviderDisclosure: false,
        }),
        now,
      );
      const promotions = new ResearchPromotionLifecycleRepository(
        this.database,
        undefined,
        this.clock,
      );
      promotions.initialize({
        experimentId,
        actorId: "ti-scale:local-research-policy",
      });
      promotions.applyLocalTransition({
        experimentId,
        expectedVersion: 1,
        action: "policy_accept",
        actorId: "ti-scale:local-research-policy",
        rationale:
          "The candidate contains one registered StrategyBundle replacement and preserves every immutable safety, evaluator, benchmark, and deployment boundary.",
        evidenceRefs: [
          `strategy-patch:${patchId}`,
          `charter:${charterId}`,
          `benchmark-snapshot:${setup.snapshot.id}`,
        ],
      });
      this.database.prepare(`
        INSERT INTO experiment_events (
          id, experiment_id, experiment_run_id, sequence, event_type,
          summary, payload_json, sensitivity, occurred_at
        ) VALUES (?, ?, NULL, 1, 'experiment.queued', ?, ?, 'internal', ?)
      `).run(
        `research_event_${randomUUID()}`,
        experimentId,
        "The named campaign owner approved one bounded candidate for the target-free synthetic development fixture.",
        canonicalJson({
          candidatePresetId: setup.candidatePresetId,
          charterHash,
          benchmarkSnapshotHash: setup.snapshot.snapshotHash,
          patchHash: setup.patchHash,
          hiddenHoldout: setup.privateHoldoutBinding
            ? "private_descriptor_bound"
            : "operator_descriptor_required",
          automaticPromotion: false,
          automaticDeployment: false,
        }),
        now,
      );
      const updated = this.database.prepare(`
        UPDATE research_campaigns
        SET status = 'approved', updated_at = ?
        WHERE id = ? AND status = 'draft' AND updated_at = ?
      `).run(now, current.id, current.updatedAt);
      if (updated.changes !== 1) {
        throw researchError(
          409,
          "research_campaign_version_conflict",
          "The campaign changed while its exact setup was being approved.",
          "conflict",
          "Refresh the Research Lab and review the current canonical state.",
        );
      }
      this.appendAudit(
        input.actorId,
        "research_campaign.setup_approved",
        current.id,
        "Named campaign owner approved the fixed target-free experiment setup.",
        {
          charterId,
          charterHash,
          experimentId,
          candidatePresetId: setup.candidatePresetId,
          baselineStrategyId,
          baselineStrategyHash: setup.baselineBundleHash,
          candidateStrategyId,
          candidateStrategyHash: setup.candidateBundleHash,
          patchId,
          patchHash: setup.patchHash,
          benchmarkFamilyId: setup.family.id,
          benchmarkSnapshotId: setup.snapshot.id,
          benchmarkSnapshotHash: setup.snapshot.snapshotHash,
          evaluatorHash: setup.snapshot.evaluatorHash,
          toolManifestHash: setup.snapshot.toolManifestHash,
          developmentScenarioId: developmentScenario.id,
          validationScenarioCount: 1,
          hiddenHoldout: setup.privateHoldoutBinding
            ? "private_descriptor_bound"
            : "operator_descriptor_required",
          publicProviderUsed: false,
          liveClientTargetAllowed: false,
          automaticPromotion: false,
          automaticDeployment: false,
        },
        now,
      );
      const campaign = this.campaigns().find(
        ({ id }) => id === current.id,
      )!;
      const response: ResearchCampaignSetupMutation = {
        schemaVersion: "2.4",
        campaign,
        setup: {
          charterId,
          charterHash,
          benchmarkFamilyId: setup.family.id,
          benchmarkSnapshotId: setup.snapshot.id,
          benchmarkSnapshotHash: setup.snapshot.snapshotHash,
          developmentScenarioId: developmentScenario.id,
          baselineStrategyId,
          baselineStrategyHash: setup.baselineBundleHash,
          candidateStrategyId,
          candidateStrategyHash: setup.candidateBundleHash,
          strategyPatchId: patchId,
          strategyPatchHash: setup.patchHash,
          experimentId,
          experimentStatus: "queued",
          candidatePresetId: setup.candidatePresetId,
          dimensionId: setup.dimensionId,
          hypothesis: setup.hypothesis,
          automaticPromotion: false,
          automaticDeployment: false,
        },
      };
      this.storeIdempotency(
        input.actorId,
        "approve-and-queue",
        input.idempotencyKey,
        requestHash,
        response,
        now,
      );
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
