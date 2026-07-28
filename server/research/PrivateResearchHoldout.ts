import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  syntheticFixtureEnvironmentDigest,
  type SyntheticBenchmarkFixture,
} from "./LabEnvironmentManager";
import {
  evaluateSyntheticResearchDefinition,
  type LocalSyntheticScenarioEvaluation,
  type SyntheticResearchDecision,
  type SyntheticResearchTrack,
  type SyntheticScenarioDefinition,
  type SyntheticScenarioInput,
} from "./SyntheticResearchFixtures";
import type { StrategyBundle } from "./StrategyBundleSchema";
import {
  canonicalJson,
  deepFreeze,
  hashCanonical,
  sha256,
  type JsonValue,
} from "./canonical";
import {
  INITIAL_RESEARCH_CAMPAIGN_IDS,
  type InitialResearchCampaignId,
} from "./ResearchTypes";

export const PRIVATE_RESEARCH_HOLDOUT_SCHEMA_VERSION =
  "ti-scale.private-research-holdout.v1" as const;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,160}$/u;
const SAFE_SIGNAL = /^[A-Za-z0-9._:/-]{1,240}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const IPV4 = /(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])/u;
const SECRET_MATERIAL =
  /(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|\bBearer\s+\S+|(?:api[-_]?key|authorization|cookie|password|private[-_]?key|secret|session[-_]?token)\s*[:=]\s*\S+)/iu;

export interface PrivateResearchHoldoutCampaign {
  readonly catalogId: InitialResearchCampaignId;
  /** Operator-private identity. It is commitment-bound and never projected. */
  readonly fixtureKey: string;
  readonly input: SyntheticScenarioInput;
  readonly groundTruth: JsonValue;
}

export interface PrivateResearchHoldoutDescriptor {
  readonly schemaVersion: typeof PRIVATE_RESEARCH_HOLDOUT_SCHEMA_VERSION;
  readonly descriptorVersion: string;
  readonly campaigns: readonly PrivateResearchHoldoutCampaign[];
}

export interface PrivateResearchHoldoutBinding {
  readonly descriptorVersionHash: string;
  readonly descriptorSourceSha256: string;
  readonly descriptorCanonicalSha256: string;
  readonly scenarioCommitment: string;
  readonly opaqueScenarioIdHash: string;
}

export interface PrivateResearchHoldoutScenario {
  readonly id: string;
  readonly split: "hidden_holdout";
  readonly name: "Private hidden-holdout fixture";
  readonly scenarioHash: string;
  readonly groundTruthRef: string;
  readonly environmentDigest: string;
  readonly budgetJson: string;
  readonly binding: PrivateResearchHoldoutBinding;
}

interface PrivateEntry {
  readonly catalogId: InitialResearchCampaignId;
  readonly scenarioId: string;
  readonly fixture: SyntheticBenchmarkFixture;
  readonly definition: SyntheticScenarioDefinition;
  readonly scenarioCommitment: string;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || (
      Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null
    )
  ) throw new Error(`${label} must be a plain object`);
  return value as JsonRecord;
}

function exactKeys(
  value: JsonRecord,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (
    actual.length !== required.length
    || actual.some((key, index) => key !== required[index])
  ) throw new Error(`${label} has unexpected or missing fields`);
}

function safeText(
  value: unknown,
  label: string,
  maximum = 240,
): string {
  if (
    typeof value !== "string"
    || value !== value.trim()
    || value.length < 1
    || value.length > maximum
    || CONTROL_CHARACTERS.test(value)
    || IPV4.test(value)
    || SECRET_MATERIAL.test(value)
  ) throw new Error(`${label} must be bounded target-free non-secret text`);
  return value;
}

function safeId(value: unknown, label: string): string {
  const parsed = safeText(value, label, 160);
  if (!SAFE_ID.test(parsed)) throw new Error(`${label} must be a safe identifier`);
  return parsed;
}

function safeSignal(value: unknown, label: string): string {
  const parsed = safeText(value, label, 240);
  if (!SAFE_SIGNAL.test(parsed)) {
    throw new Error(`${label} must be a target-free synthetic signal`);
  }
  return parsed;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function score(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be a number between zero and one`);
  }
  return value;
}

function integer(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function values(
  value: unknown,
  label: string,
  minimum = 1,
  maximum = 128,
): readonly unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum} to ${maximum} entries`);
  }
  return value;
}

function unique(valuesToCheck: readonly string[], label: string): void {
  if (new Set(valuesToCheck).size !== valuesToCheck.length) {
    throw new Error(`${label} contains duplicate identities`);
  }
}

function catalogId(value: unknown, label: string): InitialResearchCampaignId {
  const parsed = safeId(value, label);
  if (!INITIAL_RESEARCH_CAMPAIGN_IDS.includes(
    parsed as InitialResearchCampaignId,
  )) throw new Error(`${label} is not a registered Research campaign`);
  return parsed as InitialResearchCampaignId;
}

function inputForTrack(
  value: unknown,
  expectedTrack: SyntheticResearchTrack,
  label: string,
): SyntheticScenarioInput {
  const input = record(value, label);
  if (input.schemaVersion !== "ti-scale.synthetic-scenario.v1") {
    throw new Error(`${label}.schemaVersion is unsupported`);
  }
  if (input.track !== expectedTrack) {
    throw new Error(`${label}.track must match its Research campaign`);
  }
  if (expectedTrack === "repeated_no_progress_action_reduction") {
    exactKeys(input, ["schemaVersion", "track", "actions"], label);
    const actions = values(input.actions, `${label}.actions`, 3, 128)
      .map((item, index) => {
        const action = record(item, `${label}.actions[${index}]`);
        exactKeys(action, ["fingerprint", "progress"], `${label}.actions[${index}]`);
        return Object.freeze({
          fingerprint: safeSignal(
            action.fingerprint,
            `${label}.actions[${index}].fingerprint`,
          ),
          progress: booleanValue(
            action.progress,
            `${label}.actions[${index}].progress`,
          ),
        });
      });
    return deepFreeze({
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: expectedTrack,
      actions,
    });
  }
  if (expectedTrack === "specialist_routing_quality") {
    exactKeys(input, ["schemaVersion", "track", "tasks"], label);
    const tasks = values(input.tasks, `${label}.tasks`, 1, 64)
      .map((item, taskIndex) => {
        const task = record(item, `${label}.tasks[${taskIndex}]`);
        exactKeys(
          task,
          ["taskId", "requiredCapability", "candidates"],
          `${label}.tasks[${taskIndex}]`,
        );
        const candidates = values(
          task.candidates,
          `${label}.tasks[${taskIndex}].candidates`,
          1,
          32,
        ).map((candidateValue, candidateIndex) => {
          const candidate = record(
            candidateValue,
            `${label}.tasks[${taskIndex}].candidates[${candidateIndex}]`,
          );
          exactKeys(
            candidate,
            ["agentId", "capabilities", "capabilityScore"],
            `${label}.tasks[${taskIndex}].candidates[${candidateIndex}]`,
          );
          const capabilities = values(
            candidate.capabilities,
            `${label}.tasks[${taskIndex}].candidates[${candidateIndex}].capabilities`,
            1,
            32,
          ).map((capability, capabilityIndex) =>
            safeId(
              capability,
              `${label}.tasks[${taskIndex}].candidates[${candidateIndex}].capabilities[${capabilityIndex}]`,
            ));
          unique(capabilities, `${label}.tasks[${taskIndex}] candidate capabilities`);
          return Object.freeze({
            agentId: safeId(
              candidate.agentId,
              `${label}.tasks[${taskIndex}].candidates[${candidateIndex}].agentId`,
            ),
            capabilities,
            capabilityScore: score(
              candidate.capabilityScore,
              `${label}.tasks[${taskIndex}].candidates[${candidateIndex}].capabilityScore`,
            ),
          });
        });
        unique(
          candidates.map(({ agentId }) => agentId),
          `${label}.tasks[${taskIndex}] candidates`,
        );
        return Object.freeze({
          taskId: safeId(task.taskId, `${label}.tasks[${taskIndex}].taskId`),
          requiredCapability: safeId(
            task.requiredCapability,
            `${label}.tasks[${taskIndex}].requiredCapability`,
          ),
          candidates,
        });
      });
    unique(tasks.map(({ taskId }) => taskId), `${label}.tasks`);
    return deepFreeze({
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: expectedTrack,
      tasks,
    });
  }
  exactKeys(input, ["schemaVersion", "track", "candidates"], label);
  const candidates = values(input.candidates, `${label}.candidates`, 1, 128)
    .map((item, index) => {
      const candidate = record(item, `${label}.candidates[${index}]`);
      exactKeys(
        candidate,
        ["memoryId", "confidence", "verified", "sameEngagement"],
        `${label}.candidates[${index}]`,
      );
      return Object.freeze({
        memoryId: safeId(
          candidate.memoryId,
          `${label}.candidates[${index}].memoryId`,
        ),
        confidence: score(
          candidate.confidence,
          `${label}.candidates[${index}].confidence`,
        ),
        verified: booleanValue(
          candidate.verified,
          `${label}.candidates[${index}].verified`,
        ),
        sameEngagement: booleanValue(
          candidate.sameEngagement,
          `${label}.candidates[${index}].sameEngagement`,
        ),
      });
    });
  unique(candidates.map(({ memoryId }) => memoryId), `${label}.candidates`);
  return deepFreeze({
    schemaVersion: "ti-scale.synthetic-scenario.v1",
    track: expectedTrack,
    candidates,
  });
}

function groundTruthForInput(
  value: unknown,
  input: SyntheticScenarioInput,
  label: string,
): JsonValue {
  const truth = record(value, label);
  if (input.track === "repeated_no_progress_action_reduction") {
    exactKeys(truth, ["usefulActionIndexes"], label);
    const indexes = values(
      truth.usefulActionIndexes,
      `${label}.usefulActionIndexes`,
      1,
      input.actions.length,
    ).map((item, index) =>
      integer(
        item,
        0,
        input.actions.length - 1,
        `${label}.usefulActionIndexes[${index}]`,
      ));
    if (new Set(indexes).size !== indexes.length) {
      throw new Error(`${label}.usefulActionIndexes contains duplicates`);
    }
    return deepFreeze({ usefulActionIndexes: indexes } as unknown as JsonValue);
  }
  if (input.track === "specialist_routing_quality") {
    exactKeys(truth, ["assignments"], label);
    const assignments = record(truth.assignments, `${label}.assignments`);
    const taskIds = input.tasks.map(({ taskId }) => taskId).sort();
    if (
      Object.keys(assignments).sort().length !== taskIds.length
      || Object.keys(assignments).sort().some((key, index) => key !== taskIds[index])
    ) throw new Error(`${label}.assignments must cover every task exactly once`);
    const normalized = Object.fromEntries(input.tasks.map((task) => {
      const selected = assignments[task.taskId];
      if (
        selected !== null
        && (
          typeof selected !== "string"
          || !task.candidates.some(({ agentId }) => agentId === selected)
        )
      ) throw new Error(`${label}.assignments contains an unknown agent`);
      return [task.taskId, selected];
    }));
    return deepFreeze({ assignments: normalized } as unknown as JsonValue);
  }
  exactKeys(truth, ["relevantMemoryIds"], label);
  const relevant = values(
    truth.relevantMemoryIds,
    `${label}.relevantMemoryIds`,
    0,
    input.candidates.length,
  ).map((item, index) =>
    safeId(item, `${label}.relevantMemoryIds[${index}]`));
  unique(relevant, `${label}.relevantMemoryIds`);
  const known = new Set(input.candidates.map(({ memoryId }) => memoryId));
  if (relevant.some((memoryId) => !known.has(memoryId))) {
    throw new Error(`${label}.relevantMemoryIds contains an unknown memory`);
  }
  return deepFreeze({ relevantMemoryIds: relevant } as unknown as JsonValue);
}

function campaign(
  value: unknown,
  index: number,
): PrivateResearchHoldoutCampaign {
  const label = `campaigns[${index}]`;
  const raw = record(value, label);
  exactKeys(raw, ["catalogId", "fixtureKey", "input", "groundTruth"], label);
  const parsedCatalogId = catalogId(raw.catalogId, `${label}.catalogId`);
  const parsedInput = inputForTrack(raw.input, parsedCatalogId, `${label}.input`);
  return deepFreeze({
    catalogId: parsedCatalogId,
    fixtureKey: safeId(raw.fixtureKey, `${label}.fixtureKey`),
    input: parsedInput,
    groundTruth: groundTruthForInput(
      raw.groundTruth,
      parsedInput,
      `${label}.groundTruth`,
    ),
  });
}

export function parsePrivateResearchHoldoutDescriptor(
  value: unknown,
): PrivateResearchHoldoutDescriptor {
  const descriptor = record(value, "Private Research holdout descriptor");
  exactKeys(
    descriptor,
    ["schemaVersion", "descriptorVersion", "campaigns"],
    "Private Research holdout descriptor",
  );
  if (descriptor.schemaVersion !== PRIVATE_RESEARCH_HOLDOUT_SCHEMA_VERSION) {
    throw new Error("Private Research holdout descriptor schema is unsupported");
  }
  const campaigns = values(descriptor.campaigns, "campaigns", 1, 3)
    .map(campaign);
  unique(campaigns.map(({ catalogId }) => catalogId), "campaigns");
  unique(campaigns.map(({ fixtureKey }) => fixtureKey), "campaign fixture keys");
  return deepFreeze({
    schemaVersion: PRIVATE_RESEARCH_HOLDOUT_SCHEMA_VERSION,
    descriptorVersion: safeId(
      descriptor.descriptorVersion,
      "descriptorVersion",
    ),
    campaigns,
  });
}

export function loadTrustedPrivateResearchHoldoutDescriptor(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<PrivateResearchHoldoutDescriptor> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 512 * 1024 },
    parsePrivateResearchHoldoutDescriptor,
  );
}

export class PrivateResearchHoldoutRegistry {
  readonly #entriesByCatalog: ReadonlyMap<InitialResearchCampaignId, PrivateEntry>;
  readonly #entriesByScenario: ReadonlyMap<string, PrivateEntry>;
  readonly #descriptorVersionHash: string;
  readonly #descriptorSourceSha256: string;
  readonly #descriptorCanonicalSha256: string;

  constructor(
    loaded: LoadedTrustedJson<PrivateResearchHoldoutDescriptor>,
  ) {
    if (
      !SHA256.test(loaded.receipt.sourceSha256)
      || !SHA256.test(loaded.receipt.canonicalSha256)
    ) throw new Error("Private Research holdout receipt hashes are invalid");
    this.#descriptorVersionHash = sha256(loaded.value.descriptorVersion);
    this.#descriptorSourceSha256 = loaded.receipt.sourceSha256;
    this.#descriptorCanonicalSha256 = loaded.receipt.canonicalSha256;
    const entries = loaded.value.campaigns.map((campaignValue): PrivateEntry => {
      const scenarioCommitment = hashCanonical({
        schemaVersion: PRIVATE_RESEARCH_HOLDOUT_SCHEMA_VERSION,
        descriptorCanonicalSha256: loaded.receipt.canonicalSha256,
        catalogId: campaignValue.catalogId,
        fixtureKey: campaignValue.fixtureKey,
        input: campaignValue.input,
        groundTruth: campaignValue.groundTruth,
      } as unknown as JsonValue);
      const scenarioId =
        `private-holdout-${campaignValue.catalogId}-${scenarioCommitment.slice(0, 24)}`;
      const files = Object.freeze({
        "scenario.json": canonicalJson(
          campaignValue.input as unknown as JsonValue,
        ),
      });
      const fixture: SyntheticBenchmarkFixture = Object.freeze({
        scenarioId,
        targetClass: "synthetic_fixture",
        files,
        environmentDigest: syntheticFixtureEnvironmentDigest(files),
      });
      const definition: SyntheticScenarioDefinition = deepFreeze({
        scenarioId,
        track: campaignValue.catalogId,
        split: "hidden_holdout",
        input: campaignValue.input,
        groundTruth: campaignValue.groundTruth,
      });
      return Object.freeze({
        catalogId: campaignValue.catalogId,
        scenarioId,
        fixture,
        definition,
        scenarioCommitment,
      });
    });
    this.#entriesByCatalog = new Map(
      entries.map((entry) => [entry.catalogId, entry]),
    );
    this.#entriesByScenario = new Map(
      entries.map((entry) => [entry.scenarioId, entry]),
    );
  }

  hasCatalog(catalog: InitialResearchCampaignId): boolean {
    return this.#entriesByCatalog.has(catalog);
  }

  isPrivateScenario(scenarioId: string): boolean {
    return this.#entriesByScenario.has(scenarioId);
  }

  scenarioFor(input: {
    readonly catalogId: InitialResearchCampaignId;
    readonly familyId: string;
    readonly budgetJson: string;
  }): PrivateResearchHoldoutScenario | undefined {
    const entry = this.#entriesByCatalog.get(input.catalogId);
    if (!entry) return undefined;
    const scenarioHash = hashCanonical({
      id: entry.scenarioId,
      familyId: input.familyId,
      split: "hidden_holdout",
      descriptorSourceSha256: this.#descriptorSourceSha256,
      descriptorCanonicalSha256: this.#descriptorCanonicalSha256,
      scenarioCommitment: entry.scenarioCommitment,
      groundTruthRef:
        `private-holdout://commitment/${entry.scenarioCommitment}`,
      environmentDigest: entry.fixture.environmentDigest,
      budgetJson: input.budgetJson,
    } as unknown as JsonValue);
    return deepFreeze({
      id: entry.scenarioId,
      split: "hidden_holdout",
      name: "Private hidden-holdout fixture",
      scenarioHash,
      groundTruthRef:
        `private-holdout://commitment/${entry.scenarioCommitment}`,
      environmentDigest: entry.fixture.environmentDigest,
      budgetJson: input.budgetJson,
      binding: {
        descriptorVersionHash: this.#descriptorVersionHash,
        descriptorSourceSha256: this.#descriptorSourceSha256,
        descriptorCanonicalSha256: this.#descriptorCanonicalSha256,
        scenarioCommitment: entry.scenarioCommitment,
        opaqueScenarioIdHash: sha256(entry.scenarioId),
      },
    });
  }

  fixtureFor(input: {
    readonly scenarioId: string;
    readonly environmentDigest: string;
  }): SyntheticBenchmarkFixture | undefined {
    const entry = this.#entriesByScenario.get(input.scenarioId);
    if (!entry || entry.fixture.environmentDigest !== input.environmentDigest) {
      return undefined;
    }
    return entry.fixture;
  }

  evaluate(input: {
    readonly scenarioId: string;
    readonly candidate: StrategyBundle;
    readonly workerDecision: SyntheticResearchDecision;
    readonly fixtureIntegrity: boolean;
    readonly fixtureHash: string;
    readonly admissionHash: string;
  }): LocalSyntheticScenarioEvaluation {
    const entry = this.#entriesByScenario.get(input.scenarioId);
    if (!entry) throw new Error("Private hidden-holdout scenario is not loaded");
    return evaluateSyntheticResearchDefinition({
      definition: entry.definition,
      candidate: input.candidate,
      workerDecision: input.workerDecision,
      fixtureIntegrity: input.fixtureIntegrity,
      fixtureHash: input.fixtureHash,
      admissionHash: input.admissionHash,
    });
  }
}

export const PRIVATE_RESEARCH_HOLDOUT_CONFIGURATION_ENVIRONMENT =
  Object.freeze({
    trustRoot: "TI_SCALE_RESEARCH_HOLDOUT_TRUST_ROOT",
    descriptorPath: "TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_PATH",
    descriptorSha256: "TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_SHA256",
  } as const);

export type ProductionPrivateResearchHoldoutConfiguration =
  | Readonly<{
      status: "loaded";
      registry: PrivateResearchHoldoutRegistry;
      descriptorSourceSha256: string;
      descriptorCanonicalSha256: string;
    }>
  | Readonly<{
      status: "unconfigured";
      reason: string;
    }>;

export function loadProductionPrivateResearchHoldoutConfiguration(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ProductionPrivateResearchHoldoutConfiguration {
  const names = Object.values(
    PRIVATE_RESEARCH_HOLDOUT_CONFIGURATION_ENVIRONMENT,
  );
  const values = Object.fromEntries(
    names.map((name) => [name, environment[name]?.trim() || undefined]),
  ) as Record<string, string | undefined>;
  const configured = names.filter((name) => values[name]).length;
  if (configured === 0) {
    return Object.freeze({
      status: "unconfigured",
      reason:
        "No complete trusted private Research holdout descriptor is configured.",
    });
  }
  if (configured !== names.length) {
    const missing = names.filter((name) => !values[name]);
    throw new Error(
      `Private Research holdout configuration is incomplete; missing ${missing.join(", ")}`,
    );
  }
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const loaded = loadTrustedPrivateResearchHoldoutDescriptor({
    path: values[
      PRIVATE_RESEARCH_HOLDOUT_CONFIGURATION_ENVIRONMENT.descriptorPath
    ]!,
    trustRoot: values[
      PRIVATE_RESEARCH_HOLDOUT_CONFIGURATION_ENVIRONMENT.trustRoot
    ]!,
    expectedSha256: values[
      PRIVATE_RESEARCH_HOLDOUT_CONFIGURATION_ENVIRONMENT.descriptorSha256
    ]!,
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  });
  return Object.freeze({
    status: "loaded",
    registry: new PrivateResearchHoldoutRegistry(loaded),
    descriptorSourceSha256: loaded.receipt.sourceSha256,
    descriptorCanonicalSha256: loaded.receipt.canonicalSha256,
  });
}
