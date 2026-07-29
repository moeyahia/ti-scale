import type {
  BrainContextResult,
  ConfirmedBrainPreferenceProfile,
} from "../brain-runtime";
import type { ContextPackItemDisposition } from "../memory";
import type { MissionIntakeContextBinding } from "./types";

type SafeOptionalDefaults = NonNullable<
  MissionIntakeContextBinding["safeOptionalDefaults"]
>;

export interface AutonomousIntakePreferenceApplication {
  readonly memoryInfluencedDefaults: boolean;
  readonly safeOptionalDefaults?: SafeOptionalDefaults;
  readonly influenceExplanation?: string;
  readonly dispositions: readonly ContextPackItemDisposition[];
}

const EVIDENCE_FIRST_STRUCTURE = [
  "observation",
  "meaning",
  "confidence",
  "uncertainty",
  "next justified action",
] as const;

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function exactStringArray(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((item, index) => item === expected[index]);
}

function specificity(profile: ConfirmedBrainPreferenceProfile): number {
  return profile.profileScope === "engagement" ? 1 : 0;
}

function profileOrder(
  left: ConfirmedBrainPreferenceProfile,
  right: ConfirmedBrainPreferenceProfile,
): number {
  return specificity(right) - specificity(left)
    || Date.parse(right.confirmedAt) - Date.parse(left.confirmedAt)
    || right.version - left.version
    || left.nodeId.localeCompare(right.nodeId);
}

function hasApplicability(
  profile: ConfirmedBrainPreferenceProfile,
  ...required: readonly string[]
): boolean {
  return required.every((value) => profile.appliesTo.includes(value));
}

function compileSafeDefault(
  profile: ConfirmedBrainPreferenceProfile,
): Readonly<{
  defaults: Partial<SafeOptionalDefaults>;
  influenceSummary: string;
}> | undefined {
  const value = profile.value;
  if (!plainRecord(value)) return undefined;

  if (
    profile.preferenceKey === "autonomy.default_posture"
    && hasApplicability(profile, "autonomy_presentation")
    && exactKeys(value, ["boundary", "posture"])
    && value.posture === "high_autonomy"
    && value.boundary === "signed_contract_and_platform_policy"
  ) {
    return {
      defaults: { autonomyPresentation: "high_autonomy" },
      influenceSummary:
        "Applied the confirmed high-autonomy preference to intake status and explanation presentation only. The signed contract and every execution boundary remained unchanged.",
    };
  }

  if (
    profile.preferenceKey === "communication.technical_readability"
    && hasApplicability(profile, "reports")
    && exactKeys(value, ["avoid", "include", "style"])
    && value.style === "technical_readable"
    && exactStringArray(value.avoid, [
      "oversimplified wording",
      "opaque internal jargon",
    ])
    && exactStringArray(value.include, [
      "purpose",
      "operational meaning",
      "useful technical detail",
    ])
  ) {
    return {
      defaults: { explanationTemplate: "technical_readable" },
      influenceSummary:
        "Applied the confirmed readable-technical-language template to Autonomous intake explanations and report narration only. The signed contract and every execution boundary remained unchanged.",
    };
  }

  if (
    profile.preferenceKey === "communication.evidence_first"
    && hasApplicability(profile, "evidence_presentation", "reports")
    && exactKeys(value, ["rawLogs", "structure"])
    && value.rawLogs === "not_automatically_evidence"
    && exactStringArray(value.structure, EVIDENCE_FIRST_STRUCTURE)
  ) {
    return {
      defaults: { reportTemplate: "evidence_first" },
      influenceSummary:
        "Applied the confirmed evidence-first template to report narration only. Raw logs still require canonical promotion and the signed evidence policy remained unchanged.",
    };
  }

  return undefined;
}

/**
 * Compile a tiny presentation-only preference surface. The input request is
 * deliberately absent: this function cannot mutate authorization, target
 * scope, action permissions, budgets, provider/tool selection, evidence
 * requirements, safe stops, or deliverables.
 */
export function applyAutonomousIntakePreferenceDefaults(input: {
  readonly context: BrainContextResult;
  readonly profiles: readonly ConfirmedBrainPreferenceProfile[];
}): AutonomousIntakePreferenceApplication {
  const profilesByKey = new Map<string, ConfirmedBrainPreferenceProfile[]>();
  for (const profile of input.profiles) {
    const profiles = profilesByKey.get(profile.preferenceKey) ?? [];
    profiles.push(profile);
    profilesByKey.set(profile.preferenceKey, profiles);
  }
  const selectedProfiles = new Map<string, ConfirmedBrainPreferenceProfile>();
  for (const [key, profiles] of profilesByKey) {
    selectedProfiles.set(key, [...profiles].sort(profileOrder)[0]!);
  }

  const appliedByNode = new Map<
    string,
    Readonly<{ defaults: Partial<SafeOptionalDefaults>; influenceSummary: string }>
  >();
  for (const profile of selectedProfiles.values()) {
    const compiled = compileSafeDefault(profile);
    if (compiled) appliedByNode.set(profile.nodeId, compiled);
  }

  const profileByNode = new Map(input.profiles.map((profile) => [profile.nodeId, profile]));
  const selectedNodeIds = new Set(
    [...selectedProfiles.values()].map(({ nodeId }) => nodeId),
  );
  const dispositions = input.context.contextPack.items.map(
    (item): ContextPackItemDisposition => {
      const applied = appliedByNode.get(item.nodeId);
      if (applied) {
        return {
          nodeId: item.nodeId,
          used: true,
          relevanceReason: item.relevanceReason,
          influenceSummary: applied.influenceSummary,
        };
      }
      const profile = profileByNode.get(item.nodeId);
      const ignoredReason = !profile
        ? "Retrieved memory was not a current typed, explicitly confirmed operator preference profile, so it could not influence Autonomous intake defaults."
        : !selectedNodeIds.has(item.nodeId)
          ? "A more specific or more recently confirmed profile for the same preference key took precedence."
          : "The preference key, applicability, or typed value did not match the presentation-only Autonomous intake allowlist. Policy, scope, permissions, and execution defaults were not changed.";
      return {
        nodeId: item.nodeId,
        used: false,
        relevanceReason: item.relevanceReason,
        ignoredReason,
      };
    },
  );

  const used = [...appliedByNode.values()];
  if (used.length === 0) {
    return {
      memoryInfluencedDefaults: false,
      dispositions: Object.freeze(dispositions),
    };
  }
  const safeOptionalDefaults: SafeOptionalDefaults = Object.freeze({
    ...used.reduce<Partial<SafeOptionalDefaults>>(
      (defaults, item) => ({ ...defaults, ...item.defaults }),
      {},
    ),
    safetyBoundary: "presentation_only_contract_unchanged",
  });
  const labels = [
    safeOptionalDefaults.autonomyPresentation ? "high-autonomy presentation" : undefined,
    safeOptionalDefaults.explanationTemplate ? "readable technical language" : undefined,
    safeOptionalDefaults.reportTemplate ? "evidence-first report narration" : undefined,
  ].filter((value): value is string => Boolean(value));
  return {
    memoryInfluencedDefaults: true,
    safeOptionalDefaults,
    influenceExplanation:
      `Applied ${labels.join(", ")} from ${appliedByNode.size} explicitly confirmed, scope-safe operator preference profile${appliedByNode.size === 1 ? "" : "s"}. Authorization, targets, action permissions, budgets, evidence rules, tools, providers, safe stops, deliverables, and the reviewed contract hash were unchanged.`,
    dispositions: Object.freeze(dispositions),
  };
}
