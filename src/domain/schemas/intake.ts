import { array, boolean, nonEmpty, number, object, schema, string, stringList, type JsonRecord } from "./common";
import type { AutonomousMissionRequest, GuidedMissionRequest, GuidedReconnaissanceSelection, GuidedTcpPortPresetId, MissionCreateRequest } from "../types/commandOs";
import { parseAutonomousPlanningSelection } from "./commandOs";
import type {
  ActionPolicyState,
  BudgetPresetId,
  CapabilityMapping,
  DestructiveActionPolicy,
  IntakeActionClass,
  IntakeActionClassRegistry,
  IntakeDeliverable,
  IntakeEvidenceType,
  IntakeFieldDefinition,
  IntakeMissionTemplate,
  IntakeRegistrySnapshot,
  MissionBudgetPreset,
  MissionIntakeTargetInput,
  MissionTemplateId,
  ResolvedMissionIntake,
  SafeStopDefinition,
} from "../types/intake";

function literal<const T extends string>(value: unknown, choices: readonly T[], label: string): T {
  if (typeof value === "string" && choices.includes(value as T)) return value as T;
  throw new Error(`${label} is invalid`);
}

function optionalString(value: unknown, label: string): string | undefined {
  return value === undefined || value === null ? undefined : string(value, label);
}

function recordOf<T>(value: unknown, label: string, parser: (item: unknown, key: string) => T): Record<string, T> {
  const source = object(value, label);
  return Object.fromEntries(Object.entries(source).map(([key, item]) => [key, parser(item, key)]));
}

function parseCapability(value: unknown): CapabilityMapping {
  const item = object(value, "action capability");
  return {
    availability: literal(item.availability, ["supported", "unavailable", "unsupported"], "capability availability"),
    riskClassIds: stringList(item.riskClassIds, "capability risk classes"),
    agentIds: stringList(item.agentIds, "capability agents"),
    availableAgentIds: stringList(item.availableAgentIds, "available capability agents"),
    toolIds: stringList(item.toolIds, "capability tools"),
    availableToolIds: stringList(item.availableToolIds, "available capability tools"),
    mcpServerIds: stringList(item.mcpServerIds, "capability MCP servers"),
    providerModelRefs: stringList(item.providerModelRefs, "capability provider models"),
    enforcedProviderModelRefs: stringList(item.enforcedProviderModelRefs, "enforced provider models"),
    locallyEnforcedToolIds: stringList(item.locallyEnforcedToolIds, "locally enforced tools"),
    evidenceTypeIds: stringList(item.evidenceTypeIds, "capability evidence types"),
    enforcementReady: boolean(item.enforcementReady, "capability enforcement readiness"),
    readinessReasons: stringList(item.readinessReasons, "capability readiness reasons"),
  };
}

function parseActionClass(value: unknown, key: string): IntakeActionClass {
  const item = object(value, `action class ${key}`);
  return {
    id: nonEmpty(item.id, "action class id"),
    label: nonEmpty(item.label, "action class label"),
    plainLanguageDescription: nonEmpty(item.plainLanguageDescription, "action class description"),
    technicalDescription: nonEmpty(item.technicalDescription, "action class technical description"),
    riskBand: literal(item.riskBand, ["low", "moderate", "high", "critical"], "action risk band"),
    likelySideEffects: stringList(item.likelySideEffects, "action side effects"),
    defaultPolicyState: literal(item.defaultPolicyState, ["pre_authorized", "prohibited", "guided_only"], "default action policy"),
    defaultEvidenceTypeIds: stringList(item.defaultEvidenceTypeIds, "default action evidence"),
    destructiveOrDisruptive: boolean(item.destructiveOrDisruptive, "destructive action marker"),
    policyState: literal(item.policyState, ["pre_authorized", "prohibited", "guided_only"], "resolved action policy"),
    policySource: literal(item.policySource, ["platform_default", "preset", "operator_override"], "action policy source"),
    capability: parseCapability(item.capability),
    launchBlockingReasons: stringList(item.launchBlockingReasons, "action launch blockers"),
  };
}

function parseActionRegistry(value: unknown): IntakeActionClassRegistry {
  const item = object(value, "action-class registry");
  return {
    journey: literal(item.journey, ["autonomous", "guided"], "registry journey"),
    presetId: literal(item.presetId, ["safe_recon", "external_web_assessment", "internal_network_assessment", "active_directory_lab", "cloud_read_only", "htb_web_full_path", "full_authorized_lab_compromise", "custom"], "policy preset"),
    destructivePolicy: literal(item.destructivePolicy, ["prohibited", "validate_without_executing", "bounded_lab_only"], "destructive policy"),
    classes: recordOf(item.classes, "action classes", parseActionClass),
    autonomousLaunchReady: boolean(item.autonomousLaunchReady, "Autonomous launch readiness"),
    launchBlockingReasons: stringList(item.launchBlockingReasons, "registry launch blockers"),
  };
}

function parseEvidenceType(value: unknown): IntakeEvidenceType {
  const item = object(value, "evidence type");
  const capability = object(item.capability, "evidence capability");
  return {
    id: nonEmpty(item.id, "evidence type id"), label: nonEmpty(item.label, "evidence label"),
    proves: nonEmpty(item.proves, "evidence purpose"), storageAndSensitivity: nonEmpty(item.storageAndSensitivity, "evidence sensitivity"),
    normallyRequiredForActionClassIds: stringList(item.normallyRequiredForActionClassIds, "evidence action classes"),
    immutableHashRequired: boolean(item.immutableHashRequired, "evidence hash requirement"),
    chainOfCustodyRequired: boolean(item.chainOfCustodyRequired, "evidence custody requirement"),
    capability: {
      evidenceTypeId: nonEmpty(capability.evidenceTypeId, "evidence capability id"),
      runtimeEvidenceKindIds: stringList(capability.runtimeEvidenceKindIds, "runtime evidence kinds"),
      producerToolIds: stringList(capability.producerToolIds, "evidence producer tools"),
      availability: literal(capability.availability, ["supported", "unavailable", "unsupported"], "evidence availability"),
    },
  };
}

function parseDeliverable(value: unknown): IntakeDeliverable {
  const item = object(value, "deliverable");
  const capability = object(item.capability, "deliverable capability");
  return {
    id: nonEmpty(item.id, "deliverable id"), label: nonEmpty(item.label, "deliverable label"),
    purpose: nonEmpty(item.purpose, "deliverable purpose"), formats: stringList(item.formats, "deliverable formats"),
    sensitivityNotes: nonEmpty(item.sensitivityNotes, "deliverable sensitivity"),
    capability: {
      deliverableId: nonEmpty(capability.deliverableId, "deliverable capability id"),
      producerAgentIds: stringList(capability.producerAgentIds, "deliverable agents"),
      producerToolIds: stringList(capability.producerToolIds, "deliverable tools"),
      availability: literal(capability.availability, ["supported", "unavailable", "unsupported"], "deliverable availability"),
    },
  };
}

const TEMPLATE_IDS = ["safe_recon", "external_web_assessment", "internal_network_assessment", "active_directory_lab", "cloud_read_only", "htb_web_full_path", "full_authorized_lab_compromise", "custom"] as const;
const BUDGET_IDS = ["quick", "standard", "deep", "custom"] as const;

function parseTemplate(value: unknown): IntakeMissionTemplate {
  const item = object(value, "mission template");
  return {
    id: literal(item.id, TEMPLATE_IDS, "mission template id"), version: number(item.version, "mission template version"),
    label: nonEmpty(item.label, "mission template label"), summary: nonEmpty(item.summary, "mission template summary"),
    supportedJourneys: array(item.supportedJourneys, "template journeys").map((journey) => literal(journey, ["autonomous", "guided"], "template journey")),
    actionPolicyPresetId: literal(item.actionPolicyPresetId, TEMPLATE_IDS, "template policy preset"),
    scopeHints: stringList(item.scopeHints, "template scope hints"), objectivePattern: nonEmpty(item.objectivePattern, "template objective"),
    successCriteria: stringList(item.successCriteria, "template success criteria"),
    recommendedActionClassIds: stringList(item.recommendedActionClassIds, "template actions"),
    recommendedEvidenceTypeIds: stringList(item.recommendedEvidenceTypeIds, "template evidence"),
    recommendedDeliverableIds: stringList(item.recommendedDeliverableIds, "template deliverables"),
    recommendedOptionalSafeStops: stringList(item.recommendedOptionalSafeStops, "template safe stops"),
    recommendedAgentCapabilityIds: stringList(item.recommendedAgentCapabilityIds, "template agents"),
    modelReadinessRequirements: stringList(item.modelReadinessRequirements, "template model requirements"),
    budgetPreset: literal(item.budgetPreset, BUDGET_IDS, "template budget"),
    unsupportedActionClassIds: stringList(item.unsupportedActionClassIds, "unsupported template actions"),
    unavailableEvidenceTypeIds: stringList(item.unavailableEvidenceTypeIds, "unavailable template evidence"),
    unavailableDeliverableIds: stringList(item.unavailableDeliverableIds, "unavailable template deliverables"),
  };
}

function parseSafeStop(value: unknown): SafeStopDefinition {
  const item = object(value, "safe-stop definition");
  return { id: nonEmpty(item.id, "safe-stop id"), label: nonEmpty(item.label, "safe-stop label"), explanation: nonEmpty(item.explanation, "safe-stop explanation"), remediation: nonEmpty(item.remediation, "safe-stop remediation"), mandatory: boolean(item.mandatory, "safe-stop mandatory"), userRemovable: boolean(item.userRemovable, "safe-stop removability") };
}

function parseBudget(value: unknown): MissionBudgetPreset {
  const item = object(value, "budget preset");
  return {
    id: literal(item.id, ["quick", "standard", "deep"], "budget id"), label: nonEmpty(item.label, "budget label"), description: nonEmpty(item.description, "budget description"),
    timeBudgetMinutes: number(item.timeBudgetMinutes, "time budget"), tokenBudget: number(item.tokenBudget, "token budget"), estimatedCostBudget: number(item.estimatedCostBudget, "cost budget"), toolCallBudget: number(item.toolCallBudget, "tool-call budget"), retryBudget: number(item.retryBudget, "retry budget"), replanBudget: number(item.replanBudget, "replan budget"), concurrencyLimit: number(item.concurrencyLimit, "concurrency budget"), screenshotBudget: number(item.screenshotBudget, "screenshot budget"), evidenceStorageBudgetBytes: number(item.evidenceStorageBudgetBytes, "evidence storage budget"), artifactStorageBudgetBytes: number(item.artifactStorageBudgetBytes, "artifact storage budget"), maximumArtifactBytes: number(item.maximumArtifactBytes, "maximum artifact size"),
  };
}

function parseField(value: unknown): IntakeFieldDefinition {
  const item = object(value, "intake field");
  return { id: nonEmpty(item.id, "field id"), label: nonEmpty(item.label, "field label"), purpose: nonEmpty(item.purpose, "field purpose"), example: nonEmpty(item.example, "field example"), optional: boolean(item.optional, "field optional"), structuredWhenPossible: boolean(item.structuredWhenPossible, "field structure marker") };
}

const GUIDED_TCP_PRESET_IDS = ["focused_services", "web_services", "remote_management"] as const;
const GUIDED_WINDOWS_IDENTITY_OPERATIONS = [
  "smb_share_list",
  "smb_identity_summary",
  "ldap_root_dse",
  "rpc_domain_info",
] as const;
const GUIDED_WINDOWS_IDENTITY_AUTHENTICATION_MODES = [
  "anonymous",
  "credential_reference",
] as const;
const LOCAL_EXPLOIT_CVE_ID = /^CVE-[12][0-9]{3}-[0-9]{4,10}$/u;
const LOCAL_EXPLOIT_TECHNOLOGY_TEXT =
  /^[\p{L}\p{N}][\p{L}\p{N} ._+/:()#-]*$/u;

function exactKeys(
  value: JsonRecord,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (
    actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])
  ) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const parsed = number(value, label);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(
      `${label} must be a whole number from ${minimum} through ${maximum}`,
    );
  }
  return parsed;
}

function localExploitTechnologyText(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): string {
  const parsed = nonEmpty(value, label);
  if (
    parsed !== parsed.trim()
    || parsed.length < minimum
    || parsed.length > maximum
    || !LOCAL_EXPLOIT_TECHNOLOGY_TEXT.test(parsed)
  ) {
    throw new Error(
      `${label} must be ${minimum} through ${maximum} readable technology characters without command syntax`,
    );
  }
  return parsed;
}

function optionalLocalExploitTechnologyText(
  value: unknown,
  maximum: number,
  label: string,
): string | null {
  if (value === null) return null;
  return localExploitTechnologyText(value, 1, maximum, label);
}

function parseGuidedLocalExploitQuery(
  value: unknown,
): NonNullable<
  GuidedMissionRequest["guidedLocalExploitIntelligence"]
>["query"] {
  const query = object(value, "Guided local ExploitDB query");
  const kind = literal(
    query.kind,
    ["cve", "technology"],
    "Guided local ExploitDB query kind",
  );
  if (kind === "cve") {
    exactKeys(
      query,
      ["kind", "cveId", "maximumResults"],
      "Guided local ExploitDB CVE query",
    );
    const cveId = nonEmpty(
      query.cveId,
      "Guided local ExploitDB CVE ID",
    );
    if (
      cveId !== cveId.trim()
      || cveId !== cveId.toLocaleUpperCase("en-US")
      || !LOCAL_EXPLOIT_CVE_ID.test(cveId)
    ) {
      throw new Error(
        "Guided local ExploitDB CVE ID must use canonical CVE-YYYY-NNNN format",
      );
    }
    return {
      kind,
      cveId,
      maximumResults: boundedInteger(
        query.maximumResults,
        1,
        100,
        "Guided local ExploitDB result limit",
      ),
    };
  }
  exactKeys(
    query,
    ["kind", "product", "version", "platform", "maximumResults"],
    "Guided local ExploitDB technology query",
  );
  return {
    kind,
    product: localExploitTechnologyText(
      query.product,
      2,
      120,
      "Guided local ExploitDB product",
    ),
    version: optionalLocalExploitTechnologyText(
      query.version,
      80,
      "Guided local ExploitDB version",
    ),
    platform: optionalLocalExploitTechnologyText(
      query.platform,
      80,
      "Guided local ExploitDB platform",
    ),
    maximumResults: boundedInteger(
      query.maximumResults,
      1,
      100,
      "Guided local ExploitDB result limit",
    ),
  };
}

function parseGuidedLocalExploitIntelligence(
  value: unknown,
): NonNullable<GuidedMissionRequest["guidedLocalExploitIntelligence"]> {
  const selection = object(
    value,
    "Guided local ExploitDB intelligence selection",
  );
  exactKeys(
    selection,
    ["query"],
    "Guided local ExploitDB intelligence selection",
  );
  return {
    query: parseGuidedLocalExploitQuery(selection.query),
  };
}

function parseTcpPorts(value: unknown, label: string): number[] {
  return array(value, label).map((candidate, index) => {
    const port = number(candidate, `${label}[${index}]`);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
      throw new Error(`${label}[${index}] must be an individual TCP port from 1 through 65535`);
    }
    return port;
  });
}

function parseGuidedReconnaissance(value: unknown): GuidedReconnaissanceSelection {
  const item = object(value, "Guided reconnaissance selection");
  const mode = literal(item.mode, ["host_liveness", "tcp_service_scan"], "Guided reconnaissance mode");
  if (mode === "host_liveness") return { mode };
  const portSelection = object(item.portSelection, "Guided TCP port selection");
  const source = literal(portSelection.source, ["preset", "custom"], "Guided TCP port source");
  const ports = parseTcpPorts(portSelection.ports, "Guided TCP ports");
  return source === "preset"
    ? {
        mode,
        portSelection: {
          source,
          presetId: literal(portSelection.presetId, GUIDED_TCP_PRESET_IDS, "Guided TCP preset") as GuidedTcpPortPresetId,
          presetVersion: number(portSelection.presetVersion, "Guided TCP preset version"),
          ports,
        },
      }
    : { mode, portSelection: { source, ports } };
}

function parseGuidedReconnaissanceRegistry(value: unknown): IntakeRegistrySnapshot["guidedReconnaissance"] {
  const root = object(value, "Guided reconnaissance registry");
  const custom = object(root.customPorts, "Guided custom-port rules");
  const registryVersion = number(root.registryVersion, "Guided reconnaissance registry version");
  if (registryVersion !== 1) throw new Error("Guided reconnaissance registry version is unsupported");
  return {
    registryVersion: 1,
    modes: array(root.modes, "Guided reconnaissance modes").map((value) => {
      const mode = object(value, "Guided reconnaissance mode");
      if (mode.manualFallbackAvailable !== true) throw new Error("Guided reconnaissance mode must preserve manual fallback");
      return {
        id: literal(mode.id, ["host_liveness", "tcp_service_scan"], "Guided reconnaissance mode ID"),
        label: nonEmpty(mode.label, "Guided reconnaissance label"),
        description: nonEmpty(mode.description, "Guided reconnaissance description"),
        toolId: nonEmpty(mode.toolId, "Guided reconnaissance tool"),
        readiness: literal(mode.readiness, ["ready", "unavailable"], "Guided reconnaissance readiness"),
        readinessExplanation: nonEmpty(mode.readinessExplanation, "Guided reconnaissance readiness explanation"),
        remediation: nonEmpty(mode.remediation, "Guided reconnaissance remediation"),
        manualFallbackAvailable: true,
      };
    }),
    tcpPortPresets: array(root.tcpPortPresets, "Guided TCP presets").map((value) => {
      const preset = object(value, "Guided TCP preset");
      return {
        id: literal(preset.id, GUIDED_TCP_PRESET_IDS, "Guided TCP preset ID") as GuidedTcpPortPresetId,
        version: number(preset.version, "Guided TCP preset version"),
        label: nonEmpty(preset.label, "Guided TCP preset label"),
        description: nonEmpty(preset.description, "Guided TCP preset description"),
        ports: parseTcpPorts(preset.ports, "Guided TCP preset ports"),
      };
    }),
    customPorts: {
      maximumIndividualPorts: number(custom.maximumIndividualPorts, "Guided custom-port limit"),
      example: nonEmpty(custom.example, "Guided custom-port example"),
      explanation: nonEmpty(custom.explanation, "Guided custom-port explanation"),
    },
  };
}

function parseGuidedWindowsIdentity(
  value: unknown,
): NonNullable<GuidedMissionRequest["guidedWindowsIdentity"]> {
  const item = object(value, "Guided Windows or identity selection");
  const authenticationMode = literal(
    item.authenticationMode,
    GUIDED_WINDOWS_IDENTITY_AUTHENTICATION_MODES,
    "Guided Windows or identity authentication mode",
  );
  const credentialReference = authenticationMode === "anonymous"
    ? (() => {
        if (item.credentialReference !== null) {
          throw new Error("Anonymous Guided Windows or identity selection must not contain a credential reference");
        }
        return null;
      })()
    : (() => {
        const reference = object(
          item.credentialReference,
          "Guided Windows or identity credential reference",
        );
        const id = nonEmpty(
          reference.id,
          "Guided Windows or identity credential reference ID",
        );
        if (
          reference.kind !== "systemd_credential_bundle"
          || Object.keys(reference).sort().join("\u0000") !== "id\u0000kind"
          || !/^[A-Za-z0-9._:@/-]{1,200}$/u.test(id)
        ) {
          throw new Error("Guided Windows or identity credential reference kind is invalid");
        }
        return {
          kind: "systemd_credential_bundle" as const,
          id,
        };
      })();
  return {
    operation: literal(
      item.operation,
      GUIDED_WINDOWS_IDENTITY_OPERATIONS,
      "Guided Windows or identity operation",
    ),
    authenticationMode,
    credentialReference,
  };
}

function parseGuidedWindowsIdentityRegistry(
  value: unknown,
): IntakeRegistrySnapshot["guidedWindowsIdentity"] {
  const root = object(value, "Guided Windows or identity registry");
  const registryVersion = number(
    root.registryVersion,
    "Guided Windows or identity registry version",
  );
  if (registryVersion !== 1) {
    throw new Error("Guided Windows or identity registry version is unsupported");
  }
  if (root.sourceOfTruth !== "reviewed-windows-identity-tool-pack") {
    throw new Error("Guided Windows or identity registry source is invalid");
  }
  return {
    registryVersion: 1,
    sourceOfTruth: "reviewed-windows-identity-tool-pack",
    modes: array(root.modes, "Guided Windows or identity modes").map((value) => {
      const mode = object(value, "Guided Windows or identity mode");
      if (mode.requiresSingleStepAgent !== true) {
        throw new Error("Guided Windows or identity mode must require one represented agent step");
      }
      const authenticationModes = array(
        mode.authenticationModes,
        "Guided Windows or identity authentication modes",
      ).map((candidate) => literal(
        candidate,
        GUIDED_WINDOWS_IDENTITY_AUTHENTICATION_MODES,
        "Guided Windows or identity authentication mode",
      ));
      const readyAuthenticationModes = array(
        mode.readyAuthenticationModes,
        "Ready Guided Windows or identity authentication modes",
      ).map((candidate) => literal(
        candidate,
        GUIDED_WINDOWS_IDENTITY_AUTHENTICATION_MODES,
        "Ready Guided Windows or identity authentication mode",
      ));
      if (readyAuthenticationModes.some((candidate) =>
        !authenticationModes.includes(candidate))) {
        throw new Error("Ready Guided Windows or identity authentication mode is not supported by its operation");
      }
      const readiness = literal(
        mode.readiness,
        ["ready", "unavailable"],
        "Guided Windows or identity readiness",
      );
      if (
        (readiness === "ready" && readyAuthenticationModes.length === 0)
        || (readiness === "unavailable" && readyAuthenticationModes.length > 0)
      ) {
        throw new Error("Guided Windows or identity readiness contradicts its ready authentication modes");
      }
      return {
        id: literal(
          mode.id,
          GUIDED_WINDOWS_IDENTITY_OPERATIONS,
          "Guided Windows or identity mode ID",
        ),
        label: nonEmpty(mode.label, "Guided Windows or identity label"),
        description: nonEmpty(mode.description, "Guided Windows or identity description"),
        expectedResult: nonEmpty(
          mode.expectedResult,
          "Guided Windows or identity expected result",
        ),
        toolId: nonEmpty(mode.toolId, "Guided Windows or identity tool"),
        authenticationModes,
        readyAuthenticationModes,
        readiness,
        readinessExplanation: nonEmpty(
          mode.readinessExplanation,
          "Guided Windows or identity readiness explanation",
        ),
        remediation: nonEmpty(
          mode.remediation,
          "Guided Windows or identity remediation",
        ),
        requiresSingleStepAgent: true,
      };
    }),
  };
}

function parseGuidedLocalExploitIntelligenceRegistry(
  value: unknown,
): IntakeRegistrySnapshot["guidedLocalExploitIntelligence"] {
  const root = object(value, "Guided local ExploitDB registry");
  exactKeys(root, [
    "registryVersion",
    "sourceOfTruth",
    "toolId",
    "readiness",
    "readinessExplanation",
    "remediation",
    "providerContact",
    "targetContact",
    "evidencePromotion",
    "requiresSingleStepAgent",
    "queryKinds",
  ], "Guided local ExploitDB registry");
  if (number(root.registryVersion, "Guided local ExploitDB registry version") !== 1) {
    throw new Error("Guided local ExploitDB registry version is unsupported");
  }
  if (root.sourceOfTruth !== "pinned-local-exploitdb-tool-pack") {
    throw new Error("Guided local ExploitDB registry source is invalid");
  }
  if (
    root.providerContact !== false
    || root.targetContact !== false
    || root.evidencePromotion !== "none"
    || root.requiresSingleStepAgent !== true
  ) {
    throw new Error(
      "Guided local ExploitDB registry contradicts its local-only exact-step boundary",
    );
  }
  const queryKinds = array(
    root.queryKinds,
    "Guided local ExploitDB query kinds",
  );
  if (queryKinds.length !== 2) {
    throw new Error(
      "Guided local ExploitDB registry must publish exactly the CVE and technology query kinds",
    );
  }
  const cve = object(queryKinds[0], "Guided local ExploitDB CVE query kind");
  exactKeys(
    cve,
    ["id", "label", "purpose", "expectedResult", "example"],
    "Guided local ExploitDB CVE query kind",
  );
  if (cve.id !== "cve") {
    throw new Error("Guided local ExploitDB CVE query kind is missing or out of order");
  }
  const cveExample = parseGuidedLocalExploitQuery(cve.example);
  if (cveExample.kind !== "cve") {
    throw new Error("Guided local ExploitDB CVE example is invalid");
  }
  const technology = object(
    queryKinds[1],
    "Guided local ExploitDB technology query kind",
  );
  exactKeys(
    technology,
    ["id", "label", "purpose", "expectedResult", "example"],
    "Guided local ExploitDB technology query kind",
  );
  if (technology.id !== "technology") {
    throw new Error(
      "Guided local ExploitDB technology query kind is missing or out of order",
    );
  }
  const technologyExample = parseGuidedLocalExploitQuery(technology.example);
  if (technologyExample.kind !== "technology") {
    throw new Error("Guided local ExploitDB technology example is invalid");
  }
  return {
    registryVersion: 1,
    sourceOfTruth: "pinned-local-exploitdb-tool-pack",
    toolId: nonEmpty(root.toolId, "Guided local ExploitDB tool"),
    readiness: literal(
      root.readiness,
      ["ready", "unavailable"],
      "Guided local ExploitDB readiness",
    ),
    readinessExplanation: nonEmpty(
      root.readinessExplanation,
      "Guided local ExploitDB readiness explanation",
    ),
    remediation: nonEmpty(
      root.remediation,
      "Guided local ExploitDB remediation",
    ),
    providerContact: false,
    targetContact: false,
    evidencePromotion: "none",
    requiresSingleStepAgent: true,
    queryKinds: [
      {
        id: "cve",
        label: nonEmpty(cve.label, "Guided local ExploitDB CVE label"),
        purpose: nonEmpty(cve.purpose, "Guided local ExploitDB CVE purpose"),
        expectedResult: nonEmpty(
          cve.expectedResult,
          "Guided local ExploitDB CVE expected result",
        ),
        example: cveExample,
      },
      {
        id: "technology",
        label: nonEmpty(
          technology.label,
          "Guided local ExploitDB technology label",
        ),
        purpose: nonEmpty(
          technology.purpose,
          "Guided local ExploitDB technology purpose",
        ),
        expectedResult: nonEmpty(
          technology.expectedResult,
          "Guided local ExploitDB technology expected result",
        ),
        example: technologyExample,
      },
    ],
  };
}

export function parseIntakeRegistrySnapshot(payload: unknown): IntakeRegistrySnapshot {
  const root = object(payload, "intake registry"); schema(root);
  const source = object(root.source, "intake registry source");
  const evidence = object(root.evidenceTypes, "evidence registry");
  const deliverables = object(root.deliverables, "deliverable registry");
  const templates = object(root.templates, "template registry");
  const safeStops = object(root.safeStops, "safe-stop registry");
  return {
    schemaVersion: "2.4",
    source: { status: literal(source.status, ["live", "unavailable"], "registry source status"), explanation: nonEmpty(source.explanation, "registry source explanation"), counts: Object.fromEntries(Object.entries(object(source.counts, "registry source counts")).map(([key, value]) => [key, number(value, `source count ${key}`)])) },
    fields: array(root.fields, "intake fields").map(parseField),
    actionClasses: parseActionRegistry(root.actionClasses),
    evidenceTypes: { types: recordOf(evidence.types, "evidence types", (value) => parseEvidenceType(value)) },
    deliverables: { deliverables: recordOf(deliverables.deliverables, "deliverables", (value) => parseDeliverable(value)) },
    templates: { templates: recordOf(templates.templates, "mission templates", (value) => parseTemplate(value)) },
    safeStops: { mandatory: array(safeStops.mandatory, "mandatory safe stops").map(parseSafeStop), optional: array(safeStops.optional, "optional safe stops").map(parseSafeStop) },
    budgets: recordOf(root.budgets, "budget presets", (value) => parseBudget(value)) as IntakeRegistrySnapshot["budgets"],
    guidedReconnaissance: parseGuidedReconnaissanceRegistry(root.guidedReconnaissance),
    guidedWindowsIdentity: parseGuidedWindowsIdentityRegistry(root.guidedWindowsIdentity),
    guidedLocalExploitIntelligence:
      parseGuidedLocalExploitIntelligenceRegistry(
        root.guidedLocalExploitIntelligence,
      ),
  };
}

function parseGuidedRequest(root: JsonRecord): GuidedMissionRequest {
  return {
    journey: "guided", launch: true, authorizationConfirmed: true,
    title: nonEmpty(root.title, "Guided title"), objective: nonEmpty(root.objective, "Guided objective"),
    ...(optionalString(root.target, "Guided target") ? { target: optionalString(root.target, "Guided target") } : {}),
    ...(optionalString(root.engagementId, "Guided engagement") ? { engagementId: optionalString(root.engagementId, "Guided engagement") } : {}),
    explanationDepth: literal(root.explanationDepth, ["concise", "balanced", "deep"], "Guided explanation depth"),
    executionPreference: literal(root.executionPreference, ["manual", "single_step_agent"], "Guided execution preference"),
    evidenceExpectations: stringList(root.evidenceExpectations, "Guided evidence expectations"),
    ...(root.guidedReconnaissance === undefined ? {} : {
      guidedReconnaissance: parseGuidedReconnaissance(root.guidedReconnaissance),
    }),
    ...(root.guidedWindowsIdentity === undefined ? {} : {
      guidedWindowsIdentity: parseGuidedWindowsIdentity(root.guidedWindowsIdentity),
    }),
    ...(root.guidedLocalExploitIntelligence === undefined ? {} : {
      guidedLocalExploitIntelligence:
        parseGuidedLocalExploitIntelligence(
          root.guidedLocalExploitIntelligence,
        ),
    }),
  };
}

function parseAutonomousRequest(root: JsonRecord): AutonomousMissionRequest {
  const authorization = object(root.authorization, "Autonomous authorization");
  const contract = object(root.contract, "Autonomous contract");
  const tokenBudget = contract.tokenBudget === undefined ? undefined : number(contract.tokenBudget, "token budget");
  const costBudget = contract.costBudget === undefined ? undefined : number(contract.costBudget, "cost budget");
  const agentModelAssignments = array(
    contract.agentModelAssignments ?? [],
    "agent model assignments",
  ).map((value, index) => {
    const assignment = object(value, `agent model assignment ${index + 1}`);
    return {
      agentId: nonEmpty(assignment.agentId, "agent model assignment agent ID"),
      primaryConfigurationId: nonEmpty(
        assignment.primaryConfigurationId,
        "agent model assignment primary configuration ID",
      ),
      fallbackConfigurationId: assignment.fallbackConfigurationId === null
        ? null
        : nonEmpty(
            assignment.fallbackConfigurationId,
            "agent model assignment fallback configuration ID",
          ),
    };
  });
  return {
    journey: "autonomous", launch: true, title: nonEmpty(root.title, "Autonomous title"), objective: nonEmpty(root.objective, "Autonomous objective"), successCriteria: stringList(root.successCriteria, "Autonomous success criteria"),
    authorization: {
      ...(optionalString(authorization.engagementId, "engagement ID") ? { engagementId: optionalString(authorization.engagementId, "engagement ID") } : {}),
      ...(authorization.environmentClassification === undefined ? {} : {
        environmentClassification: literal(
          authorization.environmentClassification,
          ["client_or_public", "internal", "htb", "ctf", "local_disposable_lab"],
          "environment classification",
        ),
      }),
      allowedTargets: stringList(authorization.allowedTargets, "allowed targets"), prohibitedTargets: stringList(authorization.prohibitedTargets, "prohibited targets"), authorizationConfirmed: boolean(authorization.authorizationConfirmed, "authorization acknowledgement"),
      ...(optionalString(authorization.timeWindow, "time window") ? { timeWindow: optionalString(authorization.timeWindow, "time window") } : {}),
      ...(optionalString(authorization.dataHandling, "data handling") ? { dataHandling: optionalString(authorization.dataHandling, "data handling") } : {}),
    },
    contract: {
      ...(contract.outcomeProfile === undefined ? {} : {
        outcomeProfile: literal(
          contract.outcomeProfile,
          ["assessment", "complete_engagement"],
          "Autonomous outcome profile",
        ),
      }),
      allowedActionClasses: stringList(contract.allowedActionClasses, "allowed action classes"), prohibitedActionClasses: stringList(contract.prohibitedActionClasses, "prohibited action classes"), destructivePolicy: literal(contract.destructivePolicy, ["prohibited", "validate_without_executing", "bounded_lab_only"], "destructive policy"), boundedDestructiveTargets: contract.boundedDestructiveTargets === undefined ? [] : stringList(contract.boundedDestructiveTargets, "bounded destructive targets"), evidenceRequirements: stringList(contract.evidenceRequirements, "evidence requirements"),
      timeBudgetMinutes: number(contract.timeBudgetMinutes, "time budget"), ...(tokenBudget === undefined ? {} : { tokenBudget }), ...(costBudget === undefined ? {} : { costBudget }), retryBudget: number(contract.retryBudget, "retry budget"), replanBudget: number(contract.replanBudget, "replan budget"), concurrencyLimit: number(contract.concurrencyLimit, "concurrency"), evidenceStorageBudgetBytes: number(contract.evidenceStorageBudgetBytes, "evidence storage"), artifactStorageBudgetBytes: number(contract.artifactStorageBudgetBytes, "artifact storage"),
      notificationPolicy: literal(contract.notificationPolicy, ["in_app_only"], "notification policy"), reportingFormat: literal(contract.reportingFormat, ["ti_scale_json"], "reporting format"), dataHandlingPolicy: literal(contract.dataHandlingPolicy, ["local_private"], "data handling policy"), retentionPolicy: literal(contract.retentionPolicy, ["operator_managed"], "retention policy"), providerPolicy: literal(contract.providerPolicy, ["automatic_enforcing_only"], "provider policy"), toolPolicy: literal(contract.toolPolicy, ["contract_allowlist"], "tool policy"), specialistAgentIds: stringList(contract.specialistAgentIds, "specialist agents"), agentModelAssignments, memoryScopes: stringList(contract.memoryScopes, "memory scopes"), contextNodeIds: stringList(contract.contextNodeIds, "context nodes"), safeStopConditions: stringList(contract.safeStopConditions, "safe stops"), deliverables: stringList(contract.deliverables, "deliverables"),
      planningSelection: parseAutonomousPlanningSelection(
        contract.planningSelection,
        "Autonomous planning selection",
      ),
    },
  };
}

function parseMissionRequest(value: unknown): MissionCreateRequest {
  const root = object(value, "resolved mission request");
  if (root.journey === "guided") return parseGuidedRequest(root);
  if (root.journey === "autonomous") return parseAutonomousRequest(root);
  throw new Error("resolved journey is invalid");
}

export function parseResolvedMissionIntake(payload: unknown): ResolvedMissionIntake {
  const root = object(payload, "resolved mission intake"); schema(root);
  const template = object(root.template, "resolved template");
  const autonomousOutcome = root.autonomousOutcome === undefined
    ? undefined
    : object(root.autonomousOutcome, "Autonomous outcome");
  return {
    schemaVersion: "2.4", request: parseMissionRequest(root.request),
    ...(autonomousOutcome ? {
      autonomousOutcome: {
        id: literal(
          autonomousOutcome.id,
          ["assessment", "complete_engagement"],
          "Autonomous outcome ID",
        ),
        label: nonEmpty(autonomousOutcome.label, "Autonomous outcome label"),
        concisePromise: nonEmpty(
          autonomousOutcome.concisePromise,
          "Autonomous outcome promise",
        ),
        completionMeaning: nonEmpty(
          autonomousOutcome.completionMeaning,
          "Autonomous outcome completion meaning",
        ),
        requiredTerminalSuccessCriteria: stringList(
          autonomousOutcome.requiredTerminalSuccessCriteria,
          "Autonomous terminal success criteria",
        ),
        requiredActionClassIds: stringList(
          autonomousOutcome.requiredActionClassIds,
          "Autonomous terminal action classes",
        ),
      },
    } : {}),
    normalizedTargets: array(root.normalizedTargets, "normalized targets").map((value) => {
      const item = object(value, "normalized target");
      return { id: nonEmpty(item.id, "target id"), value: nonEmpty(item.value, "target value"), type: literal(item.type, ["host", "cidr", "url", "domain", "cloud_account", "scope_file", "engagement", "lab_environment"], "target type"), ...(item.excluded === true ? { excluded: true } : {}) };
    }),
    template: { id: literal(template.id, TEMPLATE_IDS, "resolved template id"), version: number(template.version, "resolved template version") },
    policyMatrix: parseActionRegistry(root.policyMatrix), evidenceTypeIds: stringList(root.evidenceTypeIds, "resolved evidence"), deliverableIds: stringList(root.deliverableIds, "resolved deliverables"), mandatorySafeStopIds: stringList(root.mandatorySafeStopIds, "mandatory safe stops"), optionalSafeStopIds: stringList(root.optionalSafeStopIds, "optional safe stops"), budget: parseBudget(root.budget), inferredFields: stringList(root.inferredFields, "inferred fields"), limitations: stringList(root.limitations, "intake limitations"),
  };
}

export type { ActionPolicyState, BudgetPresetId, DestructiveActionPolicy, MissionIntakeTargetInput, MissionTemplateId };
