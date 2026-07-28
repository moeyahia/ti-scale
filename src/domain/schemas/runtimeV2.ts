import type { RunStatus } from "../types/commandOs";
import type {
  AutonomousActivationBinding,
  AutonomousActivationPlanningSelection,
  AutonomousActivationReceipt,
  AutonomousActivationReceiptDetail,
  AutonomousActivationReceiptHistory,
  AutonomousActivationReceiptItem,
  AutonomousActivationReceiptSummary,
  DecisionMutationResult,
  DecisionsSnapshot,
  GuidedDecision,
  MissionRuntimeSnapshot,
  PlannedActionKind,
  PlanStep,
  PlansSnapshot,
  RunPage,
  RunPlan,
  RunSnapshot,
  RuntimeCheckpoint,
  RuntimeMission,
  RuntimeRun,
} from "../types/runtimeV2";
import { array, boolean, nonEmpty, nullableString, number, object, schema, string, stringList } from "./common";

const RUN_STATES = new Set<RunStatus>(["queued", "planning", "awaiting_contract_confirmation", "running", "waiting_guided_decision", "blocked", "recovering", "completed", "failed", "cancelled"]);
function journey(value: unknown): "autonomous" | "guided" { if (value === "autonomous" || value === "guided") return value; throw new Error("journey is invalid"); }
function status(value: unknown): RunStatus { const candidate = nonEmpty(value, "run.status") as RunStatus; if (!RUN_STATES.has(candidate)) throw new Error("run status is invalid"); return candidate; }
const ACTION_KINDS = new Set<PlannedActionKind>(["tool", "provider_turn", "replan", "delegation", "manual"]);
function actionKind(value: unknown): PlannedActionKind { const candidate = nonEmpty(value, "action.kind") as PlannedActionKind; if (!ACTION_KINDS.has(candidate)) throw new Error("action kind is invalid"); return candidate; }

export function parseRuntimeRun(value: unknown): RuntimeRun {
  const item = object(value, "runtime run"); return { id: nonEmpty(item.id, "run.id"), missionId: nonEmpty(item.missionId, "missionId"), missionName: nonEmpty(item.missionName, "missionName"), objective: string(item.objective, "objective"), journey: journey(item.journey), status: status(item.status), statusReason: nullableString(item.statusReason, "statusReason"), progress: Math.max(0, Math.min(1, number(item.progress, "progress"))), nextAction: nullableString(item.nextAction, "nextAction"), currentPlanId: nullableString(item.currentPlanId, "currentPlanId"), currentStepId: nullableString(item.currentStepId, "currentStepId"), currentOwnerId: nullableString(item.currentOwnerId, "currentOwnerId"), lastHeartbeatAt: nullableString(item.lastHeartbeatAt, "lastHeartbeatAt"), leaseExpiresAt: nullableString(item.leaseExpiresAt, "leaseExpiresAt"), startedAt: nullableString(item.startedAt, "startedAt"), endedAt: nullableString(item.endedAt, "endedAt"), createdAt: nonEmpty(item.createdAt, "createdAt"), updatedAt: nonEmpty(item.updatedAt, "updatedAt"), version: number(item.version, "version") };
}

function parseMission(value: unknown): RuntimeMission { const item = object(value, "runtime mission"); return { id: nonEmpty(item.id, "mission.id"), name: nonEmpty(item.name, "mission.name"), objective: string(item.objective, "mission.objective"), journey: journey(item.journey), engagementId: nullableString(item.engagementId, "engagementId"), authorizationStatus: nonEmpty(item.authorizationStatus, "authorizationStatus"), allowedTargets: stringList(item.allowedTargets, "allowedTargets"), prohibitedTargets: stringList(item.prohibitedTargets, "prohibitedTargets"), successCriteria: stringList(item.successCriteria, "successCriteria"), memoryPolicy: object(item.memoryPolicy, "memoryPolicy") }; }

export function parseMissionRuntime(payload: unknown): MissionRuntimeSnapshot { const root = object(payload, "mission runtime"); schema(root); return { schemaVersion: "2.4", mission: parseMission(root.mission), runs: array(root.runs, "runs").map(parseRuntimeRun) }; }
function parseRuntimeCheckpoint(value: unknown): RuntimeCheckpoint {
  const item = object(value, "latestCheckpoint");
  const state = object(item.state, "latestCheckpoint.state");
  const stateRun = object(state.run, "latestCheckpoint.state.run");
  const checkpointHash = nonEmpty(item.stateHash, "latestCheckpoint.stateHash");
  if (!/^[a-f0-9]{64}$/u.test(checkpointHash)) throw new Error("latestCheckpoint.stateHash must be a SHA-256 digest");
  const checkpointJourney = journey(item.journey);
  const eventSequence = number(item.eventSequence, "latestCheckpoint.eventSequence");
  const stateVersion = number(stateRun.stateVersion, "latestCheckpoint.state.run.stateVersion");
  const lastEventSequence = number(state.lastEventSequence, "latestCheckpoint.state.lastEventSequence");
  if (
    !Number.isSafeInteger(eventSequence) || eventSequence < 0 ||
    !Number.isSafeInteger(stateVersion) || stateVersion < 1 ||
    !Number.isSafeInteger(lastEventSequence) || lastEventSequence < 0
  ) throw new Error("latestCheckpoint contains an invalid integer boundary");
  return {
    id: nonEmpty(item.id, "latestCheckpoint.id"),
    journey: checkpointJourney,
    eventSequence,
    stateHash: checkpointHash,
    createdAt: nonEmpty(item.createdAt, "latestCheckpoint.createdAt"),
    state: {
      run: {
        id: nonEmpty(stateRun.id, "latestCheckpoint.state.run.id"),
        state: status(stateRun.state),
        stateVersion,
        leaseOwner: nullableString(stateRun.leaseOwner, "latestCheckpoint.state.run.leaseOwner"),
        leaseExpiresAt: nullableString(stateRun.leaseExpiresAt, "latestCheckpoint.state.run.leaseExpiresAt"),
      },
      inFlightActions: array(state.inFlightActions, "latestCheckpoint.state.inFlightActions").map((value, index) => {
        const action = object(value, `latestCheckpoint.state.inFlightActions[${index}]`);
        return {
          id: nonEmpty(action.id, `latestCheckpoint.state.inFlightActions[${index}].id`),
          status: nonEmpty(action.status, `latestCheckpoint.state.inFlightActions[${index}].status`),
          idempotent: boolean(action.idempotent, `latestCheckpoint.state.inFlightActions[${index}].idempotent`),
          destructive: boolean(action.destructive, `latestCheckpoint.state.inFlightActions[${index}].destructive`),
        };
      }),
      lastEventSequence,
    },
  };
}
const SHA256 = /^[a-f0-9]{64}$/u;
function sha256(value: unknown, label: string): string {
  const result = nonEmpty(value, label);
  if (!SHA256.test(result)) throw new Error(`${label} must be a SHA-256 digest`);
  return result;
}
function safeInteger(value: unknown, label: string, minimum = 0): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < minimum) {
    throw new Error(`${label} must be an integer of at least ${minimum}`);
  }
  return result;
}
function parseActivationIntegrity(value: unknown): AutonomousActivationReceiptSummary["integrity"] {
  const item = object(value, "activation receipt integrity");
  if (
    item.status !== "verified"
    && item.status !== "expired"
    && item.status !== "integrity_failure"
  ) throw new Error("activation receipt integrity status is invalid");
  return {
    status: item.status,
    code: nullableString(item.code, "activation receipt integrity code"),
    verifiedAt: nonEmpty(item.verifiedAt, "activation receipt verifiedAt"),
    humanMessage: nonEmpty(item.humanMessage, "activation receipt integrity message"),
    remediation: nullableString(item.remediation, "activation receipt remediation"),
  };
}
export function parseAutonomousActivationReceiptSummary(
  value: unknown,
): AutonomousActivationReceiptSummary {
  const item = object(value, "Autonomous activation receipt summary");
  if (
    item.planningRoute !== "local_deterministic"
    && item.planningRoute !== "provider_advisory"
  ) throw new Error("activation receipt planning route is invalid");
  return {
    id: nonEmpty(item.id, "activation receipt id"),
    runId: nonEmpty(item.runId, "activation receipt runId"),
    generation: safeInteger(item.generation, "activation receipt generation", 1),
    issuedAt: nonEmpty(item.issuedAt, "activation receipt issuedAt"),
    expiresAt: nonEmpty(item.expiresAt, "activation receipt expiresAt"),
    planningRoute: item.planningRoute,
    plannerId: nonEmpty(item.plannerId, "activation receipt plannerId"),
    planningModelAssignmentId: nullableString(
      item.planningModelAssignmentId,
      "activation receipt planningModelAssignmentId",
    ),
    selectedActionClassCount: safeInteger(
      item.selectedActionClassCount,
      "activation receipt selectedActionClassCount",
    ),
    activatedActionClassCount: safeInteger(
      item.activatedActionClassCount,
      "activation receipt activatedActionClassCount",
    ),
    modelRouteCount: safeInteger(item.modelRouteCount, "activation receipt modelRouteCount"),
    toolRouteCount: safeInteger(item.toolRouteCount, "activation receipt toolRouteCount"),
    bindingCount: safeInteger(item.bindingCount, "activation receipt bindingCount", 1),
    runtimeGenerationHash: sha256(
      item.runtimeGenerationHash,
      "activation receipt runtimeGenerationHash",
    ),
    brainContextPackId: nonEmpty(
      item.brainContextPackId,
      "activation receipt brainContextPackId",
    ),
    receiptHash: sha256(item.receiptHash, "activation receipt receiptHash"),
    integrity: parseActivationIntegrity(item.integrity),
  };
}
function parseActivationPlanningSelection(
  value: unknown,
): AutonomousActivationPlanningSelection {
  const item = object(value, "activation planning selection");
  if (item.route === "local_deterministic") {
    if (
      item.enforcementMode !== "local_policy"
      || item.disclosureClass !== "local_only"
      || item.executionAuthority !== "none"
    ) throw new Error("local activation planning selection is invalid");
    return {
      route: "local_deterministic",
      plannerId: nonEmpty(item.plannerId, "activation plannerId"),
      enforcementMode: "local_policy",
      disclosureClass: "local_only",
      executionAuthority: "none",
    };
  }
  if (
    item.route !== "provider_advisory"
    || item.enforcementMode !== "advisor_only"
    || item.executionAuthority !== "none"
  ) throw new Error("provider activation planning selection is invalid");
  return {
    route: "provider_advisory",
    agentId: nonEmpty(item.agentId, "activation planning agentId"),
    primaryConfigurationId: nonEmpty(
      item.primaryConfigurationId,
      "activation planning primaryConfigurationId",
    ),
    fallbackConfigurationId: nullableString(
      item.fallbackConfigurationId,
      "activation planning fallbackConfigurationId",
    ),
    enforcementMode: "advisor_only",
    disclosureClass: nonEmpty(
      item.disclosureClass,
      "activation planning disclosureClass",
    ),
    executionAuthority: "none",
  };
}
function parseActivationItem(value: unknown): AutonomousActivationReceiptItem {
  const item = object(value, "activation receipt route");
  if (item.toolBindingKind !== "local" && item.toolBindingKind !== "mcp") {
    throw new Error("activation tool binding kind is invalid");
  }
  return {
    actionClassId: nonEmpty(item.actionClassId, "activation actionClassId"),
    agentId: nonEmpty(item.agentId, "activation agentId"),
    executionModelAssignmentId: nonEmpty(
      item.executionModelAssignmentId,
      "activation executionModelAssignmentId",
    ),
    executionPrimaryConfigurationId: nonEmpty(
      item.executionPrimaryConfigurationId,
      "activation executionPrimaryConfigurationId",
    ),
    executionFallbackConfigurationId: nullableString(
      item.executionFallbackConfigurationId,
      "activation executionFallbackConfigurationId",
    ),
    toolId: nonEmpty(item.toolId, "activation toolId"),
    toolBindingKind: item.toolBindingKind,
    mcpServerId: nullableString(item.mcpServerId, "activation mcpServerId"),
    toolActivationReceiptId: nonEmpty(
      item.toolActivationReceiptId,
      "activation toolActivationReceiptId",
    ),
    toolActivationReceiptHash: sha256(
      item.toolActivationReceiptHash,
      "activation toolActivationReceiptHash",
    ),
    toolManifestHash: sha256(item.toolManifestHash, "activation toolManifestHash"),
    evidenceTypeIds: stringList(item.evidenceTypeIds, "activation evidenceTypeIds"),
    evidenceProducerIds: stringList(
      item.evidenceProducerIds,
      "activation evidenceProducerIds",
    ),
    routeExpiresAt: nonEmpty(item.routeExpiresAt, "activation routeExpiresAt"),
    routeHash: sha256(item.routeHash, "activation routeHash"),
    createdAt: nonEmpty(item.createdAt, "activation route createdAt"),
  };
}
function parseActivationBinding(value: unknown): AutonomousActivationBinding {
  const item = object(value, "activation receipt binding");
  const allowed = new Set<AutonomousActivationBinding["bindingType"]>([
    "launch",
    "planning",
    "plan_version",
    "dispatch",
    "resume",
    "restart_recovery",
  ]);
  const bindingType = nonEmpty(
    item.bindingType,
    "activation bindingType",
  ) as AutonomousActivationBinding["bindingType"];
  if (!allowed.has(bindingType)) throw new Error("activation binding type is invalid");
  return {
    id: nonEmpty(item.id, "activation binding id"),
    receiptId: nonEmpty(item.receiptId, "activation binding receiptId"),
    sequence: safeInteger(item.sequence, "activation binding sequence", 1),
    bindingType,
    subjectId: nonEmpty(item.subjectId, "activation binding subjectId"),
    subjectDigest: sha256(item.subjectDigest, "activation binding subjectDigest"),
    runtimeGenerationHash: sha256(
      item.runtimeGenerationHash,
      "activation binding runtimeGenerationHash",
    ),
    planId: nullableString(item.planId, "activation binding planId"),
    stepId: nullableString(item.stepId, "activation binding stepId"),
    actionId: nullableString(item.actionId, "activation binding actionId"),
    contextPackId: nullableString(item.contextPackId, "activation binding contextPackId"),
    providerTurnId: nullableString(
      item.providerTurnId,
      "activation binding providerTurnId",
    ),
    previousBindingHash: item.previousBindingHash === null
      ? null
      : sha256(item.previousBindingHash, "activation binding previousBindingHash"),
    boundBy: nonEmpty(item.boundBy, "activation binding boundBy"),
    boundAt: nonEmpty(item.boundAt, "activation binding boundAt"),
    bindingHash: sha256(item.bindingHash, "activation binding hash"),
  };
}
function parseActivationReceipt(value: unknown): AutonomousActivationReceipt {
  const item = object(value, "Autonomous activation receipt");
  if (item.schemaVersion !== "2.4") {
    throw new Error("unsupported Autonomous activation receipt schema version");
  }
  const planning = object(item.planning, "activation planning");
  if (planning.route !== "local_deterministic" && planning.route !== "provider_advisory") {
    throw new Error("activation planning route is invalid");
  }
  const selection = parseActivationPlanningSelection(planning.selection);
  if (selection.route !== planning.route) throw new Error("activation planning route drift");
  return {
    id: nonEmpty(item.id, "activation receipt id"),
    schemaVersion: "2.4",
    missionId: nonEmpty(item.missionId, "activation receipt missionId"),
    runId: nonEmpty(item.runId, "activation receipt runId"),
    contractId: nonEmpty(item.contractId, "activation receipt contractId"),
    generation: safeInteger(item.generation, "activation receipt generation", 1),
    contractVersion: safeInteger(
      item.contractVersion,
      "activation receipt contractVersion",
      1,
    ),
    contractHash: sha256(item.contractHash, "activation receipt contractHash"),
    runtimeGenerationHash: sha256(
      item.runtimeGenerationHash,
      "activation receipt runtimeGenerationHash",
    ),
    modelAssignmentSetHash: sha256(
      item.modelAssignmentSetHash,
      "activation receipt modelAssignmentSetHash",
    ),
    evidencePolicyHash: sha256(
      item.evidencePolicyHash,
      "activation receipt evidencePolicyHash",
    ),
    brainContextPackId: nonEmpty(
      item.brainContextPackId,
      "activation receipt brainContextPackId",
    ),
    brainContextPackHash: sha256(
      item.brainContextPackHash,
      "activation receipt brainContextPackHash",
    ),
    planning: {
      route: planning.route,
      selection,
      selectionHash: sha256(
        planning.selectionHash,
        "activation planning selectionHash",
      ),
      plannerId: nonEmpty(planning.plannerId, "activation planning plannerId"),
      modelAssignmentId: nullableString(
        planning.modelAssignmentId,
        "activation planning modelAssignmentId",
      ),
      primaryConfigurationId: nullableString(
        planning.primaryConfigurationId,
        "activation planning primaryConfigurationId",
      ),
      fallbackConfigurationId: nullableString(
        planning.fallbackConfigurationId,
        "activation planning fallbackConfigurationId",
      ),
      primaryConfigurationHash: planning.primaryConfigurationHash === null
        ? null
        : sha256(
            planning.primaryConfigurationHash,
            "activation planning primaryConfigurationHash",
          ),
      fallbackConfigurationHash: planning.fallbackConfigurationHash === null
        ? null
        : sha256(
            planning.fallbackConfigurationHash,
            "activation planning fallbackConfigurationHash",
          ),
    },
    selectedActionClassIds: stringList(
      item.selectedActionClassIds,
      "activation selectedActionClassIds",
    ),
    selectedActionClassCount: safeInteger(
      item.selectedActionClassCount,
      "activation selectedActionClassCount",
    ),
    activatedActionClassCount: safeInteger(
      item.activatedActionClassCount,
      "activation activatedActionClassCount",
    ),
    routeSetHash: sha256(item.routeSetHash, "activation routeSetHash"),
    issuedBy: nonEmpty(item.issuedBy, "activation issuedBy"),
    issuedAt: nonEmpty(item.issuedAt, "activation issuedAt"),
    expiresAt: nonEmpty(item.expiresAt, "activation expiresAt"),
    receiptHash: sha256(item.receiptHash, "activation receiptHash"),
    items: array(item.items, "activation items").map(parseActivationItem),
    bindings: array(item.bindings, "activation bindings").map(parseActivationBinding),
  };
}
export function parseAutonomousActivationReceiptHistory(
  payload: unknown,
): AutonomousActivationReceiptHistory {
  const root = object(payload, "Autonomous activation receipt history");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "activation receipt history items")
      .map(parseAutonomousActivationReceiptSummary),
  };
}
export function parseAutonomousActivationReceiptDetail(
  payload: unknown,
): AutonomousActivationReceiptDetail {
  const root = object(payload, "Autonomous activation receipt detail");
  schema(root);
  const summary = parseAutonomousActivationReceiptSummary(root.summary);
  const receipt = parseActivationReceipt(root.receipt);
  if (summary.id !== receipt.id || summary.runId !== receipt.runId) {
    throw new Error("activation receipt detail lineage is invalid");
  }
  return { schemaVersion: "2.4", summary, receipt };
}
export function parseRunSnapshot(payload: unknown): RunSnapshot {
  const root = object(payload, "run snapshot");
  schema(root);
  return {
    schemaVersion: "2.4",
    run: parseRuntimeRun(root.run),
    latestCheckpoint: root.latestCheckpoint === null
      ? null
      : parseRuntimeCheckpoint(root.latestCheckpoint),
    currentAutonomousActivationReceipt:
      root.currentAutonomousActivationReceipt === null
      || root.currentAutonomousActivationReceipt === undefined
        ? null
        : parseAutonomousActivationReceiptSummary(
            root.currentAutonomousActivationReceipt,
          ),
  };
}
export function parseRunPage(payload: unknown): RunPage { const root = object(payload, "run page"); schema(root); if (!("nextCursor" in root)) throw new Error("run page nextCursor is required"); return { schemaVersion: "2.4", items: array(root.items, "run page items").map(parseRuntimeRun), nextCursor: nullableString(root.nextCursor, "run page nextCursor") }; }

function parseStep(value: unknown): PlanStep { const item = object(value, "plan step"); const action = object(item.action, "plan step action"); return { id: nonEmpty(item.id, "step.id"), ordinal: number(item.ordinal, "ordinal"), phase: nonEmpty(item.phase, "phase"), title: nonEmpty(item.title, "title"), objective: string(item.objective, "objective"), status: nonEmpty(item.status, "status"), assignedAgentId: string(item.assignedAgentId, "assignedAgentId"), riskClass: string(item.riskClass, "riskClass"), successCriteria: stringList(item.successCriteria, "successCriteria"), dependencyStepIds: stringList(item.dependencyStepIds, "dependencyStepIds"), action: { actionType: nonEmpty(action.actionType, "actionType"), actionClass: nonEmpty(action.actionClass, "actionClass"), target: string(action.target, "target"), arguments: object(action.arguments, "action.arguments"), intentSummary: string(action.intentSummary, "intentSummary"), kind: actionKind(action.kind), idempotent: boolean(action.idempotent, "idempotent"), destructive: boolean(action.destructive, "destructive") }, explanation: string(item.explanation, "explanation"), rationale: string(item.rationale, "rationale"), reversibility: string(item.reversibility, "reversibility") }; }
function parsePlan(value: unknown): RunPlan { const item = object(value, "plan"); return { id: nonEmpty(item.id, "plan.id"), runId: nonEmpty(item.runId, "runId"), version: number(item.version, "version"), status: nonEmpty(item.status, "status"), strategySummary: string(item.strategySummary, "strategySummary"), rationaleSummary: nullableString(item.rationaleSummary, "rationaleSummary"), createdAt: nonEmpty(item.createdAt, "createdAt"), activatedAt: nullableString(item.activatedAt, "activatedAt"), steps: array(item.steps, "steps").map(parseStep) }; }
export function parsePlans(payload: unknown): PlansSnapshot { const root = object(payload, "plans"); schema(root); return { schemaVersion: "2.4", items: array(root.items, "plans.items").map(parsePlan) }; }

function parseDecision(value: unknown): GuidedDecision { const item = object(value, "guided decision"); const allowed = new Set(["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"]); const decisionStatus = nonEmpty(item.status, "decision.status"); if (!allowed.has(decisionStatus)) throw new Error("decision status invalid"); return { id: nonEmpty(item.id, "decision.id"), missionId: nonEmpty(item.missionId, "missionId"), runId: nonEmpty(item.runId, "runId"), stepId: nonEmpty(item.stepId, "stepId"), status: decisionStatus as GuidedDecision["status"], actionFingerprint: nonEmpty(item.actionFingerprint, "actionFingerprint"), requestedParameters: item.requestedParameters ?? {}, rationale: string(item.rationale, "rationale"), riskClass: nonEmpty(item.riskClass, "riskClass"), reversibility: string(item.reversibility, "reversibility"), expiresAt: nonEmpty(item.expiresAt, "expiresAt"), createdAt: nonEmpty(item.createdAt, "createdAt") }; }
export function parseDecisions(payload: unknown): DecisionsSnapshot { const root = object(payload, "decisions"); schema(root); return { schemaVersion: "2.4", items: array(root.items, "decisions.items").map(parseDecision) }; }

export function parseRunMutation(payload: unknown): RunSnapshot { return parseRunSnapshot(payload); }
export function parseDecisionMutation(payload: unknown): DecisionMutationResult { const root = object(payload, "decision mutation"); schema(root); return { schemaVersion: "2.4", decisionId: nonEmpty(root.decisionId, "decisionId"), status: nonEmpty(root.status, "status"), ...(root.action === undefined ? {} : { action: root.action }), ...(root.receipt === undefined ? {} : { receipt: root.receipt }), ...(root.run === undefined ? {} : { run: parseRuntimeRun(root.run) }) }; }
