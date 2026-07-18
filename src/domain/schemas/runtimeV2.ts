import type { RunStatus } from "../types/commandOs";
import type { DecisionMutationResult, DecisionsSnapshot, GuidedDecision, MissionRuntimeSnapshot, PlannedActionKind, PlanStep, PlansSnapshot, RunPage, RunPlan, RunSnapshot, RuntimeCheckpoint, RuntimeMission, RuntimeRun } from "../types/runtimeV2";
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
export function parseRunSnapshot(payload: unknown): RunSnapshot { const root = object(payload, "run snapshot"); schema(root); return { schemaVersion: "2.4", run: parseRuntimeRun(root.run), latestCheckpoint: root.latestCheckpoint === null ? null : parseRuntimeCheckpoint(root.latestCheckpoint) }; }
export function parseRunPage(payload: unknown): RunPage { const root = object(payload, "run page"); schema(root); return { schemaVersion: "2.4", items: array(root.items, "run page items").map(parseRuntimeRun) }; }

function parseStep(value: unknown): PlanStep { const item = object(value, "plan step"); const action = object(item.action, "plan step action"); return { id: nonEmpty(item.id, "step.id"), ordinal: number(item.ordinal, "ordinal"), phase: nonEmpty(item.phase, "phase"), title: nonEmpty(item.title, "title"), objective: string(item.objective, "objective"), status: nonEmpty(item.status, "status"), assignedAgentId: string(item.assignedAgentId, "assignedAgentId"), riskClass: string(item.riskClass, "riskClass"), successCriteria: stringList(item.successCriteria, "successCriteria"), dependencyStepIds: stringList(item.dependencyStepIds, "dependencyStepIds"), action: { actionType: nonEmpty(action.actionType, "actionType"), actionClass: nonEmpty(action.actionClass, "actionClass"), target: string(action.target, "target"), arguments: object(action.arguments, "action.arguments"), intentSummary: string(action.intentSummary, "intentSummary"), kind: actionKind(action.kind), idempotent: boolean(action.idempotent, "idempotent"), destructive: boolean(action.destructive, "destructive") }, explanation: string(item.explanation, "explanation"), rationale: string(item.rationale, "rationale"), reversibility: string(item.reversibility, "reversibility") }; }
function parsePlan(value: unknown): RunPlan { const item = object(value, "plan"); return { id: nonEmpty(item.id, "plan.id"), runId: nonEmpty(item.runId, "runId"), version: number(item.version, "version"), status: nonEmpty(item.status, "status"), strategySummary: string(item.strategySummary, "strategySummary"), rationaleSummary: nullableString(item.rationaleSummary, "rationaleSummary"), createdAt: nonEmpty(item.createdAt, "createdAt"), activatedAt: nullableString(item.activatedAt, "activatedAt"), steps: array(item.steps, "steps").map(parseStep) }; }
export function parsePlans(payload: unknown): PlansSnapshot { const root = object(payload, "plans"); schema(root); return { schemaVersion: "2.4", items: array(root.items, "plans.items").map(parsePlan) }; }

function parseDecision(value: unknown): GuidedDecision { const item = object(value, "guided decision"); const allowed = new Set(["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"]); const decisionStatus = nonEmpty(item.status, "decision.status"); if (!allowed.has(decisionStatus)) throw new Error("decision status invalid"); return { id: nonEmpty(item.id, "decision.id"), missionId: nonEmpty(item.missionId, "missionId"), runId: nonEmpty(item.runId, "runId"), stepId: nonEmpty(item.stepId, "stepId"), status: decisionStatus as GuidedDecision["status"], actionFingerprint: nonEmpty(item.actionFingerprint, "actionFingerprint"), requestedParameters: item.requestedParameters ?? {}, rationale: string(item.rationale, "rationale"), riskClass: nonEmpty(item.riskClass, "riskClass"), reversibility: string(item.reversibility, "reversibility"), expiresAt: nonEmpty(item.expiresAt, "expiresAt"), createdAt: nonEmpty(item.createdAt, "createdAt") }; }
export function parseDecisions(payload: unknown): DecisionsSnapshot { const root = object(payload, "decisions"); schema(root); return { schemaVersion: "2.4", items: array(root.items, "decisions.items").map(parseDecision) }; }

export function parseRunMutation(payload: unknown): RunSnapshot { return parseRunSnapshot(payload); }
export function parseDecisionMutation(payload: unknown): DecisionMutationResult { const root = object(payload, "decision mutation"); schema(root); return { schemaVersion: "2.4", decisionId: nonEmpty(root.decisionId, "decisionId"), status: nonEmpty(root.status, "status"), ...(root.action === undefined ? {} : { action: root.action }), ...(root.receipt === undefined ? {} : { receipt: root.receipt }), ...(root.run === undefined ? {} : { run: parseRuntimeRun(root.run) }) }; }
