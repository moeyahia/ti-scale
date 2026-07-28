import { isIP } from "node:net";
import type { SqliteDatabase } from "../db";
import {
  ACTION_CLASS_DEFINITIONS,
  type ActionClassDefinition,
} from "../domain/action-class-registry";
import type { ActionClassId } from "../domain/catalog-ids";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { MemoryRepository, SecondBrainService } from "../memory";
import type { DurableAction } from "../orchestration";
import type { FleetAgentProjection } from "../app/RuntimeProjectionService";
import { MissionRuntimeEngine } from "./MissionRuntimeEngine";
import type {
  MissionCompletionEvaluation,
  MissionOutcomeEvaluatorInput,
  MissionOutcomeEvaluatorPort,
  MissionPlanDraft,
  MissionPlannerInput,
  MissionPlannerPort,
  MissionRuntimeOptions,
  ResultAwareExecutionPort,
} from "./types";
import { CommandRuntimeError } from "./types";

export const LOCAL_GUIDED_MANUAL_AGENT_ID = "ti-scale.local-guided-manual-planner";

const ACTION_CLASSES = new Map<ActionClassId, ActionClassDefinition>(
  ACTION_CLASS_DEFINITIONS.map((definition) => [definition.id, definition]),
);

type TargetKind = "url" | "domain" | "ip" | "cidr" | "cloud" | "environment";

interface TargetProfile {
  readonly kind: TargetKind;
  readonly actionClassId: ActionClassId;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly operatorProcedure: readonly string[];
  readonly expectedObservations: readonly string[];
}

interface PresentationDirective {
  readonly nodeId: string;
  readonly directive: "concise" | "technical_depth" | "step_by_step" | "evidence_first";
  readonly influence: string;
}

function runtimeError(
  code: string,
  humanMessage: string,
  remediation: string,
): CommandRuntimeError {
  return new CommandRuntimeError(503, code, humanMessage, {
    humanMessage,
    retryable: false,
    category: "policy_denied",
    remediation,
  });
}

function actionClass(id: ActionClassId): ActionClassDefinition {
  const definition = ACTION_CLASSES.get(id);
  if (!definition) throw new Error(`Canonical action class is missing: ${id}`);
  return definition;
}

function classifyTarget(target: string): TargetProfile {
  const normalized = target.trim();
  if (/^https?:\/\//iu.test(normalized)) {
    return {
      kind: "url",
      actionClassId: "web_crawling_page_capture",
      phase: "Web baseline",
      title: "Record the approved web service baseline",
      objective: `Confirm what the approved web address ${normalized} returns before choosing deeper tests.`,
      operatorProcedure: [
        "Open only the approved address using your normal browser or an authorized HTTP client.",
        "Record the status, page title, redirects, certificate details, and visible technology identifiers.",
        "Do not follow links or submit forms outside the approved target; stop if the address redirects out of scope.",
      ],
      expectedObservations: [
        "A reachable or unreachable result with the exact address and time",
        "HTTP status and redirect chain, if present",
        "Page title, certificate identity, and attributable server or framework indicators",
      ],
    };
  }
  if (/^(?:aws|azure|gcp|cloud|subscription|project|account):/iu.test(normalized)) {
    return {
      kind: "cloud",
      actionClassId: "cloud_container_kubernetes_assessment",
      phase: "Cloud scope baseline",
      title: "Record the approved cloud environment baseline",
      objective: `Confirm the identity and visible read-only inventory boundary for ${normalized}.`,
      operatorProcedure: [
        "Use the approved cloud console or read-only inventory command already authorized for this environment.",
        "Record the account, project, or subscription identity and the visible resource groups without changing resources.",
        "Stop if the active identity or tenant does not match the approved environment.",
      ],
      expectedObservations: [
        "Confirmed tenant, account, project, or subscription identity",
        "A read-only inventory summary or a precise access blocker",
        "The operator identity class used, without retaining credentials or tokens",
      ],
    };
  }
  const cidrMatch = normalized.match(/^(.+)\/(\d{1,3})$/u);
  if (cidrMatch && (isIP(cidrMatch[1] ?? "") === 4 || isIP(cidrMatch[1] ?? "") === 6)) {
    return {
      kind: "cidr",
      actionClassId: "active_host_discovery",
      phase: "Network baseline",
      title: "Record which approved systems are reachable",
      objective: `Establish a bounded reachability baseline for the approved range ${normalized}.`,
      operatorProcedure: [
        "Use one authorized host-discovery method against only the approved range.",
        "Retain the exact input range, time, method, and reachable or unreachable result.",
        "Do not enumerate services yet; this step only establishes which approved systems respond.",
      ],
      expectedObservations: [
        "Reachable approved addresses with acquisition time",
        "A precise no-response or route blocker when nothing responds",
        "The method and scope used so another reviewer can reproduce the result",
      ],
    };
  }
  if (isIP(normalized) !== 0) {
    return {
      kind: "ip",
      actionClassId: "active_host_discovery",
      phase: "Host baseline",
      title: "Confirm the approved host is reachable",
      objective: `Establish whether the approved host ${normalized} is reachable before service enumeration.`,
      operatorProcedure: [
        "Use one bounded, authorized reachability check against the exact approved address.",
        "Record the route, response or timeout, acquisition time, and method.",
        "Do not scan additional addresses or enumerate ports in this step.",
      ],
      expectedObservations: [
        "A reachable, unreachable, or filtered result",
        "The exact approved address, method, and time",
        "A route or dependency blocker when reachability cannot be tested",
      ],
    };
  }
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/iu.test(normalized)) {
    return {
      kind: "domain",
      actionClassId: "dns_domain_certificate_discovery",
      phase: "Domain baseline",
      title: "Record the approved domain identity",
      objective: `Confirm how ${normalized} resolves and which certificate identities are attributable to it.`,
      operatorProcedure: [
        "Resolve only the approved domain using an authorized DNS client.",
        "If TLS is available, record certificate subject, issuer, validity, and approved hostnames without submitting application data.",
        "Stop if resolution or a redirect points to an address that is explicitly out of scope.",
      ],
      expectedObservations: [
        "DNS records and resolution time",
        "Certificate identity and validity when available",
        "A precise resolution, certificate, or scope blocker when the baseline cannot be completed",
      ],
    };
  }
  return {
    kind: "environment",
    actionClassId: "passive_intelligence_osint",
    phase: "Environment baseline",
    title: "Confirm the approved environment identity",
    objective: `Record enough attributable information to identify ${normalized} without expanding its scope.`,
    operatorProcedure: [
      "Open the approved environment reference or scope document without contacting unlisted systems.",
      "Record the stable identifier, environment type, and any explicit boundaries that affect the next step.",
      "Stop and report a blocker if the reference cannot be resolved to an exact authorized target.",
    ],
    expectedObservations: [
      "A stable approved environment identifier",
      "Explicit scope boundaries or a precise ambiguity blocker",
      "Provenance showing where the environment identity came from",
    ],
  };
}

function presentationDirectives(input: MissionPlannerInput): readonly PresentationDirective[] {
  const directives: PresentationDirective[] = [];
  for (const item of input.brainContext.items) {
    if (item.nodeType !== "preference") continue;
    const text = `${item.title} ${item.summary}`.toLocaleLowerCase("en-US");
    const push = (
      directive: PresentationDirective["directive"],
      influence: string,
    ): void => {
      if (directives.some((existing) => existing.nodeId === item.nodeId && existing.directive === directive)) return;
      directives.push({ nodeId: item.nodeId, directive, influence });
    };
    if (/\b(concise|brief|compact|readable)\b/u.test(text)) {
      push("concise", "Kept the represented instructions compact while preserving technical terms and evidence boundaries.");
    }
    if (/\b(technical|detail|protocol|deep)\b/u.test(text)) {
      push("technical_depth", "Included protocol- and provenance-level observations without turning the step into raw tool jargon.");
    }
    if (/\b(step[ -]?by[ -]?step|one step|manual|paced)\b/u.test(text)) {
      push("step_by_step", "Presented one bounded operator action at a time and retained the decision checkpoint between steps.");
    }
    if (/\b(evidence|provenance|source|chain of custody)\b/u.test(text)) {
      push("evidence_first", "Made acquisition time, exact scope, method, and attributable evidence explicit in each step.");
    }
  }
  return directives;
}

function citedDirectives(directives: readonly PresentationDirective[]) {
  const byNode = new Map<string, string[]>();
  for (const directive of directives) {
    const influences = byNode.get(directive.nodeId) ?? [];
    influences.push(directive.influence);
    byNode.set(directive.nodeId, influences);
  }
  return [...byNode.entries()].map(([nodeId, influences]) => ({
    nodeId,
    influence: influences.join(" "),
  }));
}

/**
 * A deterministic Guided planner for deployments with no provider or tool
 * executor. It turns an allowed target into represented MANUAL work only. It
 * never opens a socket, starts a process, calls a provider, or dispatches a
 * tool. Sanitized Brain summaries may influence presentation only.
 */
export class LocalGuidedManualPlanner implements MissionPlannerPort {
  async plan(input: MissionPlannerInput, signal: AbortSignal): Promise<MissionPlanDraft> {
    if (signal.aborted) throw new DOMException("Guided planning was cancelled", "AbortError");
    if (input.mission.journey !== "guided" || input.run.journey !== "guided") {
      throw runtimeError(
        "local_guided_planner_autonomous_forbidden",
        "The local manual planner cannot create or execute an Autonomous plan.",
        "Configure an enforcing provider, specialist fleet, and tool boundary, or create a Guided mission.",
      );
    }
    const target = input.mission.allowedTargets[0]?.trim();
    if (!target) {
      throw new CommandRuntimeError(409, "guided_target_required", "Guided planning requires an allowed target", {
        humanMessage: "Add one exact authorized target before creating the first Guided step.",
        retryable: false,
        category: "scope_conflict",
        remediation: "Return to mission scope, add an approved target, and start a new run.",
      });
    }
    const profile = classifyTarget(target);
    const baselineClass = actionClass(profile.actionClassId);
    const directives = presentationDirectives(input);
    const detailNote = directives.some((item) => item.directive === "technical_depth")
      ? ` Technical focus: retain observable protocol, identity, version, route, or certificate facts only when the result actually contains them.`
      : "";
    const conciseNote = directives.some((item) => item.directive === "concise")
      ? " The card stays compact; technical detail belongs in the submitted result."
      : "";
    const evidenceNote = directives.some((item) => item.directive === "evidence_first")
      ? " Include the exact scope, acquisition time, method, and source so the observation can be reviewed later."
      : "";
    const recoveryNote = input.rejectionReason?.trim()
      ? " This replacement step documents the changed approach and must not repeat the rejected action or parameters."
      : "";

    return {
      strategySummary: `Use one represented manual checkpoint to establish an attributable ${profile.kind} baseline for ${target}.`,
      rationaleSummary: "No execution provider, semantic interpreter, or specialist tool boundary is available. The operator remains the only target-interacting actor; Ti-Scale refreshes Brain context and can retain bounded result text with hash/redaction metadata, but that ingestion alone cannot verify evidence or complete the step.",
      steps: [
        {
          phase: profile.phase,
          title: profile.title,
          objective: profile.objective,
          explanation: `${baselineClass.plainLanguageDescription} In this deployment Ti-Scale does not perform that interaction: the operator carries out the represented procedure and returns the result.${conciseNote}${detailNote}${recoveryNote}`,
          rationale: `This baseline reduces uncertainty before any deeper action is proposed. ${baselineClass.technicalDescription}${evidenceNote}`,
          successCriteria: [
            "The operator records a result for the exact approved target",
            "The result states the method, time, and whether the baseline succeeded or was blocked",
            "No target outside the normalized mission scope is contacted",
          ],
          dependencyOrdinals: [],
          assignedAgentId: LOCAL_GUIDED_MANUAL_AGENT_ID,
          riskClass: baselineClass.riskBand === "low" ? "low" : "medium",
          reversibility: "Ti-Scale performs no target interaction. The operator can stop before the procedure; any external traffic depends solely on the operator's chosen authorized method.",
          action: {
            actionType: "guided_manual_baseline",
            actionClass: baselineClass.id,
            target,
            arguments: {
              schemaVersion: "1",
              executionMode: "operator_manual_only",
              targetKind: profile.kind,
              exactTarget: target,
              operatorProcedure: [...profile.operatorProcedure],
              expectedObservations: [...profile.expectedObservations],
              evidenceTypeIds: [...baselineClass.defaultEvidenceTypeIds],
              noProviderCall: true,
              noToolDispatch: true,
            },
            intentSummary: `Operator records one bounded ${baselineClass.label.toLocaleLowerCase("en-US")} result for ${target}`,
            kind: "manual",
            idempotent: false,
            destructive: false,
          },
        },
      ],
      planningAttribution: {
        contextPackIds: [input.brainContext.contextPackId],
        citations: citedDirectives(directives),
      },
    };
  }
}

interface EvaluationStepRow {
  readonly id: string;
  readonly title: string;
  readonly action_id: string | null;
  readonly evidence_id: string | null;
}

/** Local, evidence-linked completion evaluation for the manual-only workflow. */
export class DeterministicManualOutcomeEvaluator implements MissionOutcomeEvaluatorPort {
  private readonly brain: SecondBrainService;

  constructor(private readonly database: SqliteDatabase) {
    this.brain = new SecondBrainService(new MemoryRepository(database));
  }

  async evaluate(
    input: MissionOutcomeEvaluatorInput,
    signal: AbortSignal,
  ): Promise<MissionCompletionEvaluation> {
    if (signal.aborted) throw new DOMException("Guided evaluation was cancelled", "AbortError");
    if (input.mission.journey !== "guided" || input.run.journey !== "guided") {
      throw runtimeError(
        "local_manual_evaluator_autonomous_forbidden",
        "The manual-only evaluator cannot validate an Autonomous outcome.",
        "Use an enforcing evidence-aware Autonomous evaluator or keep this run Guided.",
      );
    }
    const plan = this.database.prepare(`
      SELECT p.id FROM plans p
      JOIN runs r ON r.id = p.run_id AND r.current_plan_id = p.id
      WHERE p.id = ? AND p.run_id = ? AND p.status IN ('active', 'completed')
    `).get(input.planId, input.run.id) as { id: string } | undefined;
    if (!plan) {
      throw new CommandRuntimeError(409, "manual_evaluation_plan_not_current", "The active plan changed before evaluation", {
        humanMessage: "The manual workflow was not evaluated because its exact active plan is no longer current.",
        retryable: false,
        category: "conflict",
        remediation: "Refresh the run and evaluate only the current immutable plan version.",
      });
    }
    const completed = new Set(input.completedActionIds);
    const steps = this.database.prepare(`
      SELECT ps.id, ps.title,
        (
          SELECT a.id FROM actions a
          WHERE a.run_id = ps.run_id AND a.step_id = ps.id AND a.status = 'succeeded'
          ORDER BY a.ended_at, a.id LIMIT 1
        ) AS action_id,
        (
          SELECT e.id FROM evidence e
          JOIN actions a ON a.id = e.action_id
          WHERE e.run_id = ps.run_id AND e.step_id = ps.id
            AND a.status = 'succeeded' AND ${verifiedEvidenceSql("e")}
          ORDER BY e.acquired_at, e.id LIMIT 1
        ) AS evidence_id
      FROM plan_steps ps
      WHERE ps.plan_id = ?
      ORDER BY ps.ordinal, ps.id
    `).all(input.planId) as EvaluationStepRow[];
    if (steps.length === 0) {
      throw new CommandRuntimeError(409, "manual_evaluation_steps_missing", "The active plan has no steps", {
        category: "evidence_insufficient",
      });
    }

    const criteria = steps.map((step) => {
      const satisfied = Boolean(
        step.action_id && step.evidence_id && completed.has(step.action_id),
      );
      return {
        criterion: `${step.title}: exact manual result retained`,
        satisfied,
        explanation: satisfied
          ? "The exact represented manual action succeeded and has linked verified operator-supplied evidence. This confirms workflow completion only; it does not independently prove a vulnerability or attack outcome."
          : "This represented step lacks either a succeeded exact action or linked verified evidence, so the deterministic evaluator cannot count it as complete.",
        evidenceIds: step.evidence_id && satisfied ? [step.evidence_id] : [],
      };
    });
    const success = criteria.every((criterion) => criterion.satisfied);

    const pack = new MemoryRepository(this.database).requireContextPack(input.brainContext.contextPackId);
    for (const item of pack.items) {
      this.brain.recordContextUse(pack.id, {
        nodeId: item.nodeId,
        used: false,
        relevanceReason: item.relevanceReason,
        ignoredReason: "The deterministic manual evaluator used only canonical action and verified-evidence relationships; memory did not alter the outcome.",
      });
    }

    return {
      success,
      summary: success
        ? "The bounded Guided manual workflow completed: every represented step has an exact succeeded action and linked verified operator evidence. Ti-Scale did not independently contact the target or claim an attack outcome."
        : "The bounded Guided manual workflow is incomplete because at least one represented step lacks an exact succeeded action with linked verified operator evidence.",
      criteria,
    };
  }
}

/** An execution boundary that can cancel an empty worker set but can never dispatch work. */
export class FailClosedManualExecutionPort implements ResultAwareExecutionPort {
  dispatchAttemptCount = 0;
  resumeAttemptCount = 0;

  async dispatch(_action: DurableAction): Promise<never> {
    this.dispatchAttemptCount += 1;
    throw runtimeError(
      "guided_manual_execution_dispatch_forbidden",
      "This Ti-Scale runtime is manual-only and cannot dispatch a target, provider, or tool action.",
      "Complete the represented step yourself and submit its result through the exact Guided decision.",
    );
  }

  async resume(_action: DurableAction): Promise<never> {
    this.resumeAttemptCount += 1;
    throw runtimeError(
      "guided_manual_execution_resume_forbidden",
      "This Ti-Scale runtime has no executable child action to resume.",
      "Return to the current represented manual decision or start a separately configured executable run.",
    );
  }

  async cancelRun(): Promise<void> {
    // No child process, provider request, socket, or tool job can exist behind
    // this port. Resolving truthfully confirms there is nothing external to
    // terminate; the coordinator still closes all canonical run records.
  }
}

export function localGuidedManualAgentProjection(): FleetAgentProjection {
  return {
    id: LOCAL_GUIDED_MANUAL_AGENT_ID,
    role: "deterministic-guided-manual-planner",
    displayName: "Local Guided Manual Planner",
    status: "available",
    providerPolicy: {
      mode: "local_deterministic",
      providerContact: false,
      publicDisclosure: false,
    },
    toolPolicy: {
      execution: "denied",
      targetInteraction: "operator_only",
      dispatchAvailable: false,
    },
    configuration: {
      journey: "guided",
      executionMode: "manual_only",
      plannerSchemaVersion: "1",
    },
    version: "guided-manual-v1",
    capabilities: [],
  };
}

export function createProductionGuidedManualRuntime(
  options: Pick<MissionRuntimeOptions, "database" | "brainContext" | "workerId" | "now" | "projectMemoryNodes" | "operationalHazardHmacKey">
    & Partial<Pick<MissionRuntimeOptions, "scanIntervalMs" | "leaseTtlMs" | "decisionTtlMs">>,
): MissionRuntimeEngine {
  return new MissionRuntimeEngine({
    database: options.database,
    ...(options.operationalHazardHmacKey
      ? { operationalHazardHmacKey: options.operationalHazardHmacKey }
      : {}),
    planner: new LocalGuidedManualPlanner(),
    outcomeEvaluator: new DeterministicManualOutcomeEvaluator(options.database),
    execution: new FailClosedManualExecutionPort(),
    supportedJourneys: ["guided"],
    ...(options.brainContext ? { brainContext: options.brainContext } : {}),
    ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    ...(options.workerId ? { workerId: options.workerId } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.scanIntervalMs ? { scanIntervalMs: options.scanIntervalMs } : {}),
    ...(options.leaseTtlMs ? { leaseTtlMs: options.leaseTtlMs } : {}),
    ...(options.decisionTtlMs ? { decisionTtlMs: options.decisionTtlMs } : {}),
  });
}
