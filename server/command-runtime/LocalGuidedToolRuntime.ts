import { isIP } from "node:net";
import type { GuidedReconnaissanceSelection } from "../missions/GuidedReconnaissance";
import type { SqliteDatabase } from "../db";
import type {
  LocalToolCapabilityManifest,
  LocalToolRouteIntent,
  LocalToolTargetKind,
  ReviewedLocalToolCapability,
} from "../local-tools";
import {
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
} from "../orchestration";
import type { BrainContextService } from "../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../memory";
import {
  DeterministicManualOutcomeEvaluator,
  LocalGuidedManualPlanner,
} from "./LocalGuidedManualRuntime";
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

interface ReviewedTargetRoute {
  readonly intent: LocalToolRouteIntent;
  readonly targetKind: LocalToolTargetKind;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly title: string;
  readonly objective: string;
  readonly explanation: string;
  readonly expectedResult: string;
  readonly requestedToolId?: string;
}

export interface LocalGuidedToolPlannerOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly logicalWorkspace: string;
  /** Synchronous receipt-backed view. Reading it must never launch a probe. */
  readonly readReadyToolIds: () => ReadonlySet<string>;
  readonly manualFallback?: MissionPlannerPort;
}

function routeTarget(target: string, logicalWorkspace: string): ReviewedTargetRoute | undefined {
  if (/^tcp:\/\//iu.test(target)) {
    let address: URL;
    try {
      address = new URL(target);
    } catch {
      return undefined;
    }
    const port = Number(address.port);
    if (
      address.protocol !== "tcp:"
      || address.username !== ""
      || address.password !== ""
      || address.pathname !== ""
      || address.search !== ""
      || address.hash !== ""
      || !address.hostname
      || !Number.isSafeInteger(port)
      || port < 1
      || port > 65_535
    ) return undefined;
    const normalizedHost = address.hostname.startsWith("[") && address.hostname.endsWith("]")
      ? address.hostname.slice(1, -1)
      : address.hostname;
    return {
      intent: "tcp_connect",
      targetKind: "ip_or_host",
      parameters: { workspace: logicalWorkspace, target: normalizedHost, port },
      title: "Check the approved TCP service",
      objective: `Establish whether the exact approved service ${target} accepts a TCP connection.`,
      explanation: "Ti-Scale will make one connection-only check to the represented host and port. It sends no application payload, does not scan neighboring ports, and closes immediately.",
      expectedResult: "A connected or refused result, or a precise route, timeout, policy, or dependency failure.",
    };
  }
  if (/^https?:\/\//iu.test(target)) {
    return {
      intent: "http_metadata",
      targetKind: "url",
      parameters: { workspace: logicalWorkspace, url: target },
      title: "Check the approved web service response",
      objective: `Confirm whether ${target} responds and retain its HTTP headers before choosing a deeper web test.`,
      explanation: "Ti-Scale will make one bounded HTTP metadata request to the exact approved address. It reports redirects without following them, sends no form data, and does not crawl the site.",
      expectedResult: "A reachable response with status and headers, a reported redirect that was not followed, or a precise connection, TLS, or timeout result.",
    };
  }
  if (isIP(target) !== 0) {
    return {
      intent: "host_liveness",
      targetKind: "ip_or_host",
      parameters: { workspace: logicalWorkspace, target },
      title: "Check whether the approved host responds",
      objective: `Establish whether ${target} responds to one bounded reachability check before any service enumeration.`,
      explanation: "Ti-Scale will send two reachability probes to the exact approved address. A timeout can mean filtering as well as an offline host, so the result will not be overstated.",
      expectedResult: "A response with timing, or a precise unreachable, filtered, permission, route, or timeout result.",
    };
  }
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}\.?$/iu.test(target)) {
    const name = target.endsWith(".") ? target.slice(0, -1) : target;
    return {
      intent: "dns_query",
      targetKind: "domain",
      parameters: { workspace: logicalWorkspace, name, recordType: "A" },
      title: "Resolve the approved domain",
      objective: `Confirm the current IPv4 address records attributable to ${name}.`,
      explanation: "Ti-Scale will make one bounded DNS A-record query for the exact approved name. It will not enumerate neighboring names or contact the returned hosts in this step.",
      expectedResult: "Current A records with resolver output, or a precise no-record, resolution, or timeout result.",
    };
  }
  if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(target)) {
    return {
      intent: "host_liveness",
      targetKind: "ip_or_host",
      parameters: { workspace: logicalWorkspace, target },
      title: "Check whether the approved host responds",
      objective: `Establish whether the approved host ${target} responds before any service enumeration.`,
      explanation: "Ti-Scale will send two reachability probes to the exact approved hostname. A timeout can mean filtering as well as an offline host, so the result will not be overstated.",
      expectedResult: "A response with timing, or a precise name-resolution, unreachable, filtered, permission, route, or timeout result.",
    };
  }
  return undefined;
}

function isSingleHost(target: string): boolean {
  if (isIP(target) !== 0) return true;
  if (target.length > 253 || target.startsWith("-")) return false;
  return target.split(".").every((part) =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part));
}

function routeSelectedReconnaissance(
  selection: GuidedReconnaissanceSelection,
  target: string,
  logicalWorkspace: string,
): ReviewedTargetRoute | undefined {
  if (!isSingleHost(target)) return undefined;
  if (selection.mode === "host_liveness") {
    return {
      intent: "host_liveness",
      targetKind: "ip_or_host",
      parameters: { workspace: logicalWorkspace, target },
      title: "Check whether the approved host responds",
      objective: `Establish whether ${target} responds to one bounded reachability check before any service enumeration.`,
      explanation: "Ti-Scale will send two reachability probes to the exact approved host. A timeout may mean filtering rather than an offline system, so the result will not be overstated.",
      expectedResult: "A response with timing, or a precise name-resolution, route, filtered, permission, or timeout result.",
      requestedToolId: "kali:ping-host-liveness",
    };
  }
  const ports = selection.portSelection.ports.join(",");
  return {
    intent: "port_scan",
    targetKind: "ip_or_host",
    parameters: { workspace: logicalWorkspace, target, ports },
    title: "Check the selected TCP services",
    objective: `Check the ${selection.portSelection.ports.length} selected TCP ports on ${target} and identify responding service versions without expanding to neighboring ports or hosts.`,
    explanation: `Ti-Scale will make ordinary TCP connections only to ports ${ports} on the exact approved host. It does not use raw sockets, port ranges, scripts, operating-system detection, vulnerability checks, or exploit attempts.`,
    expectedResult: "A bounded list of open selected ports and attributable service/version observations, or a precise route, timeout, dependency, or policy failure.",
    requestedToolId: "kali:nmap-tcp-connect-service-scan",
  };
}

function risk(tool: ReviewedLocalToolCapability): "low" | "medium" {
  return tool.riskClassIds.some((id) => id.includes("network")) ? "medium" : "low";
}

/**
 * Deterministic planner for the first executable Guided slice. It emits one
 * direct-process action only while the exact reviewed tool has a current
 * activation receipt. Every other target/readiness state falls back to the
 * represented manual planner instead of promising unavailable execution.
 */
export class LocalGuidedToolPlanner implements MissionPlannerPort {
  private readonly fallback: MissionPlannerPort;

  constructor(private readonly options: LocalGuidedToolPlannerOptions) {
    this.fallback = options.manualFallback ?? new LocalGuidedManualPlanner();
  }

  private async unavailableManualPlan(
    input: MissionPlannerInput,
    signal: AbortSignal,
    routed: ReviewedTargetRoute,
    target: string,
    reasonOverride?: string,
  ): Promise<MissionPlanDraft> {
    const fallbackResult = await this.fallback.plan(input, signal);
    const fallback = "plan" in fallbackResult ? fallbackResult.plan : fallbackResult;
    const selected = input.mission.guidedReconnaissance;
    if (!selected) return fallback;
    const manifestTool = routed.requestedToolId
      ? this.options.manifest.resolve(routed.requestedToolId)
      : undefined;
    const reason = reasonOverride ?? (manifestTool?.activation === "disabled"
      ? manifestTool.activationReason ?? "The reviewed local capability is operator-disabled."
      : routed.requestedToolId && !this.options.readReadyToolIds().has(routed.requestedToolId)
        ? "The reviewed capability has no complete, current local activation receipt."
        : "The exact reviewed local execution route is unavailable.");
    const selectedPorts = selected.mode === "tcp_service_scan"
      ? selected.portSelection.ports.join(",")
      : undefined;
    return {
      ...fallback,
      strategySummary: `Preserve the operator-selected first reconnaissance step for ${target}, but keep target interaction manual while its reviewed local execution boundary is unavailable.`,
      rationaleSummary: `${reason} Ti-Scale will not substitute another executable or silently change the approved parameters. The operator may perform the represented step manually, or an administrator may install and enable the exact reviewed binding and obtain a fresh activation receipt before a new run.`,
      steps: fallback.steps.map((step, index) => index !== 0 ? step : {
        ...step,
        phase: selected.mode === "tcp_service_scan" ? "Service baseline" : "Host baseline",
        title: selected.mode === "tcp_service_scan"
          ? "Run the selected TCP service check manually"
          : "Run the selected reachability check manually",
        objective: routed.objective,
        explanation: `${routed.explanation} Automated execution is unavailable: ${reason} Use an authorized local client manually and return the result; Ti-Scale will not dispatch an unreviewed substitute.`,
        rationale: `${routed.expectedResult} The exact selected parameters are preserved below. Raw output remains an Engagement Log record and any parsed statement remains an unverified Observation until separately validated.`,
        action: {
          ...step.action,
          actionClass: selected.mode === "tcp_service_scan"
            ? "port_service_enumeration"
            : "active_host_discovery",
          target,
          arguments: {
            ...step.action.arguments,
            operatorProcedure: selected.mode === "tcp_service_scan"
              ? [
                  `Use an authorized TCP service scanner against only ${target} and the exact individual ports ${selectedPorts}.`,
                  "Use ordinary TCP connect scanning and lightweight service identification; do not add port ranges, raw-socket scans, scripts, OS detection, vulnerability checks, or exploit attempts.",
                  "Return the exact command or procedure, acquisition time, open selected ports, service/version observations, and any route, permission, dependency, or timeout blocker.",
                ]
              : [
                  `Use one bounded reachability check against only ${target}.`,
                  "Record the route, response or timeout, acquisition time, and method without enumerating ports or neighboring systems.",
                ],
            expectedObservations: selected.mode === "tcp_service_scan"
              ? [
                  "Open ports from the exact selected list",
                  "Attributable service and version observations with uncertainty preserved",
                  "A precise route, timeout, permission, dependency, or no-open-port result",
                ]
              : [
                  "A reachable, unreachable, or filtered result",
                  "The exact approved host, method, and acquisition time",
                ],
            selectedReconnaissance: selected,
            ...(selectedPorts ? { canonicalTcpPorts: selectedPorts } : {}),
            unavailableToolId: routed.requestedToolId ?? null,
            unavailableReason: reason,
          },
          intentSummary: selected.mode === "tcp_service_scan"
            ? `Operator checks only TCP ports ${selectedPorts} on ${target}`
            : `Operator performs one bounded reachability check for ${target}`,
        },
      }),
    };
  }

  async plan(input: MissionPlannerInput, signal: AbortSignal): Promise<MissionPlanDraft> {
    if (input.mission.journey !== "guided" || input.run.journey !== "guided") {
      throw new CommandRuntimeError(409, "local_guided_tool_autonomous_forbidden", "The local Guided tool planner cannot plan Autonomous work", {
        humanMessage: "This reviewed local execution slice is available only for one operator-approved Guided step.",
        retryable: false,
        category: "policy_denied",
        remediation: "Create a Guided mission or configure the separately reviewed Autonomous runtime composition.",
      });
    }
    const target = input.mission.allowedTargets[0]?.trim();
    let routed = target
      ? input.mission.guidedReconnaissance
        ? routeSelectedReconnaissance(input.mission.guidedReconnaissance, target, this.options.logicalWorkspace)
        : routeTarget(target, this.options.logicalWorkspace)
      : undefined;
    if (target && !input.mission.guidedReconnaissance && /^https?:\/\//iu.test(target)) {
      let canonical = false;
      try {
        const parsed = new URL(target);
        canonical = parsed.href === target && parsed.search === "" && parsed.hash === "";
      } catch {
        canonical = false;
      }
      const webFingerprint = this.options.manifest.resolveRoute("web_fingerprint", "url");
      if (canonical && webFingerprint && this.options.readReadyToolIds().has(webFingerprint.toolId)) {
        routed = {
          intent: "web_fingerprint",
          targetKind: "url",
          parameters: { workspace: this.options.logicalWorkspace, url: target },
          title: "Identify the approved web service",
          objective: `Identify the server and page technologies visible at ${target} before choosing a deeper web check.`,
          explanation: "Ti-Scale will make one bounded request to the exact approved URL and inspect a small reviewed set of response and HTML signals. It does not follow redirects, submit data, crawl neighboring paths, or run vulnerability checks.",
          expectedResult: "A concise server, title, and HTML technology observation, or a precise connection, TLS, timeout, policy, or dependency failure.",
          requestedToolId: webFingerprint.toolId,
        };
      }
    }
    if (!target || !routed) {
      const result = await this.fallback.plan(input, signal);
      return "plan" in result ? result.plan : result;
    }
    if (input.mission.executionPreference !== "single_step_agent") {
      return input.mission.guidedReconnaissance
        ? this.unavailableManualPlan(
            input,
            signal,
            routed,
            target,
            "The mission is configured for operator-run commands, so Ti-Scale will not dispatch a local process for this step.",
          )
        : this.fallback.plan(input, signal).then((result) => "plan" in result ? result.plan : result);
    }
    const tool = this.options.manifest.resolveRoute(routed.intent, routed.targetKind);
    if (!tool || !this.options.readReadyToolIds().has(tool.toolId)) {
      return this.unavailableManualPlan(input, signal, routed, target);
    }
    // Compile once during planning so no malformed, additional, or
    // semantically invalid parameter can reach a decision card.
    const selectedRoutes: Array<Readonly<{
      routed: ReviewedTargetRoute;
      tool: ReviewedLocalToolCapability;
    }>> = [{ routed, tool }];
    if (routed.intent === "web_fingerprint") {
      const baseUrl = (() => {
        try {
          const parsed = new URL(target);
          return parsed.pathname.endsWith("/") ? parsed.href : null;
        } catch {
          return null;
        }
      })();
      const contentDiscovery = this.options.manifest.resolveRoute("web_content_discovery", "url");
      if (baseUrl && contentDiscovery && this.options.readReadyToolIds().has(contentDiscovery.toolId)) {
        selectedRoutes.push({
          tool: contentDiscovery,
          routed: {
            intent: "web_content_discovery",
            targetKind: "url",
            parameters: { workspace: this.options.logicalWorkspace, url: baseUrl },
            title: "Check a small reviewed set of web paths",
            objective: `Check 14 common, non-destructive paths below ${baseUrl} after the web baseline is known.`,
            explanation: "Ti-Scale will use a fixed 14-path dictionary, at most two concurrent requests, and at most ten requests per second. It does not recurse, mutate parameters, submit forms, follow redirects, or expand beyond this exact approved origin.",
            expectedResult: "A bounded list of responding paths with status, size, and redirect metadata, or a precise connection, timeout, policy, or dependency failure.",
            requestedToolId: contentDiscovery.toolId,
          },
        });
      }
    }
    for (const selected of selectedRoutes) {
      this.options.manifest.compileInvocation(selected.tool.toolId, selected.routed.parameters);
    }
    if (signal.aborted) throw new DOMException("Guided planning was cancelled", "AbortError");

    return {
      strategySummary: `Use one operator-approved local specialist action to establish the ${routed.targetKind === "url" ? "web" : routed.targetKind === "domain" ? "domain" : "host"} baseline for ${target}.`,
      rationaleSummary: "The exact executable, argv template, target, workspace, output bound, timeout, result sink, and cancellation boundary have current local receipts. The operator still decides whether this single represented action may run.",
      steps: selectedRoutes.map(({ routed: selectedRoute, tool: selectedTool }, index) => ({
        phase: selectedRoute.intent === "web_content_discovery"
          ? "Web path baseline"
          : selectedRoute.targetKind === "url" ? "Web baseline" : selectedRoute.targetKind === "domain" ? "Domain baseline" : "Host baseline",
        title: selectedRoute.title,
        objective: selectedRoute.objective,
        explanation: selectedRoute.explanation,
        rationale: `${selectedRoute.expectedResult} Raw output remains an Engagement Log record; it is not automatically promoted to verified evidence or a finding.`,
        successCriteria: [
          "The exact approved target is the only network destination represented by the step",
          "The reviewed local process returns a bounded attributable result or a precise failure",
          "Raw output remains a log unless a separate evidence policy validates and promotes it",
        ],
        dependencyOrdinals: index === 0 ? [] : [index - 1],
        assignedAgentId: this.options.manifest.specialist.id,
        riskClass: risk(selectedTool),
        reversibility: "This is a bounded read-only network check. Stop cancels the child process group; it does not change the target or write outside the resolved local workspace.",
        action: {
          actionType: selectedTool.toolId,
          actionClass: selectedTool.actionClassIds[0]!,
          target,
          arguments: {
            schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
            executionBinding: "reviewed_local_process",
            toolId: selectedTool.toolId,
            parameters: selectedRoute.parameters,
          },
          intentSummary: `${selectedTool.label} for the exact approved target ${target}`,
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
      })),
      planningAttribution: {
        contextPackIds: [input.brainContext.contextPackId],
        citations: [],
      },
    };
  }
}

interface CompletedLocalToolStepRow {
  readonly id: string;
  readonly title: string;
  readonly action_id: string | null;
  readonly result_summary: string | null;
  readonly tool_call_id: string | null;
  readonly tool_call_status: string | null;
}

/**
 * Closes the bounded workflow from canonical result correlation only. It does
 * not relabel stdout/stderr as evidence, and it cannot verify a finding.
 */
export class DeterministicGuidedToolOutcomeEvaluator implements MissionOutcomeEvaluatorPort {
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
      throw new CommandRuntimeError(409, "local_guided_tool_evaluator_autonomous_forbidden", "The local Guided evaluator cannot validate Autonomous work", {
        category: "policy_denied",
      });
    }
    const completed = new Set(input.completedActionIds);
    const steps = this.database.prepare(`
      SELECT ps.id, ps.title,
        a.id AS action_id, a.result_summary,
        tc.id AS tool_call_id, tc.status AS tool_call_status
      FROM plan_steps ps
      JOIN plans p ON p.id = ps.plan_id
      LEFT JOIN actions a ON a.step_id = ps.id AND a.run_id = ps.run_id AND a.status = 'succeeded'
      LEFT JOIN tool_calls tc ON tc.action_id = a.id
      WHERE p.id = ? AND p.run_id = ? AND p.status IN ('active', 'completed')
      ORDER BY ps.ordinal, a.ended_at, tc.created_at
    `).all(input.planId, input.run.id) as CompletedLocalToolStepRow[];
    if (steps.length === 0) {
      throw new CommandRuntimeError(409, "local_guided_tool_evaluation_missing", "The active Guided plan has no canonical tool step", {
        category: "evidence_insufficient",
      });
    }
    const criteria = steps.map((step) => {
      const satisfied = Boolean(
        step.action_id
        && completed.has(step.action_id)
        && step.result_summary?.trim()
        && step.tool_call_id
        && step.tool_call_status === "succeeded",
      );
      return {
        criterion: `${step.title}: exact reviewed local result received`,
        satisfied,
        outcome: satisfied ? "achieved" as const : "not_achieved" as const,
        explanation: satisfied
          ? "The exact approved Guided action completed through its reviewed local binding and returned a correlated bounded result. Raw process output remains an Engagement Log record and does not verify a finding."
          : "The step lacks a succeeded canonical action, terminal local tool-call receipt, or attributable result summary, so Ti-Scale cannot count it as complete.",
        evidenceIds: [],
      };
    });
    const success = criteria.every((criterion) => criterion.satisfied);
    const pack = new MemoryRepository(this.database).requireContextPack(input.brainContext.contextPackId);
    for (const item of pack.items) {
      this.brain.recordContextUse(pack.id, {
        nodeId: item.nodeId,
        used: false,
        relevanceReason: item.relevanceReason,
        ignoredReason: "The deterministic local-tool evaluator used only canonical action, tool-call, and result relationships; retained memory did not alter the outcome.",
      });
    }
    return {
      success,
      summary: success
        ? "The one-step Guided local specialist workflow completed. The result is retained for review without being mislabeled as verified evidence."
        : "The Guided local specialist workflow is incomplete because its exact terminal result boundary was not satisfied.",
      criteria,
    };
  }
}

/**
 * A single runtime can truthfully serve both Guided intake preferences. The
 * immutable represented action decides which deterministic evaluator applies;
 * a mixed or missing plan fails closed instead of guessing.
 */
export class DeterministicGuidedPreferenceOutcomeEvaluator implements MissionOutcomeEvaluatorPort {
  private readonly manual: DeterministicManualOutcomeEvaluator;
  private readonly localTool: DeterministicGuidedToolOutcomeEvaluator;

  constructor(private readonly database: SqliteDatabase) {
    this.manual = new DeterministicManualOutcomeEvaluator(database);
    this.localTool = new DeterministicGuidedToolOutcomeEvaluator(database);
  }

  async evaluate(
    input: MissionOutcomeEvaluatorInput,
    signal: AbortSignal,
  ): Promise<MissionCompletionEvaluation> {
    const rows = this.database.prepare(`
      SELECT DISTINCT json_extract(mc.value_json, '$.action.kind') AS action_kind
      FROM plan_steps ps
      JOIN mission_constraints mc
        ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      WHERE ps.plan_id = ? AND ps.run_id = ?
      ORDER BY action_kind
    `).all(input.planId, input.run.id) as Array<{ action_kind: string | null }>;
    const kinds = new Set(rows.map(({ action_kind }) => action_kind));
    if (kinds.size !== 1) {
      throw new CommandRuntimeError(409, "guided_evaluation_action_boundary_ambiguous", "The Guided plan has an ambiguous represented-action boundary", {
        humanMessage: "Ti-Scale could not determine whether this exact plan was operator-run or agent-run, so it did not claim completion.",
        category: "data_integrity",
        remediation: "Inspect the immutable plan representation and evaluate only after its exact action kind is restored.",
      });
    }
    const kind = [...kinds][0];
    if (kind === "manual") return this.manual.evaluate(input, signal);
    if (kind === "tool") return this.localTool.evaluate(input, signal);
    throw new CommandRuntimeError(409, "guided_evaluation_action_kind_unsupported", "The Guided plan action kind is unsupported", {
      humanMessage: "This Guided plan uses an action type that the local deterministic evaluator cannot validate.",
      category: "policy_denied",
      remediation: "Use a reviewed manual or exact local-tool Guided step.",
    });
  }
}

export function createProductionGuidedLocalToolRuntime(options: {
  readonly database: SqliteDatabase;
  readonly operationalHazardHmacKey?: string | Buffer;
  readonly brainContext: BrainContextService;
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  readonly manifest: LocalToolCapabilityManifest;
  readonly logicalWorkspace: string;
  readonly readReadyToolIds: () => ReadonlySet<string>;
  readonly execution: ResultAwareExecutionPort;
  readonly workerId?: string;
  readonly now?: () => Date;
  readonly scanIntervalMs?: number;
  readonly leaseTtlMs?: number;
  readonly decisionTtlMs?: number;
}): MissionRuntimeEngine {
  return new MissionRuntimeEngine({
    database: options.database,
    ...(options.operationalHazardHmacKey
      ? { operationalHazardHmacKey: options.operationalHazardHmacKey }
      : {}),
    planner: new LocalGuidedToolPlanner({
      manifest: options.manifest,
      logicalWorkspace: options.logicalWorkspace,
      readReadyToolIds: options.readReadyToolIds,
    }),
    outcomeEvaluator: new DeterministicGuidedPreferenceOutcomeEvaluator(options.database),
    execution: options.execution,
    brainContext: options.brainContext,
    ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    supportedJourneys: ["guided"],
    ...(options.workerId ? { workerId: options.workerId } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.scanIntervalMs ? { scanIntervalMs: options.scanIntervalMs } : {}),
    ...(options.leaseTtlMs ? { leaseTtlMs: options.leaseTtlMs } : {}),
    ...(options.decisionTtlMs ? { decisionTtlMs: options.decisionTtlMs } : {}),
  });
}
