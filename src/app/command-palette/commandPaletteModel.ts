import type { MissionSummary, RunStatus } from "../../domain/types/commandOs";
import type { MemoryNodeSummary } from "../../domain/types/brain";
import type { AgentRecord } from "../../domain/types/operations";
import type { GuidedDecision, RuntimeRun } from "../../domain/types/runtimeV2";

export type PaletteGroup =
  | "Journeys"
  | "Commands"
  | "Missions"
  | "Runs"
  | "Decisions"
  | "Agents"
  | "Second Brain";

export type PaletteCommandKind =
  | "navigation"
  | "journey"
  | "mission"
  | "run"
  | "decision"
  | "agent"
  | "memory"
  | "run-control"
  | "memory-candidate";

export interface PaletteCommand {
  readonly id: string;
  readonly kind: PaletteCommandKind;
  readonly group: PaletteGroup;
  readonly label: string;
  readonly description: string;
  readonly keywords?: readonly string[];
  readonly path?: string;
  readonly action?: "pause" | "resume" | "cancel" | "create-memory-candidate";
  readonly danger?: boolean;
}

export interface PaletteRouteContext {
  readonly missionId?: string;
  readonly runId?: string;
  readonly guided: boolean;
}

export const JOURNEY_COMMANDS: readonly PaletteCommand[] = [
  {
    id: "new-autonomous",
    kind: "journey",
    group: "Journeys",
    label: "Go Autonomous",
    description: "Compose and validate an authorized mission contract",
    keywords: ["new mission", "launch", "end to end"],
    path: "/missions/new/autonomous",
  },
  {
    id: "new-guided",
    kind: "journey",
    group: "Journeys",
    label: "Start Guided Mission",
    description: "Create a collaborative, deliberate step-by-step mission",
    keywords: ["new mission", "teach", "collaborate"],
    path: "/missions/new/guided",
  },
] as const;

const PAUSABLE_STATES = new Set<RunStatus>([
  "planning",
  "running",
  "waiting_guided_decision",
  "recovering",
]);
const TERMINAL_STATES = new Set<RunStatus>(["completed", "failed", "cancelled"]);

export function parsePaletteRoute(pathname: string): PaletteRouteContext {
  const guided = /^\/guided(?:\/|$)/u.test(pathname);
  const guidedMission = /^\/guided\/([^/]+)$/u.exec(pathname);
  const liveRun = /^\/live\/([^/]+)$/u.exec(pathname);
  const missionRun = /^\/missions\/([^/]+)\/runs\/([^/]+)$/u.exec(pathname);
  const mission = /^\/missions\/([^/]+)$/u.exec(pathname);
  const decode = (value: string | undefined): string | undefined => {
    if (!value) return undefined;
    try { return decodeURIComponent(value); } catch { return undefined; }
  };
  return {
    ...(guidedMission ? { missionId: decode(guidedMission[1]) } : {}),
    ...(liveRun ? { runId: decode(liveRun[1]) } : {}),
    ...(missionRun ? { missionId: decode(missionRun[1]), runId: decode(missionRun[2]) } : {}),
    ...(!missionRun && mission ? { missionId: decode(mission[1]) } : {}),
    guided,
  };
}

export function contextualRunCommands(run: RuntimeRun | undefined): readonly PaletteCommand[] {
  if (!run || TERMINAL_STATES.has(run.status)) return [];
  const commands: PaletteCommand[] = [];
  if (run.status === "blocked") {
    commands.push({
      id: `resume-run-${run.id}`,
      kind: "run-control",
      group: "Commands",
      label: "Resume current run",
      description: `${run.missionName} · resumes from its durable checkpoint`,
      keywords: [run.id, run.missionId, run.journey],
      action: "resume",
    });
  } else if (PAUSABLE_STATES.has(run.status)) {
    commands.push({
      id: `pause-run-${run.id}`,
      kind: "run-control",
      group: "Commands",
      label: "Pause current run",
      description: `${run.missionName} · pauses only at a safe durable checkpoint`,
      keywords: [run.id, run.missionId, run.journey],
      action: "pause",
    });
  }
  commands.push({
    id: `cancel-run-${run.id}`,
    kind: "run-control",
    group: "Commands",
    label: "Cancel current run",
    description: `${run.missionName} · stops child work and records a terminal checkpoint`,
    keywords: [run.id, run.missionId, run.journey, "abort", "stop"],
    action: "cancel",
    danger: true,
  });
  return commands;
}

export function missionCommand(mission: MissionSummary): PaletteCommand {
  return {
    id: `mission-${mission.id}`,
    kind: "mission",
    group: "Missions",
    label: mission.title,
    description: `${mission.journey === "autonomous" ? "Autonomous" : "Guided"} mission · ${mission.status.replaceAll("_", " ")}`,
    keywords: [mission.id, mission.journey, mission.status, mission.currentPhase ?? "", mission.nextAction ?? ""],
    path: mission.journey === "guided"
      ? `/guided/${encodeURIComponent(mission.id)}`
      : `/missions/${encodeURIComponent(mission.id)}`,
  };
}

export function runCommand(run: RuntimeRun): PaletteCommand {
  return {
    id: `run-${run.id}`,
    kind: "run",
    group: "Runs",
    label: run.missionName,
    description: `${run.journey === "autonomous" ? "Autonomous" : "Guided"} run · ${run.status.replaceAll("_", " ")} · ${run.id}`,
    keywords: [run.id, run.missionId, run.objective, run.status, run.currentStepId ?? "", run.currentOwnerId ?? "", run.nextAction ?? ""],
    path: run.journey === "guided"
      ? `/guided/${encodeURIComponent(run.missionId)}`
      : `/live/${encodeURIComponent(run.id)}`,
  };
}

export function decisionCommand(decision: GuidedDecision): PaletteCommand {
  return {
    id: `decision-${decision.id}`,
    kind: "decision",
    group: "Decisions",
    label: decision.rationale || `Guided decision ${decision.id}`,
    description: `${decision.status} · ${decision.riskClass} risk · step ${decision.stepId}`,
    keywords: [decision.id, decision.missionId, decision.runId, decision.stepId, decision.status, decision.riskClass],
    path: "/decisions",
  };
}

export function agentCommand(agent: AgentRecord): PaletteCommand {
  return {
    id: `agent-${agent.id}`,
    kind: "agent",
    group: "Agents",
    label: agent.displayName,
    description: `${agent.role} · ${agent.status} · queue ${agent.assignmentHealth.queueDepth}`,
    keywords: [agent.id, agent.role, agent.status],
    path: `/agents/${encodeURIComponent(agent.id)}`,
  };
}

export function memoryCommand(node: MemoryNodeSummary): PaletteCommand {
  return {
    id: `memory-${node.id}`,
    kind: "memory",
    group: "Second Brain",
    label: node.title,
    description: `${node.nodeType.replaceAll("_", " ")} · ${node.lifecycleStatus} · ${node.summary}`,
    keywords: [node.id, node.nodeType, node.lifecycleStatus, node.summary],
    path: `/brain/nodes/${encodeURIComponent(node.id)}`,
  };
}

function normalizedTokens(value: string): string[] {
  return value.normalize("NFKC").trim().toLocaleLowerCase("en-US").split(/\s+/u).filter(Boolean).slice(0, 20);
}

function commandText(command: PaletteCommand): string {
  return [command.label, command.description, ...(command.keywords ?? [])]
    .join(" ")
    .normalize("NFKC")
    .toLocaleLowerCase("en-US");
}

export function rankPaletteCommands(
  commands: readonly PaletteCommand[],
  query: string,
  limit = 80,
): readonly PaletteCommand[] {
  const tokens = normalizedTokens(query);
  if (tokens.length === 0) return commands.slice(0, limit);
  const normalizedQuery = tokens.join(" ");
  return commands
    .flatMap((command, index) => {
      const text = commandText(command);
      if (!tokens.every((token) => text.includes(token))) return [];
      const label = command.label.normalize("NFKC").toLocaleLowerCase("en-US");
      const score = label === normalizedQuery
        ? 0
        : label.startsWith(normalizedQuery)
          ? 1
          : label.includes(normalizedQuery)
            ? 2
            : 3;
      return [{ command, score, index }];
    })
    .sort((left, right) => left.score - right.score || left.index - right.index)
    .slice(0, limit)
    .map(({ command }) => command);
}
