import {
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { fetchMemoryNodes } from "../../data/api/brain";
import { fetchMissions } from "../../data/api/commandOs";
import { guidedCommanderApi } from "../../data/api/guidedCommander";
import { operationsApi } from "../../data/api/operations";
import { exactResumeBoundary, runtimeV2Api } from "../../data/api/runtimeV2";
import { useQueryCache } from "../../data/cache/QueryProvider";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type { GuidedCommanderMessage, GuidedCommanderStep, GuidedRememberInput } from "../../domain/types/guidedCommander";
import type { RunSnapshot, RuntimeRun } from "../../domain/types/runtimeV2";
import { suggestedMemorySummary, suggestedMemoryTitle } from "../../features/guided/guidedCommanderUi";
import { useNavigation } from "../router/navigation";
import { PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION } from "../router/routes";
import {
  agentCommand,
  commandMutationErrorMessage,
  contextualRunCommands,
  decisionCommand,
  JOURNEY_COMMANDS,
  memoryCommand,
  missionCommand,
  type PaletteCommand,
  type PaletteGroup,
  parsePaletteRoute,
  rankPaletteCommands,
  runCommand,
} from "./commandPaletteModel";

const NAVIGATION_COMMANDS: readonly PaletteCommand[] = [...PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION].map((item) => ({
  id: `navigate-${item.label.toLocaleLowerCase("en-US").replace(/\s+/gu, "-")}`,
  kind: "navigation",
  group: "Commands",
  label: item.label,
  description: `Navigate to ${item.label}`,
  keywords: item.path === "/manual" ? ["help", "how to", "documentation", "new engagement", "start mission"] : undefined,
  path: item.path,
}));

const GROUP_ORDER: readonly PaletteGroup[] = [
  "Journeys", "Commands", "Missions", "Runs", "Decisions", "Agents", "Second Brain",
];

interface PaletteData {
  readonly missions: Awaited<ReturnType<typeof fetchMissions>>["items"];
  readonly runs: Awaited<ReturnType<typeof runtimeV2Api.runs>>["items"];
  readonly decisions: Awaited<ReturnType<typeof runtimeV2Api.decisions>>["items"];
  readonly agents: Awaited<ReturnType<typeof operationsApi.agents>>["items"];
}

interface GuidedMemorySource {
  readonly message: GuidedCommanderMessage;
  readonly step: GuidedCommanderStep;
  readonly engagementAvailable: boolean;
}

type Editor =
  | { readonly kind: "run-control"; readonly command: "pause" | "resume" | "cancel" }
  | { readonly kind: "memory-candidate" };

interface MemoryDraft {
  nodeType: GuidedRememberInput["nodeType"];
  title: string;
  summary: string;
  scope: GuidedRememberInput["scope"];
  sensitivity: GuidedRememberInput["sensitivity"];
}

const EMPTY_DATA: PaletteData = { missions: [], runs: [], decisions: [], agents: [] };

function requestKey(prefix: string): string {
  const id = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${id}`;
}

function nonTerminal(run: RuntimeRun): boolean {
  return !["completed", "failed", "cancelled"].includes(run.status);
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { navigate, pathname } = useNavigation();
  const cache = useQueryCache();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const [data, setData] = useState<PaletteData>(EMPTY_DATA);
  const [remoteMatches, setRemoteMatches] = useState<PaletteData>();
  const [memoryNodes, setMemoryNodes] = useState<Awaited<ReturnType<typeof fetchMemoryNodes>>["items"]>([]);
  const [contextualSnapshot, setContextualSnapshot] = useState<RunSnapshot>();
  const [memorySource, setMemorySource] = useState<GuidedMemorySource>();
  // AppShell mounts this route chunk only after the first deliberate palette
  // request. Start in the truthful loading state so the first committed
  // dialog never advertises a settled empty catalog before its four canonical
  // domain reads have even begun.
  const [loading, setLoading] = useState(true);
  const [brainLoading, setBrainLoading] = useState(false);
  const [loadWarnings, setLoadWarnings] = useState<string[]>([]);
  const [searchWarnings, setSearchWarnings] = useState<string[]>([]);
  const [editor, setEditor] = useState<Editor>();
  const [reason, setReason] = useState("");
  const [cancelConfirmed, setCancelConfirmed] = useState(false);
  const [memoryDraft, setMemoryDraft] = useState<MemoryDraft>({
    nodeType: "source",
    title: "",
    summary: "",
    scope: "mission",
    sensitivity: "private",
  });
  const [mutationPending, setMutationPending] = useState(false);
  const [mutationError, setMutationError] = useState<string>();
  const [statusMessage, setStatusMessage] = useState<string>();
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const routeContext = useMemo(() => parsePaletteRoute(pathname), [pathname]);
  const contextualRun = contextualSnapshot?.run;
  const contextualMemoryInboxPath = contextualRun
    ? `/brain/inbox?missionId=${encodeURIComponent(contextualRun.missionId)}&runId=${encodeURIComponent(contextualRun.id)}`
    : "/brain/inbox";

  useLayoutEffect(() => {
    if (!open) {
      if (returnFocusRef.current?.isConnected) returnFocusRef.current.focus();
      returnFocusRef.current = null;
      return;
    }
    returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setLoading(true);
    setBrainLoading(false);
    setQuery("");
    setActiveIndex(0);
    setEditor(undefined);
    setReason("");
    setCancelConfirmed(false);
    setMutationError(undefined);
    setStatusMessage(undefined);
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setLoading(true);
    setLoadWarnings([]);
    // This component is lazy-mounted while open. Defer the first transport by
    // one task so React's development StrictMode mount probe can set up and
    // clean up without starting four requests that it must immediately abort.
    // The committed mount owns the only transport and ordinary close/navigation
    // still aborts genuinely in-flight work through the controller below.
    const start = window.setTimeout(() => {
      void Promise.allSettled([
        fetchMissions({ limit: 100 }, controller.signal),
        runtimeV2Api.runs({ limit: 100 }, controller.signal),
        runtimeV2Api.decisions({ limit: 100 }, controller.signal),
        operationsApi.agents({ limit: 100 }, controller.signal),
      ]).then((results) => {
        if (controller.signal.aborted) return;
        const warnings: string[] = [];
        const [missions, runs, decisions, agents] = results;
        if (missions.status === "rejected") warnings.push("missions");
        if (runs.status === "rejected") warnings.push("runs");
        if (decisions.status === "rejected") warnings.push("decisions");
        if (agents.status === "rejected") warnings.push("agents");
        setData({
          missions: missions.status === "fulfilled" ? missions.value.items : [],
          runs: runs.status === "fulfilled" ? runs.value.items : [],
          decisions: decisions.status === "fulfilled" ? decisions.value.items : [],
          agents: agents.status === "fulfilled" ? agents.value.items : [],
        });
        setLoadWarnings(warnings);
        setLoading(false);
      });
    }, 0);
    return () => {
      window.clearTimeout(start);
      controller.abort();
    };
  }, [open]);

  useEffect(() => {
    if (!open || (!routeContext.runId && !routeContext.missionId)) {
      setContextualSnapshot(undefined);
      return;
    }
    const controller = new AbortController();
    setContextualSnapshot(undefined);
    // The palette can first lazy-mount on a mission or run route. Keep this
    // contextual read under the same StrictMode ownership boundary as the
    // canonical palette collections above; otherwise the development probe
    // still starts and immediately aborts one required run/mission request.
    const start = window.setTimeout(() => {
      const load = routeContext.runId
        ? runtimeV2Api.run(routeContext.runId, controller.signal)
        : runtimeV2Api.mission(routeContext.missionId!, controller.signal).then((snapshot) => {
            const selected = snapshot.runs.find(nonTerminal) ?? snapshot.runs[0];
            return selected ? runtimeV2Api.run(selected.id, controller.signal) : undefined;
          });
      void load.then((snapshot) => { if (!controller.signal.aborted) setContextualSnapshot(snapshot); }).catch(() => {
        if (!controller.signal.aborted) setContextualSnapshot(undefined);
      });
    }, 0);
    return () => {
      window.clearTimeout(start);
      controller.abort();
    };
  }, [open, routeContext.missionId, routeContext.runId]);

  useEffect(() => {
    if (!open || !routeContext.guided || !contextualRun || contextualRun.journey !== "guided" || !nonTerminal(contextualRun)) {
      setMemorySource(undefined);
      return;
    }
    const controller = new AbortController();
    setMemorySource(undefined);
    void guidedCommanderApi.transcript(
      contextualRun.missionId,
      { runId: contextualRun.id, limit: 100 },
      controller.signal,
    ).then((transcript) => {
      if (controller.signal.aborted || !transcript.currentStep) {
        if (!controller.signal.aborted) setMemorySource(undefined);
        return;
      }
      const message = [...transcript.items].reverse().find((item) =>
        item.role === "assistant" &&
        (item.stepId === transcript.currentStep?.id || item.structuredContent.stepId === transcript.currentStep?.id));
      setMemorySource(message ? {
        message,
        step: transcript.currentStep,
        engagementAvailable: Boolean(transcript.mission.engagementId),
      } : undefined);
    }).catch(() => { if (!controller.signal.aborted) setMemorySource(undefined); });
    return () => controller.abort();
  }, [open, routeContext.guided, contextualRun?.id, contextualRun?.status]);

  useEffect(() => {
    const normalized = query.trim();
    if (!open || normalized.length < 2) {
      setRemoteMatches(undefined);
      setMemoryNodes([]);
      setBrainLoading(false);
      setSearchWarnings([]);
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => {
      setBrainLoading(true);
      void Promise.allSettled([
        fetchMissions({ query: normalized, limit: 100 }, controller.signal),
        runtimeV2Api.runs({ query: normalized, limit: 100 }, controller.signal),
        runtimeV2Api.decisions({ query: normalized, limit: 100 }, controller.signal),
        operationsApi.agents({ query: normalized, limit: 100 }, controller.signal),
        fetchMemoryNodes({ query: normalized, limit: 30 }, controller.signal),
      ]).then((results) => {
        if (controller.signal.aborted) return;
        const [missions, runs, decisions, agents, nodes] = results;
        const warnings: string[] = [];
        if (missions.status === "rejected") warnings.push("missions");
        if (runs.status === "rejected") warnings.push("runs");
        if (decisions.status === "rejected") warnings.push("decisions");
        if (agents.status === "rejected") warnings.push("agents");
        if (nodes.status === "rejected") warnings.push("Second Brain");
        setRemoteMatches({
          missions: missions.status === "fulfilled" ? missions.value.items : [],
          runs: runs.status === "fulfilled" ? runs.value.items : [],
          decisions: decisions.status === "fulfilled" ? decisions.value.items : [],
          agents: agents.status === "fulfilled" ? agents.value.items : [],
        });
        setMemoryNodes(nodes.status === "fulfilled" ? nodes.value.items : []);
        setSearchWarnings(warnings);
        setBrainLoading(false);
      });
    }, 160);
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [open, query]);

  const allCommands = useMemo(() => {
    const visibleData = query.trim().length >= 2 && remoteMatches ? remoteMatches : data;
    const contextCommands = [...contextualRunCommands(contextualRun)];
    if (memorySource && contextualRun) {
      contextCommands.push({
        id: `memory-candidate-${memorySource.message.id}`,
        kind: "memory-candidate",
        group: "Commands",
        label: "Create memory candidate from latest Guided insight",
        description: "Review and send the latest Commander insight to the Memory Inbox; it is not auto-confirmed",
        keywords: [contextualRun.id, contextualRun.missionId, memorySource.message.body],
        action: "create-memory-candidate",
      });
    }
    return [
      ...JOURNEY_COMMANDS,
      ...contextCommands,
      ...NAVIGATION_COMMANDS,
      ...visibleData.missions.map(missionCommand),
      ...visibleData.runs.map(runCommand),
      ...visibleData.decisions.map(decisionCommand),
      ...visibleData.agents.map(agentCommand),
      ...memoryNodes.map(memoryCommand),
    ];
  }, [contextualRun, data, memoryNodes, memorySource, query, remoteMatches]);
  const filtered = useMemo(() => rankPaletteCommands(allCommands, query), [allCommands, query]);

  useEffect(() => setActiveIndex(0), [query]);
  useEffect(() => setActiveIndex((index) => Math.max(0, Math.min(filtered.length - 1, index))), [filtered.length]);
  useEffect(() => {
    document.getElementById(`command-palette-option-${activeIndex}`)?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  if (!open) return null;

  function resetEditor(): void {
    setEditor(undefined);
    setReason("");
    setCancelConfirmed(false);
    setMutationError(undefined);
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  function choose(command: PaletteCommand): void {
    if (command.path) {
      navigate(command.path);
      onClose();
      return;
    }
    if (command.kind === "run-control" && command.action && command.action !== "create-memory-candidate") {
      setEditor({ kind: "run-control", command: command.action });
      setReason("");
      setCancelConfirmed(false);
      setMutationError(undefined);
      return;
    }
    if (command.kind === "memory-candidate" && memorySource) {
      setMemoryDraft({
        nodeType: "source",
        title: suggestedMemoryTitle(memorySource.message),
        summary: suggestedMemorySummary(memorySource.message),
        scope: "mission",
        sensitivity: "private",
      });
      setEditor({ kind: "memory-candidate" });
      setMutationError(undefined);
    }
  }

  async function controlRun(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!contextualRun || editor?.kind !== "run-control" || reason.trim().length < 2) return;
    if (editor.command === "cancel" && !cancelConfirmed) return;
    const resumeBoundary = contextualSnapshot ? exactResumeBoundary(contextualSnapshot) : null;
    if (editor.command === "resume" && !resumeBoundary) {
      setMutationError("The exact verified zero-in-flight checkpoint is unavailable. Refresh the run before resuming.");
      return;
    }
    setMutationPending(true);
    setMutationError(undefined);
    try {
      const updated = await runtimeV2Api.controlRun(
        contextualRun.id,
        editor.command === "resume"
          ? { command: "resume", reason: reason.trim(), boundary: resumeBoundary! }
          : { command: editor.command, reason: reason.trim() },
        requestKey(`palette-run-${editor.command}`),
      );
      setContextualSnapshot(updated);
      setData((current) => ({
        ...current,
        runs: current.runs.map((run) => run.id === updated.run.id ? updated.run : run),
      }));
      cache.invalidate("ti-scale-overview");
      cache.invalidatePrefix("autonomous-runs");
      cache.invalidatePrefix("guided-runs");
      cache.invalidatePrefix("run:");
      cache.invalidatePrefix("mission-runtime:");
      cache.invalidatePrefix("guided-mission:");
      cache.invalidatePrefix("guided-current-decision:");
      setStatusMessage(`${editor.command === "cancel" ? "Cancelled" : editor.command === "pause" ? "Paused" : "Resumed"} ${updated.run.missionName}.`);
      resetEditor();
    } catch (error) {
      setMutationError(commandMutationErrorMessage(error));
    } finally {
      setMutationPending(false);
    }
  }

  async function createMemoryCandidate(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!contextualRun || !memorySource || editor?.kind !== "memory-candidate") return;
    setMutationPending(true);
    setMutationError(undefined);
    try {
      await guidedCommanderApi.remember(contextualRun.missionId, {
        runId: contextualRun.id,
        stepId: memorySource.step.id,
        expectedFingerprint: memorySource.step.actionFingerprint,
        sourceMessageId: memorySource.message.id,
        nodeType: memoryDraft.nodeType,
        title: memoryDraft.title.trim(),
        summary: memoryDraft.summary.trim(),
        scope: memoryDraft.scope,
        sensitivity: memoryDraft.sensitivity,
      }, requestKey("palette-memory-candidate"));
      cache.invalidate("brain-summary");
      cache.invalidatePrefix("brain-candidates");
      setStatusMessage("A reviewable candidate was created. It is not confirmed memory until you approve it in the Memory Inbox.");
      resetEditor();
    } catch (error) {
      setMutationError(commandMutationErrorMessage(error));
    } finally {
      setMutationPending(false);
    }
  }

  function trapFocus(event: KeyboardEvent<HTMLDivElement>): void {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      if (editor) resetEditor(); else onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = [...(dialogRef.current?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])',
    ) ?? [])].filter((element) => !element.hidden && element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable.at(-1)!;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  const grouped = GROUP_ORDER.map((group) => ({
    group,
    commands: filtered.map((command, index) => ({ command, index })).filter(({ command }) => command.group === group),
  })).filter(({ commands }) => commands.length > 0);
  const searchStatus = loading
    ? "Loading current missions, runs, decisions, and agents"
    : brainLoading
      ? "Searching permitted Second Brain memory"
      : `${filtered.length} command${filtered.length === 1 ? "" : "s"} available`;

  return (
    <div className="os-palette-layer" role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose();
    }}>
      <div ref={dialogRef} className="os-palette" role="dialog" aria-modal="true" aria-labelledby="command-palette-title" onKeyDown={trapFocus}>
        <h2 id="command-palette-title" className="os-visually-hidden">Command palette</h2>
        {editor?.kind === "run-control" ? (
          <form className="os-palette-editor" onSubmit={controlRun}>
            <div className="os-palette-editor-heading">
              <button type="button" className="os-palette-back" onClick={resetEditor} aria-label="Back to command results">←</button>
              <div><span>Run control</span><h3>{editor.command === "cancel" ? "Cancel" : editor.command === "pause" ? "Pause" : "Resume"} {contextualRun?.missionName}</h3></div>
            </div>
            <p>{editor.command === "pause"
              ? "Pause is attempted only at a safe durable checkpoint. If child work is in flight, the runtime will reject this request."
              : editor.command === "resume"
                ? "Resume continues from the last durable checkpoint under the existing journey and policy boundaries."
                : "Cancellation propagates to child work, releases leases, creates a checkpoint, and ends this run."}</p>
            <label>Audited reason<textarea required minLength={2} maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)} autoFocus /></label>
            {editor.command === "cancel" && <label className="os-palette-confirm"><input type="checkbox" checked={cancelConfirmed} onChange={(event) => setCancelConfirmed(event.target.checked)} /><span>I understand this ends the current run and does not expand authorization.</span></label>}
            {mutationError && <p className="os-palette-error" role="alert">{mutationError}</p>}
            {editor.command === "resume" && (!contextualSnapshot || !exactResumeBoundary(contextualSnapshot)) && <p className="os-palette-error" role="alert">The exact verified zero-in-flight checkpoint is unavailable. Refresh the run before resuming.</p>}
            <div className="os-palette-editor-actions"><button className={editor.command === "cancel" ? "is-danger" : "is-primary"} disabled={mutationPending || reason.trim().length < 2 || (editor.command === "cancel" && !cancelConfirmed) || (editor.command === "resume" && (!contextualSnapshot || !exactResumeBoundary(contextualSnapshot)))}>{mutationPending ? "Applying…" : `Confirm ${editor.command}`}</button></div>
          </form>
        ) : editor?.kind === "memory-candidate" ? (
          <form className="os-palette-editor" onSubmit={createMemoryCandidate}>
            <div className="os-palette-editor-heading">
              <button type="button" className="os-palette-back" onClick={resetEditor} aria-label="Back to command results">←</button>
              <div><span>Second Brain</span><h3>Create a reviewable memory candidate</h3></div>
            </div>
            <p>This references the latest Guided Commander insight and current exact step. It enters the Memory Inbox as a candidate and is never auto-confirmed.</p>
            <div className="os-palette-editor-grid">
              <label>Type<TitaniumSelect value={memoryDraft.nodeType} onChange={(event) => setMemoryDraft((draft) => ({ ...draft, nodeType: event.target.value as MemoryDraft["nodeType"], ...(event.target.value !== "preference" && draft.scope === "global" ? { scope: "mission" } : {}) }))}><option value="source">Source</option><option value="preference">Preference</option><option value="procedure">Procedure</option><option value="tool">Tool</option><option value="tactic">Tactic</option><option value="technique">Technique</option></TitaniumSelect></label>
              <label>Scope<TitaniumSelect value={memoryDraft.scope} onChange={(event) => setMemoryDraft((draft) => ({ ...draft, scope: event.target.value as MemoryDraft["scope"] }))}><option value="mission">This mission</option>{memorySource?.engagementAvailable && <option value="engagement">This engagement</option>}{memoryDraft.nodeType === "preference" && <option value="global">Global operator preference</option>}</TitaniumSelect></label>
              <label>Sensitivity<TitaniumSelect value={memoryDraft.sensitivity} onChange={(event) => setMemoryDraft((draft) => ({ ...draft, sensitivity: event.target.value as MemoryDraft["sensitivity"] }))}><option value="internal">Internal</option><option value="private">Private</option><option value="restricted">Restricted</option></TitaniumSelect></label>
            </div>
            <label>Title<input required maxLength={500} value={memoryDraft.title} onChange={(event) => setMemoryDraft((draft) => ({ ...draft, title: event.target.value }))} autoFocus /></label>
            <label>Summary<textarea required maxLength={4000} value={memoryDraft.summary} onChange={(event) => setMemoryDraft((draft) => ({ ...draft, summary: event.target.value }))} /></label>
            {mutationError && <p className="os-palette-error" role="alert">{mutationError}</p>}
            <div className="os-palette-editor-actions"><button className="is-primary" disabled={mutationPending || !memoryDraft.title.trim() || !memoryDraft.summary.trim()}>{mutationPending ? "Creating candidate…" : "Create candidate"}</button></div>
          </form>
        ) : (
          <>
            <label className="os-palette-search">
              <span className="os-visually-hidden">Search commands, missions, runs, decisions, agents, and Second Brain</span>
              <svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" /><path d="m16 16 5 5" /></svg>
              <input
                ref={inputRef}
                role="combobox"
                aria-label="Search commands, missions, runs, decisions, agents, and Second Brain"
                aria-expanded="true"
                aria-autocomplete="list"
                value={query}
                placeholder="Search missions, runs, decisions, agents, or memory…"
                onChange={(event) => {
                  const nextQuery = event.target.value;
                  const remoteSearch = nextQuery.trim().length >= 2;
                  setBrainLoading(remoteSearch);
                  setRemoteMatches(remoteSearch ? EMPTY_DATA : undefined);
                  setMemoryNodes([]);
                  setSearchWarnings([]);
                  setQuery(nextQuery);
                }}
                onKeyDown={(event) => {
                  if (event.key === "ArrowDown") {
                    event.preventDefault();
                    setActiveIndex((index) => Math.min(filtered.length - 1, index + 1));
                  }
                  if (event.key === "ArrowUp") {
                    event.preventDefault();
                    setActiveIndex((index) => Math.max(0, index - 1));
                  }
                  if (event.key === "Enter" && filtered[activeIndex]) {
                    event.preventDefault();
                    choose(filtered[activeIndex]);
                  }
                }}
                aria-controls="command-palette-results"
                aria-activedescendant={filtered[activeIndex] ? `command-palette-option-${activeIndex}` : undefined}
              />
              <kbd>Esc</kbd>
            </label>
            <p className="os-visually-hidden" role="status" aria-live="polite" aria-atomic="true">{searchStatus}</p>
            {statusMessage && <div className="os-palette-status" role="status"><span>{statusMessage}</span>{statusMessage.includes("candidate") && <button type="button" onClick={() => { navigate(contextualMemoryInboxPath); onClose(); }}>Open Memory Inbox</button>}</div>}
            {loadWarnings.length > 0 && <p className="os-palette-warning" role="status">Some live records are unavailable: {loadWarnings.join(", ")}. Available results remain authoritative.</p>}
            {searchWarnings.length > 0 && <p className="os-palette-warning" role="status">Search results are unavailable for: {searchWarnings.join(", ")}. Results from other domains remain authoritative.</p>}
            <div id="command-palette-results" className="os-palette-results" role="listbox" aria-label="Command results">
              {filtered.length === 0 && <p className="os-palette-empty">No matching permitted commands or records.</p>}
              {grouped.map(({ group, commands }) => <div role="group" aria-label={group} key={group} className="os-palette-group"><h3 aria-hidden="true">{group}</h3>{commands.map(({ command, index }) => (
                <button
                  type="button"
                  id={`command-palette-option-${index}`}
                  key={command.id}
                  role="option"
                  aria-selected={index === activeIndex}
                  className={`${index === activeIndex ? "is-active" : ""} ${command.danger ? "is-danger" : ""}`}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => choose(command)}
                >
                  <span><strong>{command.label}</strong><small>{command.description}</small></span>
                  <span aria-hidden="true">{command.danger ? "!" : "↵"}</span>
                </button>
              ))}</div>)}
              {loading && <p className="os-palette-loading">Loading real operational records…</p>}
              {brainLoading && <p className="os-palette-loading">Searching permitted Second Brain scopes…</p>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
