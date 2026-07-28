import { createContext, type ReactNode, useContext, useLayoutEffect, useMemo, useRef, useState } from "react";
import { parseOperationalEvent } from "../../domain/schemas/commandOs";
import type { OperationalEvent } from "../../domain/types/commandOs";
import { isActionableNotificationEvent } from "../../domain/notificationEventRegistry";
import { useQueryCache } from "../cache/QueryProvider";
import { BROWSER_STORAGE_KEYS } from "../../lib/browserNamespaces";
import {
  FALLBACK_REFRESH_INTERVAL_MS,
  reconnectDelayMs,
  shouldUseAuthoritativeFallback,
  STREAM_FAILURES_BEFORE_FALLBACK,
} from "./eventStreamPolicy";

export type EventConnectionState = "connecting" | "connected" | "reconnecting" | "fallback" | "offline";

interface EventStreamContextValue {
  state: EventConnectionState;
  lastEvent?: OperationalEvent;
  fallbackActive: boolean;
  lastFallbackRefreshAt?: string;
}

interface ReplayPage {
  readonly events: readonly unknown[];
  readonly afterSequence: number;
  readonly hasMore: boolean;
}

const LAST_EVENT_STORAGE_KEY = BROWSER_STORAGE_KEYS.eventResume;
const MAX_DEDUPE_IDS = 2_000;

export function invalidateNotificationQueries(
  cache: Pick<ReturnType<typeof useQueryCache>, "invalidate">,
  event: Pick<OperationalEvent, "type" | "journey">,
): boolean {
  if (!isActionableNotificationEvent(event.type, event.journey)) return false;
  cache.invalidate("notifications:recent");
  cache.invalidate("notifications:unread");
  return true;
}

function readLastEventId(): string {
  try {
    const durable = localStorage.getItem(LAST_EVENT_STORAGE_KEY);
    if (durable) return durable;
    const sessionResume = sessionStorage.getItem(LAST_EVENT_STORAGE_KEY) ?? "";
    if (sessionResume) localStorage.setItem(LAST_EVENT_STORAGE_KEY, sessionResume);
    return sessionResume;
  } catch {
    try { return sessionStorage.getItem(LAST_EVENT_STORAGE_KEY) ?? ""; } catch { return ""; }
  }
}

function persistLastEventId(value: string): void {
  try { localStorage.setItem(LAST_EVENT_STORAGE_KEY, value); } catch {}
  try { sessionStorage.setItem(LAST_EVENT_STORAGE_KEY, value); } catch {}
}

function forgetLastEventId(): void {
  try { localStorage.removeItem(LAST_EVENT_STORAGE_KEY); } catch {}
  try { sessionStorage.removeItem(LAST_EVENT_STORAGE_KEY); } catch {}
}

function replayPage(value: unknown): ReplayPage {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid event replay page");
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.events) || !Number.isSafeInteger(record.afterSequence) || typeof record.hasMore !== "boolean") {
    throw new Error("Invalid event replay page");
  }
  return {
    events: record.events,
    afterSequence: record.afterSequence as number,
    hasMore: record.hasMore,
  };
}

const EventStreamContext = createContext<EventStreamContextValue | null>(null);

export function EventStreamProvider({ children }: { children: ReactNode }) {
  const cache = useQueryCache();
  const [state, setState] = useState<EventConnectionState>("connecting");
  const [lastEvent, setLastEvent] = useState<OperationalEvent>();
  const [fallbackActive, setFallbackActive] = useState(false);
  const [lastFallbackRefreshAt, setLastFallbackRefreshAt] = useState<string>();
  const retries = useRef(0);
  const sourceRef = useRef<EventSource | undefined>(undefined);
  const effectGenerationRef = useRef(0);

  useLayoutEffect(() => {
    const effectGeneration = effectGenerationRef.current + 1;
    effectGenerationRef.current = effectGeneration;
    let source = sourceRef.current;
    let reconnectTimer: number | undefined;
    let fallbackTimer: number | undefined;
    let fallbackRunning = false;
    let stopped = false;
    let deliveryChain = Promise.resolve();
    const sequences = new Map<string, number>();
    const seen = new Set<string>();
    const seenOrder: string[] = [];
    let lastEventId = readLastEventId();

    const onlineAndVisible = () => navigator.onLine && document.visibilityState !== "hidden";

    const stopFallback = () => {
      fallbackRunning = false;
      if (fallbackTimer !== undefined) {
        window.clearTimeout(fallbackTimer);
        fallbackTimer = undefined;
      }
      if (!stopped) setFallbackActive(false);
    };

    const fallbackRefresh = () => {
      if (stopped || !fallbackRunning || !onlineAndVisible()) {
        stopFallback();
        return;
      }
      const refreshedAt = new Date().toISOString();
      setLastFallbackRefreshAt(refreshedAt);
      cache.invalidateSubscribed();
      fallbackTimer = window.setTimeout(fallbackRefresh, FALLBACK_REFRESH_INTERVAL_MS);
    };

    const startFallback = () => {
      if (fallbackRunning || !onlineAndVisible()) return;
      fallbackRunning = true;
      setFallbackActive(true);
      setState("fallback");
      // Reconcile immediately once, then remain deliberately low-frequency.
      fallbackRefresh();
    };

    const rememberId = (id: string) => {
      if (seen.has(id)) return false;
      seen.add(id);
      seenOrder.push(id);
      if (seenOrder.length > MAX_DEDUPE_IDS) {
        const evicted = seenOrder.shift();
        if (evicted) seen.delete(evicted);
      }
      return true;
    };

    const invalidateFor = (event: OperationalEvent) => {
      cache.invalidate("ti-scale-overview");
      if (event.missionId) {
        cache.invalidate(`mission-runtime:${event.missionId}`);
        cache.invalidatePrefix(`guided-mission:${event.missionId}`);
      }
      if (event.runId) {
        cache.invalidate(`run:${event.runId}`);
        cache.invalidate(`run-plans:${event.runId}`);
        cache.invalidate(`run-events:${event.runId}`);
      }
      cache.invalidatePrefix("observability-events:");
      cache.invalidatePrefix("observability-health:");
      // Notifications are an idempotent projection of a small, explicit
      // journey-aware event registry. Ordinary operational events must not
      // create notification reads or copy raw event payload into client state.
      invalidateNotificationQueries(cache, event);
      const type = event.type.toLowerCase();
      if (event.journey === "autonomous") cache.invalidate("autonomous-runs");
      if (event.journey === "guided") cache.invalidate("guided-runs");
      if (type.includes("decision")) cache.invalidatePrefix("guided-decision");
      if (type.includes("evidence")) cache.invalidatePrefix("evidence:");
      if (type.includes("finding")) cache.invalidatePrefix("finding");
      if (type.includes("artifact") || type.includes("report")) {
        cache.invalidatePrefix("artifact");
        cache.invalidatePrefix("report");
      }
      if (type.includes("assignment") || type.includes("agent")) cache.invalidatePrefix("agent");
      if (type.includes("memory") || type.includes("context") || type.includes("vault")) cache.invalidatePrefix("brain-");
      if (type.includes("lesson") || type.includes("evaluation")) {
        cache.invalidatePrefix("lesson");
        cache.invalidatePrefix("evaluation");
      }
      if (type.includes("health") || type.includes("provider") || type.includes("mcp")) cache.invalidatePrefix("system-");
    };

    const applyEvent = (event: OperationalEvent) => {
      if (!rememberId(event.id)) return;
      if (event.runId && event.sequence !== undefined) {
        const prior = sequences.get(event.runId) ?? 0;
        sequences.set(event.runId, Math.max(prior, event.sequence));
      }
      setLastEvent(event);
      invalidateFor(event);
    };

    const repairGap = async (runId: string, afterSequence: number, expectedSequence: number) => {
      let cursor = afterSequence;
      // Bounded replay prevents one pathological run from monopolizing the UI.
      for (let pageNumber = 0; pageNumber < 20 && cursor < expectedSequence - 1; pageNumber += 1) {
        const response = await fetch(`/api/v2/events/gap?runId=${encodeURIComponent(runId)}&afterSequence=${cursor}&limit=500`, {
          credentials: "same-origin",
          cache: "no-store",
          headers: { Accept: "application/json" },
        });
        if (!response.ok) throw new Error(`Event gap replay failed with HTTP ${response.status}`);
        const page = replayPage(await response.json());
        for (const raw of page.events) applyEvent(parseOperationalEvent(raw));
        if (page.afterSequence <= cursor || !page.hasMore) break;
        cursor = page.afterSequence;
      }
    };

    const processMessage = async (message: MessageEvent<string>) => {
      const event = parseOperationalEvent(JSON.parse(message.data) as unknown);
      if (seen.has(event.id)) return;
      if (event.runId && event.sequence !== undefined) {
        const prior = sequences.get(event.runId) ?? 0;
        if (prior > 0 && event.sequence > prior + 1) {
          await repairGap(event.runId, prior, event.sequence);
        }
      }
      applyEvent(event);
      if (message.lastEventId) {
        lastEventId = message.lastEventId;
        persistLastEventId(lastEventId);
      }
    };

    const retainSource = (next: EventSource | undefined) => {
      source = next;
      sourceRef.current = next;
    };

    const bindSource = (currentSource: EventSource) => {
      retainSource(currentSource);
      currentSource.onopen = () => {
        if (source !== currentSource || stopped) return;
        retries.current = 0;
        stopFallback();
        setState("connected");
      };
      currentSource.onmessage = (message) => {
        if (source !== currentSource || stopped) return;
        deliveryChain = deliveryChain
          .then(() => processMessage(message))
          .catch(() => {
            // Reconcile authoritative views if a malformed event or replay gap
            // prevents incremental application; never apply unvalidated data.
            cache.invalidate("ti-scale-overview");
            cache.invalidatePrefix("run:");
          });
      };
      currentSource.onerror = () => {
        if (source !== currentSource || stopped) return;
        currentSource.close();
        retainSource(undefined);
        retries.current += 1;
        if (retries.current === STREAM_FAILURES_BEFORE_FALLBACK && lastEventId) {
          // The retained event may have aged out. Clear it after bounded retry
          // so a fresh stream can reconnect; the authoritative query fallback
          // reconciles any state that changed while incremental replay failed.
          lastEventId = "";
          forgetLastEventId();
        }
        if (shouldUseAuthoritativeFallback({
          consecutiveFailures: retries.current,
          online: navigator.onLine,
          visible: document.visibilityState !== "hidden",
        })) {
          startFallback();
        } else {
          setState(navigator.onLine ? "reconnecting" : "offline");
        }
        if (navigator.onLine && document.visibilityState !== "hidden") {
          reconnectTimer = window.setTimeout(connect, reconnectDelayMs(retries.current));
        }
      };
      if (currentSource.readyState === EventSource.OPEN) {
        retries.current = 0;
        stopFallback();
        setState("connected");
      }
    };

    const connect = () => {
      if (stopped || document.visibilityState === "hidden") return;
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      source?.close();
      retainSource(undefined);
      if (!fallbackRunning) setState(retries.current === 0 ? "connecting" : "reconnecting");
      const query = lastEventId ? `?lastEventId=${encodeURIComponent(lastEventId)}` : "";
      const currentSource = new EventSource(`/api/v2/events/stream${query}`, { withCredentials: true });
      bindSource(currentSource);
    };

    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        source?.close();
        retainSource(undefined);
        if (reconnectTimer !== undefined) {
          window.clearTimeout(reconnectTimer);
          reconnectTimer = undefined;
        }
        stopFallback();
      } else {
        retries.current = 0;
        connect();
      }
    };
    const onOffline = () => {
      source?.close();
      retainSource(undefined);
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      stopFallback();
      setState("offline");
    };
    const onOnline = () => {
      source?.close();
      retainSource(undefined);
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      retries.current = 0;
      connect();
    };
    const onPageHide = () => {
      source?.close();
      retainSource(undefined);
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      stopFallback();
    };

    // Establish the one retained stream in the pre-paint layout phase so
    // noncritical same-origin media cannot consume every HTTP/1.1 slot first.
    // React Strict Mode's setup -> cleanup -> setup probe reuses this exact
    // EventSource through sourceRef; the generation-bound deferred cleanup
    // below closes it only for a real unmount, never to create a ghost request.
    if (source && source.readyState !== EventSource.CLOSED) bindSource(source);
    else connect();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("offline", onOffline);
    window.addEventListener("online", onOnline);
    window.addEventListener("pagehide", onPageHide, { capture: true });
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      if (fallbackTimer !== undefined) window.clearTimeout(fallbackTimer);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("offline", onOffline);
      window.removeEventListener("online", onOnline);
      window.removeEventListener("pagehide", onPageHide, { capture: true });
      queueMicrotask(() => {
        if (effectGenerationRef.current !== effectGeneration) return;
        const retainedSource = sourceRef.current;
        retainedSource?.close();
        if (sourceRef.current === retainedSource) sourceRef.current = undefined;
      });
    };
  }, [cache]);

  const value = useMemo(
    () => ({ state, lastEvent, fallbackActive, lastFallbackRefreshAt }),
    [state, lastEvent, fallbackActive, lastFallbackRefreshAt],
  );
  return <EventStreamContext.Provider value={value}>{children}</EventStreamContext.Provider>;
}

export function useEventStream(): EventStreamContextValue {
  const value = useContext(EventStreamContext);
  if (!value) throw new Error("useEventStream must be used inside EventStreamProvider");
  return value;
}
