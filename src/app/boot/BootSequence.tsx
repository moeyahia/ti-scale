import {
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { ParticleBootMark } from "./ParticleBootMark";
import "./boot-sequence.css";

export type BootSequencePhase = "orbiting" | "aligning" | "locked" | "handoff" | "complete";

export interface BootReadiness {
  readonly ready: boolean;
  readonly status: string;
  readonly next: string;
}

export const BOOT_SEQUENCE_TIMING = Object.freeze({
  alignMs: 400,
  lockMs: 760,
  earliestHandoffMs: 960,
  handoffMs: 240,
  settledHoldMs: 120,
  elapsedRefreshMs: 1_000,
  safetyCompleteMs: 1_450,
});

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const BOOT_PHASE_ORDER: Readonly<Record<BootSequencePhase, number>> = Object.freeze({
  orbiting: 0,
  aligning: 1,
  locked: 2,
  handoff: 3,
  complete: 4,
});

function monotonicNow(): number {
  return typeof performance === "undefined" ? Date.now() : performance.now();
}

function initiallySettled(): boolean {
  if (typeof window === "undefined") return false;
  return document.visibilityState === "hidden" || window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

export function formatBootElapsed(milliseconds: number): string {
  return `${(Math.max(0, milliseconds) / 1_000).toFixed(1)}s elapsed`;
}

export function bootPhaseLabel(phase: BootSequencePhase, readiness: BootReadiness): string {
  if (phase === "orbiting") return "Synchronizing titanium particles";
  if (phase === "aligning") return "Forming Command Center core";
  if (phase === "handoff") return `Core locked · Opening ${readiness.next}`;
  if (phase === "complete") return `${readiness.next} ready`;
  return readiness.ready ? "Command core formed" : "Command core formed · Startup still in progress";
}

/**
 * One document-owned startup choreography. It never owns routing and never
 * remounts its application child, so the formed core can hand directly to the
 * real Command Center without a blank or duplicate hero frame.
 */
export function BootSequence({
  children,
  readiness,
}: {
  readonly children: ReactNode;
  readonly readiness: BootReadiness;
}) {
  const settledOnFirstPaint = useRef(initiallySettled()).current;
  const startedAtRef = useRef(monotonicNow());
  const phaseRef = useRef<BootSequencePhase>(settledOnFirstPaint ? "locked" : "orbiting");
  const settledEarlyRef = useRef(settledOnFirstPaint);
  const readinessReadyRef = useRef(readiness.ready);
  readinessReadyRef.current = readiness.ready;
  const [phase, setPhase] = useState<BootSequencePhase>(phaseRef.current);
  const [documentHidden, setDocumentHidden] = useState(() => (
    typeof document !== "undefined" && document.visibilityState === "hidden"
  ));
  const [elapsedMs, setElapsedMs] = useState(0);

  const transitionTo = useCallback((next: BootSequencePhase) => {
    // Timer, visibility, and media-query callbacks can cross in the same task.
    // Keep startup strictly forward-only so a stale locked render can never
    // regress complete -> handoff and recreate the visual boundary.
    if (BOOT_PHASE_ORDER[next] <= BOOT_PHASE_ORDER[phaseRef.current]) return;
    phaseRef.current = next;
    setPhase(next);
    setElapsedMs(monotonicNow() - startedAtRef.current);
  }, []);

  useEffect(() => {
    const reducedMotion = window.matchMedia(REDUCED_MOTION_QUERY);
    let alignTimer: number | undefined;
    let lockTimer: number | undefined;
    let visibilityTimer: number | undefined;
    let motionPreferenceTimer: number | undefined;
    let mounted = true;

    const settle = () => {
      if (phaseRef.current === "complete") return;
      settledEarlyRef.current = true;
      // Headless WebKit can report a hidden initial document without later
      // delivering visibilitychange. A resolved startup must never leave the
      // application inert behind an unseen animation.
      transitionTo(readinessReadyRef.current ? "complete" : "locked");
    };
    const onVisibilityChange = () => {
      const hidden = document.visibilityState === "hidden";
      // Firefox may deliver visibilitychange synchronously while React is
      // rendering the old document during reload. Defer this external browser
      // notification to a new task so it can never update BootSequence while
      // another component is rendering. A navigation teardown will cancel the
      // task during effect cleanup.
      if (visibilityTimer !== undefined) window.clearTimeout(visibilityTimer);
      visibilityTimer = window.setTimeout(() => {
        visibilityTimer = undefined;
        if (!mounted) return;
        setDocumentHidden(hidden);
        if (hidden) settle();
      }, 0);
    };
    const onMotionPreferenceChange = () => {
      if (motionPreferenceTimer !== undefined) {
        window.clearTimeout(motionPreferenceTimer);
      }
      motionPreferenceTimer = window.setTimeout(() => {
        motionPreferenceTimer = undefined;
        if (mounted && reducedMotion.matches) settle();
      }, 0);
    };

    if (reducedMotion.matches || document.visibilityState === "hidden") {
      settle();
    } else {
      const elapsed = monotonicNow() - startedAtRef.current;
      alignTimer = window.setTimeout(() => {
        if (!settledEarlyRef.current && phaseRef.current === "orbiting") transitionTo("aligning");
      }, Math.max(0, BOOT_SEQUENCE_TIMING.alignMs - elapsed));
      lockTimer = window.setTimeout(() => {
        if (!settledEarlyRef.current && phaseRef.current !== "complete") transitionTo("locked");
      }, Math.max(0, BOOT_SEQUENCE_TIMING.lockMs - elapsed));
    }

    document.addEventListener("visibilitychange", onVisibilityChange);
    reducedMotion.addEventListener("change", onMotionPreferenceChange);
    return () => {
      mounted = false;
      if (alignTimer !== undefined) window.clearTimeout(alignTimer);
      if (lockTimer !== undefined) window.clearTimeout(lockTimer);
      if (visibilityTimer !== undefined) window.clearTimeout(visibilityTimer);
      if (motionPreferenceTimer !== undefined) {
        window.clearTimeout(motionPreferenceTimer);
      }
      document.removeEventListener("visibilitychange", onVisibilityChange);
      reducedMotion.removeEventListener("change", onMotionPreferenceChange);
    };
  }, [transitionTo]);

  useEffect(() => {
    if (phase !== "locked" || readiness.ready) return undefined;
    const updateElapsed = () => setElapsedMs(monotonicNow() - startedAtRef.current);
    updateElapsed();
    const elapsedTimer = window.setInterval(updateElapsed, BOOT_SEQUENCE_TIMING.elapsedRefreshMs);
    return () => window.clearInterval(elapsedTimer);
  }, [phase, readiness.ready]);

  useEffect(() => {
    if (readiness.ready && settledEarlyRef.current) transitionTo("complete");
  }, [readiness.ready, transitionTo]);

  useEffect(() => {
    if (phase !== "locked" || !readiness.ready || documentHidden) return undefined;
    const minimum = settledEarlyRef.current
      ? BOOT_SEQUENCE_TIMING.settledHoldMs
      : BOOT_SEQUENCE_TIMING.earliestHandoffMs;
    const delay = Math.max(0, minimum - (monotonicNow() - startedAtRef.current));
    const handoffTimer = window.setTimeout(() => {
      if (phaseRef.current === "locked") transitionTo("handoff");
    }, delay);
    return () => window.clearTimeout(handoffTimer);
  }, [documentHidden, phase, readiness.ready, transitionTo]);

  useEffect(() => {
    if (phase !== "handoff") return undefined;
    const completionTimer = window.setTimeout(
      () => transitionTo("complete"),
      BOOT_SEQUENCE_TIMING.handoffMs,
    );
    return () => window.clearTimeout(completionTimer);
  }, [phase, transitionTo]);

  useEffect(() => {
    if (!readiness.ready || phaseRef.current === "complete") return undefined;
    const remaining = Math.max(
      0,
      BOOT_SEQUENCE_TIMING.safetyCompleteMs - (monotonicNow() - startedAtRef.current),
    );
    const safetyTimer = window.setTimeout(() => transitionTo("complete"), remaining);
    return () => window.clearTimeout(safetyTimer);
  }, [readiness.ready, transitionTo]);

  const blocking = phase !== "complete";
  const phaseLabel = bootPhaseLabel(phase, readiness);

  return (
    <div
      className="ti-boot-boundary"
      data-ti-boot-boundary="startup"
      data-ti-boot-phase={phase}
      data-ti-boot-readiness={readiness.ready ? "ready" : "pending"}
      data-ti-boot-sequence-count="1"
      aria-busy={blocking}
    >
      <fieldset
        className="ti-boot-boundary__application"
        disabled={blocking}
        aria-hidden={blocking || undefined}
        inert={blocking}
      >
        {children}
      </fieldset>

      <div
        className="ti-boot-sequence"
        data-ti-boot-sequence="startup"
        data-ti-boot-phase={phase}
        data-ti-boot-readiness={readiness.ready ? "ready" : "pending"}
        data-document-hidden={documentHidden || undefined}
        role="status"
        aria-live="polite"
        aria-atomic="true"
        hidden={!blocking}
      >
        <div className="ti-boot-sequence__mechanism" aria-hidden="true">
          <span className="ti-boot-sequence__particle-wake" />
          <ParticleBootMark />
          <span className="ti-boot-sequence__particle-lock" />
        </div>

        <p className="ti-boot-sequence__status">
          <strong>{phaseLabel}</strong>
          <span>{readiness.status}</span>
          <small>{formatBootElapsed(elapsedMs)} · Next: {readiness.next}</small>
        </p>
      </div>
    </div>
  );
}
