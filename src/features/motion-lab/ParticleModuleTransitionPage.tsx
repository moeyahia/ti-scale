import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ComponentType,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { AppLink } from "../../app/router/navigation";
import { Button, ButtonLink } from "../../design-system/components/Primitives";
import type {
  ParticleCoreCommand,
  ParticleCoreRuntimeProps,
  ParticleCoreStats,
} from "./ParticleCoreRuntime";
import { particleModuleDefinitions } from "./particleModuleGeometry";
import "./particle-module-transition.css";

interface TransitionStage {
  readonly id: string;
  readonly label: string;
  readonly title: string;
  readonly description: string;
}

const TRANSITION_STAGES: readonly TransitionStage[] = [
  {
    id: "coherent-core",
    label: "Coherent core",
    title: "One operational intelligence field.",
    description: "The approved titanium particle shell remains intact at the opening boundary.",
  },
  {
    id: "cluster-release",
    label: "Cluster release",
    title: "Fourteen regions disengage.",
    description: "The same particles separate by their existing deterministic clusters; no replacement artwork is loaded.",
  },
  {
    id: "module-alignment",
    label: "Module alignment",
    title: "The field resolves into product structure.",
    description: "Each cluster moves toward one real Ti-Scale surface while preserving particle identity and reversibility.",
  },
  {
    id: "operational-modules",
    label: "Operational modules",
    title: "The artwork becomes navigation.",
    description: "Fourteen particle panels align with keyboard-accessible links to real product routes. No synthetic mission data is shown.",
  },
] as const;

const STATIC_COMMAND: ParticleCoreCommand = { sequence: 0, type: "reset" };

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function clamp(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function isInteractiveTarget(target: EventTarget | null): boolean {
  return target instanceof Element && Boolean(target.closest("button, a, input, [role='application']"));
}

export default function ParticleModuleTransitionPage() {
  const [Runtime, setRuntime] = useState<ComponentType<ParticleCoreRuntimeProps>>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [runtimeKey, setRuntimeKey] = useState(0);
  const [stats, setStats] = useState<ParticleCoreStats>();
  const [scrollProgress, setScrollProgress] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(prefersReducedMotion);
  const [visibility, setVisibility] = useState<"active" | "paused-hidden">(() => (
    typeof document !== "undefined" && document.visibilityState === "hidden" ? "paused-hidden" : "active"
  ));
  const scrollerRef = useRef<HTMLElement>(null);
  const scrollFrameRef = useRef(0);
  const phaseCommandFrameRef = useRef(0);

  useEffect(() => {
    let active = true;
    void import("./ParticleCoreRuntime").then(
      (module) => { if (active) setRuntime(() => module.default); },
      () => { if (active) setRuntimeError("The local WebGL transition renderer could not load. The complete non-motion module map remains available."); },
    );
    return () => { active = false; };
  }, [runtimeKey]);

  useEffect(() => {
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const updateMotion = () => setReducedMotion(motion.matches);
    const updateVisibility = () => setVisibility(document.visibilityState === "hidden" ? "paused-hidden" : "active");
    updateMotion();
    updateVisibility();
    motion.addEventListener("change", updateMotion);
    document.addEventListener("visibilitychange", updateVisibility);
    return () => {
      motion.removeEventListener("change", updateMotion);
      document.removeEventListener("visibilitychange", updateVisibility);
      if (scrollFrameRef.current) cancelAnimationFrame(scrollFrameRef.current);
      if (phaseCommandFrameRef.current) cancelAnimationFrame(phaseCommandFrameRef.current);
    };
  }, []);

  const activeStageIndex = Math.max(0, Math.min(
    TRANSITION_STAGES.length - 1,
    Math.round(scrollProgress * (TRANSITION_STAGES.length - 1)),
  ));
  const activeStage = TRANSITION_STAGES[activeStageIndex] ?? TRANSITION_STAGES[0]!;
  const phaseProgress = scrollProgress * (TRANSITION_STAGES.length - 1);
  const explosionProgress = clamp(phaseProgress);
  const moduleProgress = clamp((phaseProgress - 1) / 2);
  const modulesReady = moduleProgress >= 0.94;

  const readScrollPosition = useCallback(() => {
    scrollFrameRef.current = 0;
    const scroller = scrollerRef.current;
    if (!scroller) return;
    const paginatedDistance = Math.max(1, scroller.clientHeight * (TRANSITION_STAGES.length - 1));
    setScrollProgress(clamp(scroller.scrollTop / paginatedDistance));
  }, []);

  const onScroll = useCallback(() => {
    if (scrollFrameRef.current) return;
    scrollFrameRef.current = requestAnimationFrame(readScrollPosition);
  }, [readScrollPosition]);

  const goToStage = useCallback((index: number) => {
    const scroller = scrollerRef.current;
    if (!scroller) return;
    const boundedIndex = Math.max(0, Math.min(TRANSITION_STAGES.length - 1, index));
    // Direct phase commands lock the pagination position immediately; the
    // procedural field itself performs the mechanical easing. Natural wheel,
    // trackpad, and touch scrolling remain continuously reversible.
    scroller.dataset.phaseCommand = "true";
    void scroller.offsetHeight;
    scroller.scrollTop = boundedIndex * scroller.clientHeight;
    setScrollProgress(boundedIndex / (TRANSITION_STAGES.length - 1));
    if (phaseCommandFrameRef.current) cancelAnimationFrame(phaseCommandFrameRef.current);
    phaseCommandFrameRef.current = requestAnimationFrame(() => {
      phaseCommandFrameRef.current = 0;
      delete scroller.dataset.phaseCommand;
    });
  }, []);

  const moveStage = useCallback((direction: -1 | 1) => {
    const scroller = scrollerRef.current;
    if (!scroller) return;
    const currentIndex = Math.round(scroller.scrollTop / Math.max(1, scroller.clientHeight));
    goToStage(currentIndex + direction);
  }, [goToStage]);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (isInteractiveTarget(event.target)) return;
    if (["ArrowDown", "PageDown"].includes(event.key)) {
      event.preventDefault();
      moveStage(1);
    } else if (["ArrowUp", "PageUp"].includes(event.key)) {
      event.preventDefault();
      moveStage(-1);
    } else if (event.key === "Home") {
      event.preventDefault();
      goToStage(0);
    } else if (event.key === "End") {
      event.preventDefault();
      goToStage(TRANSITION_STAGES.length - 1);
    }
  };

  const retryRuntime = () => {
    setStats(undefined);
    setRuntimeError(undefined);
    setRuntime(undefined);
    setRuntimeKey((value) => value + 1);
  };

  const runtimeLabel = reducedMotion
    ? "Static titanium particle transformation. Use the phase controls to inspect the core, separated clusters, alignment, and module geometry."
    : "Interactive titanium particle transformation. Scroll or use the phase controls to disassemble the core and reform it as product modules.";

  const stageStyle = useMemo(() => ({
    "--particle-module-progress": moduleProgress.toFixed(4),
  }) as CSSProperties, [moduleProgress]);

  return (
    <main
      ref={scrollerRef}
      className="particle-module-transition"
      data-review-boundary="review-only"
      data-transition-section={activeStage.id}
      data-transition-progress={scrollProgress.toFixed(4)}
      data-module-progress={moduleProgress.toFixed(4)}
      data-reduced-motion={reducedMotion ? "true" : "false"}
      data-motion-state={visibility}
      data-runtime-ready={stats ? "true" : "false"}
      aria-label="Particle-to-module transition review"
      tabIndex={0}
      onKeyDown={onKeyDown}
      onScroll={onScroll}
      style={stageStyle}
    >
      <div className="particle-module-transition__sticky">
        <header className="particle-module-transition__masthead">
          <div>
            <p>TI-SCALE · MOTION LAB · REVIEW BOUNDARY</p>
            <h1>Particle field to operational modules</h1>
            <span>Paginated scroll study · reversible cluster transformation</span>
          </div>
          <div>
            <span className="particle-module-transition__review-state">Review only · not integrated into Overview</span>
            <ButtonLink href="/motion-lab" variant="quiet">Return to Motion Lab</ButtonLink>
          </div>
        </header>

        <section className="particle-module-transition__visual" aria-label="Procedural particle transformation stage">
          {Runtime && !runtimeError ? (
            <Runtime
              key={runtimeKey}
              className="particle-module-transition__runtime"
              progress={explosionProgress}
              moduleProgress={moduleProgress}
              reducedMotion={reducedMotion}
              autoRotate={!reducedMotion && scrollProgress < 0.12}
              hoverEnabled={!reducedMotion && !modulesReady}
              command={STATIC_COMMAND}
              ariaLabel={runtimeLabel}
              onReady={setStats}
              onError={setRuntimeError}
            />
          ) : runtimeError ? (
            <div className="particle-module-transition__fallback" role="alert">
              <strong>Animated transition unavailable</strong>
              <p>{runtimeError}</p>
              <Button type="button" variant="secondary" onClick={retryRuntime}>Retry transition renderer</Button>
            </div>
          ) : (
            <div className="particle-module-transition__loader" role="status" aria-live="polite">
              <span aria-hidden="true" />
              <strong>Preparing the approved particle field</strong>
              <small>No image, texture, or model download</small>
            </div>
          )}

          <nav
            className={`particle-module-transition__modules ${modulesReady ? "is-ready" : ""}`}
            aria-label="Operational modules formed from particle clusters"
            aria-hidden={modulesReady ? undefined : true}
          >
            {particleModuleDefinitions.map((module, index) => (
              <AppLink
                key={module.id}
                href={module.href}
                className="particle-module-transition__module"
                tabIndex={modulesReady ? 0 : -1}
                aria-label={`Open ${module.label}: ${module.summary}`}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{module.label}</strong>
                <small>{module.summary}</small>
              </AppLink>
            ))}
          </nav>
        </section>

        <aside className="particle-module-transition__readout" aria-live="polite" aria-atomic="true">
          <span>{String(activeStageIndex + 1).padStart(2, "0")} / {String(TRANSITION_STAGES.length).padStart(2, "0")}</span>
          <div>
            <strong>{activeStage.label}</strong>
            <small>{stats ? `${stats.pointCount.toLocaleString()} local particles · one draw call` : "Deterministic local geometry"}</small>
          </div>
        </aside>

        <nav className="particle-module-transition__phase-rail" aria-label="Particle transformation phases">
          {TRANSITION_STAGES.map((stage, index) => (
            <button
              key={stage.id}
              type="button"
              aria-label={`View transition phase ${index + 1}: ${stage.label}`}
              aria-current={activeStageIndex === index ? "step" : undefined}
              onClick={() => goToStage(index)}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              <i aria-hidden="true" />
            </button>
          ))}
        </nav>

        <div className="particle-module-transition__step-controls">
          <Button
            type="button"
            variant="secondary"
            aria-label="Previous transition phase"
            disabled={activeStageIndex === 0}
            onClick={() => moveStage(-1)}
          >Previous</Button>
          <Button
            type="button"
            variant="secondary"
            aria-label="Next transition phase"
            disabled={activeStageIndex === TRANSITION_STAGES.length - 1}
            onClick={() => moveStage(1)}
          >Next</Button>
        </div>
      </div>

      <div className="particle-module-transition__scroll-track">
        {TRANSITION_STAGES.map((stage, index) => (
          <section
            key={stage.id}
            className="particle-module-transition__chapter"
            aria-labelledby={`particle-module-stage-${stage.id}`}
            data-stage-index={index}
          >
            <div>
              <p>{stage.label}</p>
              <h2 id={`particle-module-stage-${stage.id}`}>{stage.title}</h2>
              <span>{stage.description}</span>
            </div>
          </section>
        ))}
      </div>

      <p className="particle-module-transition__instructions">
        {reducedMotion
          ? "Reduced motion is active. Phase changes are immediate; every module remains available as a named link in the final section."
          : "Scroll one section at a time, use Page Up or Page Down, or choose a numbered phase. Reverse direction at any point to reassemble the core."}
      </p>
    </main>
  );
}
