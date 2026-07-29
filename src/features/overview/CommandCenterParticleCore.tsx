import {
  useEffect,
  useState,
  type ComponentType,
} from "react";
import type {
  ParticleCoreRuntimeProps,
  ParticleCoreStats,
} from "../motion-lab/ParticleCoreRuntime";

const STATIC_COMMAND = Object.freeze({ sequence: 0, type: "reset" as const });
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const BOOT_BOUNDARY_SELECTOR = '[data-ti-boot-boundary="startup"]';
const BOOT_COMPLETE_PHASE = "complete";

function initialReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

export function CommandCenterParticleCore() {
  const [Runtime, setRuntime] = useState<ComponentType<ParticleCoreRuntimeProps>>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [stats, setStats] = useState<ParticleCoreStats>();
  const [reducedMotion, setReducedMotion] = useState(initialReducedMotion);

  useEffect(() => {
    let active = true;
    let bootObserver: MutationObserver | undefined;
    let idleHandle: number | undefined;
    let timerHandle: ReturnType<typeof setTimeout> | undefined;
    let runtimeQueued = false;
    const loadRuntime = () => {
      void import("../motion-lab/ParticleCoreRuntime").then(
        (module) => { if (active) setRuntime(() => module.default); },
        () => { if (active) setRuntimeError("The interactive particle field is unavailable. Ti-Scale remains fully operable."); },
      );
    };
    const queueRuntime = () => {
      if (!active || runtimeQueued) return;
      runtimeQueued = true;
      if (typeof window.requestIdleCallback === "function") {
        idleHandle = window.requestIdleCallback(loadRuntime, { timeout: 800 });
      } else {
        timerHandle = globalThis.setTimeout(loadRuntime, 120);
      }
    };
    const bootBoundary = document.querySelector<HTMLElement>(BOOT_BOUNDARY_SELECTOR);
    if (!bootBoundary || bootBoundary.dataset.tiBootPhase === BOOT_COMPLETE_PHASE) {
      queueRuntime();
    } else {
      bootObserver = new MutationObserver(() => {
        if (bootBoundary.dataset.tiBootPhase !== BOOT_COMPLETE_PHASE) return;
        bootObserver?.disconnect();
        queueRuntime();
      });
      bootObserver.observe(bootBoundary, {
        attributes: true,
        attributeFilter: ["data-ti-boot-phase"],
      });
    }
    return () => {
      active = false;
      bootObserver?.disconnect();
      if (idleHandle !== undefined) window.cancelIdleCallback(idleHandle);
      if (timerHandle !== undefined) clearTimeout(timerHandle);
    };
  }, []);

  useEffect(() => {
    const media = window.matchMedia(REDUCED_MOTION_QUERY);
    const update = () => setReducedMotion(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return (
    <div
      className="os-brand-media ti-command-particle-core"
      data-ti-transformer-core="true"
      data-ti-exploded-model="approved-particle-core"
      data-ti-particle-artwork="operator-approved"
      data-ti-particle-status={runtimeError ? "fallback" : stats ? "active" : "loading"}
      data-ti-point-count={stats?.pointCount ?? undefined}
      data-ti-draw-calls={stats?.drawCalls ?? undefined}
    >
      <span className="ti-command-particle-core__aperture" aria-hidden="true" />
      <span className="ti-command-particle-core__brace ti-command-particle-core__brace--north" aria-hidden="true" />
      <span className="ti-command-particle-core__brace ti-command-particle-core__brace--east" aria-hidden="true" />
      <span className="ti-command-particle-core__brace ti-command-particle-core__brace--south" aria-hidden="true" />
      <span className="ti-command-particle-core__brace ti-command-particle-core__brace--west" aria-hidden="true" />

      {Runtime && !runtimeError ? (
        <Runtime
          progress={0}
          reducedMotion={reducedMotion}
          autoRotate={!reducedMotion}
          hoverEnabled={!reducedMotion}
          command={STATIC_COMMAND}
          ariaLabel={reducedMotion
            ? "Ti-Scale titanium particle core in its reduced-motion state. Use arrow keys to inspect its orientation."
            : "Ti-Scale interactive titanium particle core. Move the pointer to displace nearby particles, drag to rotate, or use arrow keys."}
          className="ti-command-particle-core__runtime"
          onReady={setStats}
          onError={setRuntimeError}
        />
      ) : runtimeError ? (
        <div className="ti-command-particle-core__fallback" role="status">
          <span aria-hidden="true" />
          <strong>Particle field unavailable</strong>
          <small>{runtimeError}</small>
        </div>
      ) : (
        <div className="ti-command-particle-core__loading" role="status" aria-live="polite">
          <div aria-hidden="true">
            {Array.from({ length: 14 }, (_, index) => <i key={index} />)}
          </div>
          <span>Materializing approved particle core</span>
        </div>
      )}

      <span className="ti-command-particle-core__caption" aria-hidden="true">
        <b>{stats ? `${new Intl.NumberFormat().format(stats.pointCount)} PARTICLES` : "PROCEDURAL FIELD"}</b>
        <small>{reducedMotion ? "STATIC ACCESSIBLE STATE" : "HOVER FIELD · DRAG ORBIT"}</small>
      </span>
    </div>
  );
}
