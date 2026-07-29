import {
  useCallback,
  useEffect,
  useState,
  type CSSProperties,
  type ComponentType,
} from "react";
import { Button, ButtonLink } from "../../design-system/components/Primitives";
import type {
  ParticleCoreCommand,
  ParticleCoreCommandType,
  ParticleCoreRuntimeProps,
  ParticleCoreStats,
} from "./ParticleCoreRuntime";
import {
  particleCoreClusterLabels,
  PARTICLE_CORE_CLUSTER_COUNT,
} from "./particleCoreGeometry";
import "./particle-core-review.css";

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function pointCountLabel(value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);
}

export default function ParticleCoreReviewPage() {
  const [Runtime, setRuntime] = useState<ComponentType<ParticleCoreRuntimeProps>>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [stats, setStats] = useState<ParticleCoreStats>();
  const [progress, setProgress] = useState(0);
  const [selectedCluster, setSelectedCluster] = useState<number>();
  const [showList, setShowList] = useState(false);
  const [systemReducedMotion, setSystemReducedMotion] = useState(prefersReducedMotion);
  const [reducedMotion, setReducedMotion] = useState(prefersReducedMotion);
  const [autoRotate, setAutoRotate] = useState(!prefersReducedMotion());
  const [runtimeKey, setRuntimeKey] = useState(0);
  const [command, setCommand] = useState<ParticleCoreCommand>({ sequence: 0, type: "reset" });

  useEffect(() => {
    let active = true;
    void import("./ParticleCoreRuntime").then(
      (module) => { if (active) setRuntime(() => module.default); },
      () => { if (active) setRuntimeError("The isolated particle renderer could not load. The 14-cluster specification remains available below."); },
    );
    return () => { active = false; };
  }, [runtimeKey]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      setSystemReducedMotion(media.matches);
      if (media.matches) {
        setReducedMotion(true);
        setAutoRotate(false);
      }
    };
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const issueCommand = useCallback((type: ParticleCoreCommandType) => {
    setCommand((current) => ({ sequence: current.sequence + 1, type }));
  }, []);

  const retryRuntime = useCallback(() => {
    setRuntime(undefined);
    setRuntimeError(undefined);
    setStats(undefined);
    setRuntimeKey((value) => value + 1);
  }, []);

  const stateLabel = progress <= 0.001
    ? "Coherent shell"
    : progress >= 0.999
      ? "Fourteen clusters separated"
      : `Expansion field · ${Math.round(progress * 100)}%`;

  return (
    <main
      className="particle-core-review"
      data-review-boundary="approved-geometry"
      data-reduced-motion={reducedMotion ? "true" : "false"}
      data-runtime-ready={stats ? "true" : "false"}
    >
      <header className="particle-core-review__masthead">
        <div className="particle-core-review__title">
          <p>TI-SCALE · MOTION LAB · PARTICLE CORE</p>
          <h1>Titanium singularity</h1>
          <span>Continuous particle shell · recessed aperture · fourteen motion clusters</span>
        </div>
        <div className="particle-core-review__header-actions">
          <div className="particle-core-review__status" role="status" aria-live="polite">
            <i aria-hidden="true" />
            <span>{stats ? "Procedural field active" : runtimeError ? "Renderer unavailable" : "Building deterministic field"}</span>
          </div>
          <ButtonLink href="/motion-lab" variant="quiet">Return to Motion Lab</ButtonLink>
        </div>
      </header>

      <section className="particle-core-review__stage" aria-label="Particle core geometry review">
        <div className="particle-core-review__state-readout" aria-live="polite">
          <span>{stateLabel}</span>
          <span>{stats ? `${pointCountLabel(stats.pointCount)} particles · ${stats.clusterCount} clusters · ${stats.drawCalls} draw call${stats.drawCalls === 1 ? "" : "s"}` : "No remote model or texture requests"}</span>
        </div>

        <div className="particle-core-review__canvas-frame">
          {Runtime && !runtimeError ? (
            <Runtime
              key={runtimeKey}
              progress={progress}
              selectedCluster={selectedCluster}
              reducedMotion={reducedMotion}
              autoRotate={autoRotate}
              command={command}
              onReady={setStats}
              onError={setRuntimeError}
            />
          ) : runtimeError ? (
            <div className="particle-core-review__error" role="alert">
              <strong>Interactive particle field unavailable</strong>
              <p>{runtimeError}</p>
              <Button type="button" variant="secondary" onClick={retryRuntime}>Retry particle renderer</Button>
            </div>
          ) : (
            <div className="particle-core-review__loader" role="status" aria-live="polite">
              <div aria-hidden="true">{particleCoreClusterLabels.map((label, index) => <i key={label} style={{ "--particle-index": index } as CSSProperties} />)}</div>
              <span>Assembling titanium particle field</span>
            </div>
          )}
        </div>

        <section className="particle-core-review__concept" aria-labelledby="particle-core-concept-title">
          <p>NEW GEOMETRY DIRECTION</p>
          <h2 id="particle-core-concept-title">A coherent field, not stacked plates.</h2>
          <span>The aperture pulls the titanium shell inward while a slow torque keeps the surface alive. Expansion separates the same field into fourteen addressable system clusters.</span>
        </section>

        <aside className="particle-core-review__clusters" aria-label="Particle field clusters">
          <div>
            <span>FIELD MAP</span>
            <button type="button" onClick={() => setSelectedCluster(undefined)} aria-pressed={selectedCluster === undefined}>All 14</button>
          </div>
          <ol>
            {particleCoreClusterLabels.map((label, index) => (
              <li key={label}>
                <button
                  type="button"
                  aria-label={`Inspect particle cluster ${index + 1}: ${label}`}
                  aria-pressed={selectedCluster === index}
                  className={selectedCluster === index ? "is-selected" : ""}
                  onClick={() => setSelectedCluster(index)}
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{label}</strong>
                </button>
              </li>
            ))}
          </ol>
        </aside>

        <div className="particle-core-review__camera" aria-label="Particle core camera controls">
          <Button type="button" variant="quiet" onClick={() => issueCommand("rotate-left")} disabled={!stats}>Rotate −</Button>
          <Button type="button" variant="quiet" onClick={() => issueCommand("rotate-right")} disabled={!stats}>Rotate +</Button>
          <Button type="button" variant="quiet" onClick={() => issueCommand("zoom-in")} disabled={!stats}>Zoom +</Button>
          <Button type="button" variant="quiet" onClick={() => issueCommand("zoom-out")} disabled={!stats}>Zoom −</Button>
          <Button type="button" variant="quiet" onClick={() => issueCommand("reset")} disabled={!stats}>Reset</Button>
        </div>

        {showList && (
          <section className="particle-core-review__accessible-list" aria-label="Accessible particle cluster list">
            <div>
              <p>NON-CANVAS FIELD DESCRIPTION</p>
              <h2>Fourteen deterministic motion clusters</h2>
              <Button type="button" variant="quiet" onClick={() => setShowList(false)}>Close list</Button>
            </div>
            <p>The visual remains one continuous procedural shell when assembled. These clusters only define how regions separate during the expansion state.</p>
            <ol>{particleCoreClusterLabels.map((label, index) => <li key={label}><span>{String(index + 1).padStart(2, "0")}</span><strong>{label}</strong><small>{index < 7 ? "Upper field" : "Lower field"}</small></li>)}</ol>
          </section>
        )}
      </section>

      <footer className="particle-core-review__controls">
        <div className="particle-core-review__presets" aria-label="Particle core expansion states">
          <Button type="button" variant={progress <= 0.001 ? "primary" : "secondary"} aria-pressed={progress <= 0.001} onClick={() => setProgress(0)}>Assembled</Button>
          <Button type="button" variant={progress > 0.001 && progress < 0.999 ? "primary" : "secondary"} aria-pressed={progress > 0.001 && progress < 0.999} onClick={() => setProgress(0.48)}>Expansion</Button>
          <Button type="button" variant={progress >= 0.999 ? "primary" : "secondary"} aria-pressed={progress >= 0.999} onClick={() => setProgress(1)}>Exploded</Button>
        </div>
        <label className="particle-core-review__scrubber">
          <span>Cluster separation</span>
          <input type="range" min="0" max="1000" step="1" value={Math.round(progress * 1000)} aria-label="Particle cluster separation" onChange={(event) => setProgress(Number(event.currentTarget.value) / 1000)} />
          <output>{Math.round(progress * 100)}%</output>
        </label>
        <label className="particle-core-review__toggle">
          <input type="checkbox" checked={autoRotate} disabled={reducedMotion} onChange={(event) => setAutoRotate(event.currentTarget.checked)} />
          <span>Orbital drift</span>
        </label>
        <label className="particle-core-review__toggle">
          <input type="checkbox" checked={reducedMotion} disabled={systemReducedMotion} onChange={(event) => { setReducedMotion(event.currentTarget.checked); if (event.currentTarget.checked) setAutoRotate(false); }} />
          <span>Reduced motion {systemReducedMotion ? "· system" : ""}</span>
        </label>
        <Button type="button" variant="secondary" aria-pressed={showList} onClick={() => setShowList((value) => !value)}>{showList ? "Hide field list" : "Show field list"}</Button>
      </footer>

      <div className="particle-core-review__boundary">
        <strong>Operator-approved particle geometry.</strong>
        <span>This deterministic field is now the active Ti-Scale Command Center artwork.</span>
        <span>{stats ? `Generated locally in ${stats.generationMilliseconds} ms` : `${PARTICLE_CORE_CLUSTER_COUNT} deterministic clusters`}</span>
      </div>
    </main>
  );
}
