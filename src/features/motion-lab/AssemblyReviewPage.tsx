import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ComponentType,
} from "react";
import { Button, ButtonLink, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { assetUrl } from "../../lib/assetUrl";
import type {
  AssemblyReviewRuntimeProps,
  AssemblyRuntimeCommand,
  AssemblyRuntimeCommandType,
  AssemblyRuntimeStats,
} from "./AssemblyReviewRuntime";
import {
  loadAssemblyReviewManifest,
  type AssemblyReviewManifest,
} from "./assemblyReviewManifest";
import "./assembly-review.css";

type ManifestState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: Error }
  | { readonly kind: "ready"; readonly manifest: AssemblyReviewManifest };

function systemPrefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function supportsWebgl2(): boolean {
  if (typeof document === "undefined") return false;
  const canvas = document.createElement("canvas");
  try {
    return Boolean(canvas.getContext("webgl2", { alpha: false, antialias: true, failIfMajorPerformanceCaveat: false }));
  } catch {
    return false;
  } finally {
    canvas.remove();
  }
}

function formatBytes(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
}

function familyLabel(value: AssemblyReviewManifest["models"][number]["materialFamily"]): string {
  if (value === "champagne-gold-carrier") return "Gold carrier";
  if (value === "architectural-graphite") return "Graphite";
  return "Titanium";
}

export default function AssemblyReviewPage() {
  const [manifestState, setManifestState] = useState<ManifestState>({ kind: "loading" });
  const [loadVersion, setLoadVersion] = useState(0);
  const [Runtime, setRuntime] = useState<ComponentType<AssemblyReviewRuntimeProps>>();
  const [runtimeKey, setRuntimeKey] = useState(0);
  const [runtimeError, setRuntimeError] = useState<string>();
  const [loadProgress, setLoadProgress] = useState({ loaded: 0, total: 14, label: "Preparing locked model review" });
  const [stats, setStats] = useState<AssemblyRuntimeStats>();
  const [progress, setProgress] = useState(0);
  const [selectedId, setSelectedId] = useState<string>();
  const [showList, setShowList] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(systemPrefersReducedMotion);
  const [systemReduced, setSystemReduced] = useState(systemPrefersReducedMotion);
  const [webglSupported, setWebglSupported] = useState(false);
  const [command, setCommand] = useState<AssemblyRuntimeCommand>({ sequence: 0, type: "reset" });

  const reload = useCallback(() => {
    setManifestState({ kind: "loading" });
    setRuntimeError(undefined);
    setStats(undefined);
    setLoadProgress({ loaded: 0, total: 14, label: "Preparing locked model review" });
    setLoadVersion((value) => value + 1);
  }, []);

  useEffect(() => {
    // Keep the immutable static read alive across React's development-only
    // StrictMode probe cleanup. Cancelling it would create a false failed
    // network record even though the immediately remounted page is healthy.
    let active = true;
    void loadAssemblyReviewManifest().then(
      (manifest) => { if (active) setManifestState({ kind: "ready", manifest }); },
      (reason: unknown) => {
        if (active) setManifestState({ kind: "error", error: reason instanceof Error ? reason : new Error("The assembly manifest could not be verified.") });
      },
    );
    return () => { active = false; };
  }, [loadVersion]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      setSystemReduced(media.matches);
      if (media.matches) setReducedMotion(true);
    };
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  useEffect(() => setWebglSupported(supportsWebgl2()), []);
  useEffect(() => {
    if (manifestState.kind !== "ready" || !webglSupported || showList || Runtime) return;
    void import("./AssemblyReviewRuntime").then(
      (module) => setRuntime(() => module.default),
      () => setRuntimeError("The WebGL review module could not load. Use the complete accessible element list while the bundle is repaired."),
    );
  }, [Runtime, manifestState.kind, showList, webglSupported]);

  const manifest = manifestState.kind === "ready" ? manifestState.manifest : undefined;
  const selected = useMemo(() => manifest?.models.find((model) => model.id === selectedId), [manifest, selectedId]);
  const stateLabel = progress <= 0.001 ? "Assembled" : progress >= 0.999 ? "Exploded" : `Interpolated · ${Math.round(progress * 100)}%`;

  const issueCommand = (type: AssemblyRuntimeCommandType) => {
    setCommand((current) => ({ sequence: current.sequence + 1, type }));
  };

  if (manifestState.kind === "loading") {
    return <main className="os-page os-narrow-page"><LoadingPanel label="Verifying the locked 14-element assembly manifest" /></main>;
  }
  if (manifestState.kind === "error") {
    return <main className="os-page os-narrow-page"><ErrorPanel title="The assembly review could not open" error={manifestState.error} onRetry={reload} /></main>;
  }
  const resolved = manifestState.manifest;

  return (
    <main className="assembly-review-page" data-review-status={resolved.status} data-reduced-motion={reducedMotion ? "true" : "false"}>
      <header className="assembly-review-page__header">
        <div>
          <p className="assembly-review-page__eyebrow">MOTION LAB · ASSEMBLY GATE</p>
          <h1>{resolved.title}</h1>
          <p>Inspect the 14 locked manufactured pieces and 26 runtime fasteners before any hero or product integration.</p>
        </div>
        <div className="assembly-review-page__header-actions">
          <StatusPill status="warning">{resolved.reviewBoundary}</StatusPill>
          <ButtonLink href="/motion-lab" variant="quiet">Return to Motion Lab</ButtonLink>
        </div>
      </header>

      <section className="assembly-review-page__boundary" aria-label="Candidate approval boundary">
        <strong>Geometry review only.</strong>
        <span>The GLB bytes are hash-verified at load. This page cannot approve, publish, or place the assembly in the Ti-Scale hero.</span>
      </section>

      <section className="assembly-review-page__workspace">
        <aside className="assembly-review-page__gallery" aria-label="Locked assembly elements">
          <div className="assembly-review-page__gallery-heading">
            <div><span>LOCKED SET</span><strong>14 elements</strong></div>
            <button type="button" onClick={() => setSelectedId(undefined)} aria-label="Show complete assembly">All</button>
          </div>
          <ol>
            {resolved.models.map((model) => (
              <li key={model.id}>
                <button
                  type="button"
                  className={selectedId === model.id ? "is-selected" : ""}
                  aria-pressed={selectedId === model.id}
                  aria-label={`Inspect element ${String(model.number).padStart(2, "0")}: ${model.name}`}
                  onClick={() => setSelectedId(model.id)}
                >
                  <span>{String(model.number).padStart(2, "0")}</span>
                  <span><strong>{model.name}</strong><small>{familyLabel(model.materialFamily)} · {model.triangleCount.toLocaleString()} tris</small></span>
                </button>
              </li>
            ))}
          </ol>
        </aside>

        <section className="assembly-review-page__stage" aria-label="14-element WebGL assembly review">
          <div className="assembly-review-page__stage-status" role="status" aria-live="polite">
            <span>{stateLabel}</span>
            <span>{stats ? `${stats.verifiedModels}/14 hashes verified · ${stats.fastenerInstances}/26 fasteners` : `${loadProgress.loaded}/${loadProgress.total} · ${loadProgress.label}`}</span>
          </div>
          {!webglSupported || showList ? (
            <div className="assembly-review-page__list-fallback" aria-label="Accessible assembly element list">
              <h2>{!webglSupported ? "WebGL is unavailable" : "Assembly element list"}</h2>
              <p>{!webglSupported ? "This browser cannot open the interactive model. Every locked element remains available below with its exact review metadata." : "The list provides the complete non-canvas alternative without changing assembly state."}</p>
              <table>
                <thead><tr><th>Element</th><th>Material</th><th>SHA-256</th><th>Size</th></tr></thead>
                <tbody>{resolved.models.map((model) => <tr key={model.id}><th>{String(model.number).padStart(2, "0")} · {model.name}</th><td>{familyLabel(model.materialFamily)}</td><td><code>{model.sha256.slice(0, 16)}…</code></td><td>{formatBytes(model.bytes)}</td></tr>)}</tbody>
              </table>
            </div>
          ) : Runtime && !runtimeError ? (
            <Runtime
              key={runtimeKey}
              manifest={resolved}
              progress={progress}
              selectedId={selectedId}
              reducedMotion={reducedMotion}
              command={command}
              onProgress={(loaded, total, label) => setLoadProgress({ loaded, total, label })}
              onReady={setStats}
              onError={setRuntimeError}
            />
          ) : runtimeError ? (
            <div className="assembly-review-page__runtime-error" role="alert"><strong>Interactive assembly unavailable</strong><p>{runtimeError}</p><Button type="button" variant="secondary" onClick={() => { setStats(undefined); setRuntimeError(undefined); setRuntimeKey((value) => value + 1); setRuntime(undefined); }}>Retry 3D viewer</Button></div>
          ) : (
            <LoadingPanel label="Loading the isolated WebGL assembly runtime" />
          )}
          <div className="assembly-review-page__view-controls" aria-label="Assembly camera controls">
            <Button type="button" variant="quiet" onClick={() => issueCommand("rotate-left")} disabled={!stats || showList} aria-label="Rotate assembly left">Rotate −</Button>
            <Button type="button" variant="quiet" onClick={() => issueCommand("rotate-right")} disabled={!stats || showList} aria-label="Rotate assembly right">Rotate +</Button>
            <Button type="button" variant="quiet" onClick={() => issueCommand("zoom-in")} disabled={!stats || showList} aria-label="Zoom into assembly">Zoom +</Button>
            <Button type="button" variant="quiet" onClick={() => issueCommand("zoom-out")} disabled={!stats || showList} aria-label="Zoom out of assembly">Zoom −</Button>
            <Button type="button" variant="quiet" onClick={() => issueCommand("fit")} disabled={!stats || showList} aria-label="Fit complete assembly in view">Fit</Button>
            <Button type="button" variant="quiet" onClick={() => issueCommand("reset")} disabled={!stats || showList} aria-label="Reset assembly camera">Reset</Button>
          </div>
        </section>

        <aside className="assembly-review-page__inspector" aria-label="Assembly review details">
          <figure>
            <img src={assetUrl(resolved.sourceArtwork.path)} alt="Approved Ti-Scale source artwork used as the assembly comparison authority" width={resolved.sourceArtwork.width} height={resolved.sourceArtwork.height} />
            <figcaption>Approved source artwork · comparison authority</figcaption>
          </figure>
          <div className="assembly-review-page__selected-detail">
            <span>{selected ? `ELEMENT ${String(selected.number).padStart(2, "0")}` : "COMPLETE ASSEMBLY"}</span>
            <h2>{selected?.name ?? "All locked elements"}</h2>
            <p>{selected ? `${familyLabel(selected.materialFamily)} · ${selected.triangleCount.toLocaleString()} triangles · ${formatBytes(selected.bytes)}` : "Fourteen independent GLBs with 26 deterministic runtime fasteners."}</p>
            {selected && <code title={selected.sha256}>{selected.sha256}</code>}
          </div>
          {stats && <dl className="assembly-review-page__receipt"><div><dt>Verified loads</dt><dd>{stats.verifiedModels} / 14</dd></div><div><dt>Model meshes</dt><dd>{stats.modelMeshCount} / {resolved.visualIntegrity.expectedModelMeshCount}</dd></div><div><dt>Fastener instances</dt><dd>{stats.fastenerInstances} / 26</dd></div><div><dt>Triangles</dt><dd>{stats.triangles.toLocaleString()}</dd></div><div><dt>Model bytes</dt><dd>{formatBytes(stats.modelBytes)}</dd></div><div><dt>Visible model area</dt><dd>{(stats.visibleModelCoverage * 100).toFixed(1)}%</dd></div><div><dt>Visible model pixels</dt><dd>{stats.visibleModelPixels.toLocaleString()}</dd></div><div><dt>Draw calls</dt><dd>{stats.drawCalls}</dd></div><div><dt>Verified in</dt><dd>{stats.loadMilliseconds} ms</dd></div></dl>}
        </aside>
      </section>

      <footer className="assembly-review-page__controls">
        <div className="assembly-review-page__state-buttons" aria-label="Assembly states">
          <Button type="button" variant={progress <= 0.001 ? "primary" : "secondary"} aria-pressed={progress <= 0.001} onClick={() => setProgress(0)}>Assembled</Button>
          <Button type="button" variant={progress >= 0.999 ? "primary" : "secondary"} aria-pressed={progress >= 0.999} onClick={() => setProgress(1)}>Exploded</Button>
        </div>
        <label className="assembly-review-page__scrubber">
          <span>Explosion interpolation</span>
          <input type="range" min="0" max="1000" step="1" value={Math.round(progress * 1000)} aria-label="Assembly explosion progress" onChange={(event) => setProgress(Number(event.currentTarget.value) / 1000)} />
          <output>{Math.round(progress * 100)}%</output>
        </label>
        <label className="assembly-review-page__motion-toggle">
          <input type="checkbox" checked={reducedMotion} disabled={systemReduced} onChange={(event) => setReducedMotion(event.currentTarget.checked)} />
          <span>Reduced motion {systemReduced ? "· system" : ""}</span>
        </label>
        <Button type="button" variant="secondary" onClick={() => setShowList((value) => !value)} aria-pressed={showList}>{showList ? "Show interactive assembly" : "Show accessible element list"}</Button>
      </footer>
    </main>
  );
}
