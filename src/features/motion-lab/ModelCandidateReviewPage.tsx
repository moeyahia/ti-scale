import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ComponentType,
} from "react";
import { fetchModelCandidateReview } from "../../data/api/modelCandidateReview";
import { Button, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type {
  AvailableModelCandidateReview,
  ModelCandidateReviewAsset,
} from "../../domain/types/modelCandidateReview";
import type { CandidateModelRuntimeProps } from "./CandidateModelRuntime";
import "./model-candidate-review.css";

type PageState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: Error }
  | { readonly kind: "unconfigured"; readonly humanMessage: string; readonly remediation: string }
  | { readonly kind: "ready"; readonly review: AvailableModelCandidateReview };

function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => (
    typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  ));
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return reduced;
}

function hasWebgl2(): boolean {
  if (typeof document === "undefined") return false;
  const canvas = document.createElement("canvas");
  try {
    const context = canvas.getContext("webgl2", {
      alpha: true,
      antialias: true,
      // Review loading is explicit and isolated, so a software WebGL 2
      // implementation remains useful. The production runtime keeps its
      // stricter high-performance capability gate.
      failIfMajorPerformanceCaveat: false,
      powerPreference: "high-performance",
    });
    if (!context) return false;
    // A non-null context can still be unusable in software/headless browser
    // configurations. Validate the minimum shader precision Three requires,
    // but do not deliberately lose this probe context immediately before the
    // review canvas is mounted.
    return Boolean(
      context.getShaderPrecisionFormat(context.VERTEX_SHADER, context.HIGH_FLOAT)
      && context.getShaderPrecisionFormat(context.FRAGMENT_SHADER, context.HIGH_FLOAT),
    );
  } catch {
    return false;
  } finally {
    canvas.remove();
  }
}

function formatBytes(bytes: number): string {
  return bytes >= 1024 * 1024
    ? `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    : `${Math.round(bytes / 1024)} KB`;
}

function ImageStage({ asset }: { readonly asset: ModelCandidateReviewAsset }) {
  return (
    <figure className="candidate-review__image-stage">
      <img
        src={asset.url}
        alt={`${asset.label}: ${asset.description}`}
        width={asset.width}
        height={asset.height}
        decoding="async"
      />
      <figcaption>{asset.description}</figcaption>
    </figure>
  );
}

export default function ModelCandidateReviewPage() {
  const [pageState, setPageState] = useState<PageState>({ kind: "loading" });
  const [selectedId, setSelectedId] = useState<string>();
  const [runtimeRequested, setRuntimeRequested] = useState(false);
  const [Runtime, setRuntime] = useState<ComponentType<CandidateModelRuntimeProps>>();
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [runtimeReady, setRuntimeReady] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string>();
  const [playing, setPlaying] = useState(false);
  const [yawDegrees, setYawDegrees] = useState(24);
  const [webglSupported, setWebglSupported] = useState(false);
  const reducedMotion = useReducedMotion();

  const load = useCallback(() => {
    setPageState({ kind: "loading" });
    void fetchModelCandidateReview().then(
      (review) => {
        if (review.availability === "not_configured") {
          setPageState({
            kind: "unconfigured",
            humanMessage: review.humanMessage,
            remediation: review.remediation,
          });
          return;
        }
        setPageState({ kind: "ready", review });
        setSelectedId(review.assets.find((asset) => asset.kind === "source-image")?.id);
      },
      (reason: unknown) => {
        setPageState({ kind: "error", error: reason instanceof Error ? reason : new Error("Candidate review could not load") });
      },
    );
  }, []);

  useEffect(() => load(), [load]);
  useEffect(() => setWebglSupported(hasWebgl2()), []);

  const review = pageState.kind === "ready" ? pageState.review : undefined;
  const sourceAssets = useMemo(() => review?.assets.filter((asset) => asset.kind === "source-image") ?? [], [review]);
  const model = review?.assets.find((asset) => asset.kind === "model-glb");
  const turntable = review?.assets.find((asset) => asset.kind === "turntable-image");
  const reviewTabs = useMemo(() => [
    ...sourceAssets,
    ...(model ? [model] : []),
  ], [model, sourceAssets]);
  const selected = reviewTabs.find((asset) => asset.id === selectedId) ?? reviewTabs[0];

  const selectAsset = (asset: ModelCandidateReviewAsset) => {
    setSelectedId(asset.id);
    setPlaying(false);
  };

  const requestRuntime = () => {
    if (!model || reducedMotion || !webglSupported || Runtime || runtimeRequested) return;
    setRuntimeRequested(true);
    setRuntimeError(undefined);
    void import("./CandidateModelRuntime").then(
      (module) => setRuntime(() => module.default),
      () => setRuntimeError("The isolated 3D viewer could not be loaded. Use the verified static turntable below."),
    );
  };

  const turn = (delta: number) => {
    setPlaying(false);
    setYawDegrees((current) => (current + delta + 360) % 360);
  };

  if (pageState.kind === "loading") {
    return <main className="os-page os-narrow-page"><LoadingPanel label="Loading the isolated 3D candidate review" /></main>;
  }
  if (pageState.kind === "error") {
    return <main className="os-page os-narrow-page"><ErrorPanel title="Candidate review could not be verified" error={pageState.error} onRetry={load} /></main>;
  }
  if (pageState.kind === "unconfigured") {
    const error = Object.assign(new Error(pageState.humanMessage), { remediation: pageState.remediation });
    return (
      <main className="os-page os-narrow-page">
        <PageHeader eyebrow="Motion Lab · review boundary" title="No 3D candidate is mounted" description="The production identity and approved WebGL manifest remain unchanged." />
        <ErrorPanel title="Local candidate review is not configured" error={error} />
      </main>
    );
  }

  return (
    <main
      className="candidate-review"
      data-review-status={review!.status}
      data-reduced-motion={reducedMotion ? "true" : "false"}
    >
      <PageHeader
        eyebrow="Motion Lab · isolated candidate"
        title={review!.title}
        description={review!.summary}
        actions={<StatusPill status={review!.status}>{review!.status === "candidate" ? "Candidate · unreviewed" : review!.status}</StatusPill>}
      />

      <section className="candidate-review__decision-boundary" aria-label="Operator approval boundary">
        <strong>This is a review surface, not an approval action.</strong>
        <p>Your explicit operator decision owns approval. Nothing on this page can place the model in the hero, production identity, or approved WebGL manifest.</p>
      </section>

      <div className="candidate-review__workspace">
        <nav className="candidate-review__tabs" role="tablist" aria-label="Candidate outputs">
          {reviewTabs.map((asset) => (
            <button
              key={asset.id}
              type="button"
              role="tab"
              aria-selected={selected?.id === asset.id}
              aria-controls="candidate-review-stage"
              id={`candidate-review-tab-${asset.id}`}
              onClick={() => selectAsset(asset)}
            >
              <span>{asset.kind === "model-glb" ? "03" : asset.id.endsWith("a") ? "01" : "02"}</span>
              <strong>{asset.kind === "model-glb" ? "3D candidate" : asset.label}</strong>
              <small>{formatBytes(asset.bytes)}</small>
            </button>
          ))}
        </nav>

        <section
          className="candidate-review__stage"
          id="candidate-review-stage"
          role="tabpanel"
          aria-labelledby={selected ? `candidate-review-tab-${selected.id}` : undefined}
        >
          {selected?.kind === "source-image" && <ImageStage asset={selected} />}
          {selected?.kind === "model-glb" && model && turntable && (
            <div className="candidate-review__model-stage">
              {(!runtimeRequested || !Runtime || runtimeError || reducedMotion || !webglSupported) && (
                <ImageStage asset={turntable} />
              )}
              {runtimeRequested && Runtime && !runtimeError && !reducedMotion && webglSupported && (
                <Runtime
                  model={model}
                  playing={playing}
                  yawDegrees={yawDegrees}
                  visible
                  onLoading={setRuntimeLoading}
                  onReady={() => setRuntimeReady(true)}
                  onError={setRuntimeError}
                />
              )}
              <div className="candidate-review__runtime-status" role="status" aria-live="polite">
                {reducedMotion
                  ? "Reduced motion is active. The verified twelve-angle contact sheet is shown instead of live rotation."
                  : !webglSupported
                    ? "WebGL 2 is unavailable. The verified twelve-angle contact sheet remains available."
                    : runtimeError
                      ? runtimeError
                      : runtimeLoading
                        ? `Verifying and loading ${formatBytes(model.bytes)} of review-only model data…`
                        : runtimeReady
                          ? "Candidate model verified against its review manifest. It remains unapproved."
                          : "The 3D model has not been downloaded. Load it only when you are ready to inspect it."}
              </div>

              {!reducedMotion && webglSupported && !runtimeRequested && (
                <Button type="button" variant="secondary" onClick={requestRuntime}>Load 3D candidate</Button>
              )}
              {runtimeRequested && Runtime && runtimeReady && !runtimeError && !reducedMotion && (
                <div className="candidate-review__turntable-controls" role="group" aria-label="3D candidate controls">
                  <Button type="button" variant="secondary" onClick={() => setPlaying((current) => !current)}>
                    {playing ? "Pause turntable" : "Play turntable"}
                  </Button>
                  <Button type="button" variant="quiet" onClick={() => turn(-15)}>Rotate candidate left</Button>
                  <Button type="button" variant="quiet" onClick={() => turn(15)}>Rotate candidate right</Button>
                  <Button type="button" variant="quiet" onClick={() => { setPlaying(false); setYawDegrees(24); }}>Reset candidate view</Button>
                </div>
              )}
            </div>
          )}
        </section>

        <aside className="candidate-review__facts" aria-label="Candidate generation receipt">
          <p className="os-eyebrow">Generation receipt</p>
          <dl>
            <div><dt>Status</dt><dd>{review!.reviewState}</dd></div>
            <div><dt>Generation cost</dt><dd>{review!.provenance.imageCredits + review!.provenance.modelCredits} credits</dd></div>
            <div><dt>Image task</dt><dd>{review!.provenance.imageTaskId}</dd></div>
            <div><dt>Model task</dt><dd>{review!.provenance.modelTaskId}</dd></div>
            {model && <>
              <div><dt>Triangles</dt><dd>{model.triangleCount?.toLocaleString("en-US")}</dd></div>
              <div><dt>Vertices</dt><dd>{model.vertexCount?.toLocaleString("en-US")}</dd></div>
              <div><dt>Integrity</dt><dd className="os-mono">{model.sha256.slice(0, 16)}…</dd></div>
            </>}
          </dl>
        </aside>
      </div>
    </main>
  );
}
