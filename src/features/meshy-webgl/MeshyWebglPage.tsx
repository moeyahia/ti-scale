import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ComponentType,
  type KeyboardEvent as ReactKeyboardEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import { Button } from "../../design-system/components/Primitives";
import {
  adjacentMeshyState,
  advanceMeshyTransition,
  beginMeshyTransition,
  settledMeshyMotion,
  type MeshyMotionPresentation,
} from "./meshyMotionState";
import {
  APPROVED_IDENTITY_SOURCE_PATH,
  loadApprovedMeshyWebglManifest,
  meshyWebglAssetUrl,
  type MeshyAssemblyState,
  type MeshyWebglManifest,
} from "./meshyWebglManifest";
import type { MeshyWebglRuntimeProps } from "./MeshyWebglRuntime";
import "./meshy-webgl.css";

type ManifestState =
  | { readonly kind: "loading" }
  | { readonly kind: "missing" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "approved"; readonly manifest: MeshyWebglManifest };

export interface WebglCapability {
  readonly supported: boolean;
  readonly reason?: string;
}

const FALLBACK_ALT = "Layered titanium, graphite, and gold Ti-Scale core with a negative-space centre.";
const WHEEL_THRESHOLD = 46;
const WHEEL_COOLDOWN_MS = 680;

const STATE_COPY: Readonly<Record<MeshyAssemblyState, { readonly label: string; readonly detail: string }>> = {
  assembled: {
    label: "Assembled core",
    detail: "The approved titanium, graphite, and gold plates are locked around the open centre.",
  },
  exploded: {
    label: "Controlled exploded view",
    detail: "Each authored part separates along its own local surface normal without changing its identity.",
  },
  chassis: {
    label: "Architectural chassis",
    detail: "The separated parts resolve into the approved structural arrangement.",
  },
  "section-formation": {
    label: "Interface module formation",
    detail: "The same parts travel into authored interface-module positions for the paginated product transition.",
  },
};

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

function useDocumentVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === "undefined" || document.visibilityState === "visible");
  useEffect(() => {
    const update = () => setVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", update);
    update();
    return () => document.removeEventListener("visibilitychange", update);
  }, []);
  return visible;
}

export function detectWebgl2Capability(): WebglCapability {
  if (typeof document === "undefined") return { supported: false, reason: "WebGL capability is checked in the browser." };
  const canvas = document.createElement("canvas");
  let context: WebGL2RenderingContext | null = null;
  try {
    context = canvas.getContext("webgl2", {
      alpha: true,
      antialias: true,
      failIfMajorPerformanceCaveat: true,
      powerPreference: "high-performance",
    });
    if (!context) {
      return {
        supported: false,
        reason: "This browser or graphics policy cannot provide the required WebGL 2 renderer.",
      };
    }
    return { supported: true };
  } catch {
    return { supported: false, reason: "The WebGL 2 capability check failed safely." };
  } finally {
    context?.getExtension("WEBGL_lose_context")?.loseContext();
    canvas.remove();
  }
}

function StaticIdentityFallback({ status }: { readonly status: string }) {
  return (
    <figure className="meshy-webgl__fallback" data-testid="meshy-static-fallback">
      <img
        src={meshyWebglAssetUrl(APPROVED_IDENTITY_SOURCE_PATH)}
        alt={FALLBACK_ALT}
        width="1344"
        height="768"
        decoding="async"
      />
      <figcaption>{status}</figcaption>
    </figure>
  );
}

function isControlTarget(target: EventTarget | null): boolean {
  return target instanceof Element && Boolean(target.closest("button, a, input, [role='button']"));
}

export default function MeshyWebglPage() {
  const [manifestState, setManifestState] = useState<ManifestState>({ kind: "loading" });
  const [capability, setCapability] = useState<WebglCapability>();
  const [Runtime, setRuntime] = useState<ComponentType<MeshyWebglRuntimeProps>>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [loadProgress, setLoadProgress] = useState(0);
  const [modelReady, setModelReady] = useState(false);
  const [presentation, setPresentation] = useState<MeshyMotionPresentation>(() => settledMeshyMotion());
  const presentationRef = useRef(presentation);
  const lastFrameRef = useRef<number | undefined>(undefined);
  const lastWheelAtRef = useRef(0);
  const reducedMotion = useReducedMotion();
  const documentVisible = useDocumentVisible();

  useEffect(() => {
    let active = true;
    void loadApprovedMeshyWebglManifest().then(
      (manifest) => {
        if (!active) return;
        setManifestState(manifest ? { kind: "approved", manifest } : { kind: "missing" });
      },
      (error: unknown) => {
        if (!active) return;
        setManifestState({
          kind: "error",
          message: error instanceof Error ? error.message : "The WebGL approval manifest could not be verified.",
        });
      },
    );
    return () => { active = false; };
  }, []);

  useEffect(() => setCapability(detectWebgl2Capability()), []);

  const manifest = manifestState.kind === "approved" ? manifestState.manifest : undefined;
  const runtimeAllowed = Boolean(manifest && capability?.supported && !reducedMotion && !runtimeError);

  useEffect(() => {
    if (!runtimeAllowed || Runtime) return;
    let active = true;
    void import("./MeshyWebglRuntime").then(
      (module) => {
        if (active) setRuntime(() => module.default);
      },
      () => {
        if (active) setRuntimeError("The isolated 3D renderer could not be loaded. The approved static identity remains available.");
      },
    );
    return () => { active = false; };
  }, [Runtime, runtimeAllowed]);

  useEffect(() => {
    presentationRef.current = presentation;
  }, [presentation]);

  useEffect(() => {
    if (reducedMotion || !documentVisible || presentation.progress >= 1) {
      lastFrameRef.current = undefined;
      return;
    }
    let frame = 0;
    const tick = (timestamp: number) => {
      const prior = lastFrameRef.current ?? timestamp;
      lastFrameRef.current = timestamp;
      const next = advanceMeshyTransition(presentationRef.current, Math.min(64, timestamp - prior));
      presentationRef.current = next;
      setPresentation(next);
      if (next.progress < 1) frame = requestAnimationFrame(tick);
      else lastFrameRef.current = undefined;
    };
    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      lastFrameRef.current = undefined;
    };
  }, [documentVisible, presentation.revision, reducedMotion]);

  const selectState = useCallback((target: MeshyAssemblyState) => {
    if (reducedMotion) {
      setPresentation((current) => settledMeshyMotion(target, current.revision + 1));
      return;
    }
    setPresentation((current) => beginMeshyTransition(current, target));
  }, [reducedMotion]);

  const currentState = presentation.progress >= 0.5 ? presentation.to : presentation.from;
  const moveState = useCallback((direction: -1 | 1) => {
    selectState(adjacentMeshyState(presentationRef.current.to, direction));
  }, [selectState]);

  const onWheel = (event: ReactWheelEvent<HTMLElement>) => {
    if (isControlTarget(event.target) || Math.abs(event.deltaY) < WHEEL_THRESHOLD || presentation.progress < 1) return;
    const now = performance.now();
    if (now - lastWheelAtRef.current < WHEEL_COOLDOWN_MS) return;
    lastWheelAtRef.current = now;
    moveState(event.deltaY > 0 ? 1 : -1);
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (isControlTarget(event.target) || presentation.progress < 1) return;
    if (["ArrowRight", "ArrowDown", "PageDown"].includes(event.key)) {
      event.preventDefault();
      moveState(1);
    } else if (["ArrowLeft", "ArrowUp", "PageUp"].includes(event.key)) {
      event.preventDefault();
      moveState(-1);
    } else if (event.key === "Home") {
      event.preventDefault();
      selectState("assembled");
    } else if (event.key === "End") {
      event.preventDefault();
      selectState("section-formation");
    }
  };

  const fallbackStatus = manifestState.kind === "loading"
    ? "Checking for an operator-approved 3D model."
    : manifestState.kind === "missing"
      ? "No operator-approved Meshy model is connected. The WebGL runtime remains disabled."
      : manifestState.kind === "error"
        ? `${manifestState.message} No candidate model was loaded.`
        : reducedMotion
          ? "Reduced motion is active. The approved static identity is shown without loading the 3D runtime."
          : capability && !capability.supported
            ? `${capability.reason} The approved static identity remains available.`
            : runtimeError ?? "Preparing the isolated WebGL renderer.";

  const stateCopy = STATE_COPY[currentState];

  return (
    <section
      className="meshy-webgl"
      aria-label="Ti-Scale WebGL motion laboratory"
      data-runtime-allowed={runtimeAllowed ? "true" : "false"}
      data-motion-state={currentState}
      tabIndex={0}
      onWheel={onWheel}
      onKeyDown={onKeyDown}
    >
      <header className="meshy-webgl__header">
        <div>
          <p className="os-eyebrow">TI-SCALE · APPROVED ASSET LAB</p>
          <h1>Material transformation runtime</h1>
          <p>The original plates remain the identity. WebGL only controls their verified 3D counterparts after operator approval.</p>
        </div>
        <p className="meshy-webgl__runtime-state" role="status" aria-live="polite">
          <span aria-hidden="true" />
          {modelReady ? "Verified model ready" : runtimeAllowed ? `Loading verified model · ${Math.round(loadProgress * 100)}%` : "3D runtime gated"}
        </p>
      </header>

      <div className="meshy-webgl__stage">
        {runtimeAllowed && Runtime && manifest ? (
          <Runtime
            manifest={manifest}
            presentation={presentation}
            visible={documentVisible}
            onProgress={setLoadProgress}
            onReady={() => setModelReady(true)}
            onError={(message) => setRuntimeError(message)}
          />
        ) : (
          <StaticIdentityFallback status={fallbackStatus} />
        )}
      </div>

      <aside className="meshy-webgl__state-copy" aria-live="polite" aria-atomic="true">
        <p>{String(Math.max(1, ["assembled", "exploded", "chassis", "section-formation"].indexOf(currentState) + 1)).padStart(2, "0")} / 04</p>
        <div>
          <h2>{stateCopy.label}</h2>
          <p>{stateCopy.detail}</p>
        </div>
      </aside>

      {manifest && (
        <nav className="meshy-webgl__controls" aria-label="3D assembly states">
          {(Object.keys(STATE_COPY) as MeshyAssemblyState[]).map((state) => (
            <Button
              key={state}
              type="button"
              variant={currentState === state ? "primary" : "secondary"}
              aria-pressed={currentState === state}
              disabled={!modelReady || presentation.progress < 1}
              onClick={() => selectState(state)}
            >
              {STATE_COPY[state].label}
            </Button>
          ))}
        </nav>
      )}
    </section>
  );
}
