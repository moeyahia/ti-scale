import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type TouchEvent as ReactTouchEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import { Button, ButtonLink } from "../../design-system/components/Primitives";
import {
  loadMotionLabManifest,
  motionAssetUrl,
  type MotionLabManifest,
} from "./motionManifest";
import "./motion-lab.css";

type ManifestState =
  | { readonly kind: "loading" }
  | { readonly kind: "missing" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "ready"; readonly manifest: MotionLabManifest };

const WHEEL_THRESHOLD = 42;
const WHEEL_COOLDOWN_MS = 480;
const TOUCH_THRESHOLD = 48;
const motionObjectUrls = new Map<string, Promise<string>>();

function loadMotionObjectUrl(path: string): Promise<string> {
  const asset = motionAssetUrl(path);
  const existing = motionObjectUrls.get(asset);
  if (existing) return existing;
  const pending = fetch(asset, { cache: "force-cache", headers: { Accept: "video/webm,video/mp4" } })
    .then(async (response) => {
      if (!response.ok) throw new Error(`Motion asset request returned HTTP ${response.status}`);
      return URL.createObjectURL(await response.blob());
    });
  motionObjectUrls.set(asset, pending);
  return pending;
}

function waitForVideoMetadata(video: HTMLVideoElement): Promise<void> {
  if (video.readyState >= HTMLMediaElement.HAVE_METADATA) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      video.removeEventListener("loadedmetadata", onLoaded);
      video.removeEventListener("error", onError);
    };
    const onLoaded = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(new Error("The production clip could not be decoded."));
    };
    video.addEventListener("loadedmetadata", onLoaded, { once: true });
    video.addEventListener("error", onError, { once: true });
  });
}

function isInteractiveTarget(target: EventTarget | null): boolean {
  return target instanceof Element && Boolean(target.closest("button, input, a, [role='slider']"));
}

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

function formatTime(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0:00";
  const whole = Math.floor(value);
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, "0")}`;
}

export default function MotionLabPage() {
  const [manifestState, setManifestState] = useState<ManifestState>({ kind: "loading" });
  const [progress, setProgress] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [mediaError, setMediaError] = useState<string>();
  const [motionObjectUrl, setMotionObjectUrl] = useState<string>();
  const [motionLoading, setMotionLoading] = useState(false);
  const [videoMode, setVideoMode] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const touchStartRef = useRef<{ x: number; y: number } | undefined>(undefined);
  const lastWheelAtRef = useRef(0);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    // React development strict mode mounts this effect twice. Keep the static
    // manifest request alive across the probe cleanup so the browser never
    // reports an aborted production-asset read; only suppress the stale state
    // write from the discarded mount.
    let active = true;
    void loadMotionLabManifest().then(
      (manifest) => {
        if (active) setManifestState(manifest ? { kind: "ready", manifest } : { kind: "missing" });
      },
      (error: unknown) => {
        if (!active) return;
        setManifestState({
          kind: "error",
          message: error instanceof Error ? error.message : "The motion manifest could not be read.",
        });
      },
    );
    return () => { active = false; };
  }, []);

  const manifest = manifestState.kind === "ready" ? manifestState.manifest : undefined;
  const stages = manifest?.stages ?? [];
  const activeStageIndex = useMemo(() => {
    let index = 0;
    stages.forEach((stage, stageIndex) => {
      if (stage.progress <= progress + 0.008) index = stageIndex;
    });
    return index;
  }, [progress, stages]);
  const activeStage = stages[activeStageIndex];
  const duration = videoRef.current?.duration && Number.isFinite(videoRef.current.duration)
    ? videoRef.current.duration
    : manifest?.motion?.durationSeconds ?? 0;
  const canPlay = Boolean(manifest?.motion && !reducedMotion && !mediaError);

  const prepareMotion = useCallback(async (): Promise<string> => {
    const motion = manifest?.motion;
    if (!motion || reducedMotion) throw new Error("Motion playback is unavailable.");
    if (motionObjectUrl) return motionObjectUrl;
    setMotionLoading(true);
    try {
      const url = await loadMotionObjectUrl(motion.path);
      setMotionObjectUrl(url);
      return url;
    } finally {
      setMotionLoading(false);
    }
  }, [manifest?.motion, motionObjectUrl, reducedMotion]);

  const attachMotion = useCallback(async (video: HTMLVideoElement): Promise<void> => {
    const source = await prepareMotion();
    if (video.src !== source) {
      video.src = source;
      video.load();
    }
    await waitForVideoMetadata(video);
  }, [prepareMotion]);

  const setTimelineProgress = useCallback((nextProgress: number) => {
    const normalized = Math.min(1, Math.max(0, nextProgress));
    setProgress(normalized);
  }, []);

  const seekVideo = useCallback(async (nextProgress: number) => {
    const normalized = Math.min(1, Math.max(0, nextProgress));
    setProgress(normalized);
    const video = videoRef.current;
    if (video) {
      try {
        await attachMotion(video);
      } catch (error) {
        setMediaError(error instanceof Error ? error.message : "The production clip could not be prepared.");
        setVideoMode(false);
        return;
      }
      const resolvedDuration = Number.isFinite(video.duration) && video.duration > 0
        ? video.duration
        : manifest?.motion?.durationSeconds ?? 0;
      if (resolvedDuration > 0) video.currentTime = normalized * resolvedDuration;
      setVideoMode(true);
    }
  }, [attachMotion, manifest?.motion?.durationSeconds]);

  const selectStage = useCallback((index: number) => {
    const stage = stages[Math.min(stages.length - 1, Math.max(0, index))];
    if (!stage) return;
    videoRef.current?.pause();
    setPlaying(false);
    setVideoMode(false);
    setTimelineProgress(stage.progress);
  }, [setTimelineProgress, stages]);

  const moveStage = useCallback((direction: -1 | 1) => {
    selectStage(activeStageIndex + direction);
  }, [activeStageIndex, selectStage]);

  const togglePlayback = useCallback(async () => {
    const video = videoRef.current;
    if (!video || !canPlay) return;
    setMediaError(undefined);
    if (!video.paused) {
      video.pause();
      setPlaying(false);
      return;
    }
    try {
      await attachMotion(video);
    } catch (error) {
      setMediaError(error instanceof Error ? error.message : "The production clip could not be prepared.");
      setPlaying(false);
      setVideoMode(false);
      return;
    }
    const nextProgress = progress >= 0.999 ? 0 : progress;
    const resolvedDuration = Number.isFinite(video.duration) && video.duration > 0
      ? video.duration
      : manifest?.motion?.durationSeconds ?? 0;
    if (!videoMode || nextProgress !== progress) {
      if (resolvedDuration > 0) video.currentTime = nextProgress * resolvedDuration;
      setProgress(nextProgress);
    }
    setVideoMode(true);
    try {
      await video.play();
      setPlaying(true);
    } catch {
      setMediaError("Playback was blocked. Use Restart motion, then press Play motion again.");
      setPlaying(false);
    }
  }, [attachMotion, canPlay, manifest?.motion?.durationSeconds, progress, videoMode]);

  const restart = useCallback(() => {
    const video = videoRef.current;
    video?.pause();
    if (video && Number.isFinite(video.duration) && video.duration > 0) video.currentTime = 0;
    setPlaying(false);
    setMediaError(undefined);
    setVideoMode(false);
    setTimelineProgress(0);
  }, [setTimelineProgress]);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (isInteractiveTarget(event.target)) return;
    if (["ArrowRight", "ArrowDown", "PageDown"].includes(event.key)) {
      event.preventDefault();
      moveStage(1);
    } else if (["ArrowLeft", "ArrowUp", "PageUp"].includes(event.key)) {
      event.preventDefault();
      moveStage(-1);
    } else if (event.key === "Home") {
      event.preventDefault();
      selectStage(0);
    } else if (event.key === "End") {
      event.preventDefault();
      selectStage(stages.length - 1);
    } else if (event.key === " ") {
      event.preventDefault();
      void togglePlayback();
    }
  };

  const onWheel = (event: ReactWheelEvent<HTMLElement>) => {
    if (isInteractiveTarget(event.target) || Math.abs(event.deltaY) < WHEEL_THRESHOLD) return;
    const now = performance.now();
    if (now - lastWheelAtRef.current < WHEEL_COOLDOWN_MS) return;
    lastWheelAtRef.current = now;
    moveStage(event.deltaY > 0 ? 1 : -1);
  };

  const onTouchStart = (event: ReactTouchEvent<HTMLElement>) => {
    const touch = event.touches[0];
    if (touch) touchStartRef.current = { x: touch.clientX, y: touch.clientY };
  };

  const onTouchEnd = (event: ReactTouchEvent<HTMLElement>) => {
    const start = touchStartRef.current;
    const touch = event.changedTouches[0];
    touchStartRef.current = undefined;
    if (!start || !touch || isInteractiveTarget(event.target)) return;
    const x = touch.clientX - start.x;
    const y = touch.clientY - start.y;
    const dominant = Math.abs(y) >= Math.abs(x) ? y : x;
    if (Math.abs(dominant) >= TOUCH_THRESHOLD) moveStage(dominant < 0 ? 1 : -1);
  };

  if (manifestState.kind !== "ready") {
    const title = manifestState.kind === "error" ? "Motion study unavailable" : "Generation in progress";
    const detail = manifestState.kind === "error"
      ? `${manifestState.message} The main Ti-Scale experience remains unchanged.`
      : manifestState.kind === "loading"
        ? "Loading the current Higgsfield production receipt and available keyframes."
        : "The production manifest has not been published yet. This page will populate from verified Higgsfield assets when generation completes.";
    return (
      <div className="motion-lab motion-lab--pending">
        <div className="motion-lab__pending" role="status" aria-live="polite">
          <p className="motion-lab__eyebrow">TI-SCALE · MOTION LAB</p>
          <h1>{title}</h1>
          <p>{detail}</p>
        </div>
      </div>
    );
  }
  const resolvedManifest = manifestState.manifest;

  return (
    <section
      className="motion-lab"
      data-motion-status={resolvedManifest.status}
      data-reduced-motion={reducedMotion ? "true" : "false"}
      aria-label="Titanium motion review stage"
      tabIndex={0}
      onKeyDown={onKeyDown}
      onWheel={onWheel}
      onTouchStart={onTouchStart}
      onTouchEnd={onTouchEnd}
    >
      <header className="motion-lab__masthead">
        <div>
          <p className="motion-lab__eyebrow">TI-SCALE · MOTION LAB</p>
          <h1>{resolvedManifest.studyTitle}</h1>
        </div>
        <div className="motion-lab__masthead-actions">
          <p className="motion-lab__production-state">
            <span aria-hidden="true" />
            {resolvedManifest.status === "ready" ? "Production render" : resolvedManifest.status === "failed" ? "Generation stopped" : "Final sequence rendering"}
          </p>
          <div className="motion-lab__review-links">
            <ButtonLink href="/motion-lab/particle-core" variant="primary">Inspect active particle core</ButtonLink>
            <ButtonLink href="/motion-lab/particle-module-transition" variant="quiet">Review particle-to-module transition</ButtonLink>
            <ButtonLink href="/motion-lab/candidates" variant="quiet">Review 3D pilot</ButtonLink>
          </div>
        </div>
      </header>

      <div className="motion-lab__media" aria-describedby="motion-lab-stage-description">
        {resolvedManifest.motion && !reducedMotion && (
          <video
            ref={videoRef}
            className={videoMode ? "motion-lab__video is-active" : "motion-lab__video is-idle"}
            muted
            playsInline
            preload="metadata"
            poster={motionAssetUrl(resolvedManifest.motion.posterPath)}
            width={resolvedManifest.motion.width}
            height={resolvedManifest.motion.height}
            aria-label="Titanium core mechanical transformation animation"
            onTimeUpdate={(event) => {
              const nextDuration = event.currentTarget.duration;
              if (Number.isFinite(nextDuration) && nextDuration > 0) setProgress(event.currentTarget.currentTime / nextDuration);
            }}
            onPlay={() => setPlaying(true)}
            onPause={() => setPlaying(false)}
            onEnded={() => {
              setPlaying(false);
              setProgress(1);
            }}
            onError={() => {
              setPlaying(false);
              setMediaError("The production clip could not be decoded. Static verified keyframes remain available.");
            }}
          />
        )}
        {activeStage && (!videoMode || reducedMotion || !resolvedManifest.motion || !motionObjectUrl) ? (
          <img
            key={activeStage.id}
            className="motion-lab__still"
            src={motionAssetUrl(activeStage.imagePath)}
            alt={activeStage.imageAlt}
            width={activeStage.width}
            height={activeStage.height}
            decoding="async"
            fetchPriority="high"
            onError={() => setMediaError("The selected verified keyframe could not be loaded from the motion asset set.")}
          />
        ) : null}
      </div>

      <div className="motion-lab__stage-copy" aria-live="polite" aria-atomic="true">
        <p>{String(activeStageIndex + 1).padStart(2, "0")} / {String(stages.length).padStart(2, "0")}</p>
        <div>
          <h2>{activeStage?.label ?? "Awaiting keyframe"}</h2>
          <p id="motion-lab-stage-description">{activeStage?.summary ?? resolvedManifest.statusDetail}</p>
        </div>
      </div>

      <nav className="motion-lab__stages" aria-label="Motion stages">
        {stages.map((stage, index) => (
          <button
            key={stage.id}
            type="button"
            className={index === activeStageIndex ? "is-active" : ""}
            aria-label={`View stage ${index + 1}: ${stage.label}`}
            aria-current={index === activeStageIndex ? "step" : undefined}
            onClick={() => selectStage(index)}
          >
            <span>{String(index + 1).padStart(2, "0")}</span>
            <i aria-hidden="true" />
          </button>
        ))}
      </nav>

      <footer className="motion-lab__controls">
        <div className="motion-lab__transport">
          <Button type="button" variant="secondary" onClick={() => moveStage(-1)} disabled={activeStageIndex === 0} aria-label="Previous motion stage">Previous</Button>
          <Button type="button" variant="primary" onClick={() => void togglePlayback()} disabled={!canPlay} aria-label={playing ? "Pause motion" : "Play motion"}>{playing ? "Pause" : "Play"}</Button>
          <Button type="button" variant="secondary" onClick={restart} aria-label="Restart motion">Restart</Button>
          <Button type="button" variant="secondary" onClick={() => moveStage(1)} disabled={activeStageIndex === stages.length - 1} aria-label="Next motion stage">Next</Button>
        </div>
        <label className="motion-lab__timeline">
          <span>Motion timeline</span>
          <input
            type="range"
            role="slider"
            aria-label="Motion timeline"
            min="0"
            max="1000"
            step="1"
            value={Math.round(progress * 1000)}
            onChange={(event) => void seekVideo(Number(event.currentTarget.value) / 1000)}
            disabled={!canPlay}
          />
          <output>{formatTime(progress * duration)} / {formatTime(duration)}</output>
        </label>
        <p className="motion-lab__guidance">
          {reducedMotion
            ? "Reduced motion is active. Use the stage controls to inspect verified keyframes."
            : motionLoading
              ? "Preparing the background-free production sequence for smooth local seeking."
              : resolvedManifest.motion
              ? "Scroll, swipe, use arrow keys, or scrub the production sequence."
              : resolvedManifest.statusDetail}
        </p>
        {mediaError && <p className="motion-lab__media-error" role="alert">{mediaError}</p>}
      </footer>
    </section>
  );
}
