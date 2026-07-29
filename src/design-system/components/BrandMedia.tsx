import {
  useEffect,
  useRef,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { assetUrl } from "../../lib/assetUrl";

type TitaniumCoreVariant = "command" | "journeys";

const POINTER_DEPTH_SEGMENTS = 5;
const CORE_FACET_COUNT = 8;

function pointerDepthSegment(position: number, size: number): string {
  if (!Number.isFinite(position) || !Number.isFinite(size) || size <= 0) return "2";
  return String(Math.max(0, Math.min(
    POINTER_DEPTH_SEGMENTS - 1,
    Math.floor((position / size) * POINTER_DEPTH_SEGMENTS),
  )));
}

function TitaniumCore({ variant }: { variant: TitaniumCoreVariant }) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);
  const lockedFacetsRef = useRef(new Set<EventTarget>());
  const core640Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.avif");
  const core1024Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1024.avif");
  const core1344Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1344.avif");
  const core640Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.webp");
  const core1024Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1024.webp");
  const core1344Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1344.webp");
  const metalGradientId = `ti-adaptive-metal-${variant}`;
  const darkGradientId = `ti-adaptive-graphite-${variant}`;

  useEffect(() => {
    const root = rootRef.current;
    const settleFacet = (event: AnimationEvent) => {
      if (event.animationName !== "ti-transformer-facet-lock") return;
      const target = event.target;
      if (!(target instanceof HTMLElement) || !target.matches("[data-ti-core-facet]")) return;
      lockedFacetsRef.current.add(target);
      if (lockedFacetsRef.current.size >= CORE_FACET_COUNT && root) {
        root.dataset.tiCoreState = "locked";
      }
    };
    root?.addEventListener("animationend", settleFacet);
    root?.addEventListener("animationcancel", settleFacet);
    // Animation events can be throttled while a tab is being backgrounded.
    // This finite safety deadline releases compositor hints even in that case.
    const lockSafetyTimer = window.setTimeout(() => {
      const root = rootRef.current;
      if (root) root.dataset.tiCoreState = "locked";
    }, 1_900);
    return () => {
      root?.removeEventListener("animationend", settleFacet);
      root?.removeEventListener("animationcancel", settleFacet);
      window.clearTimeout(lockSafetyTimer);
      if (animationFrameRef.current !== null) {
        window.cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, []);

  const setPointerDepth = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (
      typeof window === "undefined" || document.visibilityState === "hidden" || event.pointerType === "touch" ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) return;
    const root = rootRef.current;
    if (!root) return;
    const bounds = root.getBoundingClientRect();
    const column = pointerDepthSegment(event.clientX - bounds.left, bounds.width);
    const row = pointerDepthSegment(event.clientY - bounds.top, bounds.height);
    if (animationFrameRef.current !== null) window.cancelAnimationFrame(animationFrameRef.current);
    animationFrameRef.current = window.requestAnimationFrame(() => {
      root.dataset.tiPointerColumn = column;
      root.dataset.tiPointerRow = row;
      animationFrameRef.current = null;
    });
  };

  const resetPointerDepth = () => {
    const root = rootRef.current;
    if (!root) return;
    if (animationFrameRef.current !== null) window.cancelAnimationFrame(animationFrameRef.current);
    animationFrameRef.current = window.requestAnimationFrame(() => {
      root.dataset.tiPointerColumn = "2";
      root.dataset.tiPointerRow = "2";
      animationFrameRef.current = null;
    });
  };

  return (
    <div
      ref={rootRef}
      className={`os-brand-media os-brand-media--${variant} ti-scale-core ti-scale-core--${variant}`}
      data-ti-transformer-core="true"
      data-ti-exploded-model="pending-approval"
      data-ti-core-state="assembling"
      data-ti-pointer-column="2"
      data-ti-pointer-row="2"
      aria-hidden="true"
      onPointerMove={setPointerDepth}
      onPointerLeave={resetPointerDepth}
      onPointerCancel={resetPointerDepth}
    >
      <span className="ti-scale-core__wake" />
      <span className="ti-scale-core__hud ti-scale-core__hud--north" />
      <span className="ti-scale-core__hud ti-scale-core__hud--east" />
      <span className="ti-scale-core__hud ti-scale-core__hud--south" />
      <span className="ti-scale-core__hud ti-scale-core__hud--west" />
      <svg className="ti-scale-core__architecture" viewBox="0 0 800 620" preserveAspectRatio="xMidYMid meet" focusable="false">
        <defs>
          <linearGradient id={metalGradientId} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#fffefa" stopOpacity="0.12" />
            <stop offset="0.4" stopColor="#aeb4b8" stopOpacity="0.42" />
            <stop offset="0.72" stopColor="#6c737a" stopOpacity="0.2" />
            <stop offset="1" stopColor="#fffefa" stopOpacity="0.04" />
          </linearGradient>
          <linearGradient id={darkGradientId} x1="1" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#111315" stopOpacity="0.34" />
            <stop offset="0.52" stopColor="#596168" stopOpacity="0.13" />
            <stop offset="1" stopColor="#8d795b" stopOpacity="0.08" />
          </linearGradient>
        </defs>
        <path className="ti-scale-core__plate ti-scale-core__plate--far" fill={`url(#${metalGradientId})`} d="M78 354 292 66l126 75-174 392-196-42Z" />
        <path className="ti-scale-core__plate ti-scale-core__plate--upper" fill={`url(#${darkGradientId})`} d="m385 72 338 155-91 139-278-206Z" />
        <path className="ti-scale-core__plate ti-scale-core__plate--lower" fill={`url(#${metalGradientId})`} d="m255 418 347-116 137 195-359 73Z" />
      </svg>
      <span className="ti-scale-core__shards">
        {Array.from({ length: CORE_FACET_COUNT }, (_, index) => (
          <span
            className={`ti-scale-core__shard ti-scale-core__shard--${index + 1}`}
            key={index}
            data-ti-core-facet={index + 1}
          />
        ))}
      </span>
      <picture className="ti-scale-core__media" data-ti-raster-canvas="static">
        <source
          type="image/avif"
          srcSet={`${core640Avif} 640w, ${core1024Avif} 1024w, ${core1344Avif} 1344w`}
          sizes={variant === "command" ? "(max-width: 760px) 88vw, (max-width: 1200px) 48vw, 620px" : "(max-width: 760px) 86vw, 520px"}
        />
        <source
          type="image/webp"
          srcSet={`${core640Webp} 640w, ${core1024Webp} 1024w, ${core1344Webp} 1344w`}
          sizes={variant === "command" ? "(max-width: 760px) 88vw, (max-width: 1200px) 48vw, 620px" : "(max-width: 760px) 86vw, 520px"}
        />
        <img
          src={core1024Webp}
          width="1344"
          height="768"
          alt=""
          loading={variant === "command" ? "eager" : "lazy"}
          fetchPriority={variant === "command" ? "high" : "auto"}
          decoding={variant === "command" ? "sync" : "async"}
          draggable="false"
        />
      </picture>
      <span className="ti-scale-core__sheen" />
    </div>
  );
}

export function CommandCenterAmbient() {
  return <TitaniumCore variant="command" />;
}

export function JourneyAmbient() {
  return <TitaniumCore variant="journeys" />;
}
