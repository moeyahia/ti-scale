import { useEffect, useRef, type PointerEvent as ReactPointerEvent } from "react";
import { assetUrl } from "../../lib/assetUrl";

type TitaniumCoreVariant = "command" | "journeys";

function TitaniumCore({ variant }: { variant: TitaniumCoreVariant }) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);
  const core640Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.avif");
  const core1024Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1024.avif");
  const core1344Avif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1344.avif");
  const core640Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.webp");
  const core1024Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1024.webp");
  const core1344Webp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-1344.webp");

  useEffect(() => () => {
    if (animationFrameRef.current !== null) {
      window.cancelAnimationFrame(animationFrameRef.current);
    }
  }, []);

  const setPointerDepth = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (typeof window === "undefined" || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const root = rootRef.current;
    if (!root) return;
    const bounds = root.getBoundingClientRect();
    const x = Math.max(-1, Math.min(1, ((event.clientX - bounds.left) / bounds.width - 0.5) * 2));
    const y = Math.max(-1, Math.min(1, ((event.clientY - bounds.top) / bounds.height - 0.5) * 2));
    if (animationFrameRef.current !== null) window.cancelAnimationFrame(animationFrameRef.current);
    animationFrameRef.current = window.requestAnimationFrame(() => {
      root.style.setProperty("--ti-pointer-x", x.toFixed(3));
      root.style.setProperty("--ti-pointer-y", y.toFixed(3));
      root.style.setProperty("--ti-rotate-x", `${(-y * 3.2).toFixed(2)}deg`);
      root.style.setProperty("--ti-rotate-y", `${(x * 4.2).toFixed(2)}deg`);
      root.style.setProperty("--ti-shift-x", `${(x * 8).toFixed(2)}px`);
      root.style.setProperty("--ti-shift-y", `${(y * 6).toFixed(2)}px`);
      animationFrameRef.current = null;
    });
  };

  const resetPointerDepth = () => {
    const root = rootRef.current;
    if (!root) return;
    if (animationFrameRef.current !== null) window.cancelAnimationFrame(animationFrameRef.current);
    animationFrameRef.current = window.requestAnimationFrame(() => {
      root.style.setProperty("--ti-pointer-x", "0");
      root.style.setProperty("--ti-pointer-y", "0");
      root.style.setProperty("--ti-rotate-x", "0deg");
      root.style.setProperty("--ti-rotate-y", "0deg");
      root.style.setProperty("--ti-shift-x", "0px");
      root.style.setProperty("--ti-shift-y", "0px");
      animationFrameRef.current = null;
    });
  };

  return (
    <div
      ref={rootRef}
      className={`os-brand-media os-brand-media--${variant} ti-scale-core ti-scale-core--${variant}`}
      aria-hidden="true"
      onPointerMove={setPointerDepth}
      onPointerLeave={resetPointerDepth}
      onPointerCancel={resetPointerDepth}
    >
      <span className="ti-scale-core__field" />
      <span className="ti-scale-core__guide ti-scale-core__guide--horizontal" />
      <span className="ti-scale-core__guide ti-scale-core__guide--vertical" />
      <span className="ti-scale-core__orbit ti-scale-core__orbit--outer" />
      <span className="ti-scale-core__orbit ti-scale-core__orbit--inner" />
      <picture className="ti-scale-core__media">
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
          loading="lazy"
          decoding="async"
          draggable="false"
        />
      </picture>
      <span className="ti-scale-core__node ti-scale-core__node--north" />
      <span className="ti-scale-core__node ti-scale-core__node--east" />
      <span className="ti-scale-core__node ti-scale-core__node--south" />
      <span className="ti-scale-core__node ti-scale-core__node--west" />
    </div>
  );
}

export function CommandCenterAmbient() {
  return <TitaniumCore variant="command" />;
}

export function JourneyAmbient() {
  return <TitaniumCore variant="journeys" />;
}
