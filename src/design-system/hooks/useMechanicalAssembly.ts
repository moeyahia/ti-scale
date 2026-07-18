import { useEffect, useRef, type RefObject } from "react";

const MODULE_SELECTOR = "[data-ti-module]";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function settleModules(root: HTMLElement, phase: "disassembled" | "locked"): void {
  root.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach((module, index) => {
    module.style.setProperty("--ti-module-index", String(index));
    module.style.setProperty("--ti-module-delay", `${Math.min(index, 8) * 34}ms`);
    module.dataset.tiPhase = phase;
  });
}

/**
 * Viewport-owned mechanical choreography for the Command Center. Modules are
 * ordinary semantic HTML; this hook only adds finite presentation states.
 * Hidden tabs and reduced-motion users receive an immediately locked layout.
 */
export function useMechanicalAssembly(): RefObject<HTMLDivElement | null> {
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;

    const reducedMotion = window.matchMedia(REDUCED_MOTION_QUERY);
    let observer: IntersectionObserver | undefined;
    let mutationObserver: MutationObserver | undefined;
    let viewportFrame: number | undefined;
    let cancelled = false;

    const stopObserver = () => {
      observer?.disconnect();
      observer = undefined;
    };

    const activateVisibleModules = () => {
      viewportFrame = undefined;
      if (cancelled || reducedMotion.matches || document.visibilityState === "hidden") return;
      const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
      root.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach((module) => {
        const bounds = module.getBoundingClientRect();
        const intersectsViewport = bounds.bottom > viewportHeight * 0.04 && bounds.top < viewportHeight * 0.96;
        if (intersectsViewport && module.dataset.tiPhase !== "locked" && module.dataset.tiPhase !== "assembling") {
          module.dataset.tiPhase = "assembling";
        }
      });
    };

    const scheduleViewportCheck = () => {
      if (viewportFrame !== undefined || cancelled) return;
      viewportFrame = window.requestAnimationFrame(activateVisibleModules);
    };

    const configure = () => {
      stopObserver();
      if (cancelled) return;
      const modules = [...root.querySelectorAll<HTMLElement>(MODULE_SELECTOR)];
      modules.forEach((module, index) => {
        module.style.setProperty("--ti-module-index", String(index));
        module.style.setProperty("--ti-module-delay", `${Math.min(index, 8) * 34}ms`);
      });

      if (
        reducedMotion.matches ||
        document.visibilityState === "hidden" ||
        typeof IntersectionObserver === "undefined"
      ) {
        settleModules(root, "locked");
        root.dataset.tiAssembly = reducedMotion.matches ? "reduced" : "paused";
        return;
      }

      root.dataset.tiAssembly = "active";
      settleModules(root, "disassembled");
      observer = new IntersectionObserver((entries) => {
        for (const entry of entries) {
          const module = entry.target as HTMLElement;
          if (entry.isIntersecting) {
            if (module.dataset.tiPhase !== "locked") module.dataset.tiPhase = "assembling";
          } else if (entry.boundingClientRect.bottom < 0 || entry.boundingClientRect.top > window.innerHeight) {
            module.dataset.tiPhase = "disassembled";
          }
        }
      }, {
        rootMargin: "7% 0px -5% 0px",
        threshold: [0.08, 0.2],
      });
      modules.forEach((module) => observer?.observe(module));
      scheduleViewportCheck();
    };

    const registerAddedModule = (module: HTMLElement) => {
      const modules = [...root.querySelectorAll<HTMLElement>(MODULE_SELECTOR)];
      const index = Math.max(0, modules.indexOf(module));
      module.style.setProperty("--ti-module-index", String(index));
      module.style.setProperty("--ti-module-delay", `${Math.min(index, 8) * 34}ms`);
      if (
        reducedMotion.matches ||
        document.visibilityState === "hidden" ||
        typeof IntersectionObserver === "undefined" ||
        !observer
      ) {
        module.dataset.tiPhase = "locked";
        return;
      }
      module.dataset.tiPhase = "disassembled";
      observer.observe(module);
      scheduleViewportCheck();
    };

    const onAnimationEnd = (event: AnimationEvent) => {
      if (event.animationName !== "ti-module-assemble") return;
      const module = (event.target as Element).closest<HTMLElement>(MODULE_SELECTOR);
      if (module && root.contains(module)) module.dataset.tiPhase = "locked";
    };
    const onVisibilityChange = () => configure();
    const onMotionPreferenceChange = () => configure();

    root.addEventListener("animationend", onAnimationEnd);
    document.addEventListener("scroll", scheduleViewportCheck, true);
    window.addEventListener("resize", scheduleViewportCheck);
    document.addEventListener("visibilitychange", onVisibilityChange);
    reducedMotion.addEventListener("change", onMotionPreferenceChange);
    mutationObserver = new MutationObserver((records) => {
      for (const record of records) {
        for (const addedNode of record.addedNodes) {
          if (!(addedNode instanceof HTMLElement)) continue;
          if (addedNode.matches(MODULE_SELECTOR)) registerAddedModule(addedNode);
          addedNode.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach(registerAddedModule);
        }
      }
    });
    mutationObserver.observe(root, { childList: true, subtree: true });
    configure();

    return () => {
      cancelled = true;
      stopObserver();
      mutationObserver?.disconnect();
      if (viewportFrame !== undefined) window.cancelAnimationFrame(viewportFrame);
      root.removeEventListener("animationend", onAnimationEnd);
      document.removeEventListener("scroll", scheduleViewportCheck, true);
      window.removeEventListener("resize", scheduleViewportCheck);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      reducedMotion.removeEventListener("change", onMotionPreferenceChange);
    };
  }, []);

  return rootRef;
}
