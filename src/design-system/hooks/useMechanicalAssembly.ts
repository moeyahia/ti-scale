import { useLayoutEffect, useRef, type RefObject } from "react";

const MODULE_SELECTOR = "[data-ti-module]";
const CORE_SELECTOR = "[data-ti-transformer-core='true']";
const CORE_FACET_SELECTOR = "[data-ti-core-facet]";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const MODULE_ASSEMBLY_DURATION_MS = 920;
const MODULE_ASSEMBLY_STAGGER_MS = 34;
const MODULE_ASSEMBLY_MAX_ORDER = 8;
const MODULE_LOCK_SAFETY_MS = 160;
const CORE_TRANSFER_DURATION_MS = 680;
const CORE_TRANSFER_STAGGER_MS = 32;

type CoreTransferDirection = "release" | "recall";

interface FacetDestination {
  destination: HTMLElement;
  destinationName: string;
  facet: HTMLElement;
  facetIndex: number;
}

interface ActiveCoreTransfer {
  animations: Animation[];
  direction: CoreTransferDirection;
  layer: HTMLElement;
  version: number;
}

function assignModuleOrder(module: HTMLElement, index: number): void {
  module.dataset.tiOrder = String(Math.min(index, MODULE_ASSEMBLY_MAX_ORDER));
}

function moduleDestinationName(module: HTMLElement, occurrence: number): string {
  const rawName = module.dataset.tiModule?.trim() || "module";
  return `${rawName}-${occurrence}`;
}

function measuredTransform(rect: DOMRect, width: number, height: number): string {
  const x = rect.left + (rect.width / 2) - (width / 2);
  const y = rect.top + (rect.height / 2) - (height / 2);
  return `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0)`;
}

function measuredAnchor(rect: DOMRect): string {
  return `${(rect.left + (rect.width / 2)).toFixed(2)},${(rect.top + (rect.height / 2)).toFixed(2)}`;
}

/**
 * Viewport-owned mechanical choreography for the Command Center. Modules stay
 * as ordinary semantic HTML. A short-lived, aria-hidden overlay carries CSS
 * titanium ghost facets between measured core and module anchors; it never
 * moves, clips, or removes the actual content or its focus targets.
 */
export function useMechanicalAssembly(): RefObject<HTMLDivElement | null> {
  const rootRef = useRef<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;

    const reducedMotion = window.matchMedia(REDUCED_MOTION_QUERY);
    let observer: IntersectionObserver | undefined;
    let mutationObserver: MutationObserver | undefined;
    let viewportFrame: number | undefined;
    let cancelled = false;
    let transferVersion = 0;
    let activeTransfer: ActiveCoreTransfer | undefined;
    const lockTimers = new Map<HTMLElement, number>();
    const assembledModules = new WeakSet<HTMLElement>();

    const clearLockTimer = (module: HTMLElement) => {
      const timer = lockTimers.get(module);
      if (timer !== undefined) window.clearTimeout(timer);
      lockTimers.delete(module);
    };

    const lockModule = (module: HTMLElement) => {
      clearLockTimer(module);
      if (root.contains(module)) {
        assembledModules.add(module);
        module.dataset.tiPhase = "locked";
      }
    };

    const disassembleModule = (module: HTMLElement) => {
      if (assembledModules.has(module)) {
        lockModule(module);
        return;
      }
      clearLockTimer(module);
      module.dataset.tiPhase = "disassembled";
    };

    const beginModuleAssembly = (module: HTMLElement) => {
      if (assembledModules.has(module) || module.dataset.tiPhase === "locked") {
        lockModule(module);
        return;
      }
      // WebKit may report one target at several observer thresholds during a
      // single scroll. Keep exactly one animation owner and lock deadline.
      if (module.dataset.tiPhase === "assembling" && lockTimers.has(module)) return;
      module.dataset.tiPhase = "assembling";
      const order = Number.parseInt(module.dataset.tiOrder ?? "0", 10);
      const boundedOrder = Number.isFinite(order)
        ? Math.max(0, Math.min(MODULE_ASSEMBLY_MAX_ORDER, order))
        : 0;
      const timer = window.setTimeout(
        () => lockModule(module),
        MODULE_ASSEMBLY_DURATION_MS + (boundedOrder * MODULE_ASSEMBLY_STAGGER_MS) + MODULE_LOCK_SAFETY_MS,
      );
      lockTimers.set(module, timer);
    };

    const settleAllModules = (phase: "disassembled" | "locked") => {
      root.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach((module, index) => {
        assignModuleOrder(module, index);
        if (phase === "locked") lockModule(module);
        else disassembleModule(module);
      });
    };

    const mapFacetDestinations = (): FacetDestination[] => {
      const core = root.querySelector<HTMLElement>(CORE_SELECTOR);
      if (!core) return [];
      const facets = Array.from(core.querySelectorAll<HTMLElement>(CORE_FACET_SELECTOR));
      const coreModule = core.closest<HTMLElement>(MODULE_SELECTOR);
      const destinations = Array.from(root.querySelectorAll<HTMLElement>(MODULE_SELECTOR))
        .filter((module) => module !== coreModule);
      const usableDestinations = destinations.length > 0
        ? destinations
        : coreModule ? [coreModule] : [];
      if (facets.length === 0 || usableDestinations.length === 0) return [];

      const occurrences = new Map<string, number>();
      const names = usableDestinations.map((destination) => {
        const key = destination.dataset.tiModule?.trim() || "module";
        const occurrence = (occurrences.get(key) ?? 0) + 1;
        occurrences.set(key, occurrence);
        const name = moduleDestinationName(destination, occurrence);
        destination.dataset.tiTransformDestination = name;
        return name;
      });

      return facets.map((facet, facetIndex) => {
        const targetIndex = facetIndex % usableDestinations.length;
        const destination = usableDestinations[targetIndex]!;
        const destinationName = names[targetIndex]!;
        facet.dataset.tiDestination = destinationName;
        return { destination, destinationName, facet, facetIndex };
      });
    };

    const cancelCoreTransfer = () => {
      transferVersion += 1;
      if (!activeTransfer) return;
      for (const animation of activeTransfer.animations) animation.cancel();
      activeTransfer.layer.remove();
      activeTransfer = undefined;
    };

    const settleCoreTransfer = (direction: CoreTransferDirection, state = direction === "release" ? "released" : "recalled") => {
      root.dataset.tiCoreFlow = direction === "release" ? "released" : "recalled";
      root.dataset.tiCoreTransferState = state;
    };

    const startCoreTransfer = (direction: CoreTransferDirection) => {
      cancelCoreTransfer();
      if (cancelled) return;

      const mappings = mapFacetDestinations();
      root.dataset.tiTransferCount = String(mappings.length);
      root.dataset.tiCoreFlow = direction === "release" ? "releasing" : "recalling";
      root.dataset.tiCoreTransferState = direction === "release" ? "releasing" : "recalling";

      if (
        mappings.length === 0 ||
        reducedMotion.matches ||
        document.visibilityState === "hidden" ||
        typeof Element.prototype.animate !== "function"
      ) {
        settleCoreTransfer(direction, "static");
        return;
      }

      const version = transferVersion;
      const layer = document.createElement("div");
      layer.className = "ti-core-transfer-layer";
      layer.dataset.tiCoreTransferLayer = direction;
      layer.setAttribute("aria-hidden", "true");
      document.body.append(layer);

      const animations = mappings.map((mapping) => {
        const ghost = document.createElement("span");
        ghost.className = `ti-core-transfer-ghost ti-core-transfer-ghost--${mapping.facetIndex + 1}`;
        ghost.dataset.tiTransferDestination = mapping.destinationName;
        ghost.dataset.tiTransferFacet = String(mapping.facetIndex + 1);
        layer.append(ghost);

        const ghostWidth = 82;
        const ghostHeight = 54;
        const sourceRect = mapping.facet.getBoundingClientRect();
        const destinationRect = mapping.destination.getBoundingClientRect();
        ghost.dataset.tiSourceAnchor = measuredAnchor(sourceRect);
        ghost.dataset.tiDestinationAnchor = measuredAnchor(destinationRect);
        const sourceTransform = measuredTransform(sourceRect, ghostWidth, ghostHeight);
        const destinationTransform = measuredTransform(destinationRect, ghostWidth, ghostHeight);
        const startTransform = direction === "release" ? sourceTransform : destinationTransform;
        const endTransform = direction === "release" ? destinationTransform : sourceTransform;
        const rotation = ((mapping.facetIndex % 2 === 0 ? -1 : 1) * (4 + mapping.facetIndex)).toFixed(1);
        const animation = ghost.animate([
          { opacity: 0, transform: `${startTransform} rotate(0deg) scale(.54)` },
          { opacity: 0.94, offset: 0.16, transform: `${startTransform} rotate(${rotation}deg) scale(1)` },
          { opacity: 0.76, offset: 0.72, transform: `${endTransform} rotate(${rotation}deg) scale(.72)` },
          { opacity: 0, transform: `${endTransform} rotate(0deg) scale(.28)` },
        ], {
          delay: mapping.facetIndex * CORE_TRANSFER_STAGGER_MS,
          duration: CORE_TRANSFER_DURATION_MS,
          easing: "cubic-bezier(.2,.78,.16,1)",
          fill: "both",
        });
        return animation;
      });

      activeTransfer = { animations, direction, layer, version };
      void Promise.all(animations.map(async (animation) => {
        try {
          await animation.finished;
        } catch {
          // Cancellation is the expected path when scroll direction reverses.
        }
      })).then(() => {
        if (cancelled || !activeTransfer || activeTransfer.version !== version) return;
        activeTransfer.layer.remove();
        activeTransfer = undefined;
        settleCoreTransfer(direction);
      });
    };

    const updateCoreFlow = () => {
      if (reducedMotion.matches || document.visibilityState === "hidden") {
        cancelCoreTransfer();
        root.dataset.tiCoreFlow = "static";
        root.dataset.tiCoreTransferState = "static";
        return;
      }
      const core = root.querySelector<HTMLElement>(CORE_SELECTOR);
      if (!core) return;
      // The operator-approved particle sculpture owns its motion inside one
      // WebGL draw call. It is not decomposed into the retired CSS/GLB ghost
      // transfer. A future cluster-to-module transition must use the same
      // approved particle coordinates and receive its own interaction proof.
      if (core.dataset.tiExplodedModel === "approved-particle-core") {
        if (activeTransfer) cancelCoreTransfer();
        root.dataset.tiCoreFlow = "static";
        root.dataset.tiCoreTransferState = "particle-core-approved";
        root.dataset.tiTransferCount = "0";
        return;
      }
      // The approved raster remains one static visual plane until an
      // operator-approved, content-addressed exploded model is mounted. Do
      // not manufacture an invisible transfer from placeholder CSS facets:
      // it creates false motion evidence and can reintroduce the duplicate
      // hero flash that this boundary is meant to prevent.
      if (core.dataset.tiExplodedModel !== "approved") {
        if (activeTransfer) cancelCoreTransfer();
        root.dataset.tiCoreFlow = "static";
        root.dataset.tiCoreTransferState = "awaiting-artwork-approval";
        return;
      }
      const bounds = core.getBoundingClientRect();
      const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
      const current = root.dataset.tiCoreFlow ?? "primed";
      const shouldRelease = window.scrollY > 120 && bounds.bottom < viewportHeight * 0.82;
      const shouldRecall = window.scrollY < 45 || bounds.bottom > viewportHeight * 0.93;

      if (shouldRecall && (current === "released" || current === "releasing")) {
        startCoreTransfer("recall");
      } else if (shouldRelease && !["released", "releasing"].includes(current)) {
        startCoreTransfer("release");
      } else if (current === "static" && !shouldRelease) {
        root.dataset.tiCoreFlow = "primed";
        root.dataset.tiCoreTransferState = "primed";
      }
    };

    const stopObserver = () => {
      observer?.disconnect();
      observer = undefined;
    };

    const activateVisibleModules = () => {
      viewportFrame = undefined;
      if (cancelled || reducedMotion.matches || document.visibilityState === "hidden") return;
      updateCoreFlow();
      const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
      root.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach((module) => {
        const bounds = module.getBoundingClientRect();
        const intersectsViewport = bounds.bottom > viewportHeight * 0.04 && bounds.top < viewportHeight * 0.96;
        if (intersectsViewport) beginModuleAssembly(module);
      });
    };

    const scheduleViewportCheck = () => {
      if (viewportFrame !== undefined || cancelled) return;
      viewportFrame = window.requestAnimationFrame(activateVisibleModules);
    };

    const configure = (preserveLockedModules = false) => {
      stopObserver();
      if (cancelled) return;
      const modules = Array.from(root.querySelectorAll<HTMLElement>(MODULE_SELECTOR));
      modules.forEach(assignModuleOrder);
      mapFacetDestinations();

      if (
        reducedMotion.matches ||
        document.visibilityState === "hidden" ||
        typeof IntersectionObserver === "undefined"
      ) {
        cancelCoreTransfer();
        settleAllModules("locked");
        root.dataset.tiAssembly = reducedMotion.matches ? "reduced" : "paused";
        root.dataset.tiCoreFlow = "static";
        root.dataset.tiCoreTransferState = "static";
        return;
      }

      root.dataset.tiAssembly = "active";
      if (!preserveLockedModules && root.dataset.tiAssemblyInitialized !== "true") {
        settleAllModules("disassembled");
      } else {
        modules.forEach((module) => {
          if (!module.dataset.tiPhase) disassembleModule(module);
        });
      }
      observer = new IntersectionObserver((entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) beginModuleAssembly(entry.target as HTMLElement);
        }
      }, {
        rootMargin: "7% 0px -5% 0px",
        threshold: [0.08, 0.2],
      });
      modules.forEach((module) => observer?.observe(module));
      root.dataset.tiAssemblyInitialized = "true";
      scheduleViewportCheck();
    };

    const registerAddedModule = (module: HTMLElement) => {
      const modules = Array.from(root.querySelectorAll<HTMLElement>(MODULE_SELECTOR));
      const index = Math.max(0, modules.indexOf(module));
      assignModuleOrder(module, index);
      mapFacetDestinations();
      if (
        reducedMotion.matches ||
        document.visibilityState === "hidden" ||
        typeof IntersectionObserver === "undefined" ||
        !observer
      ) {
        lockModule(module);
        return;
      }
      disassembleModule(module);
      observer.observe(module);
      scheduleViewportCheck();
    };

    const settleCompletedAnimation = (event: AnimationEvent) => {
      if (event.animationName !== "ti-module-assemble") return;
      const module = (event.target as Element).closest<HTMLElement>(MODULE_SELECTOR);
      if (module && root.contains(module)) lockModule(module);
    };
    const onFocusIn = (event: FocusEvent) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const module = target.closest<HTMLElement>(MODULE_SELECTOR);
      if (module && root.contains(module)) lockModule(module);
    };
    const onVisibilityChange = () => configure(document.visibilityState === "visible");
    const onMotionPreferenceChange = () => configure();
    const onResize = () => {
      if (activeTransfer) startCoreTransfer(activeTransfer.direction);
      else scheduleViewportCheck();
    };

    root.addEventListener("animationend", settleCompletedAnimation);
    root.addEventListener("animationcancel", settleCompletedAnimation);
    root.addEventListener("focusin", onFocusIn);
    document.addEventListener("scroll", scheduleViewportCheck, true);
    window.addEventListener("resize", onResize);
    document.addEventListener("visibilitychange", onVisibilityChange);
    reducedMotion.addEventListener("change", onMotionPreferenceChange);
    mutationObserver = new MutationObserver((records) => {
      for (const record of records) {
        if (
          record.type === "attributes" &&
          record.target instanceof HTMLElement &&
          assembledModules.has(record.target) &&
          record.target.dataset.tiPhase !== "locked"
        ) {
          lockModule(record.target);
        }
        for (const addedNode of Array.from(record.addedNodes)) {
          if (!(addedNode instanceof HTMLElement)) continue;
          if (addedNode.matches(MODULE_SELECTOR)) registerAddedModule(addedNode);
          addedNode.querySelectorAll<HTMLElement>(MODULE_SELECTOR).forEach(registerAddedModule);
        }
      }
    });
    mutationObserver.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["data-ti-phase"],
    });
    configure();

    return () => {
      cancelled = true;
      cancelCoreTransfer();
      stopObserver();
      mutationObserver?.disconnect();
      for (const timer of lockTimers.values()) window.clearTimeout(timer);
      lockTimers.clear();
      if (viewportFrame !== undefined) window.cancelAnimationFrame(viewportFrame);
      root.removeEventListener("animationend", settleCompletedAnimation);
      root.removeEventListener("animationcancel", settleCompletedAnimation);
      root.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("scroll", scheduleViewportCheck, true);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      reducedMotion.removeEventListener("change", onMotionPreferenceChange);
    };
  }, []);

  return rootRef;
}
