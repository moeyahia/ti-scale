import {
  createContext,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { flushSync } from "react-dom";
import { preloadRouteModule } from "./routeModules";

export type RouteTransitionPhase = "idle" | "disassembling" | "committing" | "assembling";
export type RouteTransitionMode = "native" | "fallback" | "bypass";

export const MECHANICAL_NAVIGATION_REQUEST_EVENT = "ti-scale:mechanical-navigate";
export const MECHANICAL_ROUTE_TRANSITION_EVENT = "ti-scale:route-transition";
export const MECHANICAL_ROUTE_TIMING = Object.freeze({
  disassembleMs: 180,
  fallbackAssembleMs: 360,
  maximumMs: 840,
});

interface NavigationOptions {
  replace?: boolean;
}

interface NavigationContextValue {
  pathname: string;
  search: string;
  hash: string;
  navigate: (path: string, options?: NavigationOptions) => void;
}

export interface LocationSnapshot {
  pathname: string;
  search: string;
  hash: string;
}

export interface ViewTransitionHandle {
  readonly finished: Promise<void>;
  readonly updateCallbackDone: Promise<void>;
  skipTransition: () => void;
}

export interface RouteTransitionPresentation {
  readonly phase: RouteTransitionPhase;
  readonly mode?: Exclude<RouteTransitionMode, "bypass">;
  readonly from?: string;
  readonly to?: string;
  readonly revision: number;
}

export interface MechanicalRouteTransitionRuntime {
  shouldBypass: () => boolean;
  sleep: (milliseconds: number, signal: AbortSignal) => Promise<boolean>;
  publish: (presentation: RouteTransitionPresentation) => void;
  startViewTransition?: (update: () => void | Promise<void>) => ViewTransitionHandle;
}

export interface MechanicalRouteTransitionRequest {
  readonly from: string;
  readonly to: string;
  readonly prepare?: () => Promise<unknown>;
  readonly commit: (mode: RouteTransitionMode) => void | Promise<void>;
}

export type MechanicalRouteTransitionOutcome = "completed" | "cancelled" | "bypassed";

const NavigationContext = createContext<NavigationContextValue | null>(null);

function safeInternalPath(path: string): string {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) return "/";
  return path;
}

function currentLocation(): LocationSnapshot {
  if (typeof window === "undefined") {
    return { pathname: "/", search: "", hash: "" };
  }
  return {
    pathname: window.location.pathname,
    search: window.location.search,
    hash: window.location.hash,
  };
}

function locationTarget(location: LocationSnapshot): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

export type NavigationChangeKind = "noop" | "location-only" | "route";

export function classifyLocationChange(previous: LocationSnapshot, next: LocationSnapshot): NavigationChangeKind {
  if (locationTarget(previous) === locationTarget(next)) return "noop";
  return previous.pathname === next.pathname ? "location-only" : "route";
}

export function shouldInterceptAppLinkClick(input: {
  readonly href: string;
  readonly button: number;
  readonly detail: number;
  readonly defaultPrevented: boolean;
  readonly metaKey: boolean;
  readonly ctrlKey: boolean;
  readonly shiftKey: boolean;
  readonly altKey: boolean;
  readonly target?: string;
  readonly hasDownload: boolean;
}): boolean {
  if (input.defaultPrevented) return false;
  const nonPrimaryPointer = input.detail > 0 && input.button !== 0;
  const opensSeparateContext = Boolean(input.target && input.target.toLowerCase() !== "_self");
  const isInternal = input.href.startsWith("/") && !input.href.startsWith("//") && !input.href.includes("\\");
  return !(
    nonPrimaryPointer
    || input.metaKey
    || input.ctrlKey
    || input.shiftKey
    || input.altKey
    || opensSeparateContext
    || input.hasDownload
    || !isInternal
  );
}

function abortableSleep(milliseconds: number, signal: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve(false);
      return;
    }
    const timeout = globalThis.setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve(true);
    }, milliseconds);
    const onAbort = () => {
      globalThis.clearTimeout(timeout);
      resolve(false);
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

type DeadlineResult = "resolved" | "rejected" | "timeout" | "cancelled";

function settleBeforeDeadline(promise: Promise<void>, milliseconds: number, signal: AbortSignal): Promise<DeadlineResult> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve("cancelled");
      return;
    }
    let settled = false;
    const finish = (result: DeadlineResult) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timeout);
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const timeout = globalThis.setTimeout(() => finish("timeout"), Math.max(0, milliseconds));
    const onAbort = () => finish("cancelled");
    signal.addEventListener("abort", onAbort, { once: true });
    void promise.then(() => finish("resolved"), () => finish("rejected"));
  });
}

function consumeViewTransitionRejections(transition: ViewTransitionHandle): ViewTransitionHandle {
  // WebKit rejects both promises with AbortError when skipTransition() wins a
  // rapid navigation race. Attach handlers immediately, before either promise
  // can be skipped, while the controller still inspects their settled state.
  void transition.updateCallbackDone.catch(() => undefined);
  void transition.finished.catch(() => undefined);
  return transition;
}

function safelySkipViewTransition(transition: ViewTransitionHandle | undefined): void {
  if (!transition) return;
  consumeViewTransitionRejections(transition);
  try {
    transition.skipTransition();
  } catch {
    // A transition can finish between the state check and this call. The
    // route state machine remains authoritative and will settle to idle.
  }
}

/**
 * One finite, latest-request-wins route mechanism. It deliberately owns no
 * React or history state, so its ordering and cancellation contract can be
 * verified without a browser renderer.
 */
export class MechanicalRouteTransitionController {
  private revision = 0;
  private phase: RouteTransitionPhase = "idle";
  private abortController?: AbortController;
  private activeViewTransition?: ViewTransitionHandle;

  constructor(private readonly runtime: MechanicalRouteTransitionRuntime) {}

  cancel(): void {
    if (this.phase === "idle" && !this.abortController && !this.activeViewTransition) return;
    this.revision += 1;
    this.abortController?.abort();
    safelySkipViewTransition(this.activeViewTransition);
    this.abortController = undefined;
    this.activeViewTransition = undefined;
    this.present({ phase: "idle", revision: this.revision });
  }

  async transition(request: MechanicalRouteTransitionRequest): Promise<MechanicalRouteTransitionOutcome> {
    this.revision += 1;
    const revision = this.revision;
    this.abortController?.abort();
    safelySkipViewTransition(this.activeViewTransition);
    this.activeViewTransition = undefined;

    const signalController = new AbortController();
    this.abortController = signalController;
    const signal = signalController.signal;
    let committed = false;
    const isCurrent = () => revision === this.revision && !signal.aborted;
    const commitOnce = async (mode: RouteTransitionMode) => {
      if (committed || !isCurrent()) return;
      committed = true;
      await request.commit(mode);
    };

    if (request.prepare) {
      try {
        await request.prepare();
      } catch {
        // Route rendering owns the explicit chunk-load error state. Keeping the
        // current screen intact until this point avoids disassembling into a
        // Suspense placeholder when the destination is still in flight.
      }
      if (!isCurrent()) return "cancelled";
    }

    const startedAt = Date.now();

    if (this.runtime.shouldBypass()) {
      if (this.phase !== "idle") this.present({ phase: "idle", revision });
      await commitOnce("bypass");
      if (revision === this.revision) this.abortController = undefined;
      return "bypassed";
    }

    let mode: Exclude<RouteTransitionMode, "bypass"> = this.runtime.startViewTransition ? "native" : "fallback";
    this.present({ phase: "disassembling", mode, from: request.from, to: request.to, revision });

    try {
      const disassembled = await this.runtime.sleep(MECHANICAL_ROUTE_TIMING.disassembleMs, signal);
      if (!disassembled || !isCurrent()) return "cancelled";

      if (mode === "native" && this.runtime.startViewTransition) {
        this.present({ phase: "committing", mode, from: request.from, to: request.to, revision });
        let transition: ViewTransitionHandle;
        try {
          transition = consumeViewTransitionRejections(
            this.runtime.startViewTransition(() => commitOnce("native")),
          );
        } catch {
          mode = "fallback";
          return await this.completeFallback(request, revision, signal, commitOnce);
        }
        this.activeViewTransition = transition;
        const updateResult = await settleBeforeDeadline(
          transition.updateCallbackDone,
          MECHANICAL_ROUTE_TIMING.maximumMs - (Date.now() - startedAt),
          signal,
        );
        if (!isCurrent() || updateResult === "cancelled") return "cancelled";
        if (!committed) await commitOnce(updateResult === "resolved" ? "native" : "fallback");
        if (!isCurrent()) return "cancelled";
        this.present({ phase: "assembling", mode, from: request.from, to: request.to, revision });
        const finishResult = await settleBeforeDeadline(
          transition.finished,
          MECHANICAL_ROUTE_TIMING.maximumMs - (Date.now() - startedAt),
          signal,
        );
        if (finishResult === "timeout" || finishResult === "rejected") safelySkipViewTransition(transition);
        if (!isCurrent()) return "cancelled";
      } else {
        return await this.completeFallback(request, revision, signal, commitOnce);
      }

      this.finish(revision);
      return "completed";
    } catch {
      if (!isCurrent()) return "cancelled";
      if (!committed) await commitOnce("fallback");
      this.finish(revision);
      return "completed";
    } finally {
      if (revision === this.revision) {
        this.abortController = undefined;
        this.activeViewTransition = undefined;
      }
    }
  }

  private async completeFallback(
    request: MechanicalRouteTransitionRequest,
    revision: number,
    signal: AbortSignal,
    commitOnce: (mode: RouteTransitionMode) => Promise<void>,
  ): Promise<MechanicalRouteTransitionOutcome> {
    if (revision !== this.revision || signal.aborted) return "cancelled";
    this.present({ phase: "committing", mode: "fallback", from: request.from, to: request.to, revision });
    await commitOnce("fallback");
    if (revision !== this.revision || signal.aborted) return "cancelled";
    this.present({ phase: "assembling", mode: "fallback", from: request.from, to: request.to, revision });
    const assembled = await this.runtime.sleep(MECHANICAL_ROUTE_TIMING.fallbackAssembleMs, signal);
    if (!assembled || revision !== this.revision || signal.aborted) return "cancelled";
    this.finish(revision);
    return "completed";
  }

  private finish(revision: number): void {
    if (revision !== this.revision) return;
    this.present({ phase: "idle", revision });
  }

  private present(presentation: RouteTransitionPresentation): void {
    this.phase = presentation.phase;
    this.runtime.publish(presentation);
  }
}

const phaseClasses = [
  "is-route-transitioning",
  "is-route-disassembling",
  "is-route-committing",
  "is-route-assembling",
] as const;

function publishTransitionToDocument(documentValue: Document, presentation: RouteTransitionPresentation): void {
  const application = documentValue.querySelector<HTMLElement>(".ti-scale");
  const targets: HTMLElement[] = application
    ? [documentValue.documentElement, application]
    : [documentValue.documentElement];

  for (const target of targets) {
    target.setAttribute("data-route-transition", presentation.phase);
    target.classList.remove(...phaseClasses);
    if (presentation.phase === "idle") {
      target.removeAttribute("data-route-transition-mode");
      target.removeAttribute("data-route-from");
      target.removeAttribute("data-route-to");
      target.removeAttribute("data-route-transition-revision");
      continue;
    }
    target.setAttribute("data-route-transition-mode", presentation.mode ?? "fallback");
    target.setAttribute("data-route-from", presentation.from ?? "");
    target.setAttribute("data-route-to", presentation.to ?? "");
    target.setAttribute("data-route-transition-revision", String(presentation.revision));
    target.classList.add("is-route-transitioning", `is-route-${presentation.phase}`);
  }

  const EventConstructor = documentValue.defaultView?.CustomEvent;
  if (EventConstructor) {
    documentValue.dispatchEvent(new EventConstructor<RouteTransitionPresentation>(
      MECHANICAL_ROUTE_TRANSITION_EVENT,
      { detail: presentation },
    ));
  }
}

function createBrowserTransitionRuntime(documentValue: Document): MechanicalRouteTransitionRuntime {
  return {
    shouldBypass: () => {
      if (documentValue.visibilityState !== "visible") return true;
      try {
        return documentValue.defaultView?.matchMedia("(prefers-reduced-motion: reduce)").matches ?? false;
      } catch {
        return false;
      }
    },
    sleep: abortableSleep,
    publish: (presentation) => publishTransitionToDocument(documentValue, presentation),
    // Native View Transition pseudo-layers obscure the live fixed plate
    // mechanism and produced an uncovered 350–400 ms commit frame in WebKit.
    // The finite real-DOM path is intentionally canonical until that browser
    // contract can provide equivalent visual and cancellation guarantees.
    startViewTransition: undefined,
  };
}

function focusRouteSurface(): void {
  window.queueMicrotask(() => {
    document.getElementById("ti-scale-content")?.focus({ preventScroll: true });
  });
}

export function requestMechanicalNavigation(path: string, options?: NavigationOptions): boolean {
  if (typeof window === "undefined") return false;
  return window.dispatchEvent(new CustomEvent(MECHANICAL_NAVIGATION_REQUEST_EVENT, {
    detail: { path, replace: options?.replace === true },
  }));
}

export function NavigationProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(currentLocation);
  const locationRef = useRef(location);
  const controller = useMemo(() => (
    typeof document === "undefined"
      ? null
      : new MechanicalRouteTransitionController(createBrowserTransitionRuntime(document))
  ), []);

  const commitLocation = useCallback((
    next: LocationSnapshot,
    historyMethod: "pushState" | "replaceState" | undefined,
    mode: RouteTransitionMode,
    resetScroll: boolean,
  ) => {
    const update = () => {
      if (historyMethod) window.history[historyMethod]({}, "", locationTarget(next));
      locationRef.current = next;
      setLocation(next);
    };
    if (mode === "native" || mode === "fallback") flushSync(update);
    else update();
    if (resetScroll) window.scrollTo({ top: 0, behavior: "instant" });
    focusRouteSurface();
  }, []);

  useEffect(() => {
    const onPopState = () => {
      const next = currentLocation();
      const previous = locationRef.current;
      const change = classifyLocationChange(previous, next);
      if (change === "noop") {
        controller?.cancel();
        return;
      }
      if (change === "location-only") {
        controller?.cancel();
        locationRef.current = next;
        setLocation(next);
        return;
      }
      if (!controller) {
        locationRef.current = next;
        setLocation(next);
        return;
      }
      void controller.transition({
        from: previous.pathname,
        to: next.pathname,
        prepare: () => preloadRouteModule(next.pathname),
        commit: (mode) => commitLocation(next, undefined, mode, false),
      });
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [commitLocation, controller]);

  useEffect(() => () => controller?.cancel(), [controller]);

  const navigate = useCallback((path: string, options?: NavigationOptions) => {
    const requested = safeInternalPath(path);
    const parsed = new URL(requested, window.location.origin);
    const next: LocationSnapshot = {
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
    };
    const previous = locationRef.current;
    const target = locationTarget(next);
    const change = classifyLocationChange(previous, next);
    if (change === "noop") {
      controller?.cancel();
      return;
    }
    const historyMethod = options?.replace ? "replaceState" : "pushState";
    if (change === "location-only" || !controller) {
      controller?.cancel();
      if (historyMethod) window.history[historyMethod]({}, "", target);
      locationRef.current = next;
      setLocation(next);
      return;
    }
    void controller.transition({
      from: previous.pathname,
      to: next.pathname,
      prepare: () => preloadRouteModule(next.pathname),
      commit: (mode) => commitLocation(next, historyMethod, mode, true),
    });
  }, [commitLocation, controller]);

  useEffect(() => {
    const onMechanicalNavigation = (event: Event) => {
      const detail = (event as CustomEvent<unknown>).detail;
      if (!detail || typeof detail !== "object") return;
      const candidate = detail as { path?: unknown; replace?: unknown };
      if (typeof candidate.path !== "string") return;
      navigate(candidate.path, { replace: candidate.replace === true });
    };
    window.addEventListener(MECHANICAL_NAVIGATION_REQUEST_EVENT, onMechanicalNavigation);
    return () => window.removeEventListener(MECHANICAL_NAVIGATION_REQUEST_EVENT, onMechanicalNavigation);
  }, [navigate]);

  const value = useMemo<NavigationContextValue>(() => ({ ...location, navigate }), [location, navigate]);

  return (
    <NavigationContext.Provider value={value}>
      {children}
      <div className="ti-route-mechanism" data-route-transition-mechanism="titanium-plate-assembly" aria-hidden="true">
        {Array.from({ length: 8 }, (_, index) => <span key={index} className="ti-route-mechanism__plate" />)}
      </div>
    </NavigationContext.Provider>
  );
}

export function useNavigation(): NavigationContextValue {
  const value = useContext(NavigationContext);
  if (!value) throw new Error("useNavigation must be used inside NavigationProvider");
  return value;
}

type AppLinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href" | "onClick"> & {
  href: string;
  onClick?: () => void;
};

export function AppLink({ href, children, onClick, target, download, ...props }: AppLinkProps) {
  const { navigate } = useNavigation();
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.defaultPrevented) {
      onClick?.();
      return;
    }
    if (!shouldInterceptAppLinkClick({
      href,
      button: event.button,
      detail: event.detail,
      defaultPrevented: event.defaultPrevented,
      metaKey: event.metaKey,
      ctrlKey: event.ctrlKey,
      shiftKey: event.shiftKey,
      altKey: event.altKey,
      target,
      hasDownload: download !== undefined,
    })) return;
    event.preventDefault();
    navigate(href);
    onClick?.();
  };
  return <a href={href} target={target} download={download} onClick={handleClick} {...props}>{children}</a>;
}

export function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const patternParts = pattern.split("/").filter(Boolean);
  const pathParts = pathname.split("/").filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < patternParts.length; index += 1) {
    const patternPart = patternParts[index];
    const pathPart = pathParts[index];
    if (patternPart.startsWith(":")) params[patternPart.slice(1)] = decodeURIComponent(pathPart);
    else if (patternPart !== pathPart) return null;
  }
  return params;
}
