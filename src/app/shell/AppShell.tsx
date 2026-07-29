import { lazy, Suspense, type ReactNode, useEffect, useState } from "react";
import { useEventStream } from "../../data/events/EventStreamProvider";
import { Icon } from "../../design-system/components/Icon";
import { AppLink, useNavigation } from "../router/navigation";
import { isNavigationItemActive, PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION } from "../router/routes";
import { NotificationCenter } from "../../features/notifications/NotificationCenter";
import { assetUrl } from "../../lib/assetUrl";
import { useAuth } from "../providers/AuthProvider";
import { operatorText } from "../../lib/operatorLanguage";
import { PRODUCT_NAME } from "../../lib/productIdentity";

const CommandPalette = lazy(() => import("../command-palette/CommandPalette").then((module) => ({
  default: module.CommandPalette,
})));

function CommandPaletteLoading() {
  return (
    <div className="os-palette-layer" role="presentation">
      <div className="os-palette" role="status" aria-live="polite">
        <p className="os-palette-loading">Opening live command search…</p>
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { pathname } = useNavigation();
  const stream = useEventStream();
  const auth = useAuth();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteRequested, setPaletteRequested] = useState(false);
  const [motionState, setMotionState] = useState<"active" | "paused">(() => (
    typeof document !== "undefined" && document.visibilityState === "hidden" ? "paused" : "active"
  ));
  const streamLabel = stream.state === "connected"
    ? "Live updates connected"
    : stream.state === "fallback"
      ? "Live stream degraded; authoritative views refresh every 30 seconds"
      : stream.state === "reconnecting"
        ? "Reconnecting live updates"
        : stream.state === "offline"
          ? "Offline; showing last validated state"
          : "Connecting live updates";

  useEffect(() => {
    setNavigationOpen(false);
  }, [pathname]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => {
          const next = !open;
          if (next) setPaletteRequested(true);
          return next;
        });
      }
      if (event.key === "Escape") {
        setPaletteOpen(false);
        setNavigationOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    let mounted = true;
    let visibilityTimer: number | undefined;
    const onVisibilityChange = () => {
      const next =
        document.visibilityState === "hidden" ? "paused" : "active";
      // Firefox can deliver visibilitychange while React is rendering the
      // route being discarded or restored. Defer the shell update so an
      // external document event never mutates AppShell during child render.
      if (visibilityTimer !== undefined) {
        window.clearTimeout(visibilityTimer);
      }
      visibilityTimer = window.setTimeout(() => {
        visibilityTimer = undefined;
        if (mounted) setMotionState(next);
      }, 0);
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      mounted = false;
      if (visibilityTimer !== undefined) {
        window.clearTimeout(visibilityTimer);
      }
      document.removeEventListener(
        "visibilitychange",
        onVisibilityChange,
      );
    };
  }, []);

  return (
    <div className="ti-scale" data-motion-state={motionState}>
      <a className="os-skip-link" href="#ti-scale-content">Skip to content</a>
      <header className="os-topbar">
        <button className="os-icon-button os-menu-button" type="button" aria-label="Open navigation" aria-expanded={navigationOpen} onClick={() => setNavigationOpen(true)}>
          <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
        <AppLink href="/" className="os-brand" aria-label={`${PRODUCT_NAME} home`}>
          <img src={assetUrl("brand-v2/source/ti-scale-wordmark.svg")} alt="" />
          <span><strong>COMMAND INTELLIGENCE</strong><small>2.4 live</small></span>
        </AppLink>
        <button type="button" className="os-command-trigger" aria-label="Search or run a command" onClick={() => {
          setPaletteRequested(true);
          setPaletteOpen(true);
        }}>
          <svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" /><path d="m16 16 5 5" /></svg>
          <span>Search or run a command</span>
          <kbd>{navigator.platform.toLowerCase().includes("mac") ? "⌘" : "Ctrl"} K</kbd>
        </button>
        <div className="os-topbar-actions">
          <NotificationCenter />
          <div
            className={`os-stream os-stream--${stream.state}`}
            title={`${streamLabel}${stream.lastEvent?.summary ? ` · ${operatorText(stream.lastEvent.summary, { kind: "event" })}` : ""}`}
          >
            <span aria-hidden="true" />
            <span>{stream.state === "connected" ? "Live" : stream.state === "fallback" ? "Fallback refresh" : stream.state}</span>
          </div>
          <button
            type="button"
            className="os-icon-button"
            aria-label={`Sign out of ${PRODUCT_NAME}`}
            title={`Signed in as ${auth.session.actorId ?? "local operator"}`}
            onClick={() => void auth.signOut()}
          >
            <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M10 5H5v14h5M14 8l4 4-4 4M18 12H9" /></svg>
          </button>
        </div>
        <p className="os-visually-hidden" role="status" aria-live="polite" aria-atomic="true">{streamLabel}</p>
      </header>

      <div className="os-frame">
        {navigationOpen && <button className="os-nav-backdrop" type="button" aria-label="Close navigation" onClick={() => setNavigationOpen(false)} />}
        <aside className={`os-sidebar ${navigationOpen ? "is-open" : ""}`} aria-label="Primary navigation">
          <div className="os-sidebar-heading">
            <span>Operations</span>
            <button type="button" className="os-icon-button" aria-label="Close navigation" onClick={() => setNavigationOpen(false)}>
              <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></svg>
            </button>
          </div>
          <nav>
            {PRIMARY_NAVIGATION.map((item) => {
              const active = isNavigationItemActive(item, pathname);
              return (
                <AppLink key={item.path} href={item.path} className={`os-nav-item ${active ? "is-active" : ""}`} aria-label={item.label}>
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                </AppLink>
              );
            })}
          </nav>
          <div className="os-sidebar-footer">
            <AppLink href={USER_MANUAL_NAVIGATION.path} className={`os-manual-link ${isNavigationItemActive(USER_MANUAL_NAVIGATION, pathname) ? "is-active" : ""}`} aria-label={USER_MANUAL_NAVIGATION.label}>
              <span>{USER_MANUAL_NAVIGATION.label}</span>
              <Icon name={USER_MANUAL_NAVIGATION.icon} />
            </AppLink>
            <p>Authorized operations only</p>
          </div>
        </aside>

        <main id="ti-scale-content" className="os-content" tabIndex={-1}>{children}</main>
      </div>
      {paletteRequested && (
        <Suspense fallback={<CommandPaletteLoading />}>
          <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
        </Suspense>
      )}
    </div>
  );
}
