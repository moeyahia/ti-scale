import { createContext, type MouseEvent, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";

interface NavigationContextValue {
  pathname: string;
  search: string;
  hash: string;
  navigate: (path: string, options?: { replace?: boolean }) => void;
}

interface LocationSnapshot {
  pathname: string;
  search: string;
  hash: string;
}

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

export function NavigationProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(currentLocation);

  useEffect(() => {
    const onPopState = () => setLocation(currentLocation());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((path: string, options?: { replace?: boolean }) => {
    const requested = safeInternalPath(path);
    const parsed = new URL(requested, window.location.origin);
    const target = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (target === current) return;
    const pathnameChanged = parsed.pathname !== window.location.pathname;
    window.history[options?.replace ? "replaceState" : "pushState"]({}, "", target);
    setLocation({ pathname: parsed.pathname, search: parsed.search, hash: parsed.hash });
    // Query-only state (filters, graph selection, cursors) must not move the
    // surface underneath an active pointer or keyboard interaction.
    if (pathnameChanged) window.scrollTo({ top: 0, behavior: "instant" });
  }, []);

  const value = useMemo<NavigationContextValue>(() => ({ ...location, navigate }), [location, navigate]);

  return <NavigationContext.Provider value={value}>{children}</NavigationContext.Provider>;
}

export function useNavigation(): NavigationContextValue {
  const value = useContext(NavigationContext);
  if (!value) throw new Error("useNavigation must be used inside NavigationProvider");
  return value;
}

export function AppLink({ href, children, className, onClick, ...props }: {
  href: string;
  children: ReactNode;
  className?: string;
  onClick?: () => void;
  "aria-label"?: string;
}) {
  const { navigate } = useNavigation();
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.defaultPrevented) {
      onClick?.();
      return;
    }
    const nonPrimaryPointer = event.detail > 0 && event.button !== 0;
    if (nonPrimaryPointer || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(href);
    onClick?.();
  };
  return <a href={href} className={className} onClick={handleClick} {...props}>{children}</a>;
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
