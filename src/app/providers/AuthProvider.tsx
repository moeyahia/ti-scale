import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createLocalSession, deleteLocalSession, fetchLocalSession } from "../../data/api/auth";
import type { LocalSessionState } from "../../domain/types/auth";
import { ApiError } from "../../data/api/client";
import { Button, ErrorPanel } from "../../design-system/components/Primitives";
import { assetUrl } from "../../lib/assetUrl";
import { BROWSER_STORAGE_KEYS, clearBrowserStoragePrefix } from "../../lib/browserNamespaces";
import { PRODUCT_BRAND_LINE, PRODUCT_NAME } from "../../lib/productIdentity";
import type { BootReadiness } from "../boot/BootSequence";

interface AuthContextValue {
  readonly session: LocalSessionState;
  readonly signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AUTH_STARTUP_DELAY_NOTICE_MS = 3_000;
export const AUTH_STARTUP_TIMEOUT_MS = 8_000;

type MutationAttemptStorage = Pick<
  Storage,
  "key" | "length" | "removeItem"
>;

export function clearMutationAttemptStorage(
  storage?: MutationAttemptStorage,
): void {
  const target = storage
    ?? (
      typeof window === "undefined"
        ? undefined
        : window.sessionStorage
    );
  if (!target) return;
  try {
    clearBrowserStoragePrefix(
      target,
      `${BROWSER_STORAGE_KEYS.recoveryMutationIntentPrefix}.`,
    );
    clearBrowserStoragePrefix(
      target,
      `${BROWSER_STORAGE_KEYS.researchPromotionIntentPrefix}.`,
    );
  } catch {}
}

export function resolveLocalSessionState(
  session: LocalSessionState,
  now = Date.now(),
  storage?: MutationAttemptStorage,
): LocalSessionState {
  const expiresAt = session.expiresAt ? Date.parse(session.expiresAt) : Number.NaN;
  const expired = Number.isFinite(expiresAt) && expiresAt <= now;
  if (!session.authenticated || expired) {
    clearMutationAttemptStorage(storage);
  }
  return expired && session.authenticated
    ? {
        schemaVersion: "2.4",
        configured: session.configured,
        authenticated: false,
      }
    : session;
}

function LoginSurface({
  configured,
  onAuthenticated,
}: {
  readonly configured: boolean;
  readonly onAuthenticated: (session: LocalSessionState) => void;
}) {
  const [operatorToken, setOperatorToken] = useState("");
  const [error, setError] = useState<Error>();
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!operatorToken) {
      setError(new Error("Enter the private local operator token configured for Ti-Scale."));
      return;
    }
    setSubmitting(true);
    setError(undefined);
    try {
      const session = await createLocalSession(operatorToken);
      setOperatorToken("");
      onAuthenticated(session);
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Sign-in failed"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="os-auth-shell" aria-labelledby="ti-scale-sign-in-title">
      <section className="os-auth-panel">
        <img src={assetUrl("brand-v2/source/ti-scale-mark.svg")} alt="" className="os-auth-logo" />
        <p className="os-eyebrow">{PRODUCT_BRAND_LINE}</p>
        <h1 id="ti-scale-sign-in-title">Enter Ti-Scale</h1>
        <p>Authenticate locally before mission, evidence, memory, or runtime data is loaded. The token is exchanged for an HttpOnly, same-site session and is never stored in browser storage.</p>
        {!configured ? (
          <div className="os-validation-summary" role="alert">
            <strong>Local authentication is not configured</strong>
            <p>Set <code>TI_SCALE_OPERATOR_TOKEN</code> to a private value of at least 24 bytes, then restart Ti-Scale.</p>
          </div>
        ) : (
          <form onSubmit={submit} className="os-auth-form">
            <label htmlFor="ti-scale-operator-token">Local operator token</label>
            <input
              id="ti-scale-operator-token"
              type="password"
              value={operatorToken}
              onChange={(event) => setOperatorToken(event.target.value)}
              autoComplete="current-password"
              spellCheck={false}
              autoFocus
            />
            <Button type="submit" disabled={submitting}>{submitting ? "Signing in…" : `Sign in to ${PRODUCT_NAME}`}</Button>
          </form>
        )}
        {error && <ErrorPanel
          title={error instanceof ApiError && error.status === 401 ? "Operator token not accepted" : "Sign-in could not complete"}
          error={error}
        />}
        <small>Authorized security operations only · Ti-Scale 2.4</small>
      </section>
    </main>
  );
}

export function AuthProvider({
  children,
  onStartupReadinessChange,
}: {
  readonly children: ReactNode;
  readonly onStartupReadinessChange?: (readiness: BootReadiness) => void;
}) {
  const [session, setSession] = useState<LocalSessionState>();
  const [error, setError] = useState<Error>();
  const initialRefreshStartedRef = useRef(false);

  const refresh = useCallback(async () => {
    setError(undefined);
    onStartupReadinessChange?.({
      ready: false,
      status: "Verifying protected operator session",
      next: "Command Center",
    });
    const controller = new AbortController();
    const delayedNotice = window.setTimeout(() => {
      onStartupReadinessChange?.({
        ready: false,
        status: "Session service response delayed · Connection remains pending",
        next: "Authentication recovery if the 8s startup bound is reached",
      });
    }, AUTH_STARTUP_DELAY_NOTICE_MS);
    const timeout = window.setTimeout(() => {
      controller.abort("Ti-Scale session startup bound reached");
    }, AUTH_STARTUP_TIMEOUT_MS);
    try {
      const next = resolveLocalSessionState(
        await fetchLocalSession(controller.signal),
      );
      setSession(next);
      onStartupReadinessChange?.(next.authenticated ? {
        ready: true,
        status: "Protected operator session verified",
        next: "Command Center",
      } : {
        ready: true,
        status: "Protected session required",
        next: "Local operator sign-in",
      });
    } catch (reason) {
      const startupError = controller.signal.aborted
        ? new Error("The Ti-Scale session service did not respond within the 8 second startup bound. Check the local service connection, then retry.")
        : reason instanceof Error ? reason : new Error("Session readiness failed");
      setError(startupError);
      onStartupReadinessChange?.({
        ready: true,
        status: controller.signal.aborted
          ? "Session service startup bound reached"
          : "Session verification needs attention",
        next: "Authentication recovery",
      });
    } finally {
      window.clearTimeout(delayedNotice);
      window.clearTimeout(timeout);
    }
  }, [onStartupReadinessChange]);

  useEffect(() => {
    // Strict Mode replays effects during development. Keep one startup request
    // so the authenticated application and its hero mount exactly once.
    if (initialRefreshStartedRef.current) return;
    initialRefreshStartedRef.current = true;
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!session?.authenticated || !session.expiresAt) return;
    const expiresAt = Date.parse(session.expiresAt);
    if (!Number.isFinite(expiresAt)) return;
    const expire = () => {
      clearMutationAttemptStorage();
      setSession({
        schemaVersion: "2.4",
        configured: session.configured,
        authenticated: false,
      });
    };
    let timeout: number | undefined;
    const schedule = () => {
      const delay = expiresAt - Date.now();
      if (delay <= 0) {
        expire();
        return;
      }
      timeout = window.setTimeout(schedule, Math.min(delay, 2_147_483_647));
    };
    schedule();
    return () => {
      if (timeout !== undefined) window.clearTimeout(timeout);
    };
  }, [session?.authenticated, session?.configured, session?.expiresAt]);

  const signOut = useCallback(async () => {
    try {
      setSession(resolveLocalSessionState(await deleteLocalSession()));
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Sign-out failed"));
    }
  }, []);
  const value = useMemo(() => session?.authenticated ? { session, signOut } : null, [session, signOut]);

  if (error) {
    return <main className="os-auth-shell"><section className="os-auth-panel"><ErrorPanel title={`${PRODUCT_NAME} authentication readiness is unavailable`} error={error} onRetry={() => void refresh()} /></section></main>;
  }
  if (!session) return <main className="os-auth-shell"><p role="status">Verifying Ti-Scale session…</p></main>;
  if (!session.authenticated) return <LoginSurface configured={session.configured} onAuthenticated={setSession} />;
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside an authenticated AuthProvider");
  return value;
}
