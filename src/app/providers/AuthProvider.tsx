import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { createLocalSession, deleteLocalSession, fetchLocalSession } from "../../data/api/auth";
import type { LocalSessionState } from "../../domain/types/auth";
import { ApiError } from "../../data/api/client";
import { Button, ErrorPanel } from "../../design-system/components/Primitives";
import { assetUrl } from "../../lib/assetUrl";
import { PRODUCT_BRAND_LINE, PRODUCT_NAME } from "../../lib/productIdentity";

interface AuthContextValue {
  readonly session: LocalSessionState;
  readonly signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

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

export function AuthProvider({ children }: { readonly children: ReactNode }) {
  const [session, setSession] = useState<LocalSessionState>();
  const [error, setError] = useState<Error>();

  const refresh = useCallback(async () => {
    setError(undefined);
    try {
      setSession(await fetchLocalSession());
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Session readiness failed"));
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const signOut = useCallback(async () => {
    try {
      const next = await deleteLocalSession();
      setSession(next);
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
