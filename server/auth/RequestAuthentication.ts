import {
  LocalSessionAuth,
  V2_CSRF_COOKIE,
  V2_SESSION_COOKIE,
  parseCookieHeader,
  type LocalSessionFailure,
} from "./LocalSessionAuth";

export type RequestAuthentication =
  | {
      readonly authenticated: true;
      readonly actorId: string;
      readonly method: "bearer" | "signed_session";
    }
  | {
      readonly authenticated: false;
      readonly failure: LocalSessionFailure | "bearer_invalid";
    };

export interface AuthenticateRequestInput {
  readonly auth: LocalSessionAuth;
  readonly authorization?: string;
  readonly cookie?: string;
  readonly csrfHeader?: string;
  readonly unsafeMethod: boolean;
}

function equal(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return mismatch === 0;
}

/**
 * Resolves one unambiguous V2 authentication method. An explicitly supplied
 * invalid Bearer header fails closed instead of falling back to a browser
 * cookie. Cookie-authenticated mutations require a bound double-submit CSRF.
 */
export function authenticateRequest(input: AuthenticateRequestInput): RequestAuthentication {
  if (input.authorization !== undefined) {
    const token = input.authorization.startsWith("Bearer ")
      ? input.authorization.slice("Bearer ".length)
      : "";
    return token && input.auth.verifyOperatorToken(token)
      ? { authenticated: true, actorId: input.auth.configuredActorId, method: "bearer" }
      : { authenticated: false, failure: "bearer_invalid" };
  }

  const cookies = parseCookieHeader(input.cookie);
  let csrf: string | undefined;
  if (input.unsafeMethod) {
    const cookieCsrf = cookies[V2_CSRF_COOKIE];
    if (!cookieCsrf || !input.csrfHeader) {
      return { authenticated: false, failure: "csrf_missing" };
    }
    if (!equal(cookieCsrf, input.csrfHeader)) {
      return { authenticated: false, failure: "csrf_invalid" };
    }
    csrf = input.csrfHeader;
  }
  const verified = input.auth.verify(cookies[V2_SESSION_COOKIE], csrf);
  return verified.authenticated
    ? { authenticated: true, actorId: verified.claims.actorId, method: "signed_session" }
    : verified;
}
