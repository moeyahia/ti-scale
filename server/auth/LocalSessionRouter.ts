import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts";
import {
  LocalSessionAuth,
  V2_CSRF_COOKIE,
  V2_SESSION_COOKIE,
  parseCookieHeader,
} from "./LocalSessionAuth";

export interface LocalSessionRouterOptions {
  readonly auth?: LocalSessionAuth;
  readonly secureCookies: boolean;
}

function tokenFromBody(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const token = (value as Record<string, unknown>).operatorToken;
  return typeof token === "string" ? token : undefined;
}

function cookieOptions(secure: boolean, httpOnly: boolean, maxAge: number, path: string) {
  return {
    httpOnly,
    secure,
    sameSite: "strict" as const,
    path,
    maxAge,
  };
}

function clearedCookieOptions(secure: boolean, httpOnly: boolean, path: string) {
  return {
    httpOnly,
    secure,
    sameSite: "strict" as const,
    path,
  };
}

export function createLocalSessionRouter(options: LocalSessionRouterOptions): Router {
  const router = Router();

  router.post("/api/v2/auth/session", (request: Request, response: Response) => {
    const traceId = attachV2RequestId(request, response);
    if (!options.auth) {
      sendV2Error(response, traceId, {
        status: 503,
        code: "ti_scale_authentication_unconfigured",
        message: "Ti-Scale operator authentication is not configured",
        humanMessage: "Ti-Scale is not ready for sign-in.",
        retryable: false,
        category: "authentication_missing",
        remediation: "Set TI_SCALE_OPERATOR_TOKEN to a private value of at least 24 bytes and restart Ti-Scale.",
      });
      return;
    }
    const token = tokenFromBody(request.body);
    if (!token || !options.auth.verifyOperatorToken(token)) {
      sendV2Error(response, traceId, {
        status: 401,
        code: "ti_scale_authentication_failed",
        message: "The supplied local operator token is invalid",
        humanMessage: "The local operator token was not accepted.",
        retryable: false,
        category: "authentication_missing",
        remediation: "Use the private operator token configured for Ti-Scale.",
      });
      return;
    }
    const issued = options.auth.issue();
    const maxAge = Math.max(0, Date.parse(issued.claims.expiresAt) - Date.now());
    response.cookie(
      V2_SESSION_COOKIE,
      issued.sessionToken,
      cookieOptions(options.secureCookies, true, maxAge, "/api/v2"),
    );
    response.cookie(
      V2_CSRF_COOKIE,
      issued.csrfToken,
      cookieOptions(options.secureCookies, false, maxAge, "/"),
    );
    response.setHeader("Cache-Control", "no-store");
    response.json({
      schemaVersion: "2.4",
      authenticated: true,
      actorId: issued.claims.actorId,
      expiresAt: issued.claims.expiresAt,
    });
  });

  router.get("/api/v2/auth/session", (request, response) => {
    if (!options.auth) {
      response.setHeader("Cache-Control", "no-store");
      response.json({ schemaVersion: "2.4", configured: false, authenticated: false });
      return;
    }
    const cookies = parseCookieHeader(request.get("Cookie"));
    const result = options.auth.verify(cookies[V2_SESSION_COOKIE]);
    response.setHeader("Cache-Control", "no-store");
    response.json(result.authenticated
      ? {
          schemaVersion: "2.4",
          configured: true,
          authenticated: true,
          actorId: result.claims.actorId,
          expiresAt: result.claims.expiresAt,
        }
      : { schemaVersion: "2.4", configured: true, authenticated: false });
  });

  router.delete("/api/v2/auth/session", (_request, response) => {
    // Do not pass maxAge to clearCookie. Express converts maxAge=0 into an
    // Expires value equal to the response time; WebKit can retain that empty
    // cookie until the next navigation. Let clearCookie emit its canonical
    // epoch expiry while preserving the exact issuance path and attributes.
    response.clearCookie(
      V2_SESSION_COOKIE,
      clearedCookieOptions(options.secureCookies, true, "/api/v2"),
    );
    response.clearCookie(
      V2_CSRF_COOKIE,
      clearedCookieOptions(options.secureCookies, false, "/"),
    );
    response.setHeader("Cache-Control", "no-store");
    response.json({ schemaVersion: "2.4", authenticated: false });
  });

  return router;
}
