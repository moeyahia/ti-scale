import { describe, expect, test } from "bun:test";
import {
  LocalSessionAuth,
  V2_CSRF_COOKIE,
  V2_SESSION_COOKIE,
  authenticateRequest,
  parseCookieHeader,
} from "../../../server/auth";

const OPERATOR_TOKEN = "operator-token-for-v2-tests-000000000000";

function auth(at = "2026-07-16T09:00:00.000Z") {
  let counter = 1;
  return new LocalSessionAuth({
    operatorToken: OPERATOR_TOKEN,
    actorId: "operator-v2",
    sessionTtlMs: 10 * 60_000,
    clock: () => new Date(at),
    random: (bytes) => Buffer.alloc(bytes, counter++),
  });
}

describe("isolated local V2 browser sessions", () => {
  test("issues a signed HttpOnly-session payload and verifies its bound CSRF token", () => {
    const service = auth();
    const issued = service.issue();
    expect(issued.sessionToken).not.toContain(OPERATOR_TOKEN);
    expect(issued.csrfToken).not.toBe(issued.sessionToken);
    expect(service.verify(issued.sessionToken)).toMatchObject({ authenticated: true });
    expect(service.verify(issued.sessionToken, issued.csrfToken)).toMatchObject({
      authenticated: true,
      claims: { actorId: "operator-v2" },
    });
  });

  test("fails closed for tampering, wrong CSRF, missing data, and expiry", () => {
    const issued = auth().issue();
    expect(auth().verify(undefined)).toEqual({ authenticated: false, failure: "missing" });
    expect(auth().verify(`${issued.sessionToken}x`)).toEqual({
      authenticated: false,
      failure: "signature_invalid",
    });
    expect(auth().verify(issued.sessionToken, "wrong-csrf-token")).toEqual({
      authenticated: false,
      failure: "csrf_invalid",
    });
    const expired = auth("2026-07-16T09:11:00.000Z").verify(issued.sessionToken);
    expect(expired).toEqual({ authenticated: false, failure: "expired" });
  });

  test("compares the configured operator token and parses cookies without accepting malformed escapes", () => {
    const service = auth();
    expect(service.verifyOperatorToken(OPERATOR_TOKEN)).toBe(true);
    expect(service.verifyOperatorToken(`${OPERATOR_TOKEN}x`)).toBe(false);
    expect(parseCookieHeader("a=one%20two; malformed=%ZZ; b=three")).toEqual({
      a: "one two",
      b: "three",
    });
  });

  test("accepts bearer or signed sessions while requiring double-submit CSRF for cookie mutations", () => {
    const service = auth();
    const issued = service.issue();
    expect(authenticateRequest({
      auth: service,
      authorization: `Bearer ${OPERATOR_TOKEN}`,
      unsafeMethod: true,
    })).toEqual({ authenticated: true, actorId: "operator-v2", method: "bearer" });
    expect(authenticateRequest({
      auth: service,
      authorization: "Bearer invalid-token-that-does-not-fallback",
      cookie: `${V2_SESSION_COOKIE}=${issued.sessionToken}`,
      unsafeMethod: false,
    })).toEqual({ authenticated: false, failure: "bearer_invalid" });
    const cookie = `${V2_SESSION_COOKIE}=${issued.sessionToken}; ${V2_CSRF_COOKIE}=${issued.csrfToken}`;
    expect(authenticateRequest({ auth: service, cookie, unsafeMethod: false })).toMatchObject({
      authenticated: true,
      method: "signed_session",
    });
    expect(authenticateRequest({ auth: service, cookie, unsafeMethod: true })).toEqual({
      authenticated: false,
      failure: "csrf_missing",
    });
    expect(authenticateRequest({
      auth: service,
      cookie,
      csrfHeader: issued.csrfToken,
      unsafeMethod: true,
    })).toMatchObject({ authenticated: true, method: "signed_session" });
  });
});
