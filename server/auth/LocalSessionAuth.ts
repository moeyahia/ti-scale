import { createHmac, createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const V2_SESSION_COOKIE = "ti_scale_session" as const;
export const V2_CSRF_COOKIE = "ti_scale_csrf" as const;
export const V2_CSRF_HEADER = "x-ti-scale-csrf" as const;

export interface LocalSessionClaims {
  readonly version: 1;
  readonly actorId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly csrfHash: string;
  readonly nonce: string;
}

export interface IssuedLocalSession {
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly claims: LocalSessionClaims;
}

export type LocalSessionFailure =
  | "missing"
  | "malformed"
  | "signature_invalid"
  | "expired"
  | "actor_invalid"
  | "csrf_missing"
  | "csrf_invalid";

export type LocalSessionVerification =
  | { readonly authenticated: true; readonly claims: LocalSessionClaims }
  | { readonly authenticated: false; readonly failure: LocalSessionFailure };

interface LocalSessionAuthOptions {
  readonly operatorToken: string;
  readonly actorId: string;
  readonly sessionTtlMs?: number;
  readonly clock?: () => Date;
  readonly random?: (bytes: number) => Buffer;
}

const ACTOR_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1_000;
const MIN_SESSION_TTL_MS = 5 * 60_000;
const MAX_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function equalText(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

function parseClaims(encoded: string): LocalSessionClaims | undefined {
  try {
    const value = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    const record = value as Record<string, unknown>;
    if (
      record.version !== 1
      || typeof record.actorId !== "string"
      || typeof record.issuedAt !== "string"
      || typeof record.expiresAt !== "string"
      || typeof record.csrfHash !== "string"
      || typeof record.nonce !== "string"
    ) return undefined;
    return {
      version: 1,
      actorId: record.actorId,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
      csrfHash: record.csrfHash,
      nonce: record.nonce,
    };
  } catch {
    return undefined;
  }
}

export function parseCookieHeader(value: string | undefined): Readonly<Record<string, string>> {
  if (!value) return {};
  const cookies: Record<string, string> = {};
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)) continue;
    const raw = part.slice(separator + 1).trim();
    try {
      cookies[name] = decodeURIComponent(raw);
    } catch {
      // Malformed percent escapes are ignored rather than partially decoded.
    }
  }
  return cookies;
}

/** Stateless, signed, local-only browser sessions for the Ti-Scale API. */
export class LocalSessionAuth {
  private readonly operatorToken: string;
  private readonly actorId: string;
  private readonly sessionTtlMs: number;
  private readonly clock: () => Date;
  private readonly random: (bytes: number) => Buffer;

  constructor(options: LocalSessionAuthOptions) {
    if (Buffer.byteLength(options.operatorToken, "utf8") < 24) {
      throw new Error("Local session operator token must contain at least 24 bytes");
    }
    if (!ACTOR_ID.test(options.actorId)) throw new Error("Local session actor ID is invalid");
    const sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    if (
      !Number.isSafeInteger(sessionTtlMs)
      || sessionTtlMs < MIN_SESSION_TTL_MS
      || sessionTtlMs > MAX_SESSION_TTL_MS
    ) throw new RangeError("Local session TTL is outside the supported range");
    this.operatorToken = options.operatorToken;
    this.actorId = options.actorId;
    this.sessionTtlMs = sessionTtlMs;
    this.clock = options.clock ?? (() => new Date());
    this.random = options.random ?? randomBytes;
  }

  verifyOperatorToken(candidate: string): boolean {
    return equalText(candidate, this.operatorToken);
  }

  get configuredActorId(): string {
    return this.actorId;
  }

  issue(): IssuedLocalSession {
    const now = this.clock();
    const csrfToken = base64Url(this.random(32));
    const claims: LocalSessionClaims = {
      version: 1,
      actorId: this.actorId,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.sessionTtlMs).toISOString(),
      csrfHash: sha256(csrfToken),
      nonce: base64Url(this.random(24)),
    };
    const payload = base64Url(JSON.stringify(claims));
    const signature = this.sign(payload);
    return { sessionToken: `${payload}.${signature}`, csrfToken, claims };
  }

  verify(sessionToken: string | undefined, csrfToken?: string): LocalSessionVerification {
    if (!sessionToken) return { authenticated: false, failure: "missing" };
    const parts = sessionToken.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { authenticated: false, failure: "malformed" };
    }
    if (!equalText(parts[1], this.sign(parts[0]))) {
      return { authenticated: false, failure: "signature_invalid" };
    }
    const claims = parseClaims(parts[0]);
    if (!claims) return { authenticated: false, failure: "malformed" };
    if (!ACTOR_ID.test(claims.actorId) || claims.actorId !== this.actorId) {
      return { authenticated: false, failure: "actor_invalid" };
    }
    const now = this.clock().getTime();
    const issuedAt = Date.parse(claims.issuedAt);
    const expiresAt = Date.parse(claims.expiresAt);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= now || issuedAt > now + 60_000) {
      return { authenticated: false, failure: "expired" };
    }
    if (csrfToken !== undefined) {
      if (!csrfToken) return { authenticated: false, failure: "csrf_missing" };
      if (!equalText(sha256(csrfToken), claims.csrfHash)) {
        return { authenticated: false, failure: "csrf_invalid" };
      }
    }
    return { authenticated: true, claims };
  }

  private sign(payload: string): string {
    return createHmac("sha256", this.operatorToken)
      .update("ti-scale.session.v1\0", "utf8")
      .update(payload, "utf8")
      .digest("base64url");
  }
}
