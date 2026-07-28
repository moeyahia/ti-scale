import { createHash } from "node:crypto";
import { z } from "zod";
import {
  CveIdSchema,
  NVD_API_ORIGIN,
  NVD_API_PATH,
  NVD_RECORD_ORIGIN,
  PublicNvdCveDetailSchema,
  PublicNvdError,
  type PublicNvdCveDetail,
  type PublicNvdLookupPort,
} from "./types";

const DEFAULT_TOTAL_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_ATTEMPTS = 2;
const DEFAULT_RETRY_DELAY_MS = 250;
const DEFAULT_MAX_RETRY_AFTER_MS = 5_000;
const MAX_DESCRIPTION_CHARACTERS = 32 * 1024;

const RawCvssDataSchema = z.object({
  version: z.string().min(1).max(16),
  vectorString: z.string().min(1).max(512),
  baseScore: z.number().min(0).max(10),
  baseSeverity: z.string().max(32).optional(),
}).passthrough();

const RawMetricSchema = z.object({
  cvssData: RawCvssDataSchema,
  baseSeverity: z.string().max(32).optional(),
}).passthrough();

// NVD's `metrics` object is an extensible family registry. Alongside CVSS
// families it currently includes records such as `ssvcV203`, whose entries
// deliberately have no `cvssData`. Keep the outer structure bounded, retain
// unknown entries only long enough to inspect them, and promote solely the
// entries that independently pass RawMetricSchema below.
const RawMetricFamiliesSchema = z.record(
  z.string().min(1).max(64),
  z.array(z.unknown()).max(64),
).refine(
  (families) => Object.keys(families).length <= 64,
  "NVD returned too many metric families",
);

const RawCveSchema = z.object({
  id: z.string().max(64),
  published: z.string().max(128).optional(),
  lastModified: z.string().max(128).optional(),
  descriptions: z.array(z.object({
    lang: z.string().max(16),
    value: z.string().max(128 * 1024),
  }).passthrough()).max(64).optional(),
  metrics: RawMetricFamiliesSchema.optional(),
  weaknesses: z.array(z.object({
    description: z.array(z.object({
      lang: z.string().max(16),
      value: z.string().max(128),
    }).passthrough()).max(32).optional(),
  }).passthrough()).max(64).optional(),
  references: z.array(z.object({
    url: z.string().max(4_096),
  }).passthrough()).max(512).optional(),
}).passthrough();

const RawNvdEnvelopeSchema = z.object({
  totalResults: z.number().int().nonnegative(),
  vulnerabilities: z.array(z.object({ cve: RawCveSchema }).passthrough()).max(4),
}).passthrough();

export type PublicNvdFetch = (
  input: string | URL,
  init: RequestInit,
) => Promise<Response>;

export interface PublicNvdClientOptions {
  readonly fetch?: PublicNvdFetch;
  readonly clock?: () => Date;
  readonly monotonicNow?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly totalTimeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly maxAttempts?: number;
  readonly retryDelayMs?: number;
  readonly maxRetryAfterMs?: number;
}

interface BoundedResponse {
  readonly status: number;
  readonly headers: Headers;
  readonly bytes?: Uint8Array;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function normalizeExternalText(value: string): string {
  return value
    .normalize("NFC")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ")
    .slice(0, MAX_DESCRIPTION_CHARACTERS);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeTimestamp(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : undefined;
}

function severity(value: string | undefined): PublicNvdCveDetail["cvss"][number]["baseSeverity"] {
  const normalized = value?.toUpperCase();
  return normalized === "NONE"
      || normalized === "LOW"
      || normalized === "MEDIUM"
      || normalized === "HIGH"
      || normalized === "CRITICAL"
    ? normalized
    : "UNKNOWN";
}

function extractCvss(metrics: z.infer<typeof RawCveSchema>["metrics"]): PublicNvdCveDetail["cvss"] {
  const results: PublicNvdCveDetail["cvss"][number][] = [];
  const seen = new Set<string>();
  for (const entries of Object.values(metrics ?? {})) {
    for (const candidate of entries) {
      const parsed = RawMetricSchema.safeParse(candidate);
      if (!parsed.success) continue;
      const entry = parsed.data;
      const data = entry.cvssData;
      const key = `${data.version}\u0000${data.vectorString}\u0000${data.baseScore}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push({
        version: data.version,
        vector: normalizeExternalText(data.vectorString),
        baseScore: data.baseScore,
        baseSeverity: severity(data.baseSeverity ?? entry.baseSeverity),
      });
      if (results.length === 16) return results;
    }
  }
  return results;
}

function extractWeaknesses(weaknesses: z.infer<typeof RawCveSchema>["weaknesses"]): string[] {
  const results = new Set<string>();
  for (const weakness of weaknesses ?? []) {
    for (const description of weakness.description ?? []) {
      const normalized = description.value.toUpperCase();
      if (/^CWE-(?:\d+|NOINFO|OTHER)$/u.test(normalized)) results.add(normalized);
      if (results.size === 64) return [...results];
    }
  }
  return [...results];
}

function extractReferences(references: z.infer<typeof RawCveSchema>["references"]): string[] {
  const results = new Set<string>();
  for (const reference of references ?? []) {
    try {
      const url = new URL(reference.url);
      if ((url.protocol === "https:" || url.protocol === "http:") && url.href.length <= 2_048) {
        results.add(url.href);
      }
    } catch {
      // Invalid source links are omitted rather than promoted as trusted provenance.
    }
    if (results.size === 64) break;
  }
  return [...results];
}

function parseRetryAfter(headers: Headers, now: Date, maximumMs: number): number | undefined {
  const raw = headers.get("retry-after")?.trim();
  if (!raw) return undefined;
  const seconds = Number(raw);
  const milliseconds = Number.isFinite(seconds) && seconds >= 0
    ? Math.ceil(seconds * 1_000)
    : Math.max(0, Date.parse(raw) - now.getTime());
  if (!Number.isFinite(milliseconds)) return undefined;
  return Math.min(milliseconds, maximumMs);
}

async function readBoundedBody(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > maximumBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new PublicNvdError(
        "response_too_large",
        "NVD returned more data than the sidecar is permitted to process.",
        false,
      );
    }
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new PublicNvdError(
          "response_too_large",
          "NVD returned more data than the sidecar is permitted to process.",
          false,
        );
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

export class PublicNvdClient implements PublicNvdLookupPort {
  private readonly fetchImpl: PublicNvdFetch;
  private readonly clock: () => Date;
  private readonly monotonicNow: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly totalTimeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxAttempts: number;
  private readonly retryDelayMs: number;
  private readonly maxRetryAfterMs: number;

  constructor(options: PublicNvdClientOptions = {}) {
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.clock = options.clock ?? (() => new Date());
    this.monotonicNow = options.monotonicNow ?? (() => performance.now());
    this.sleep = options.sleep ?? defaultSleep;
    this.totalTimeoutMs = boundedInteger(options.totalTimeoutMs, DEFAULT_TOTAL_TIMEOUT_MS, 100, 30_000, "totalTimeoutMs");
    this.maxResponseBytes = boundedInteger(options.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 1_024, 4 * 1024 * 1024, "maxResponseBytes");
    this.maxAttempts = boundedInteger(options.maxAttempts, DEFAULT_MAX_ATTEMPTS, 1, 3, "maxAttempts");
    this.retryDelayMs = boundedInteger(options.retryDelayMs, DEFAULT_RETRY_DELAY_MS, 0, 5_000, "retryDelayMs");
    this.maxRetryAfterMs = boundedInteger(options.maxRetryAfterMs, DEFAULT_MAX_RETRY_AFTER_MS, 0, 10_000, "maxRetryAfterMs");
  }

  async getCveDetails(cveId: string): Promise<PublicNvdCveDetail> {
    const parsedId = CveIdSchema.safeParse(cveId);
    if (!parsedId.success) {
      throw new PublicNvdError(
        "invalid_cve_id",
        "Enter an uppercase CVE identifier such as CVE-2021-44228.",
        false,
      );
    }

    const url = new URL(NVD_API_PATH, NVD_API_ORIGIN);
    url.searchParams.set("cveId", parsedId.data);
    const deadline = this.monotonicNow() + this.totalTimeoutMs;
    let lastRetryAfterMs: number | undefined;

    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      const remaining = Math.floor(deadline - this.monotonicNow());
      if (remaining <= 0) throw this.timeoutError();
      let response: BoundedResponse;
      try {
        response = await this.request(url, remaining);
      } catch (error) {
        if (error instanceof PublicNvdError) {
          if (error.code === "request_timeout" || !error.retryable || attempt === this.maxAttempts) throw error;
        } else if (attempt === this.maxAttempts) {
          throw new PublicNvdError(
            "network_error",
            "The NVD service could not be reached through the public-intelligence connection.",
            true,
          );
        }
        await this.waitForRetry(this.retryDelayMs, deadline);
        continue;
      }

      if (response.status === 200 && response.bytes) {
        return this.parseDetail(parsedId.data, url, response.bytes);
      }
      if (response.status === 404) {
        throw new PublicNvdError(
          "not_found",
          `${parsedId.data} was not found in the official NVD service.`,
          false,
        );
      }
      if (response.status === 429) {
        lastRetryAfterMs = parseRetryAfter(response.headers, this.clock(), this.maxRetryAfterMs)
          ?? this.retryDelayMs;
        if (attempt < this.maxAttempts) {
          await this.waitForRetry(lastRetryAfterMs, deadline);
          continue;
        }
        throw new PublicNvdError(
          "rate_limited",
          "NVD is temporarily limiting requests. Ti-Scale preserved the mission state and can retry later.",
          true,
          lastRetryAfterMs,
        );
      }
      if (response.status >= 500 && response.status <= 599) {
        if (attempt < this.maxAttempts) {
          const delay = parseRetryAfter(response.headers, this.clock(), this.maxRetryAfterMs)
            ?? this.retryDelayMs;
          await this.waitForRetry(delay, deadline);
          continue;
        }
        throw new PublicNvdError(
          "upstream_unavailable",
          "NVD is temporarily unavailable. No target was contacted and the lookup can be retried later.",
          true,
        );
      }
      throw new PublicNvdError(
        "upstream_rejected",
        "NVD rejected the public-intelligence request. No target was contacted.",
        false,
      );
    }
    throw new PublicNvdError(
      "network_error",
      "The NVD service could not be reached through the public-intelligence connection.",
      true,
      lastRetryAfterMs,
    );
  }

  private async request(url: URL, timeoutMs: number): Promise<BoundedResponse> {
    const abort = new AbortController();
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let activeResponse: Response | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
        reject(this.timeoutError());
      }, timeoutMs);
    });
    try {
      const response = await Promise.race([
        this.fetchImpl(url, {
          method: "GET",
          redirect: "error",
          signal: abort.signal,
          headers: {
            Accept: "application/json",
            "User-Agent": `Ti-Scale-Public-NVD-MCP/${PUBLIC_NVD_CLIENT_VERSION}`,
          },
        }),
        timeout,
      ]);
      activeResponse = response;
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        return { status: response.status, headers: response.headers };
      }
      const bytes = await Promise.race([
        readBoundedBody(response, this.maxResponseBytes),
        timeout,
      ]);
      return { status: response.status, headers: response.headers, bytes };
    } catch (error) {
      if (timedOut) void activeResponse?.body?.cancel().catch(() => undefined);
      if (error instanceof PublicNvdError) throw error;
      if (timedOut || (error instanceof Error && error.name === "AbortError")) throw this.timeoutError();
      throw new PublicNvdError(
        "network_error",
        "The NVD service could not be reached through the public-intelligence connection.",
        true,
      );
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private parseDetail(cveId: string, apiUrl: URL, bytes: Uint8Array): PublicNvdCveDetail {
    let decoded: string;
    let parsed: unknown;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      parsed = JSON.parse(decoded);
    } catch {
      throw new PublicNvdError(
        "invalid_response",
        "NVD returned data that could not be safely interpreted.",
        false,
      );
    }
    const envelope = RawNvdEnvelopeSchema.safeParse(parsed);
    if (!envelope.success) {
      throw new PublicNvdError(
        "invalid_response",
        "NVD returned data that did not match the reviewed response contract.",
        false,
      );
    }
    if (envelope.data.totalResults === 0 || envelope.data.vulnerabilities.length === 0) {
      throw new PublicNvdError("not_found", `${cveId} was not found in the official NVD service.`, false);
    }
    const matches = envelope.data.vulnerabilities.filter(({ cve }) => cve.id === cveId);
    if (matches.length !== 1) {
      throw new PublicNvdError(
        "invalid_response",
        "NVD returned a record that did not match the requested CVE identifier.",
        false,
      );
    }
    const raw = matches[0].cve;
    const rawDescription = raw.descriptions?.find(({ lang }) => lang.toLowerCase() === "en")?.value
      ?? raw.descriptions?.[0]?.value
      ?? "No description was supplied by NVD.";
    const description = normalizeExternalText(rawDescription);
    const detail: PublicNvdCveDetail = {
      schemaVersion: "ti-scale.public-nvd.cve-detail.v1",
      cveId,
      targetInteraction: false,
      ...(normalizeTimestamp(raw.published) ? { publishedAt: normalizeTimestamp(raw.published) } : {}),
      ...(normalizeTimestamp(raw.lastModified) ? { lastModifiedAt: normalizeTimestamp(raw.lastModified) } : {}),
      description: {
        text: description,
        contentSha256: sha256(description),
        classification: "external_untrusted",
        lifecycle: "quarantined",
        promptEligible: false,
        normalization: "unicode_nfc_control_filtered",
        reason: "External NVD text requires local validation before model use",
      },
      cvss: extractCvss(raw.metrics),
      weaknesses: extractWeaknesses(raw.weaknesses),
      references: extractReferences(raw.references),
      trustBoundary: {
        classification: "external_untrusted",
        promptUse: "quarantined",
        reviewed: false,
        appliesTo: "entire_payload",
        textFields: [
          "description.text",
          "cvss[].version",
          "cvss[].vector",
          "references[]",
        ],
      },
      provenance: {
        authority: "NIST National Vulnerability Database",
        api: "NVD API 2.0",
        apiUrl: apiUrl.href,
        recordUrl: new URL(`/vuln/detail/${encodeURIComponent(cveId)}`, NVD_RECORD_ORIGIN).href,
        retrievedAt: this.clock().toISOString(),
        httpStatus: 200,
        sourceType: "public_vulnerability_intelligence",
      },
    };
    const validated = PublicNvdCveDetailSchema.safeParse(detail);
    if (!validated.success) {
      throw new PublicNvdError(
        "invalid_response",
        "NVD returned data that could not be normalized into the reviewed output contract.",
        false,
      );
    }
    return validated.data;
  }

  private async waitForRetry(milliseconds: number, deadline: number): Promise<void> {
    if (milliseconds <= 0) return;
    if (this.monotonicNow() + milliseconds >= deadline) throw this.timeoutError();
    await this.sleep(milliseconds);
  }

  private timeoutError(): PublicNvdError {
    return new PublicNvdError(
      "request_timeout",
      "The public NVD lookup exceeded its time limit. No target was contacted.",
      true,
    );
  }
}

const PUBLIC_NVD_CLIENT_VERSION = "0.1.0";
