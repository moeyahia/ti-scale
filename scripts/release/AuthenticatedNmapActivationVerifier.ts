import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";
import type { NmapActivationPostStartVerifier } from "./NmapActivationBundle";

const EXACT_NMAP_TOOL_ID = "kali:nmap-tcp-connect-service-scan" as const;
/**
 * `AutonomousRuntimeComposition` emits ready action classes in canonical
 * lexical order. Verification is bound to the complete currently reviewed
 * production composition, rather than the original three-class Nmap slice.
 * This keeps an older capability verifier usable after forward-only reviewed
 * additions without accepting an arbitrary subset, superset, reordering, or
 * duplicate.
 */
const EXACT_AUTONOMOUS_SAFE_RECON_ACTION_CLASSES = Object.freeze([
  "active_host_discovery",
  "cve_intelligence_applicability_validation",
  "dns_domain_certificate_discovery",
  "exploit_validation",
  "os_technology_fingerprinting",
  "port_service_enumeration",
  "vulnerability_configuration_assessment",
  "web_content_endpoint_discovery_fuzzing",
  "web_crawling_page_capture",
] as const);
const EXACT_DEPENDENCY_IDS = Object.freeze([
  "operator-activation",
  "executable-integrity",
  "isolated-target-free-readiness",
  "direct-argv-adapter",
  "workspace-confinement",
  "result-sink",
  "cancellation",
] as const);
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const DEFAULT_BASE_URL = "http://127.0.0.1:3132";
const DEFAULT_TOKEN_PATH = "/etc/ti-scale/operator-token";
const DEFAULT_TOKEN_TRUST_ROOT = "/etc/ti-scale";
const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;

type Fetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;
type Delay = (milliseconds: number) => Promise<void>;

export interface AuthenticatedNmapActivationVerifierOptions {
  readonly baseUrl?: string;
  readonly tokenPath?: string;
  /** Test/deployment trust root; production intentionally uses /etc/ti-scale. */
  readonly tokenTrustRoot?: string;
  readonly fetch?: Fetch;
  readonly clock?: () => Date;
  readonly delay?: Delay;
  readonly activationDeadlineMs?: number;
  readonly priorHealthDeadlineMs?: number;
  readonly requestTimeoutMs?: number;
  readonly pollIntervalMs?: number;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactIsoMilliseconds(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : undefined;
}

function validateLoopbackBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1"
    || url.username || url.password || url.search || url.hash
    || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("The activation verifier endpoint must be an exact loopback HTTP origin");
  }
  return url.origin;
}

function validateTokenBuffer(bytes: Buffer): string {
  const bounded = bytes.length > 0 && bytes[bytes.length - 1] === 0x0a
    ? bytes.subarray(0, bytes.length - 1)
    : bytes;
  if (bounded.length < 24 || bounded.length > 4_096
    || bounded.includes(0x00) || bounded.includes(0x0a) || bounded.includes(0x0d)) {
    throw new Error("The Ti-Scale operator token file has an invalid bounded value");
  }
  return bounded.toString("utf8");
}

export async function withRootOperatorToken<T>(
  tokenPathValue: string,
  tokenTrustRootValue: string,
  operation: (token: string) => Promise<T>,
): Promise<T> {
  const tokenPath = resolve(tokenPathValue);
  const tokenTrustRoot = resolve(tokenTrustRootValue);
  if (tokenPath !== tokenPathValue || tokenTrustRoot !== tokenTrustRootValue
    || tokenPath !== resolve(tokenTrustRoot, "operator-token")) {
    throw new Error("The activation verifier token must use the exact trusted operator-token path");
  }
  const trustRoot = lstatSync(tokenTrustRoot, { bigint: true });
  if (trustRoot.isSymbolicLink() || !trustRoot.isDirectory() || trustRoot.uid !== 0n
    || (trustRoot.mode & 0o022n) !== 0n) {
    throw new Error("The activation verifier token trust root is not a private root-owned directory");
  }
  const before = lstatSync(tokenPath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile() || before.uid !== 0n
    || (before.mode & 0o077n) !== 0n || before.size < 24n || before.size > 4_097n) {
    throw new Error("The Ti-Scale operator token file is not a private root-owned regular file");
  }
  const descriptor = openSync(tokenPath, constants.O_RDONLY | NO_FOLLOW);
  let bytes: Buffer | undefined;
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs || before.ctimeNs !== opened.ctimeNs) {
      throw new Error("The Ti-Scale operator token file changed before it was read");
    }
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw new Error("The Ti-Scale operator token file changed while it was read");
    }
    return await operation(validateTokenBuffer(bytes));
  } finally {
    bytes?.fill(0);
    closeSync(descriptor);
  }
}

async function boundedJson(response: Response): Promise<unknown> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(advertised) && advertised > MAX_RESPONSE_BYTES) {
    throw new Error("The local verification response exceeded its size boundary");
  }
  if (!response.body) throw new Error("The local verification response has no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("The local verification response exceeded its size boundary");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total);
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch {
    throw new Error("The local verification response was not valid JSON");
  } finally {
    body.fill(0);
  }
}

function healthyDatabaseAndEventStream(payload: unknown): boolean {
  const root = object(payload);
  const database = object(root?.database);
  const eventStream = object(root?.eventStream);
  return root?.schemaVersion === "2.4"
    && database?.healthy === true
    && eventStream?.status === "healthy";
}

function healthyApplication(payload: unknown): boolean {
  const root = object(payload);
  return root?.status === "healthy" && healthyDatabaseAndEventStream(payload);
}

export function exactAutonomousSafeReconActionClasses(value: unknown): boolean {
  if (!Array.isArray(value)
    || value.length !== EXACT_AUTONOMOUS_SAFE_RECON_ACTION_CLASSES.length
    || new Set(value).size !== value.length) {
    return false;
  }
  return value.every((actionClassId, index) =>
    actionClassId === EXACT_AUTONOMOUS_SAFE_RECON_ACTION_CLASSES[index]);
}

function exactLocalAutonomousRuntimeReady(payload: unknown): boolean {
  const root = object(payload);
  const execution = object(root?.execution);
  const dependencies = object(root?.dependencies);
  const autonomousRuntime = object(dependencies?.autonomousRuntime);
  const components = object(autonomousRuntime?.components);
  return healthyDatabaseAndEventStream(payload)
    && execution?.autonomous === "ready"
    && autonomousRuntime?.status === "ready"
    && components?.localProcessExecution === true
    && components.mcpExecution === false
    && components.enforcingProvider === true
    && components.resultAwareSpecialistExecution === true
    && exactAutonomousSafeReconActionClasses(autonomousRuntime?.readyActionClassIds);
}

function exactFreshResult(
  value: unknown,
  componentKind: "tool" | "tool_dependency",
  componentId: string,
  testKind: "local_executable_attestation" | "manifest_dependency",
  now: number,
): { readonly observedAt: string; readonly expiresAt: string } | undefined {
  const entry = object(value);
  const component = object(entry?.component);
  const freshness = object(entry?.freshness);
  const authorization = object(entry?.executionAuthorization);
  const observedAt = freshness?.observedAt;
  const expiresAt = freshness?.expiresAt;
  const observed = exactIsoMilliseconds(observedAt);
  const expires = exactIsoMilliseconds(expiresAt);
  if (component?.kind !== componentKind || component.id !== componentId
    || entry?.testKind !== testKind || entry.status !== "pass"
    || entry.availability !== "available" || freshness?.state !== "fresh"
    || observed === undefined || expires === undefined || observed > now + 1_000
    || expires <= now || expires <= observed
    || authorization?.state !== "not_granted"
    || authorization.grantsMissionExecution !== false) {
    return undefined;
  }
  return { observedAt: observedAt as string, expiresAt: expiresAt as string };
}

export function exactNmapCapabilityAvailable(payload: unknown, now: Date): boolean {
  const root = object(payload);
  const accounting = object(root?.accounting);
  const results = Array.isArray(root?.results) ? root.results : [];
  if (root?.schemaVersion !== "2.4" || root.readOnly !== true
    || root.grantsMissionExecution !== false || accounting?.runtimeRegistryRead !== true
    || accounting.manifestValid !== true || accounting.complete !== true) {
    return false;
  }
  const toolMatches = results.filter((entry) => {
    const component = object(object(entry)?.component);
    return component?.kind === "tool" && component.id === EXACT_NMAP_TOOL_ID;
  });
  if (toolMatches.length !== 1) return false;
  const toolFreshness = exactFreshResult(
    toolMatches[0],
    "tool",
    EXACT_NMAP_TOOL_ID,
    "local_executable_attestation",
    now.getTime(),
  );
  if (!toolFreshness) return false;

  const dependencyFreshness: Array<Readonly<{ observedAt: string; expiresAt: string }>> = [];
  for (const suffix of EXACT_DEPENDENCY_IDS) {
    const id = `${EXACT_NMAP_TOOL_ID}/${suffix}`;
    const matches = results.filter((entry) => {
      const component = object(object(entry)?.component);
      return component?.kind === "tool_dependency" && component.id === id;
    });
    if (matches.length !== 1) return false;
    const verified = exactFreshResult(
      matches[0],
      "tool_dependency",
      id,
      "manifest_dependency",
      now.getTime(),
    );
    if (!verified) return false;
    dependencyFreshness.push(verified);
  }
  const activation = dependencyFreshness[0];
  return activation !== undefined
    && dependencyFreshness.every((entry) => entry.observedAt === activation.observedAt
      && entry.expiresAt === activation.expiresAt)
    && Date.parse(activation.expiresAt) <= Date.parse(toolFreshness.expiresAt);
}

export class AuthenticatedNmapActivationVerifier implements NmapActivationPostStartVerifier {
  readonly #baseUrl: string;
  readonly #tokenPath: string;
  readonly #tokenTrustRoot: string;
  readonly #fetch: Fetch;
  readonly #clock: () => Date;
  readonly #delay: Delay;
  readonly #activationDeadlineMs: number;
  readonly #priorHealthDeadlineMs: number;
  readonly #requestTimeoutMs: number;
  readonly #pollIntervalMs: number;

  constructor(options: AuthenticatedNmapActivationVerifierOptions = {}) {
    this.#baseUrl = validateLoopbackBaseUrl(options.baseUrl ?? DEFAULT_BASE_URL);
    this.#tokenPath = options.tokenPath ?? DEFAULT_TOKEN_PATH;
    this.#tokenTrustRoot = options.tokenTrustRoot ?? DEFAULT_TOKEN_TRUST_ROOT;
    this.#fetch = options.fetch ?? fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#delay = options.delay ?? ((milliseconds) => new Promise((resolveDelay) => {
      setTimeout(resolveDelay, milliseconds);
    }));
    this.#activationDeadlineMs = options.activationDeadlineMs ?? 20_000;
    this.#priorHealthDeadlineMs = options.priorHealthDeadlineMs ?? 20_000;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 2_000;
    this.#pollIntervalMs = options.pollIntervalMs ?? 500;
    for (const [name, value] of Object.entries({
      activationDeadlineMs: this.#activationDeadlineMs,
      priorHealthDeadlineMs: this.#priorHealthDeadlineMs,
      requestTimeoutMs: this.#requestTimeoutMs,
      pollIntervalMs: this.#pollIntervalMs,
    })) {
      if (!Number.isSafeInteger(value) || value <= 0 || value > 120_000) {
        throw new Error(`${name} is outside the bounded activation verification policy`);
      }
    }
  }

  async #request(path: string, authorization?: string): Promise<unknown> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method: "GET",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(this.#requestTimeoutMs),
      headers: {
        Accept: "application/json",
        ...(authorization ? { Authorization: `Bearer ${authorization}` } : {}),
      },
    });
    if (response.status !== 200) throw new Error("The local verification endpoint was unavailable");
    return boundedJson(response);
  }

  async #healthIsReady(): Promise<boolean> {
    try { return healthyApplication(await this.#request("/api/v2/health")); }
    catch { return false; }
  }

  async #activatedHealthIsReady(): Promise<boolean> {
    try {
      const [liveness, readiness] = await Promise.all([
        this.#request("/api/v2/health"),
        this.#request("/api/v2/system/readiness"),
      ]);
      return healthyApplication(liveness) && exactLocalAutonomousRuntimeReady(readiness);
    }
    catch { return false; }
  }

  async #poll(deadlineMs: number, check: () => Promise<boolean>, failure: string): Promise<void> {
    const deadline = Date.now() + deadlineMs;
    do {
      if (await check()) return;
      if (Date.now() >= deadline) break;
      await this.#delay(this.#pollIntervalMs);
    } while (Date.now() < deadline);
    throw new Error(failure);
  }

  async verifyActivated(toolId: typeof EXACT_NMAP_TOOL_ID): Promise<void> {
    if (toolId !== EXACT_NMAP_TOOL_ID) {
      throw new Error("Activation verification is restricted to the exact reviewed Nmap binding");
    }
    await this.#poll(this.#activationDeadlineMs, async () => {
      if (!await this.#activatedHealthIsReady()) return false;
      try {
        return await withRootOperatorToken(this.#tokenPath, this.#tokenTrustRoot, async (token) =>
          exactNmapCapabilityAvailable(
            await this.#request("/api/v2/system/capability-self-tests", token),
            this.#clock(),
          ));
      } catch {
        return false;
      }
    }, "Ti-Scale restarted but did not prove HTTP health and exact fresh Nmap availability");
  }

  async verifyPriorServiceHealthy(): Promise<void> {
    await this.#poll(
      this.#priorHealthDeadlineMs,
      () => this.#healthIsReady(),
      "The prior Ti-Scale configuration did not restore HTTP, database, and event-stream health",
    );
  }
}
