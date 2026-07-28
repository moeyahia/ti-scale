export const EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS = 8_000;
export const EARLY_AUTHENTICATION_ADMISSION_SCHEMA =
  "ti-scale.early-authentication-admission.v1" as const;

const SESSION_SCHEMA = "2.4" as const;
const SESSION_PATH = "/api/v2/auth/session" as const;

export interface EarlyAuthenticationProcessIdentity {
  readonly activeState: string;
  readonly mainPid: number;
  readonly invocationId: string;
}

export interface EarlyAuthenticationStartBoundary {
  readonly requestedAt: string;
  readonly monotonicMs: number;
}

export interface EarlyAuthenticationSessionResponse {
  readonly status: number;
  readonly body: unknown;
}

export interface EarlyAuthenticationAdmissionReceipt {
  readonly schemaVersion: typeof EARLY_AUTHENTICATION_ADMISSION_SCHEMA;
  readonly endpointPath: typeof SESSION_PATH;
  readonly method: "GET";
  readonly requestedAt: string;
  readonly respondedAt: string;
  readonly deadlineMs: number;
  readonly responseAfterStartMs: number;
  readonly requestLatencyMs: number;
  readonly failedConnectionAttempts: number;
  readonly httpStatus: 200;
  readonly sessionSchemaVersion: typeof SESSION_SCHEMA;
  readonly configured: true;
  readonly authenticated: false;
  readonly previousInvocationId: string;
  readonly observedInvocationId: string;
  readonly observedMainPid: number;
}

export interface EarlyAuthenticationAttemptContext {
  readonly remainingMs: number;
  readonly signal: AbortSignal;
}

export interface WaitForEarlyAuthenticationAdmissionOptions {
  readonly start: EarlyAuthenticationStartBoundary;
  readonly previousInvocationId: string;
  readonly observeProcess: (
    context: EarlyAuthenticationAttemptContext,
  ) => EarlyAuthenticationProcessIdentity | Promise<EarlyAuthenticationProcessIdentity>;
  readonly requestSession: (
    context: EarlyAuthenticationAttemptContext,
  ) => EarlyAuthenticationSessionResponse | Promise<EarlyAuthenticationSessionResponse>;
  readonly timeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly signal?: AbortSignal;
  readonly now?: () => number;
  readonly clock?: () => Date;
  readonly sleep?: (milliseconds: number) => void | Promise<void>;
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function exactPositiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return Number(value);
}

function exactNonnegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a nonnegative safe integer`);
  }
  return Number(value);
}

function sessionBody(value: unknown): {
  readonly schemaVersion: typeof SESSION_SCHEMA;
  readonly configured: true;
  readonly authenticated: false;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Early authentication admission returned a non-object session body");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort((left, right) => left.localeCompare(right, "en"));
  if (
    JSON.stringify(keys) !== JSON.stringify(["authenticated", "configured", "schemaVersion"])
    || record.schemaVersion !== SESSION_SCHEMA
    || record.configured !== true
    || record.authenticated !== false
  ) {
    throw new Error("Early authentication admission returned an invalid unauthenticated session contract");
  }
  return {
    schemaVersion: SESSION_SCHEMA,
    configured: true,
    authenticated: false,
  };
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new Error(typeof signal.reason === "string"
      ? signal.reason
      : "Early authentication admission was cancelled");
}

async function bounded<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw abortError(signal);
  let onAbort: (() => void) | undefined;
  const cancelled = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([operation, cancelled]);
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

async function boundedSleep(
  milliseconds: number,
  sleep: (milliseconds: number) => void | Promise<void>,
  signal: AbortSignal,
): Promise<void> {
  await bounded(Promise.resolve(sleep(milliseconds)), signal);
}

export function captureEarlyAuthenticationStartBoundary(
  now: () => number = performance.now.bind(performance),
  clock: () => Date = () => new Date(),
): EarlyAuthenticationStartBoundary {
  const monotonicMs = now();
  const requestedAt = clock().toISOString();
  if (!Number.isFinite(monotonicMs) || !validTimestamp(requestedAt)) {
    throw new Error("Early authentication start boundary could not be captured");
  }
  return Object.freeze({ requestedAt, monotonicMs });
}

/**
 * Proves that the first usable, unauthenticated browser-session response from
 * one newly started process is available inside the release startup bound.
 * Connection failures before the listener exists are counted; any HTTP
 * response with the wrong status or payload fails immediately rather than
 * being retried into a misleading success.
 */
export async function waitForEarlyAuthenticationAdmission(
  options: WaitForEarlyAuthenticationAdmissionOptions,
): Promise<EarlyAuthenticationAdmissionReceipt> {
  const timeoutMs = exactPositiveInteger(
    options.timeoutMs ?? EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
    "Early authentication deadline",
  );
  if (timeoutMs > EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS) {
    throw new Error(
      `Early authentication deadline cannot exceed ${String(EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS)}ms`,
    );
  }
  const pollIntervalMs = exactPositiveInteger(
    options.pollIntervalMs ?? 50,
    "Early authentication poll interval",
  );
  if (pollIntervalMs > timeoutMs) {
    throw new Error("Early authentication poll interval cannot exceed its deadline");
  }
  if (!validTimestamp(options.start.requestedAt) || !Number.isFinite(options.start.monotonicMs)) {
    throw new Error("Early authentication start boundary is invalid");
  }
  if (!options.previousInvocationId) {
    throw new Error("Early authentication admission requires the pre-restart invocation identity");
  }

  const now = options.now ?? performance.now.bind(performance);
  const clock = options.clock ?? (() => new Date());
  const sleep = options.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  }));
  if (now() < options.start.monotonicMs) {
    throw new Error("Early authentication monotonic clock moved backwards");
  }
  const deadline = options.start.monotonicMs + timeoutMs;
  const deadlineController = new AbortController();
  const parentAbort = (): void => {
    if (!deadlineController.signal.aborted) {
      deadlineController.abort(options.signal?.reason ?? "Early authentication admission was cancelled");
    }
  };
  if (options.signal?.aborted) parentAbort();
  else options.signal?.addEventListener("abort", parentAbort, { once: true });
  const remainingAtStart = Math.max(1, Math.ceil(deadline - now()));
  const deadlineTimer = setTimeout(() => {
    if (!deadlineController.signal.aborted) {
      deadlineController.abort("Early authentication admission exceeded its 8 second startup deadline");
    }
  }, remainingAtStart);

  let failedConnectionAttempts = 0;
  let lastIdentity: EarlyAuthenticationProcessIdentity | undefined;
  let lastConnectionError: string | undefined;
  try {
    while (now() < deadline && !deadlineController.signal.aborted) {
      const remainingMs = Math.max(1, Math.floor(deadline - now()));
      const context = Object.freeze({
        remainingMs,
        signal: deadlineController.signal,
      });
      try {
        lastIdentity = await bounded(
          Promise.resolve(options.observeProcess(context)),
          deadlineController.signal,
        );
      } catch (error) {
        if (deadlineController.signal.aborted) throw abortError(deadlineController.signal);
        lastConnectionError = error instanceof Error ? error.message : "process identity unavailable";
      }

      const newProcessIsActive = lastIdentity?.activeState === "active"
        && Number.isSafeInteger(lastIdentity.mainPid)
        && lastIdentity.mainPid > 0
        && Boolean(lastIdentity.invocationId)
        && lastIdentity.invocationId !== options.previousInvocationId;
      if (newProcessIsActive) {
        const requestStartedAt = now();
        let response: EarlyAuthenticationSessionResponse;
        try {
          response = await bounded(
            Promise.resolve(options.requestSession(context)),
            deadlineController.signal,
          );
        } catch (error) {
          if (deadlineController.signal.aborted) throw abortError(deadlineController.signal);
          failedConnectionAttempts += 1;
          lastConnectionError = error instanceof Error ? error.message : "session connection failed";
          const sleepMs = Math.min(pollIntervalMs, Math.max(1, deadline - now()));
          await boundedSleep(sleepMs, sleep, deadlineController.signal);
          continue;
        }
        const respondedAtMonotonic = now();
        const responseAfterStartMs = Math.ceil(respondedAtMonotonic - options.start.monotonicMs);
        const requestLatencyMs = Math.ceil(respondedAtMonotonic - requestStartedAt);
        if (responseAfterStartMs >= timeoutMs) {
          throw new Error("Early authentication session response reached or exceeded its startup deadline");
        }
        if (response.status !== 200) {
          throw new Error(`Early authentication admission returned HTTP ${String(response.status)}`);
        }
        const session = sessionBody(response.body);
        const respondedAt = clock().toISOString();
        if (!validTimestamp(respondedAt)) {
          throw new Error("Early authentication response timestamp is invalid");
        }
        return assertEarlyAuthenticationAdmissionReceipt({
          schemaVersion: EARLY_AUTHENTICATION_ADMISSION_SCHEMA,
          endpointPath: SESSION_PATH,
          method: "GET",
          requestedAt: options.start.requestedAt,
          respondedAt,
          deadlineMs: timeoutMs,
          responseAfterStartMs,
          requestLatencyMs,
          failedConnectionAttempts,
          httpStatus: 200,
          sessionSchemaVersion: session.schemaVersion,
          configured: session.configured,
          authenticated: session.authenticated,
          previousInvocationId: options.previousInvocationId,
          observedInvocationId: lastIdentity!.invocationId,
          observedMainPid: lastIdentity!.mainPid,
        }, {
          previousInvocationId: options.previousInvocationId,
          currentInvocationId: lastIdentity!.invocationId,
        });
      }

      const sleepMs = Math.min(pollIntervalMs, Math.max(1, deadline - now()));
      await boundedSleep(sleepMs, sleep, deadlineController.signal);
    }
  } catch (error) {
    if (deadlineController.signal.aborted && !options.signal?.aborted) {
      throw new Error(
        `Ti-Scale did not expose its unauthenticated session contract within ${String(timeoutMs)}ms` +
        `${lastIdentity ? ` (last invocation ${lastIdentity.invocationId || "missing"})` : ""}` +
        `${lastConnectionError ? `; last connection error: ${lastConnectionError}` : ""}`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    clearTimeout(deadlineTimer);
    options.signal?.removeEventListener("abort", parentAbort);
  }
  throw new Error(
    `Ti-Scale did not expose its unauthenticated session contract within ${String(timeoutMs)}ms` +
    `${lastIdentity ? ` (last invocation ${lastIdentity.invocationId || "missing"})` : ""}` +
    `${lastConnectionError ? `; last connection error: ${lastConnectionError}` : ""}`,
  );
}

export function assertEarlyAuthenticationAdmissionReceipt(
  value: unknown,
  expected: {
    readonly previousInvocationId?: string;
    readonly currentInvocationId?: string;
  } = {},
): EarlyAuthenticationAdmissionReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Early authentication admission receipt is missing or invalid");
  }
  const receipt = value as Partial<EarlyAuthenticationAdmissionReceipt>;
  const deadlineMs = exactPositiveInteger(receipt.deadlineMs, "Early authentication receipt deadline");
  const responseAfterStartMs = exactNonnegativeInteger(
    receipt.responseAfterStartMs,
    "Early authentication response time",
  );
  const requestLatencyMs = exactNonnegativeInteger(
    receipt.requestLatencyMs,
    "Early authentication request latency",
  );
  exactNonnegativeInteger(
    receipt.failedConnectionAttempts,
    "Early authentication failed connection count",
  );
  if (
    receipt.schemaVersion !== EARLY_AUTHENTICATION_ADMISSION_SCHEMA
    || receipt.endpointPath !== SESSION_PATH
    || receipt.method !== "GET"
    || !validTimestamp(receipt.requestedAt)
    || !validTimestamp(receipt.respondedAt)
    || deadlineMs > EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS
    || responseAfterStartMs >= deadlineMs
    || requestLatencyMs > responseAfterStartMs
    || receipt.httpStatus !== 200
    || receipt.sessionSchemaVersion !== SESSION_SCHEMA
    || receipt.configured !== true
    || receipt.authenticated !== false
    || typeof receipt.previousInvocationId !== "string"
    || !receipt.previousInvocationId
    || typeof receipt.observedInvocationId !== "string"
    || !receipt.observedInvocationId
    || receipt.observedInvocationId === receipt.previousInvocationId
    || !Number.isSafeInteger(receipt.observedMainPid)
    || Number(receipt.observedMainPid) <= 0
    || Date.parse(receipt.respondedAt) < Date.parse(receipt.requestedAt)
  ) {
    throw new Error("Early authentication admission receipt does not prove the release startup contract");
  }
  if (
    expected.previousInvocationId !== undefined
    && receipt.previousInvocationId !== expected.previousInvocationId
  ) {
    throw new Error("Early authentication admission receipt is bound to the wrong previous invocation");
  }
  if (
    expected.currentInvocationId !== undefined
    && receipt.observedInvocationId !== expected.currentInvocationId
  ) {
    throw new Error("Early authentication admission receipt is bound to the wrong restarted invocation");
  }
  return Object.freeze({ ...receipt } as EarlyAuthenticationAdmissionReceipt);
}
