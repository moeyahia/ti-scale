import { describe, expect, test } from "bun:test";
import {
  assertEarlyAuthenticationAdmissionReceipt,
  captureEarlyAuthenticationStartBoundary,
  EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
  waitForEarlyAuthenticationAdmission,
  type EarlyAuthenticationAdmissionReceipt,
} from "../../../scripts/release/EarlyAuthenticationAdmission";

const REQUESTED_AT = "2026-07-22T12:00:00.000Z";
const RESPONDED_AT = "2026-07-22T12:00:00.062Z";

function validReceipt(
  overrides: Partial<EarlyAuthenticationAdmissionReceipt> = {},
): EarlyAuthenticationAdmissionReceipt {
  return {
    schemaVersion: "ti-scale.early-authentication-admission.v1",
    endpointPath: "/api/v2/auth/session",
    method: "GET",
    requestedAt: REQUESTED_AT,
    respondedAt: RESPONDED_AT,
    deadlineMs: EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
    responseAfterStartMs: 62,
    requestLatencyMs: 12,
    failedConnectionAttempts: 1,
    httpStatus: 200,
    sessionSchemaVersion: "2.4",
    configured: true,
    authenticated: false,
    previousInvocationId: "invocation-before-restart",
    observedInvocationId: "invocation-after-restart",
    observedMainPid: 4_201,
    ...overrides,
  };
}

describe("early authentication release admission", () => {
  test("binds the first valid session response inside eight seconds to one new process", async () => {
    let now = 0;
    let processObservations = 0;
    let requests = 0;
    const receipt = await waitForEarlyAuthenticationAdmission({
      start: { requestedAt: REQUESTED_AT, monotonicMs: 0 },
      previousInvocationId: "invocation-before-restart",
      timeoutMs: EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
      pollIntervalMs: 25,
      now: () => now,
      clock: () => new Date(RESPONDED_AT),
      sleep: (milliseconds) => { now += milliseconds; },
      observeProcess: () => {
        processObservations += 1;
        return processObservations === 1
          ? { activeState: "inactive", mainPid: 0, invocationId: "invocation-before-restart" }
          : { activeState: "active", mainPid: 4_201, invocationId: "invocation-after-restart" };
      },
      requestSession: () => {
        requests += 1;
        if (requests === 1) throw new TypeError("listener not accepting connections yet");
        now += 12;
        return {
          status: 200,
          body: { schemaVersion: "2.4", configured: true, authenticated: false },
        };
      },
    });

    expect(receipt).toEqual(validReceipt());
    expect(assertEarlyAuthenticationAdmissionReceipt(receipt, {
      previousInvocationId: "invocation-before-restart",
      currentInvocationId: "invocation-after-restart",
    })).toEqual(receipt);
    expect(processObservations).toBe(3);
    expect(requests).toBe(2);
  });

  test("captures a monotonic and UTC restart boundary without secret material", () => {
    const boundary = captureEarlyAuthenticationStartBoundary(
      () => 123.5,
      () => new Date(REQUESTED_AT),
    );
    expect(boundary).toEqual({ requestedAt: REQUESTED_AT, monotonicMs: 123.5 });
    expect(Object.isFrozen(boundary)).toBe(true);
    expect(JSON.stringify(boundary)).not.toContain("token");
  });

  test("rejects the old invocation, a malformed session, and a response at the deadline", async () => {
    let now = 0;
    await expect(waitForEarlyAuthenticationAdmission({
      start: { requestedAt: REQUESTED_AT, monotonicMs: 0 },
      previousInvocationId: "same-invocation",
      timeoutMs: 20,
      pollIntervalMs: 10,
      now: () => now,
      sleep: (milliseconds) => { now += milliseconds; },
      observeProcess: () => ({ activeState: "active", mainPid: 1, invocationId: "same-invocation" }),
      requestSession: () => {
        throw new Error("must not request against the old process");
      },
    })).rejects.toThrow("within 20ms");

    now = 0;
    await expect(waitForEarlyAuthenticationAdmission({
      start: { requestedAt: REQUESTED_AT, monotonicMs: 0 },
      previousInvocationId: "old",
      timeoutMs: 20,
      pollIntervalMs: 5,
      now: () => now,
      clock: () => new Date(RESPONDED_AT),
      sleep: (milliseconds) => { now += milliseconds; },
      observeProcess: () => ({ activeState: "active", mainPid: 2, invocationId: "new" }),
      requestSession: () => ({
        status: 200,
        body: { schemaVersion: "2.4", configured: false, authenticated: false },
      }),
    })).rejects.toThrow("invalid unauthenticated session contract");

    now = 0;
    await expect(waitForEarlyAuthenticationAdmission({
      start: { requestedAt: REQUESTED_AT, monotonicMs: 0 },
      previousInvocationId: "old",
      timeoutMs: 20,
      pollIntervalMs: 5,
      now: () => now,
      clock: () => new Date(RESPONDED_AT),
      sleep: (milliseconds) => { now += milliseconds; },
      observeProcess: () => ({ activeState: "active", mainPid: 2, invocationId: "new" }),
      requestSession: () => {
        now = 20;
        return {
          status: 200,
          body: { schemaVersion: "2.4", configured: true, authenticated: false },
        };
      },
    })).rejects.toThrow("reached or exceeded");
  });

  test("enforces a real outer deadline when an injected request ignores cancellation", async () => {
    const start = captureEarlyAuthenticationStartBoundary();
    const startedAt = performance.now();
    await expect(waitForEarlyAuthenticationAdmission({
      start,
      previousInvocationId: "old",
      timeoutMs: 25,
      pollIntervalMs: 5,
      observeProcess: () => ({ activeState: "active", mainPid: 2, invocationId: "new" }),
      requestSession: () => new Promise(() => {
        // A transport that never settles and ignores the supplied AbortSignal.
      }),
    })).rejects.toThrow("within 25ms");
    expect(performance.now() - startedAt).toBeLessThan(500);
  });

  test("receipt validation rejects deadline, identity, session, and timing ambiguity", () => {
    expect(() => assertEarlyAuthenticationAdmissionReceipt(validReceipt({
      deadlineMs: EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS + 1,
    }))).toThrow("does not prove");
    expect(() => assertEarlyAuthenticationAdmissionReceipt(validReceipt({
      responseAfterStartMs: EARLY_AUTHENTICATION_ADMISSION_DEADLINE_MS,
    }))).toThrow("does not prove");
    expect(() => assertEarlyAuthenticationAdmissionReceipt(validReceipt({
      observedInvocationId: "invocation-before-restart",
    }))).toThrow("does not prove");
    expect(() => assertEarlyAuthenticationAdmissionReceipt(validReceipt({
      authenticated: true as false,
    }))).toThrow("does not prove");
    expect(() => assertEarlyAuthenticationAdmissionReceipt(validReceipt(), {
      currentInvocationId: "another-process",
    })).toThrow("wrong restarted invocation");
  });
});
