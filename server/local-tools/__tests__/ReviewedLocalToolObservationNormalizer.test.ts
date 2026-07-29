import { describe, expect, test } from "bun:test";
import type { DurableAction } from "../../orchestration";
import {
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID,
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION,
  classifyReviewedLocalToolResult,
  normalizeReviewedLocalToolObservation,
  type LocalProcessToolResult,
} from "../index";

const STARTED = "2026-07-19T12:00:00.000Z";
const ENDED = "2026-07-19T12:00:01.000Z";

function action(
  toolId: string,
  target: string,
  parameters: Readonly<Record<string, unknown>>,
): DurableAction {
  return {
    id: `action_${toolId.replaceAll(/[^A-Za-z0-9]/gu, "_")}`,
    missionId: "mission-normalizer",
    runId: "run-normalizer",
    stepId: "step-normalizer",
    actionType: toolId,
    actionClass: "active_host_discovery",
    fingerprint: "f".repeat(64),
    arguments: {
      schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
      executionBinding: "reviewed_local_process",
      toolId,
      parameters,
    },
    target,
    kind: "tool",
    intentSummary: "Run one exact reviewed local check.",
    status: "running",
    idempotent: true,
    destructive: false,
    guidedDecisionId: "decision-normalizer",
    contractId: null,
    contextPackId: null,
    resultSummary: null,
    errorCategory: null,
    retryCount: 0,
    progressSignature: null,
    createdAt: STARTED,
    startedAt: STARTED,
    endedAt: null,
  };
}

function result(input: Readonly<{
  toolId: string;
  target: string;
  parameters: Readonly<Record<string, unknown>>;
  exitCode: number | null;
  stdout?: string;
  stderr?: string;
  termination?: LocalProcessToolResult["termination"];
}>): LocalProcessToolResult {
  return {
    invocationId: `local_tool_${input.toolId.replaceAll(/[^A-Za-z0-9]/gu, "_")}`,
    action: action(input.toolId, input.target, input.parameters),
    toolId: input.toolId,
    startedAt: STARTED,
    endedAt: ENDED,
    wallClockMs: 1_000,
    exitCode: input.exitCode,
    signal: null,
    termination: input.termination ?? "exited",
    spawnErrorCode: null,
    stdout: input.stdout ?? "",
    stderr: input.stderr ?? "",
    observedOutputBytes: (input.stdout?.length ?? 0) + (input.stderr?.length ?? 0),
    retainedOutputBytes: (input.stdout?.length ?? 0) + (input.stderr?.length ?? 0),
    outputSha256: "a".repeat(64),
    outputTruncated: false,
    executable: {
      sourcePath: "/usr/bin/reviewed-tool",
      sourceSha256: "b".repeat(64),
      snapshotSha256: "b".repeat(64),
      sandboxPath: "/run/ti-scale/tool",
    },
    sandbox: {
      executablePath: "/usr/bin/bwrap",
      executableSha256: "c".repeat(64),
      shell: false,
      environmentSha256: "d".repeat(64),
    },
  };
}

function normalize(input: LocalProcessToolResult) {
  return normalizeReviewedLocalToolObservation(input, classifyReviewedLocalToolResult(input));
}

describe("normalizeReviewedLocalToolObservation", () => {
  test("normalizes positive HTTP, DNS, ping, and TCP results without copying raw output", () => {
    const http = normalize(result({
      toolId: "kali:curl-http-metadata",
      target: "https://example.test/health",
      parameters: { workspace: "/engagements", url: "https://example.test/health" },
      exitCode: 0,
      stdout: "HTTP/2 204 No Content\r\nServer: fixture\r\nSet-Cookie: must-not-copy\r\n\r\n",
    }));
    expect(http).toMatchObject({
      observationType: "http_metadata_response",
      confidence: 0.95,
      completeForCandidate: false,
      normalizedValue: {
        semanticOutcome: "positive_observation",
        actionId: "action_kali_curl_http_metadata",
        target: "https://example.test/health",
        result: {
          method: "HEAD",
          statusCode: 204,
          responseObserved: true,
          headerNames: ["server", "set-cookie"],
        },
      },
    });
    expect(JSON.stringify(http)).not.toContain("must-not-copy");

    const dns = normalize(result({
      toolId: "kali:host-dns-query",
      target: "example.test",
      parameters: { workspace: "/engagements", name: "example.test", recordType: "A" },
      exitCode: 0,
      stdout: "example.test has address 192.0.2.10\n",
    }));
    expect(dns).toMatchObject({
      observationType: "dns_record_query",
      completeForCandidate: true,
      normalizedValue: { result: {
        queryName: "example.test",
        recordType: "A",
        answerCount: 1,
        answers: [{ kind: "address", value: "192.0.2.10" }],
        noRecord: false,
      } },
    });

    const ping = normalize(result({
      toolId: "kali:ping-host-liveness",
      target: "192.0.2.10",
      parameters: { workspace: "/engagements", target: "192.0.2.10" },
      exitCode: 0,
      stdout: "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 0.020/0.030/0.040/0.010 ms\n",
    }));
    expect(ping).toMatchObject({
      observationType: "host_liveness",
      confidence: 0.9,
      completeForCandidate: true,
      normalizedValue: { result: {
        host: "192.0.2.10",
        responded: true,
        transmitted: 2,
        received: 2,
        packetLossPercent: 0,
        timingMs: { minimum: 0.02, average: 0.03, maximum: 0.04, deviation: 0.01 },
      } },
    });

    const tcp = normalize(result({
      toolId: "kali:ncat-tcp-connect",
      target: "tcp://192.0.2.10:443",
      parameters: { workspace: "/engagements", target: "192.0.2.10", port: 443 },
      exitCode: 0,
      stderr: "Ncat: Connected to 192.0.2.10:443.\n",
    }));
    expect(tcp).toMatchObject({
      observationType: "tcp_connectivity",
      confidence: 0.9,
      completeForCandidate: true,
      normalizedValue: { result: {
        host: "192.0.2.10",
        port: 443,
        transport: "tcp",
        connectionEstablished: true,
        applicationPayloadSent: false,
      } },
    });
  });

  test("preserves expected negative answers as careful target observations", () => {
    const http = normalize(result({
      toolId: "kali:curl-http-metadata",
      target: "https://example.test/missing",
      parameters: { workspace: "/engagements", url: "https://example.test/missing" },
      exitCode: 22,
      stdout: "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    }));
    expect(http).toMatchObject({
      completeForCandidate: false,
      normalizedValue: { semanticOutcome: "negative_observation", result: { statusCode: 404 } },
    });
    expect(http?.statement).toContain("service responded");

    const dns = normalize(result({
      toolId: "kali:host-dns-query",
      target: "absent.invalid",
      parameters: { workspace: "/engagements", name: "absent.invalid", recordType: "A" },
      exitCode: 1,
      stderr: "Host absent.invalid not found: 3(NXDOMAIN)\n",
    }));
    expect(dns).toMatchObject({
      confidence: 0.85,
      completeForCandidate: true,
      normalizedValue: { semanticOutcome: "negative_observation", result: { noRecord: true, answerCount: 0 } },
    });

    const ping = normalize(result({
      toolId: "kali:ping-host-liveness",
      target: "192.0.2.1",
      parameters: { workspace: "/engagements", target: "192.0.2.1" },
      exitCode: 1,
      stdout: "2 packets transmitted, 0 received, 100% packet loss, time 1022ms\n",
    }));
    expect(ping).toMatchObject({
      confidence: 0.7,
      completeForCandidate: true,
      normalizedValue: { semanticOutcome: "negative_observation", result: { responded: false, received: 0 } },
    });
    expect(ping?.statement).toContain("filtering");

    const tcp = normalize(result({
      toolId: "kali:ncat-tcp-connect",
      target: "tcp://127.0.0.1:9",
      parameters: { workspace: "/engagements", target: "127.0.0.1", port: 9 },
      exitCode: 1,
      stderr: "Ncat: Connection refused.\n",
    }));
    expect(tcp).toMatchObject({
      confidence: 0.9,
      completeForCandidate: true,
      normalizedValue: { semanticOutcome: "negative_observation", result: {
        connectionEstablished: false,
        refusalObserved: true,
      } },
    });
  });

  test("normalizes bounded nmap TCP-connect facts while retaining raw output only as a log", () => {
    const scan = normalize(result({
      toolId: "kali:nmap-tcp-connect-service-scan",
      target: "127.0.0.1",
      parameters: {
        workspace: "/engagements/review",
        target: "127.0.0.1",
        ports: "22,80,45555",
      },
      exitCode: 0,
      stdout: [
        "Nmap scan report for 127.0.0.1",
        "Host is up (0.00015s latency).",
        "PORT      STATE SERVICE VERSION",
        "80/tcp    open  http    nginx 1.24.0",
        "45555/tcp open  http    SimpleHTTPServer 0.6 (Python 3.13.12)",
        "MAC Address: raw-log-only-value",
        "Nmap done: 1 IP address (1 host up) scanned in 6.10 seconds",
      ].join("\n"),
    }));
    expect(scan).toMatchObject({
      observationType: "tcp_service_scan",
      confidence: 0.95,
      completeForCandidate: false,
      normalizedValue: {
        semanticOutcome: "positive_observation",
        result: {
          host: "127.0.0.1",
          transport: "tcp",
          scanTechnique: "tcp_connect",
          requestedPorts: [22, 80, 45555],
          requestedPortCount: 3,
          openPortCount: 2,
          hostReportedUp: true,
          scanCompleted: true,
          versionDetection: "light",
          scriptsExecuted: false,
          osDetectionRequested: false,
          rawSocketRequired: false,
          openPorts: [
            { port: 80, transport: "tcp", state: "open", service: "http", version: "nginx 1.24.0" },
            { port: 45555, transport: "tcp", state: "open", service: "http", version: "SimpleHTTPServer 0.6 (Python 3.13.12)" },
          ],
        },
      },
    });
    expect(scan?.statement).toContain("found 2 open services");
    expect(JSON.stringify(scan)).not.toContain("raw-log-only-value");

    const noOpenPorts = normalize(result({
      toolId: "kali:nmap-tcp-connect-service-scan",
      target: "127.0.0.1",
      parameters: { workspace: "/engagements/review", target: "127.0.0.1", ports: "9" },
      exitCode: 0,
      stdout: "Nmap scan report for 127.0.0.1\nHost is up.\nNmap done: 1 IP address (1 host up) scanned in 0.03 seconds\n",
    }));
    expect(noOpenPorts).toMatchObject({
      observationType: "tcp_service_scan",
      completeForCandidate: false,
      normalizedValue: { result: { requestedPortCount: 1, openPortCount: 0, scanCompleted: true } },
    });
    expect(noOpenPorts?.statement).toContain("found no open service");
  });

  test("does not convert process failures into target observations", () => {
    const timedOut = result({
      toolId: "kali:ping-host-liveness",
      target: "192.0.2.1",
      parameters: { workspace: "/engagements", target: "192.0.2.1" },
      exitCode: null,
      termination: "timed_out",
    });
    expect(normalize(timedOut)).toBeNull();

    const unresolvedTcpTarget = result({
      toolId: "kali:ncat-tcp-connect",
      target: "tcp://missing.invalid:443",
      parameters: { workspace: "/engagements", target: "missing.invalid", port: 443 },
      exitCode: 1,
      stderr: "Ncat: Could not resolve hostname missing.invalid: Name or service not known. QUITTING.\n",
    });
    expect(classifyReviewedLocalToolResult(unresolvedTcpTarget)).toMatchObject({
      success: false,
      outcome: "execution_failure",
      category: "deterministic_tool_error",
    });
    expect(normalize(unresolvedTcpTarget)).toBeNull();
    expect(REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID).toBe("ti-scale.reviewed-local-tool-normalizer");
    expect(REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION).toBe("1.1.0");
  });
});
