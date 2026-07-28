import { reviewedLocalToolActionEnvelope } from "../orchestration";
import type {
  LocalProcessToolResult,
  ReviewedLocalToolResultClassification,
  ReviewedLocalToolSemanticOutcome,
} from "./LocalProcessToolExecution";

export const REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID =
  "ti-scale.reviewed-local-tool-normalizer" as const;
export const REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION = "1.1.0" as const;
export const REVIEWED_LOCAL_TOOL_OBSERVATION_SCHEMA_VERSION =
  "ti-scale.reviewed-local-tool-observation.v1" as const;

export interface ReviewedLocalToolObservationNormalization {
  readonly observationType:
    | "http_metadata_response"
    | "dns_record_query"
    | "host_liveness"
    | "tcp_connectivity"
    | "tcp_service_scan"
    | "web_technology_fingerprint"
    | "web_endpoint_discovery";
  readonly statement: string;
  readonly normalizedValue: Readonly<{
    schemaVersion: typeof REVIEWED_LOCAL_TOOL_OBSERVATION_SCHEMA_VERSION;
    semanticOutcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">;
    missionId: string;
    runId: string;
    stepId: string;
    actionId: string;
    toolCallId: string;
    toolId: string;
    target: string;
    /** Revalidated by OperationalTruthService's bounded JSON sanitizer. */
    result: Readonly<Record<string, unknown>>;
  }>;
  readonly confidence: number;
  /** A candidate still requires a matching mission evidence policy. */
  readonly completeForCandidate: boolean;
}

function output(result: LocalProcessToolResult): string {
  return `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n");
}

function bounded(value: string, maximum = 500): string {
  const normalized = value.trim().replace(/\s+/gu, " ");
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function parameters(result: LocalProcessToolResult): Readonly<Record<string, unknown>> {
  return reviewedLocalToolActionEnvelope(result.action.arguments)?.parameters ?? {};
}

function base(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
  normalizedResult: Readonly<Record<string, unknown>>,
): ReviewedLocalToolObservationNormalization["normalizedValue"] {
  return Object.freeze({
    schemaVersion: REVIEWED_LOCAL_TOOL_OBSERVATION_SCHEMA_VERSION,
    semanticOutcome: outcome,
    missionId: result.action.missionId,
    runId: result.action.runId,
    stepId: result.action.stepId,
    actionId: result.action.id,
    toolCallId: result.invocationId,
    toolId: result.toolId,
    target: result.action.target,
    result: normalizedResult,
  });
}

function http(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const matches = [...output(result).matchAll(/^HTTP\/(?:0\.9|1\.[01]|2|3)\s+([1-5]\d{2})(?:\s+([^\n]+))?$/gimu)];
  const terminal = matches.at(-1);
  const statusCode = terminal ? Number(terminal[1]) : null;
  const reason = terminal?.[2] ? bounded(terminal[2], 160) : null;
  const headerNames = [...new Set(
    output(result).split("\n").flatMap((line) => {
      const match = line.match(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+):/u);
      return match?.[1] ? [match[1].toLocaleLowerCase("en-US")] : [];
    }),
  )].sort().slice(0, 100);
  const responseObserved = statusCode !== null || result.exitCode === 0 || result.exitCode === 22;
  const statement = statusCode === null
    ? `The exact HTTP metadata check for ${bounded(result.action.target, 1_000)} completed, but no status line was retained.`
    : outcome === "negative_observation"
      ? `The exact HTTP metadata check for ${bounded(result.action.target, 1_000)} received HTTP ${statusCode}; the service responded but did not satisfy this request.`
      : `The exact HTTP metadata check for ${bounded(result.action.target, 1_000)} received HTTP ${statusCode}.`;
  return {
    observationType: "http_metadata_response",
    statement,
    normalizedValue: base(result, outcome, {
      method: "HEAD",
      url: typeof input.url === "string" ? input.url : result.action.target,
      responseObserved,
      statusCode,
      reason,
      headerNames,
    }),
    confidence: statusCode === null ? 0.75 : 0.95,
    // The current reviewed curl binding retains response metadata, not a full
    // request/response pair. It is therefore an Observation only even when a
    // mission requests the broader `http_exchange` evidence type.
    completeForCandidate: false,
  };
}

interface DnsAnswer {
  readonly kind: "address" | "ipv6_address" | "alias" | "mail_exchange" | "name_server" | "soa" | "text";
  readonly value: string;
}

function dnsAnswer(line: string): DnsAnswer | undefined {
  const patterns: readonly [DnsAnswer["kind"], RegExp][] = [
    ["address", /\shas address\s+(.+)$/iu],
    ["ipv6_address", /\shas IPv6 address\s+(.+)$/iu],
    ["alias", /\sis an alias for\s+(.+)$/iu],
    ["mail_exchange", /\smail is handled by\s+(.+)$/iu],
    ["name_server", /\sname server\s+(.+)$/iu],
    ["soa", /\shas SOA record\s+(.+)$/iu],
    ["text", /\sdescriptive text\s+(.+)$/iu],
  ];
  for (const [kind, pattern] of patterns) {
    const match = line.match(pattern);
    if (match?.[1]) return { kind, value: bounded(match[1]) };
  }
  return undefined;
}

function dns(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const name = typeof input.name === "string" ? input.name : result.action.target;
  const recordType = typeof input.recordType === "string" ? input.recordType : "unknown";
  const answers = output(result).split("\n")
    .map((line) => dnsAnswer(line.trim()))
    .filter((answer): answer is DnsAnswer => answer !== undefined)
    .slice(0, 100);
  const noRecord = outcome === "negative_observation";
  return {
    observationType: "dns_record_query",
    statement: noRecord
      ? `The exact DNS ${recordType} query for ${bounded(name)} completed without the requested record.`
      : answers.length === 1
        ? `The exact DNS ${recordType} query for ${bounded(name)} returned one parsed answer.`
        : `The exact DNS ${recordType} query for ${bounded(name)} returned ${answers.length} parsed answers.`,
    normalizedValue: base(result, outcome, {
      queryName: name,
      recordType,
      answerCount: answers.length,
      answers,
      noRecord,
    }),
    confidence: noRecord ? 0.85 : answers.length > 0 ? 0.9 : 0.7,
    completeForCandidate: noRecord || answers.length > 0,
  };
}

function ping(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const summary = output(result).match(
    /(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received(?:,\s*\+?\d+\s+errors?)?,\s*([\d.]+)%\s+packet loss/iu,
  );
  const timing = output(result).match(
    /(?:round-trip|rtt)\s+min\/avg\/max\/(?:mdev|stddev)\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/iu,
  );
  const transmitted = summary ? Number(summary[1]) : null;
  const received = summary ? Number(summary[2]) : null;
  const packetLossPercent = summary ? Number(summary[3]) : null;
  const responded = received === null ? outcome === "positive_observation" : received > 0;
  const target = typeof input.target === "string"
    ? input.target
    : result.action.target;
  return {
    observationType: "host_liveness",
    statement: responded
      ? `The exact liveness check for ${bounded(target)} received a reply.`
      : `The exact liveness check for ${bounded(target)} received no reply; filtering and an offline host remain possible explanations.`,
    normalizedValue: base(result, outcome, {
      host: target,
      responded,
      transmitted,
      received,
      packetLossPercent,
      timingMs: timing ? {
        minimum: Number(timing[1]),
        average: Number(timing[2]),
        maximum: Number(timing[3]),
        deviation: Number(timing[4]),
      } : null,
    }),
    confidence: responded ? 0.9 : 0.7,
    completeForCandidate: summary !== null,
  };
}

function tcp(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const host = typeof input.target === "string" ? input.target : result.action.target;
  const port = typeof input.port === "number" && Number.isSafeInteger(input.port) ? input.port : null;
  const connected = outcome === "positive_observation";
  const refused = !connected && /connection refused/iu.test(output(result));
  const timedOut = !connected && /\b(?:connection\s+)?timed?\s*out\b/iu.test(output(result));
  const routeUnavailable = !connected
    && /\b(?:network is unreachable|no route to host)\b/iu.test(output(result));
  const endpoint = port === null ? host : `${host}:${port}`;
  return {
    observationType: "tcp_connectivity",
    statement: connected
      ? `The exact TCP connection check for ${bounded(endpoint)} established a connection without sending an application payload.`
      : refused
        ? `The exact TCP connection check for ${bounded(endpoint)} was refused; no connection was established.`
        : `The exact TCP connection check for ${bounded(endpoint)} did not establish a connection.`,
    normalizedValue: base(result, outcome, {
      host,
      port,
      transport: "tcp",
      connectionEstablished: connected,
      refusalObserved: refused,
      timeoutObserved: timedOut,
      routeUnavailableObserved: routeUnavailable,
      applicationPayloadSent: false,
    }),
    confidence: connected || refused ? 0.9 : 0.75,
    completeForCandidate: port !== null && (connected || refused || timedOut || routeUnavailable),
  };
}

interface NmapOpenPort {
  readonly port: number;
  readonly transport: "tcp";
  readonly state: "open";
  readonly service: string;
  readonly version: string | null;
}

function nmapOpenPort(line: string): NmapOpenPort | undefined {
  const match = line.trim().match(
    /^(\d{1,5})\/tcp\s+open\s+([A-Za-z0-9?._/-]{1,80})(?:\s+(.+))?$/u,
  );
  if (!match?.[1] || !match[2]) return undefined;
  const port = Number(match[1]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return undefined;
  return {
    port,
    transport: "tcp",
    state: "open",
    service: bounded(match[2], 80),
    version: match[3] ? bounded(match[3], 300) : null,
  };
}

function nmap(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const host = typeof input.target === "string" ? input.target : result.action.target;
  const requestedPorts = typeof input.ports === "string"
    ? input.ports.split(",").map(Number).filter((port) => Number.isSafeInteger(port))
    : [];
  const openPorts = output(result).split("\n")
    .map(nmapOpenPort)
    .filter((record): record is NmapOpenPort => record !== undefined)
    .slice(0, 1_024);
  const scanCompleted = /\bNmap done:\s+1 IP address \(1 host up\) scanned in\b/iu.test(output(result));
  const hostReportedUp = /\bHost is up\b/iu.test(output(result));
  const count = openPorts.length;
  const statement = count === 0
    ? `The approved TCP connect scan checked ${requestedPorts.length} port${requestedPorts.length === 1 ? "" : "s"} on ${bounded(host)} and found no open service in that set.`
    : `The approved TCP connect scan checked ${requestedPorts.length} port${requestedPorts.length === 1 ? "" : "s"} on ${bounded(host)} and found ${count} open service${count === 1 ? "" : "s"}.`;
  return {
    observationType: "tcp_service_scan",
    statement,
    normalizedValue: base(result, outcome, {
      host,
      transport: "tcp",
      scanTechnique: "tcp_connect",
      requestedPorts,
      requestedPortCount: requestedPorts.length,
      openPortCount: count,
      openPorts,
      hostReportedUp,
      scanCompleted,
      versionDetection: "light",
      scriptsExecuted: false,
      osDetectionRequested: false,
      rawSocketRequired: false,
      outputTruncated: result.outputTruncated,
    }),
    confidence: scanCompleted && !result.outputTruncated ? 0.95 : 0.75,
    // Parsed scan facts remain an unverified Observation. The raw process
    // output remains an Engagement Log and is never promoted automatically.
    completeForCandidate: false,
  };
}

function whatweb(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const retained = output(result);
  const status = retained.match(/\[([1-5]\d{2})\s+[A-Za-z][^\]]*\]/u);
  const title = retained.match(/\bTitle\[([^\]]{1,500})\]/u);
  const server = retained.match(/\bHTTPServer\[([^\]]{1,500})\]/u);
  const poweredBy = retained.match(/\bX-Powered-By\[([^\]]{1,500})\]/u);
  const html5 = /(?:^|[\s,])HTML5(?:[\s,]|$)/u.test(retained);
  const url = typeof input.url === "string" ? input.url : result.action.target;
  const signals = [
    ...(server?.[1] ? [{ kind: "http_server", value: bounded(server[1], 300) }] : []),
    ...(title?.[1] ? [{ kind: "page_title", value: bounded(title[1], 300) }] : []),
    ...(poweredBy?.[1] ? [{ kind: "powered_by", value: bounded(poweredBy[1], 300) }] : []),
    ...(html5 ? [{ kind: "html5", value: true }] : []),
  ];
  return {
    observationType: "web_technology_fingerprint",
    statement: signals.length > 0
      ? `The bounded web fingerprint for ${bounded(url, 1_000)} retained ${signals.length} attributable technology signal${signals.length === 1 ? "" : "s"}.`
      : `The bounded web fingerprint for ${bounded(url, 1_000)} completed without a recognized reviewed technology signal.`,
    normalizedValue: base(result, outcome, {
      url,
      statusCode: status?.[1] ? Number(status[1]) : null,
      signalCount: signals.length,
      signals,
      redirectFollowed: false,
      requestBudget: 1,
      outputTruncated: result.outputTruncated,
    }),
    confidence: signals.length > 0 && !result.outputTruncated ? 0.9 : 0.7,
    completeForCandidate: false,
  };
}

interface FfufMatch {
  readonly url: string;
  readonly status: number;
  readonly length: number | null;
  readonly words: number | null;
  readonly lines: number | null;
  readonly redirectLocation: string | null;
}

function ffufMatch(line: string, expectedOrigin: string): FfufMatch | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line) as unknown;
  } catch {
    return undefined;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record.url !== "string" || !Number.isSafeInteger(record.status)) return undefined;
  let url: URL;
  try {
    url = new URL(record.url);
  } catch {
    return undefined;
  }
  if (url.origin !== expectedOrigin || url.username || url.password) return undefined;
  const number = (candidate: unknown): number | null =>
    Number.isSafeInteger(candidate) && Number(candidate) >= 0 ? Number(candidate) : null;
  return {
    url: url.href,
    status: Number(record.status),
    length: number(record.length),
    words: number(record.words),
    lines: number(record.lines),
    redirectLocation: typeof record.redirectlocation === "string"
      ? bounded(record.redirectlocation, 1_000)
      : null,
  };
}

function ffuf(
  result: LocalProcessToolResult,
  outcome: Exclude<ReviewedLocalToolSemanticOutcome, "execution_failure">,
): ReviewedLocalToolObservationNormalization {
  const input = parameters(result);
  const baseUrl = typeof input.url === "string" ? input.url : result.action.target;
  const origin = new URL(baseUrl).origin;
  const matches = output(result).split("\n")
    .map((line) => ffufMatch(line.trim(), origin))
    .filter((match): match is FfufMatch => match !== undefined)
    .slice(0, 14);
  return {
    observationType: "web_endpoint_discovery",
    statement: matches.length === 0
      ? `The fixed 14-path check below ${bounded(baseUrl, 1_000)} completed without a matching response.`
      : `The fixed 14-path check below ${bounded(baseUrl, 1_000)} retained ${matches.length} responding path${matches.length === 1 ? "" : "s"}.`,
    normalizedValue: base(result, outcome, {
      baseUrl,
      fixedDictionaryVersion: "ti-scale.web-paths.v1",
      requestBudget: 14,
      maximumConcurrency: 2,
      maximumRatePerSecond: 10,
      recursive: false,
      redirectFollowed: false,
      matchCount: matches.length,
      matches,
      outputTruncated: result.outputTruncated,
    }),
    confidence: !result.outputTruncated ? 0.9 : 0.7,
    completeForCandidate: false,
  };
}

/**
 * Converts only successful target observations (including expected negative
 * answers) into bounded structured facts. Runtime/process failures remain
 * technical logs and never become target observations.
 */
export function normalizeReviewedLocalToolObservation(
  result: LocalProcessToolResult,
  classification: ReviewedLocalToolResultClassification,
): ReviewedLocalToolObservationNormalization | null {
  if (!classification.success || classification.outcome === "execution_failure") return null;
  switch (result.toolId) {
    case "kali:curl-http-metadata": return http(result, classification.outcome);
    case "kali:host-dns-query": return dns(result, classification.outcome);
    case "kali:ping-host-liveness": return ping(result, classification.outcome);
    case "kali:ncat-tcp-connect": return tcp(result, classification.outcome);
    case "kali:nmap-tcp-connect-service-scan": return nmap(result, classification.outcome);
    case "kali:whatweb-bounded-fingerprint": return whatweb(result, classification.outcome);
    case "kali:ffuf-bounded-content-discovery": return ffuf(result, classification.outcome);
    default: return null;
  }
}
