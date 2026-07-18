import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import type { LegacyEngagementManifest } from "./LegacyEngagementDiscovery";

export interface LegacyReconServiceObservation {
  readonly port: number;
  readonly transport: "tcp" | "udp" | "sctp";
  readonly state: string;
  readonly serviceName?: string;
  readonly productVersion?: string;
}

export interface LegacyReconHostObservation {
  readonly address: string;
  readonly hostname?: string;
  readonly hostStatus: "up" | "reported";
  readonly osHints: readonly string[];
  readonly services: readonly LegacyReconServiceObservation[];
  readonly sourceRelativePath: string;
  readonly sourceHash: string;
  readonly observedAt: string;
}

export interface LegacyReconParseIssue {
  readonly relativePath: string;
  readonly code: "source_changed" | "read_failed" | "bounded_limit";
  readonly explanation: string;
}

export interface LegacyReconSemanticParseResult {
  readonly hosts: readonly LegacyReconHostObservation[];
  readonly issues: readonly LegacyReconParseIssue[];
}

const MAX_RECON_BYTES = 2 * 1024 * 1024;
const MAX_LINES = 200_000;
const MAX_HOSTS = 5_000;
const MAX_SERVICES_PER_HOST = 4_096;
const SAFE_OBSERVED_VALUE = /^[\p{L}\p{N}][\p{L}\p{N} .:_/@+()\[\]-]{0,499}$/u;

function clean(value: string | undefined, maximum = 500): string | undefined {
  if (!value) return undefined;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim().slice(0, maximum);
  return normalized && SAFE_OBSERVED_VALUE.test(normalized) ? normalized : undefined;
}

function parseHostLabel(value: string): { address: string; hostname?: string } | undefined {
  const normalized = clean(value, 300);
  if (!normalized) return undefined;
  const named = /^(.*?) \(([^()]+)\)$/u.exec(normalized);
  if (named) {
    const hostname = clean(named[1], 253);
    const address = clean(named[2], 253);
    return address ? { address, ...(hostname ? { hostname } : {}) } : undefined;
  }
  return { address: normalized };
}

function serviceKey(service: LegacyReconServiceObservation): string {
  return `${service.port}/${service.transport}/${service.state}/${service.serviceName ?? ""}/${service.productVersion ?? ""}`;
}

function finishHost(
  output: LegacyReconHostObservation[],
  current: {
    address: string;
    hostname?: string;
    hostStatus: "up" | "reported";
    osHints: string[];
    services: LegacyReconServiceObservation[];
  } | undefined,
  source: Pick<LegacyReconHostObservation, "sourceRelativePath" | "sourceHash" | "observedAt">,
): void {
  if (!current || output.length >= MAX_HOSTS) return;
  const uniqueServices = [...new Map(current.services.map((service) => [serviceKey(service), service])).values()]
    .sort((left, right) => left.port - right.port || left.transport.localeCompare(right.transport));
  output.push({
    address: current.address,
    ...(current.hostname ? { hostname: current.hostname } : {}),
    hostStatus: current.hostStatus,
    osHints: [...new Set(current.osHints)].sort(),
    services: uniqueServices.slice(0, MAX_SERVICES_PER_HOST),
    ...source,
  });
}

function parseNormalOutput(
  text: string,
  source: Pick<LegacyReconHostObservation, "sourceRelativePath" | "sourceHash" | "observedAt">,
): LegacyReconHostObservation[] {
  const output: LegacyReconHostObservation[] = [];
  let current: {
    address: string;
    hostname?: string;
    hostStatus: "up" | "reported";
    osHints: string[];
    services: LegacyReconServiceObservation[];
  } | undefined;
  for (const line of text.split(/\r?\n/u).slice(0, MAX_LINES)) {
    const report = /^Nmap scan report for (.+)$/u.exec(line.trim());
    if (report) {
      finishHost(output, current, source);
      const host = parseHostLabel(report[1]!);
      current = host ? { ...host, hostStatus: "reported", osHints: [], services: [] } : undefined;
      continue;
    }
    if (!current) continue;
    if (/^Host is up\b/iu.test(line.trim())) current.hostStatus = "up";
    const os = /^(?:Running|OS details|Aggressive OS guesses):\s*(.+)$/iu.exec(line.trim());
    if (os) {
      const hint = clean(os[1], 500);
      if (hint) current.osHints.push(hint);
      continue;
    }
    const service = /^(\d{1,5})\/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.+))?$/iu.exec(line.trim());
    if (!service || !service[3]!.toLowerCase().startsWith("open")) continue;
    const port = Number(service[1]);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) continue;
    const serviceName = clean(service[4], 120);
    const productVersion = clean(service[5], 500);
    current.services.push({
      port,
      transport: service[2]!.toLowerCase() as LegacyReconServiceObservation["transport"],
      state: service[3]!.toLowerCase(),
      ...(serviceName ? { serviceName } : {}),
      ...(productVersion ? { productVersion } : {}),
    });
  }
  finishHost(output, current, source);
  return output;
}

function parseGrepableOutput(
  text: string,
  source: Pick<LegacyReconHostObservation, "sourceRelativePath" | "sourceHash" | "observedAt">,
): LegacyReconHostObservation[] {
  const output: LegacyReconHostObservation[] = [];
  for (const line of text.split(/\r?\n/u).slice(0, MAX_LINES)) {
    const host = /^Host:\s+(\S+)(?:\s+\(([^)]*)\))?\s+(.*)$/u.exec(line.trim());
    if (!host) continue;
    const address = clean(host[1], 253);
    const hostname = clean(host[2], 253);
    if (!address) continue;
    const remainder = host[3]!;
    const status = /Status:\s+Up\b/iu.test(remainder) ? "up" : "reported";
    const portsText = /Ports:\s+(.+?)(?:\s+Ignored State:|\s+Seq Index:|\s+IP ID Seq:|\s+OS:|$)/u.exec(remainder)?.[1] ?? "";
    const services: LegacyReconServiceObservation[] = [];
    for (const raw of portsText.split(/,\s*/u)) {
      const fields = raw.split("/");
      const port = Number(fields[0]);
      const state = fields[1]?.trim().toLowerCase() ?? "";
      const transport = fields[2]?.trim().toLowerCase();
      if (!Number.isInteger(port) || port < 1 || port > 65_535 || !state.startsWith("open")) continue;
      if (transport !== "tcp" && transport !== "udp" && transport !== "sctp") continue;
      const serviceName = clean(fields[4], 120);
      const productVersion = clean(fields[6], 500);
      services.push({
        port,
        transport,
        state,
        ...(serviceName ? { serviceName } : {}),
        ...(productVersion ? { productVersion } : {}),
      });
    }
    const osHint = clean(/\bOS:\s+([^\t]+)/u.exec(remainder)?.[1], 500);
    output.push({
      address,
      ...(hostname ? { hostname } : {}),
      hostStatus: status,
      osHints: osHint ? [osHint] : [],
      services: [...new Map(services.map((service) => [serviceKey(service), service])).values()]
        .sort((left, right) => left.port - right.port || left.transport.localeCompare(right.transport))
        .slice(0, MAX_SERVICES_PER_HOST),
      ...source,
    });
    if (output.length >= MAX_HOSTS) break;
  }
  return output;
}

/**
 * Extracts only bounded, deterministic observations from hash-verified Nmap
 * text artifacts. The observations describe what historical output reported;
 * they never imply that a host or service is still reachable now.
 */
export function parseLegacyReconSemantics(manifest: LegacyEngagementManifest): LegacyReconSemanticParseResult {
  const hosts: LegacyReconHostObservation[] = [];
  const issues: LegacyReconParseIssue[] = [];
  for (const file of manifest.files) {
    if (file.kind !== "recon") continue;
    const extension = extname(file.relativePath).toLowerCase();
    if (extension !== ".nmap" && extension !== ".gnmap") continue;
    if (file.byteSize > MAX_RECON_BYTES) {
      issues.push({ relativePath: file.relativePath, code: "bounded_limit", explanation: "Recon artifact exceeds the bounded semantic-parser size limit." });
      continue;
    }
    let bytes: Buffer;
    try { bytes = readFileSync(file.absolutePath); }
    catch {
      issues.push({ relativePath: file.relativePath, code: "read_failed", explanation: "Recon artifact could not be reread for semantic projection." });
      continue;
    }
    const hash = createHash("sha256").update(bytes).digest("hex");
    if (hash !== file.sha256) {
      issues.push({ relativePath: file.relativePath, code: "source_changed", explanation: "Recon artifact changed after discovery and was not semantically projected." });
      continue;
    }
    const source = { sourceRelativePath: file.relativePath, sourceHash: file.sha256, observedAt: file.modifiedAt };
    const text = bytes.toString("utf8");
    hosts.push(...(extension === ".gnmap" ? parseGrepableOutput(text, source) : parseNormalOutput(text, source)));
    if (hosts.length >= MAX_HOSTS) {
      issues.push({ relativePath: file.relativePath, code: "bounded_limit", explanation: "Recon semantic projection reached the per-engagement host limit." });
      break;
    }
  }
  return {
    hosts: hosts.slice(0, MAX_HOSTS).sort((left, right) => (
      left.address.localeCompare(right.address)
      || left.sourceRelativePath.localeCompare(right.sourceRelativePath)
    )),
    issues,
  };
}
