import { createHash } from "node:crypto";
import { classifyWindowsIdentityTerminalResult } from "./failureTaxonomy";
import {
  WINDOWS_IDENTITY_NORMALIZATION_SCHEMA_VERSION,
  type WindowsIdentityNormalizedResult,
  type WindowsIdentityObservation,
  type WindowsIdentityRawResult,
  type WindowsIdentityToolId,
} from "./types";

const PEM_BLOCK = /-----BEGIN [^-\r\n]+-----[\s\S]*?-----END [^-\r\n]+-----/gu;
const AUTHORIZATION_HEADER = /\b(authorization)\s*[:=]\s*[^\r\n]*/giu;
const COOKIE_HEADER = /\b(set-cookie|cookie)\s*[:=]\s*[^\r\n]*/giu;
const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|secret|token|cookie|authorization|api[-_]?key|private[-_]?key)\s*[:=]\s*([^\s,;]+)/giu;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/giu;
const NTLM_PAIR = /\b[a-f0-9]{32}(?::[a-f0-9]{32})?\b/giu;
const SAMBA_INLINE_PASSWORD = /((?:^|\s)-U\s+[^%\s]+)%[^\s]+/gmu;
const MAX_NORMALIZED_OBSERVATIONS = 512;

export function redactWindowsIdentityOutput(value: string): string {
  return value
    .replace(PEM_BLOCK, "[REDACTED_PRIVATE_MATERIAL]")
    .replace(SECRET_ASSIGNMENT, (_match, key: string) => `${key}=[REDACTED]`)
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(NTLM_PAIR, "[REDACTED_NTLM]")
    .replace(SAMBA_INLINE_PASSWORD, "$1%[REDACTED]")
    // Run whole-header rules last: generic assignment matching must never
    // leave a multi-token Authorization or Cookie value partially visible.
    .replace(AUTHORIZATION_HEADER, (_match, key: string) => `${key}: [REDACTED]`)
    .replace(COOKIE_HEADER, (_match, key: string) => `${key}: [REDACTED]`);
}

function observation(
  sourceToolId: WindowsIdentityToolId,
  type: WindowsIdentityObservation["type"],
  statement: string,
  normalizedValue: WindowsIdentityObservation["normalizedValue"],
  confidence = 0.8,
): WindowsIdentityObservation {
  return Object.freeze({
    type,
    statement,
    normalizedValue: Object.freeze({ ...normalizedValue }),
    confidence,
    sourceToolId,
    verified: false,
  });
}

function smbShares(toolId: WindowsIdentityToolId, output: string): WindowsIdentityObservation[] {
  const records: WindowsIdentityObservation[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const match = /^(Disk|IPC|Printer)\|([^|\r\n]{1,255})\|([^\r\n]*)$/u.exec(line.trim());
    if (!match) continue;
    const shareType = match[1]!;
    const share = match[2]!.trim();
    const comment = match[3]!.trim();
    records.push(observation(
      toolId,
      "smb_share",
      `The SMB service reported the ${share} share (${shareType}).`,
      { share, shareType, comment: comment || null },
      0.85,
    ));
    if (records.length >= MAX_NORMALIZED_OBSERVATIONS) break;
  }
  return records;
}

function nxcIdentity(toolId: WindowsIdentityToolId, output: string): WindowsIdentityObservation[] {
  const records: WindowsIdentityObservation[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const match = /^SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s+(.+)$/u.exec(line.trim());
    if (!match) continue;
    const details = match[4]!;
    const domain = /\(domain:([^)]*)\)/u.exec(details)?.[1]?.trim() || null;
    const signing = /\(signing:(True|False)\)/iu.exec(details)?.[1]?.toLowerCase() === "true";
    const smbV1 = /\(SMBv1:(True|False)\)/iu.exec(details)?.[1]?.toLowerCase() === "true";
    records.push(observation(
      toolId,
      "smb_host_identity",
      `The SMB service identified ${match[3]} on ${match[1]}:${match[2]}.`,
      {
        address: match[1]!,
        port: Number(match[2]!),
        hostName: match[3]!,
        domain,
        signingRequired: signing,
        smbV1Enabled: smbV1,
        productSummary: details.replace(/\s*\((?:domain|signing|SMBv1):[^)]*\)/giu, "").trim(),
      },
      0.85,
    ));
    if (records.length >= MAX_NORMALIZED_OBSERVATIONS) break;
  }
  return records;
}

function namedFields(
  toolId: WindowsIdentityToolId,
  output: string,
  kind: "ldap" | "rpc",
): WindowsIdentityObservation[] {
  const accepted = kind === "ldap"
    ? new Set([
        "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
        "schemaNamingContext", "dnsHostName", "supportedLDAPVersion", "supportedSASLMechanisms",
      ])
    : new Set([
        "Domain", "Server Role", "Num Users", "Num Domain Groups", "Num Local Groups",
      ]);
  const values: Record<string, string> = {};
  for (const line of output.split(/\r?\n/u)) {
    const separator = line.indexOf(":");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (accepted.has(key) && value && value.length <= 1_024) values[key] = value;
  }
  if (Object.keys(values).length === 0) return [];
  return [observation(
    toolId,
    kind === "ldap" ? "ldap_directory_metadata" : "rpc_domain_metadata",
    kind === "ldap"
      ? "The LDAP root directory entry exposed directory naming and protocol metadata."
      : "The RPC service returned domain summary metadata.",
    values,
    0.9,
  )];
}

function parsedObservations(
  toolId: WindowsIdentityToolId,
  output: string,
): readonly WindowsIdentityObservation[] {
  switch (toolId) {
    case "kali:smbclient-share-list": return smbShares(toolId, output);
    case "kali:nxc-smb-summary": return nxcIdentity(toolId, output);
    case "kali:ldapsearch-root-dse": return namedFields(toolId, output, "ldap");
    case "kali:rpcclient-domain-info": return namedFields(toolId, output, "rpc");
  }
}

export function normalizeWindowsIdentityResult(
  result: WindowsIdentityRawResult,
): WindowsIdentityNormalizedResult {
  const stdout = redactWindowsIdentityOutput(result.stdout);
  const stderr = redactWindowsIdentityOutput(result.stderr);
  const failure = classifyWindowsIdentityTerminalResult({ ...result, stdout, stderr });
  const observations = failure === null
    ? parsedObservations(result.toolId, `${stdout}\n${stderr}`)
    : [];
  const status = result.cancelled ? "cancelled" : failure ? "failed" : "completed";
  const outputSha256 = createHash("sha256")
    .update(stdout, "utf8")
    .update("\u0000", "utf8")
    .update(stderr, "utf8")
    .digest("hex");
  return Object.freeze({
    schemaVersion: WINDOWS_IDENTITY_NORMALIZATION_SCHEMA_VERSION,
    stage: "engagement_log_and_observations",
    toolId: result.toolId,
    actionFingerprint: result.actionFingerprint,
    status,
    summary: status === "completed"
      ? observations.length > 0
        ? `${observations.length} structured identity observation${observations.length === 1 ? " was" : "s were"} parsed from the bounded tool result.`
        : "The bounded identity read completed without a structured observation."
      : failure?.humanMessage ?? "The identity read was cancelled.",
    observations: Object.freeze(observations),
    engagementLog: Object.freeze({
      stdout,
      stderr,
      outputSha256,
      outputTruncated: result.outputTruncated,
    }),
    evidenceCandidates: [] as const,
    verifiedEvidence: [] as const,
    failure,
  });
}
