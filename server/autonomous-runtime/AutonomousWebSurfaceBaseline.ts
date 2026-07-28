import { isIP } from "node:net";
import type { LocalToolCapabilityManifest } from "../local-tools";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
} from "../domain";

export const AUTONOMOUS_HTTP_METADATA_ACTION_TYPE =
  "ti-scale:autonomous-http-metadata-baseline" as const;
export const AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE =
  "ti-scale:autonomous-whatweb-fingerprint" as const;
export const AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE =
  "ti-scale:autonomous-endpoint-discovery" as const;
export const AUTONOMOUS_HTTP_METADATA_TOOL_ID = "kali:curl-http-metadata" as const;
export const AUTONOMOUS_WHATWEB_TOOL_ID = "kali:whatweb-bounded-fingerprint" as const;
export const AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID =
  "kali:ffuf-bounded-content-discovery" as const;
export const AUTONOMOUS_HTTP_METADATA_ACTION_CLASS = "web_crawling_page_capture" as const;
export const AUTONOMOUS_WHATWEB_ACTION_CLASS = "os_technology_fingerprinting" as const;
export const AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS =
  "web_content_endpoint_discovery_fuzzing" as const;
export const AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE = "http_exchange" as const;
export const AUTONOMOUS_WHATWEB_EVIDENCE_TYPE = "service_version_fingerprint" as const;
export const AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE =
  "endpoint_discovery_result" as const;
export const AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS = 32 as const;
/** Shared by the verifier and the next-phase authorization checker without a module cycle. */
export const AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION =
  "ti-scale.autonomous-web-evidence-verifier.v1" as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const CONTROL = /[\u0000-\u001F\u007F]/u;

export interface AutonomousWebSurfacePlanningConfiguration {
  readonly policyId: string;
  readonly httpMetadataBindingId: string;
  readonly whatwebBindingId: string;
  /** Additive opt-in; both endpoint fields must be present together. */
  readonly endpointDiscoveryBindingId?: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly logicalWorkspace: string;
  readonly maximumOrigins: number;
  readonly httpMetadataSuccessCriterion: string;
  readonly whatwebSuccessCriterion: string;
  readonly endpointDiscoverySuccessCriterion?: string;
}

export function autonomousEndpointDiscoveryEnabled(
  input: AutonomousWebSurfacePlanningConfiguration,
): input is AutonomousWebSurfacePlanningConfiguration & Readonly<{
  endpointDiscoveryBindingId: string;
  endpointDiscoverySuccessCriterion: string;
}> {
  return input.endpointDiscoveryBindingId !== undefined
    && input.endpointDiscoverySuccessCriterion !== undefined;
}

export interface VerifiedTcpServiceFingerprint {
  readonly port: number;
  readonly transport: "tcp";
  readonly state: "open";
  readonly service: string | null;
  readonly version?: string | null;
}

function stableId(value: string, label: string): void {
  if (value !== value.trim() || !PUBLIC_ID.test(value)) {
    throw new TypeError(`${label} must be one stable public ID`);
  }
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new TypeError("The Autonomous web-surface parent target must be one exact IP literal");
  }
  const hostname = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (normalized !== value.toLowerCase()) {
    throw new TypeError("The Autonomous web-surface parent target must use canonical IP spelling");
  }
  return normalized;
}

function schemeForService(value: string | null): "http" | "https" | null {
  const service = value?.trim().toLowerCase() ?? "";
  if (["https", "https-alt", "ssl/http", "ssl/http-alt"].includes(service)) return "https";
  if (["http", "http-alt", "http-proxy"].includes(service)) return "http";
  return null;
}

/**
 * Converts only evidence-backed HTTP service labels into canonical origins.
 * Port-number guesses, hostnames, redirects, and path expansion are forbidden.
 */
export function deriveAutonomousWebOrigins(
  target: string,
  fingerprints: readonly VerifiedTcpServiceFingerprint[],
  maximumOrigins: number = AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
): readonly string[] {
  const ip = canonicalIp(target);
  if (!Number.isSafeInteger(maximumOrigins) || maximumOrigins < 1
    || maximumOrigins > AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS) {
    throw new RangeError(`maximumOrigins must be 1 through ${AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS}`);
  }
  const host = isIP(ip) === 6 ? `[${ip}]` : ip;
  const origins = fingerprints.flatMap((fingerprint) => {
    if (!Number.isSafeInteger(fingerprint.port) || fingerprint.port < 1
      || fingerprint.port > 65_535 || fingerprint.transport !== "tcp"
      || fingerprint.state !== "open") {
      throw new TypeError("Verified service fingerprints contain an invalid open TCP record");
    }
    const scheme = schemeForService(fingerprint.service);
    if (!scheme) return [];
    const defaultPort = (scheme === "http" && fingerprint.port === 80)
      || (scheme === "https" && fingerprint.port === 443);
    return [`${scheme}://${host}${defaultPort ? "" : `:${fingerprint.port}`}/`];
  });
  const unique = [...new Set(origins)].sort((left, right) => left.localeCompare(right));
  if (unique.length > maximumOrigins) {
    throw new RangeError(
      `Verified reconnaissance derived ${unique.length} web origins, above the reviewed ${maximumOrigins}-origin bound`,
    );
  }
  return Object.freeze(unique);
}

export function validateAutonomousWebSurfaceConfiguration(
  input: AutonomousWebSurfacePlanningConfiguration,
  manifest: LocalToolCapabilityManifest,
): AutonomousWebSurfacePlanningConfiguration {
  stableId(input.policyId, "webSurface.policyId");
  stableId(input.httpMetadataBindingId, "webSurface.httpMetadataBindingId");
  stableId(input.whatwebBindingId, "webSurface.whatwebBindingId");
  if ((input.endpointDiscoveryBindingId === undefined)
    !== (input.endpointDiscoverySuccessCriterion === undefined)) {
    throw new TypeError(
      "Autonomous endpoint discovery requires both its binding ID and canonical success criterion",
    );
  }
  if (input.endpointDiscoveryBindingId !== undefined) {
    stableId(input.endpointDiscoveryBindingId, "webSurface.endpointDiscoveryBindingId");
  }
  stableId(input.agentId, "webSurface.agentId");
  stableId(input.providerId, "webSurface.providerId");
  stableId(input.modelId, "webSurface.modelId");
  if (!SHA256.test(input.modelConfigurationHash)) {
    throw new TypeError("webSurface.modelConfigurationHash must be SHA-256");
  }
  if (!input.logicalWorkspace.startsWith("/") || input.logicalWorkspace !== input.logicalWorkspace.trim()
    || input.logicalWorkspace.length > 4_096 || CONTROL.test(input.logicalWorkspace)) {
    throw new TypeError("webSurface.logicalWorkspace must be one safe absolute logical path");
  }
  if (!Number.isSafeInteger(input.maximumOrigins) || input.maximumOrigins < 1
    || input.maximumOrigins > AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS) {
    throw new RangeError(`webSurface.maximumOrigins must be 1 through ${AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS}`);
  }
  if (input.httpMetadataSuccessCriterion !== AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION
    || input.whatwebSuccessCriterion !== AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION) {
    throw new TypeError("Autonomous web-surface success criteria must use the canonical outcome registry");
  }
  if (input.endpointDiscoverySuccessCriterion !== undefined
    && input.endpointDiscoverySuccessCriterion !== AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION) {
    throw new TypeError(
      "Autonomous endpoint discovery must use the canonical outcome registry criterion",
    );
  }
  const http = manifest.resolve(AUTONOMOUS_HTTP_METADATA_TOOL_ID);
  const whatweb = manifest.resolve(AUTONOMOUS_WHATWEB_TOOL_ID);
  if (!http || http.activation !== "enabled" || http.routing.targetKind !== "url"
    || !http.actionClassIds.includes(AUTONOMOUS_HTTP_METADATA_ACTION_CLASS)
    || !http.evidenceTypeIds.includes(AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE)) {
    throw new TypeError("The exact reviewed HTTP metadata tool is missing from the active manifest");
  }
  if (!whatweb || whatweb.activation !== "enabled" || whatweb.routing.targetKind !== "url"
    || !whatweb.actionClassIds.includes(AUTONOMOUS_WHATWEB_ACTION_CLASS)
    || !whatweb.evidenceTypeIds.includes(AUTONOMOUS_WHATWEB_EVIDENCE_TYPE)) {
    throw new TypeError("The exact reviewed WhatWeb tool is missing from the active manifest");
  }
  if (autonomousEndpointDiscoveryEnabled(input)) {
    const endpoint = manifest.resolve(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID);
    if (!endpoint || endpoint.activation !== "enabled" || endpoint.routing.targetKind !== "url"
      || endpoint.routing.intent !== "web_content_discovery"
      || endpoint.stagedInput?.kind !== "fixed_lines"
      || endpoint.stagedInput.lines.length !== 14
      || !endpoint.actionClassIds.includes(AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS)
      || !endpoint.evidenceTypeIds.includes(AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE)) {
      throw new TypeError(
        "The exact reviewed fixed-dictionary endpoint-discovery tool is missing from the active manifest",
      );
    }
  }
  return Object.freeze({ ...input });
}
