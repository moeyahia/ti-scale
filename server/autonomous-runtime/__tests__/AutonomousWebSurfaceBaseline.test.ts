import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
} from "../../domain";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
} from "../../local-tools";
import { composeReviewedWebAssessmentLocalManifest } from "../../web-assessment-tools";
import {
  AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  createAutonomousFullTcpBaselineManifest,
  deriveAutonomousWebOrigins,
  validateAutonomousWebSurfaceConfiguration,
  type AutonomousWebSurfacePlanningConfiguration,
} from "..";

function manifest(): LocalToolCapabilityManifest {
  const base = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL(
      "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
      import.meta.url,
    ),
    "utf8",
  )) as unknown);
  const fullTcp = createAutonomousFullTcpBaselineManifest().list()
    .map(({ bindingSha256: _bindingSha256, ...tool }) => tool);
  const withFullTcp = new LocalToolCapabilityManifest({
    ...base,
    manifestVersion: "autonomous-web-baseline-test-v1",
    tools: [...base.tools, ...fullTcp],
  });
  return composeReviewedWebAssessmentLocalManifest(withFullTcp);
}

function configuration(): AutonomousWebSurfacePlanningConfiguration {
  return {
    policyId: "policy:autonomous-web-test",
    httpMetadataBindingId: "binding:autonomous-http-metadata-test",
    whatwebBindingId: "binding:autonomous-whatweb-test",
    agentId: "specialist:autonomous-web-test",
    providerId: "provider:local-deterministic-test",
    modelId: "policy:local-autonomous-web-test",
    modelConfigurationHash: "a".repeat(64),
    logicalWorkspace: "/engagements/autonomous-web-test",
    maximumOrigins: 8,
    httpMetadataSuccessCriterion: AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
    whatwebSuccessCriterion: AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
  };
}

describe("Autonomous evidence-derived web origins", () => {
  test("derives only explicit HTTP service labels without guessing ports", () => {
    expect(deriveAutonomousWebOrigins("192.0.2.10", [
      { port: 80, transport: "tcp", state: "open", service: "http" },
      { port: 8443, transport: "tcp", state: "open", service: "https-alt" },
      { port: 443, transport: "tcp", state: "open", service: "unknown" },
      { port: 22, transport: "tcp", state: "open", service: "ssh" },
    ])).toEqual([
      "http://192.0.2.10/",
      "https://192.0.2.10:8443/",
    ]);
  });

  test("canonicalizes IPv6 origins and preserves evidence-backed non-default ports", () => {
    expect(deriveAutonomousWebOrigins("2001:db8::5", [
      { port: 8080, transport: "tcp", state: "open", service: "http-alt" },
      { port: 443, transport: "tcp", state: "open", service: "ssl/http" },
    ])).toEqual([
      "http://[2001:db8::5]:8080/",
      "https://[2001:db8::5]/",
    ]);
  });

  test("rejects adversarial near-matches instead of expanding contact authority", () => {
    expect(deriveAutonomousWebOrigins("192.0.2.12", [
      { port: 9001, transport: "tcp", state: "open", service: "httpsomething" },
      { port: 9002, transport: "tcp", state: "open", service: "xssl/httpx" },
      { port: 9003, transport: "tcp", state: "open", service: "http/custom" },
      { port: 9004, transport: "tcp", state: "open", service: "custom/http" },
      { port: 9005, transport: "tcp", state: "open", service: "ssl/http-alt" },
    ])).toEqual(["https://192.0.2.12:9005/"]);
  });

  test("fails closed when verified origins exceed the reviewed bound", () => {
    const fingerprints = Array.from({ length: AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS + 1 },
      (_, index) => ({
        port: 1_000 + index,
        transport: "tcp" as const,
        state: "open" as const,
        service: "http",
      }));
    expect(() => deriveAutonomousWebOrigins(
      "192.0.2.11",
      fingerprints,
      AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
    )).toThrow("above the reviewed");
  });

  test("binds the exact reviewed curl and WhatWeb physical tools", () => {
    const value = validateAutonomousWebSurfaceConfiguration(configuration(), manifest());
    expect(value.maximumOrigins).toBe(8);
    expect(manifest().resolve(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID)).toBeDefined();
    expect(manifest().resolve(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID)).toBeDefined();
  });

  test("enables endpoint discovery only with the paired canonical binding and reviewed FFUF dictionary", () => {
    const value = validateAutonomousWebSurfaceConfiguration({
      ...configuration(),
      endpointDiscoveryBindingId: "binding:autonomous-endpoint-test",
      endpointDiscoverySuccessCriterion: AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
    }, manifest());
    expect(value.endpointDiscoveryBindingId).toBe("binding:autonomous-endpoint-test");
    const endpoint = manifest().resolve(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID);
    expect(endpoint).toMatchObject({
      activation: "enabled",
      routing: { intent: "web_content_discovery", targetKind: "url" },
      stagedInput: { kind: "fixed_lines" },
    });
    if (endpoint?.stagedInput?.kind !== "fixed_lines") {
      throw new Error("reviewed endpoint dictionary is unavailable");
    }
    expect(endpoint.stagedInput.lines).toHaveLength(14);
    expect(() => validateAutonomousWebSurfaceConfiguration({
      ...configuration(),
      endpointDiscoveryBindingId: "binding:autonomous-endpoint-test",
    }, manifest())).toThrow("requires both");
  });
});
