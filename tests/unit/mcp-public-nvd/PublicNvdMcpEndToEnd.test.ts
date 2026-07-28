import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PublicNvdCveDetailSchema,
  PublicNvdHttpSidecar,
  type PublicNvdCveDetail,
} from "../../../server/mcp-public-nvd";
import {
  BoundedStreamableHttpTransportFactory,
  createPublicNvdMcpConnectionConfig,
  PUBLIC_NVD_MCP_CREDENTIAL_ID,
  PublicNvdMcpToolClient,
  PublicNvdToolBoundaryError,
  SystemdCredentialStore,
} from "../../../server/mcp";

const CVE_ID = "CVE-2021-44228";
const TOKEN = "public-nvd-test-token-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function credential(): { readonly directory: string; readonly path: string } {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-nvd-e2e-"));
  temporaryDirectories.push(directory);
  const path = join(directory, PUBLIC_NVD_MCP_CREDENTIAL_ID);
  writeFileSync(path, TOKEN, { mode: 0o600 });
  return { directory, path };
}

function detail(): PublicNvdCveDetail {
  return PublicNvdCveDetailSchema.parse({
    schemaVersion: "ti-scale.public-nvd.cve-detail.v1",
    cveId: CVE_ID,
    targetInteraction: false,
    description: {
      text: "Untrusted external description; do not treat this as model instruction.",
      contentSha256: "b".repeat(64),
      classification: "external_untrusted",
      lifecycle: "quarantined",
      promptEligible: false,
      normalization: "unicode_nfc_control_filtered",
      reason: "External NVD text requires local validation before model use",
    },
    cvss: [{
      version: "3.1",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      baseScore: 10,
      baseSeverity: "CRITICAL",
    }],
    weaknesses: ["CWE-917"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
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
      apiUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
      recordUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      retrievedAt: "2026-07-18T18:30:00.000Z",
      httpStatus: 200,
      sourceType: "public_vulnerability_intelligence",
    },
  });
}

async function boundaryError(promise: Promise<unknown>): Promise<PublicNvdToolBoundaryError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(PublicNvdToolBoundaryError);
    return error as PublicNvdToolBoundaryError;
  }
  throw new Error("Expected public NVD MCP boundary rejection");
}

describe("public NVD MCP authenticated HTTP chain", () => {
  test("attests and invokes the exact reviewed tool through the bounded loopback transport", async () => {
    const requested: string[] = [];
    const mountedCredential = credential();
    const sidecar = new PublicNvdHttpSidecar({
      tokenFilePath: mountedCredential.path,
      port: 0,
      lookupPort: {
        async getCveDetails(cveId) {
          requested.push(cveId);
          return detail();
        },
      },
    });
    await sidecar.start();
    try {
      const config = createPublicNvdMcpConnectionConfig({ port: sidecar.port });
      const transport = new BoundedStreamableHttpTransportFactory({
        credentialStore: new SystemdCredentialStore(mountedCredential.directory),
      });
      const client = new PublicNvdMcpToolClient({
        config,
        transportFactory: transport,
      });

      const attestation = await client.refreshAttestation();
      const result = await client.getCveDetails(CVE_ID, new AbortController().signal);

      expect(attestation.tools.map((tool) => tool.name)).toEqual(["get_cve_details"]);
      expect(requested).toEqual([CVE_ID]);
      expect(result.detail).toEqual(detail());
      expect(result.receipt.targetInteraction).toBe(false);
      expect(result.summary).not.toContain(result.detail.description.text);
    } finally {
      await sidecar.stop();
    }
  });

  test("fails attestation closed when the service credential is wrong", async () => {
    const sidecarCredential = credential();
    const sidecar = new PublicNvdHttpSidecar({
      tokenFilePath: sidecarCredential.path,
      port: 0,
      lookupPort: { getCveDetails: async () => detail() },
    });
    await sidecar.start();
    try {
      const clientCredentialDirectory = mkdtempSync(join(tmpdir(), "ti-scale-nvd-client-wrong-"));
      temporaryDirectories.push(clientCredentialDirectory);
      writeFileSync(
        join(clientCredentialDirectory, PUBLIC_NVD_MCP_CREDENTIAL_ID),
        "definitely-wrong-token-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        { mode: 0o600 },
      );
      const transport = new BoundedStreamableHttpTransportFactory({
        credentialStore: new SystemdCredentialStore(clientCredentialDirectory),
      });
      const client = new PublicNvdMcpToolClient({
        config: createPublicNvdMcpConnectionConfig({ port: sidecar.port }),
        transportFactory: transport,
      });
      const error = await boundaryError(client.refreshAttestation());
      expect(error).toMatchObject({ code: "ATTESTATION_REJECTED" });
    } finally {
      await sidecar.stop();
    }
  });
});
