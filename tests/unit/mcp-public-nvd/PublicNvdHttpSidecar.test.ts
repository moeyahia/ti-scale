import { afterEach, describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  chmodSync,
  chownSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { request as nodeHttpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PUBLIC_NVD_MCP_BIND,
  PUBLIC_NVD_MCP_PATH,
  PublicNvdHttpSidecar,
  loadPublicNvdBearerToken,
  resolvePublicNvdHttpPort,
} from "../../../server/mcp-public-nvd/PublicNvdHttpSidecar";
import {
  PUBLIC_NVD_TOOL_NAME,
  PublicNvdCveDetailSchema,
  type PublicNvdCveDetail,
} from "../../../server/mcp-public-nvd/types";

const TOKEN = "ti_scale_nvd_test_token_abcdefghijklmnopqrstuvwxyz_0123456789";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

function credential(mode = 0o600): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-public-nvd-http-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "mcp-token");
  writeFileSync(path, `${TOKEN}\n`, { mode });
  chmodSync(path, mode);
  return path;
}

function detail(): PublicNvdCveDetail {
  return PublicNvdCveDetailSchema.parse({
    schemaVersion: "ti-scale.public-nvd.cve-detail.v1",
    cveId: "CVE-2021-44228",
    targetInteraction: false,
    description: {
      text: "External NVD description",
      contentSha256: "b".repeat(64),
      classification: "external_untrusted",
      lifecycle: "quarantined",
      promptEligible: false,
      normalization: "unicode_nfc_control_filtered",
      reason: "External NVD text requires local validation before model use",
    },
    cvss: [],
    weaknesses: [],
    references: [],
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
      retrievedAt: "2026-07-18T15:00:00.000Z",
      httpStatus: 200,
      sourceType: "public_vulnerability_intelligence",
    },
  });
}

async function startSidecar(options: {
  readonly maxRequestBytes?: number;
  readonly lookup?: (cveId: string) => Promise<PublicNvdCveDetail>;
} = {}): Promise<PublicNvdHttpSidecar> {
  const sidecar = new PublicNvdHttpSidecar({
    tokenFilePath: credential(),
    port: 0,
    ...(options.maxRequestBytes !== undefined
      ? { maxRequestBytes: options.maxRequestBytes }
      : {}),
    lookupPort: {
      getCveDetails: options.lookup ?? (async () => detail()),
    },
  });
  await sidecar.start();
  return sidecar;
}

function authorizedHeaders(contentType = "application/json") {
  return {
    Authorization: `Bearer ${TOKEN}`,
    "Content-Type": contentType,
  };
}

async function chunkedPost(endpoint: URL, chunks: readonly string[]): Promise<{
  readonly status: number;
  readonly body: string;
}> {
  return await new Promise((resolveRequest, rejectRequest) => {
    const request = nodeHttpRequest(endpoint, {
      method: "POST",
      headers: {
        ...authorizedHeaders(),
        "Transfer-Encoding": "chunked",
      },
    }, (response) => {
      const body: Buffer[] = [];
      response.on("data", (chunk) => body.push(Buffer.from(chunk)));
      response.once("end", () => resolveRequest({
        status: response.statusCode ?? 0,
        body: Buffer.concat(body).toString("utf8"),
      }));
    });
    request.once("error", rejectRequest);
    for (const chunk of chunks) request.write(chunk);
    request.end();
  });
}

describe("PublicNvdHttpSidecar", () => {
  test("loads only a private regular credential file and rejects unsafe paths", () => {
    const path = credential();
    expect(Buffer.from(loadPublicNvdBearerToken(path)).toString("utf8")).toBe(TOKEN);

    const broad = credential(0o644);
    expect(() => loadPublicNvdBearerToken(broad)).toThrow("must not be accessible to group or other users");

    if (typeof process.geteuid === "function" && process.geteuid() === 0) {
      const wrongOwner = credential();
      chownSync(wrongOwner, 65_534, 65_534);
      expect(() => loadPublicNvdBearerToken(wrongOwner, 65_533)).toThrow(
        "must be owned by root or the sidecar service user",
      );
    }

    const directory = mkdtempSync(join(tmpdir(), "ti-scale-public-nvd-link-"));
    temporaryDirectories.push(directory);
    const link = join(directory, "linked-token");
    symlinkSync(path, link);
    expect(() => loadPublicNvdBearerToken(link)).toThrow("regular, non-symlink file");
    expect(() => loadPublicNvdBearerToken("relative-token")).toThrow("must be absolute");
  });

  test("binds only IPv4 loopback at the fixed MCP path and completes list/call over authenticated Streamable HTTP", async () => {
    const requested: string[] = [];
    const sidecar = await startSidecar({
      lookup: async (cveId) => {
        requested.push(cveId);
        return detail();
      },
    });
    const transport = new StreamableHTTPClientTransport(sidecar.endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    const client = new Client({ name: "public-nvd-http-test", version: "0.0.0" }, { capabilities: {} });
    try {
      expect(sidecar.endpoint.hostname).toBe(PUBLIC_NVD_MCP_BIND);
      expect(sidecar.endpoint.pathname).toBe(PUBLIC_NVD_MCP_PATH);
      await client.connect(transport);
      const listed = await client.listTools();
      expect(listed.tools.map(({ name }) => name)).toEqual([PUBLIC_NVD_TOOL_NAME]);
      const result = await client.callTool({
        name: PUBLIC_NVD_TOOL_NAME,
        arguments: { cveId: "CVE-2021-44228" },
      });
      expect(result.isError).not.toBe(true);
      expect(PublicNvdCveDetailSchema.parse(result.structuredContent).targetInteraction).toBe(false);
      expect(requested).toEqual(["CVE-2021-44228"]);
    } finally {
      await client.close().catch(() => undefined);
      await sidecar.stop();
    }
  });

  test("requires the exact bearer credential without reflecting it in any response", async () => {
    const sidecar = await startSidecar();
    try {
      for (const authorization of [undefined, "Bearer wrong-token-value-which-is-long-enough"] as const) {
        const response = await fetch(sidecar.endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(authorization ? { Authorization: authorization } : {}),
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
        });
        expect(response.status).toBe(401);
        expect(response.headers.get("www-authenticate")).toBe('Bearer realm="ti-scale-public-nvd"');
        const body = await response.text();
        expect(body).not.toContain(TOKEN);
        expect(body).not.toContain("wrong-token-value");
      }
    } finally {
      await sidecar.stop();
    }
  });

  test("rejects every non-POST method and non-JSON content type before MCP handling", async () => {
    const sidecar = await startSidecar();
    try {
      const get = await fetch(sidecar.endpoint, {
        method: "GET",
        headers: { Authorization: `Bearer ${TOKEN}` },
      });
      expect(get.status).toBe(405);
      expect(get.headers.get("allow")).toBe("POST");

      const wrongType = await fetch(sidecar.endpoint, {
        method: "POST",
        headers: authorizedHeaders("text/plain"),
        body: "{}",
      });
      expect(wrongType.status).toBe(415);

      const wrongPath = await fetch(new URL("/other", sidecar.endpoint), {
        method: "POST",
        headers: authorizedHeaders(),
        body: "{}",
      });
      expect(wrongPath.status).toBe(404);

      const wrongOrigin = await fetch(sidecar.endpoint, {
        method: "POST",
        headers: { ...authorizedHeaders(), Origin: "https://untrusted.example" },
        body: "{}",
      });
      expect(wrongOrigin.status).toBe(403);
    } finally {
      await sidecar.stop();
    }
  });

  test("rejects malformed and oversized request bodies before the MCP SDK", async () => {
    const sidecar = await startSidecar({ maxRequestBytes: 1_024 });
    try {
      const malformed = await fetch(sidecar.endpoint, {
        method: "POST",
        headers: authorizedHeaders(),
        body: "{not-json",
      });
      expect(malformed.status).toBe(400);
      expect(await malformed.text()).not.toContain(TOKEN);

      const oversized = await fetch(sidecar.endpoint, {
        method: "POST",
        headers: authorizedHeaders(),
        body: JSON.stringify({ padding: "x".repeat(2_000) }),
      });
      expect(oversized.status).toBe(413);
      expect(await oversized.text()).toContain("request_too_large");

      const chunked = await chunkedPost(sidecar.endpoint, ["x".repeat(800), "x".repeat(800)]);
      expect(chunked.status).toBe(413);
      expect(chunked.body).toContain("request_too_large");
    } finally {
      await sidecar.stop();
    }
  });

  test("closes the loopback listener during graceful shutdown", async () => {
    const sidecar = await startSidecar();
    const endpoint = sidecar.endpoint;
    expect(sidecar.port).toBeGreaterThan(0);
    await sidecar.stop();
    expect(() => sidecar.port).toThrow("not listening");
    await expect(fetch(endpoint, { signal: AbortSignal.timeout(500) })).rejects.toBeDefined();
  });

  test("does not expose an unexpected lookup error or bearer token on the wire", async () => {
    const upstreamSecret = `unexpected-upstream-${TOKEN}`;
    const sidecar = await startSidecar({
      lookup: async () => { throw new Error(upstreamSecret); },
    });
    const transport = new StreamableHTTPClientTransport(sidecar.endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    const client = new Client({ name: "public-nvd-http-error-test", version: "0.0.0" }, { capabilities: {} });
    try {
      await client.connect(transport);
      const result = await client.callTool({
        name: PUBLIC_NVD_TOOL_NAME,
        arguments: { cveId: "CVE-2021-44228" },
      });
      const serialized = JSON.stringify(result);
      expect(result.isError).toBe(true);
      expect(serialized).not.toContain(TOKEN);
      expect(serialized).not.toContain(upstreamSecret);
      expect(serialized).toContain("could not be processed safely");
      expect(serialized).toContain('"ti-scale/targetInteraction":false');
    } finally {
      await client.close().catch(() => undefined);
      await sidecar.stop();
    }
  });

  test("validates the optional sidecar port without allowing alternate bind addresses", () => {
    expect(resolvePublicNvdHttpPort(undefined)).toBe(43_142);
    expect(resolvePublicNvdHttpPort("43143")).toBe(43_143);
    expect(() => resolvePublicNvdHttpPort("0")).toThrow();
    expect(() => resolvePublicNvdHttpPort("not-a-port")).toThrow();
  });
});
